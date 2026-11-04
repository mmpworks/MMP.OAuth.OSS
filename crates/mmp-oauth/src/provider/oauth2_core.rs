//! The shared `oauth2` 5.0 client code for every provider adapter.
//!
//! Google and Microsoft run the same RFC 6749 authorization-code flow with PKCE.
//! They differ in a few places: extra consent-URL parameters, whether a client
//! secret is sent, whether a revocation endpoint exists, and which provider error
//! codes mean "ask for consent again". [`Core`] holds the common flow, and each
//! adapter passes its differences in as data or as a classifier function.
//!
//! No response text reaches an error. `OAuthError`'s Display and Debug end up in
//! logs and UI, and a provider's `error_description`, an extension error code, a
//! serde message that quotes a field value, or a Content-Type header can each carry
//! a credential. An error carries only fixed text: an allowlisted RFC 6749 section
//! 5.2 code name and, for a parse failure, the name of a known token-response field.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use oauth2::basic::{BasicClient, BasicErrorResponseType};
use oauth2::{
    AsyncHttpClient, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken,
    EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest, HttpResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, RefreshToken, RevocationUrl, Scope, TokenResponse, TokenUrl,
};

use crate::error::OAuthError;
use crate::flow::{AuthSession, PendingExchange};
use crate::provider::ProviderProfile;
use crate::token::{AccessGrant, RefreshedGrant, TokenPair};
use crate::Secret;

/// The `oauth2` client type every adapter uses. The endpoint type-state markers, in
/// oauth2 5.0 order, are: auth=Set, device=NotSet, introspection=NotSet,
/// revocation=MaybeSet, token=Set. "`MaybeSet`" lets one type serve a provider with a
/// revocation endpoint (Google) and one without (Microsoft); `revoke_token` then
/// returns a configuration error when the URL is absent.
pub(crate) type CoreClient =
    BasicClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointSet>;

/// Maps an RFC 6749 section 5.2 error code from the token endpoint to an
/// [`OAuthError`]. Each adapter passes one; [`classify_token_error`] is the default.
pub(crate) type Classifier = fn(&BasicErrorResponseType) -> OAuthError;

/// A redirect URI for the clients that refresh and revoke. `oauth2` needs one to
/// build the client, but a refresh request (RFC 6749 section 6) and a revocation
/// request (RFC 7009 section 2.1) send no `redirect_uri`, so this value never
/// reaches the wire. The code exchange uses the real URI from the `PendingExchange`.
const LOOPBACK_REDIRECT_PLACEHOLDER: &str = "http://127.0.0.1/callback";

/// The longest `Retry-After` wait this crate reports. The value comes from the
/// network, and a host may sleep on it, so a huge value must not stall the host.
const MAX_RETRY_AFTER: Duration = Duration::from_secs(86_400);

/// Why an HTTP call produced no usable response.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpFailure {
    /// The HTTP client's own error (connect, timeout, body read). It carries no
    /// response bytes.
    #[error("{0}")]
    Transport(oauth2::HttpClientError<reqwest::Error>),
    /// The server answered with a 5xx status. Its body is never read.
    #[error("server error {0}")]
    ServerError(u16),
    /// The server answered HTTP 429.
    #[error("rate limited")]
    Throttled { retry_after: Option<Duration> },
}

impl HttpFailure {
    /// The [`OAuthError`] for this failure. `context` names the failed request.
    fn into_error(self, context: &str) -> OAuthError {
        match self {
            HttpFailure::Throttled { retry_after } => OAuthError::Throttled { retry_after },
            HttpFailure::ServerError(status) => {
                OAuthError::Transient(format!("{context}: the provider returned HTTP {status}"))
            }
            HttpFailure::Transport(e) => OAuthError::Transient(format!("{context}: {e}")),
        }
    }
}

/// The reqwest client, plus the status check `oauth2` cannot make for this crate.
/// `oauth2` gives its caller the error body of a failed request but not the HTTP status
/// or the headers, so a 429 or a 503 looks like a 400 with the same body. This client
/// checks the status before it reads the body, so a body failure cannot hide it.
struct StatusAwareHttp(reqwest::Client);

impl<'c> AsyncHttpClient<'c> for StatusAwareHttp {
    type Error = HttpFailure;
    type Future =
        Pin<Box<dyn Future<Output = Result<HttpResponse, HttpFailure>> + Send + Sync + 'c>>;

    fn call(&'c self, request: HttpRequest) -> Self::Future {
        Box::pin(async move {
            let request = reqwest::Request::try_from(request).map_err(transport_failure)?;
            let response = self.0.execute(request).await.map_err(transport_failure)?;
            let status = response.status();
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                return Err(HttpFailure::Throttled {
                    retry_after: retry_after(response.headers()),
                });
            }
            if status.is_server_error() {
                return Err(HttpFailure::ServerError(status.as_u16()));
            }
            let mut builder = oauth2::http::Response::builder()
                .status(status)
                .version(response.version());
            for (name, value) in response.headers() {
                builder = builder.header(name, value);
            }
            let body = response.bytes().await.map_err(transport_failure)?;
            builder
                .body(body.to_vec())
                .map_err(|e| HttpFailure::Transport(oauth2::HttpClientError::Http(e)))
        })
    }
}

/// Wrap a reqwest error. `oauth2`'s wrapper displays a fixed label.
fn transport_failure(e: reqwest::Error) -> HttpFailure {
    HttpFailure::Transport(oauth2::HttpClientError::Reqwest(Box::new(e)))
}

/// The response's `Retry-After` value in seconds, capped at [`MAX_RETRY_AFTER`].
/// `None` when the header is absent, or holds an HTTP date or anything else that is
/// not a number of seconds (RFC 9110 section 10.2.3 also allows a date).
fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    let value = headers
        .get(oauth2::http::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    // A run of digits that overflows u64 is still "a very long wait", so it caps too.
    let seconds = value.parse::<u64>().unwrap_or(u64::MAX);
    Some(Duration::from_secs(seconds).min(MAX_RETRY_AFTER))
}

/// The common flow for one provider profile.
pub(crate) struct Core {
    pub(crate) profile: ProviderProfile,
    /// The reqwest client that `oauth2` posts through, with redirects off as an
    /// SSRF guard.
    http: StatusAwareHttp,
    /// The client secret to send, when the provider's client type needs one.
    pub(crate) client_secret: Option<Secret>,
    classify: Classifier,
}

impl Core {
    /// Build the common flow for `profile`, with `classify` for token errors.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the TLS backend cannot start.
    pub(crate) fn new(profile: ProviderProfile, classify: Classifier) -> Result<Self, OAuthError> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OAuthError::Config(format!("could not build HTTP client: {e}")))?;
        Ok(Self {
            profile,
            http: StatusAwareHttp(http),
            client_secret: None,
            classify,
        })
    }

    /// Build the `oauth2` client for one loopback redirect URI. The redirect URI
    /// changes per flow (the loopback port), so the client is built per call, not
    /// cached. Building it is cheap, and the per-flow URI stays out of shared state.
    fn client(&self, redirect_uri: &str) -> Result<CoreClient, OAuthError> {
        let p = &self.profile;
        let auth_url = AuthUrl::new(p.auth_url.clone())
            .map_err(|e| OAuthError::Config(format!("bad auth URL: {e}")))?;
        let token_url = TokenUrl::new(p.token_url.clone())
            .map_err(|e| OAuthError::Config(format!("bad token URL: {e}")))?;
        let redirect = RedirectUrl::new(redirect_uri.to_string())
            .map_err(|e| OAuthError::Config(format!("bad redirect URL: {e}")))?;
        let revocation = p
            .revocation_url
            .clone()
            .map(RevocationUrl::new)
            .transpose()
            .map_err(|e| OAuthError::Config(format!("bad revocation URL: {e}")))?;

        let client = BasicClient::new(ClientId::new(p.client_id.clone()))
            .set_auth_uri(auth_url)
            .set_token_uri(token_url)
            .set_redirect_uri(redirect)
            .set_revocation_url_option(revocation);
        Ok(match &self.client_secret {
            Some(secret) => {
                client.set_client_secret(ClientSecret::new(secret.expose().to_string()))
            }
            None => client,
        })
    }

    /// Build the consent URL with PKCE S256 and a CSRF `state`, plus the adapter's
    /// `scopes` and `extra_params`, and return the session that holds the verifier
    /// and the `state` in memory.
    ///
    /// It cannot fail, because the `Provider` trait requires that. If the client
    /// cannot be built (a bad URL), it still returns a session, with an
    /// `authorize_url` that names the misconfiguration. The flow then fails at once
    /// and visibly instead of opening a broken browser tab.
    pub(crate) fn begin(
        &self,
        scopes: Vec<String>,
        redirect_uri: &str,
        extra_params: &[(&str, &str)],
    ) -> AuthSession {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let csrf = CsrfToken::new_random();
        let authorize_url = match self.client(redirect_uri) {
            Ok(client) => {
                let mut builder = client
                    .authorize_url(|| csrf.clone())
                    .set_pkce_challenge(challenge);
                for scope in &scopes {
                    builder = builder.add_scope(Scope::new(scope.clone()));
                }
                for (name, value) in extra_params {
                    builder = builder.add_extra_param(*name, *value);
                }
                builder.url().0.to_string()
            }
            Err(e) => format!("about:blank#mmp-oauth-config-error={e}"),
        };
        AuthSession::new(
            authorize_url,
            redirect_uri,
            csrf.secret().clone(),
            Secret::new(verifier.secret().clone()),
            scopes,
        )
    }

    /// Exchange the authorization code for the first token pair. `missing_refresh`
    /// is the error text when the response carries no refresh token; it names what
    /// the provider needs (Google: offline access; Microsoft: `offline_access`).
    pub(crate) async fn exchange(
        &self,
        pending: PendingExchange,
        missing_refresh: &str,
    ) -> Result<TokenPair, OAuthError> {
        // RFC 6749 section 4.1.3: the token request's `redirect_uri` must equal the one
        // in the authorization request, with the real loopback port. A provider
        // rejects a mismatch, so this uses the redirect URI carried in the
        // PendingExchange, never a placeholder without the port.
        let client = self.client(&pending.redirect_uri)?;
        let verifier = PkceCodeVerifier::new(pending.pkce_verifier.expose().to_string());
        let response = client
            .exchange_code(AuthorizationCode::new(pending.code))
            .set_pkce_verifier(verifier)
            .request_async(&self.http)
            .await
            .map_err(|e| map_token_error(e, self.classify))?;

        // An empty refresh token is not a credential. Saving "" would leave the account
        // unable to refresh.
        let refresh = response
            .refresh_token()
            .filter(|rt| !rt.secret().is_empty())
            .map(|rt| Secret::new(rt.secret().clone()))
            .ok_or_else(|| OAuthError::Config(missing_refresh.into()))?;

        // The response's `scope` is what the user granted; consent can narrow it. With
        // no `scope` field, the requested scopes were granted (RFC 6749 section 5.1).
        let granted = response_scopes(&response).unwrap_or(pending.requested_scopes);
        Ok(TokenPair {
            grant: grant_from_response(&response, granted),
            refresh_token: refresh,
        })
    }

    /// Get a new access token from a refresh token. The request sends no `scope`,
    /// which RFC 6749 section 6 reads as "the scope originally granted".
    pub(crate) async fn refresh(
        &self,
        refresh_token: &Secret,
    ) -> Result<RefreshedGrant, OAuthError> {
        let client = self.client(LOOPBACK_REDIRECT_PLACEHOLDER)?;
        let response = client
            .exchange_refresh_token(&RefreshToken::new(refresh_token.expose().to_string()))
            .request_async(&self.http)
            .await
            .map_err(|e| map_token_error(e, self.classify))?;
        // A response `scope` is the new token's scope. An omitted `scope` arrives as an
        // empty list, and the service then applies the refresh token's consent scope.
        let scopes = response_scopes(&response).unwrap_or_default();
        // A rotating provider returns a new refresh token, which replaces the stored
        // one (RFC 6749 section 6). A provider that does not rotate returns none.
        let rotated = response
            .refresh_token()
            .map(|rt| Secret::new(rt.secret().clone()));
        Ok(RefreshedGrant {
            grant: grant_from_response(&response, scopes),
            refresh_token: rotated,
        })
    }

    /// Revoke a refresh token at the profile's RFC 7009 revocation endpoint.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the profile has no revocation endpoint, and
    /// [`OAuthError::Transient`] when the request fails.
    pub(crate) async fn revoke(&self, refresh_token: &Secret) -> Result<(), OAuthError> {
        use oauth2::StandardRevocableToken;
        let client = self.client(LOOPBACK_REDIRECT_PLACEHOLDER)?;
        let token = StandardRevocableToken::RefreshToken(RefreshToken::new(
            refresh_token.expose().to_string(),
        ));
        client
            .revoke_token(token)
            .map_err(|e| OAuthError::Config(format!("revocation not configured: {e}")))?
            .request_async(&self.http)
            .await
            .map_err(map_revoke_error)?;
        Ok(())
    }
}

/// Classify a revocation-endpoint error, with the same classes as a token error. A
/// dead token (`invalid_grant`, or `invalid_token`, a code outside RFC 6749 section 5.2
/// that a server can send for a dead token) means new consent. A client error, or an unsupported token
/// type (RFC 7009 section 2.2.1), is a configuration fault. As in [`map_token_error`],
/// no response text reaches the error.
pub(crate) fn map_revoke_error(
    e: oauth2::RequestTokenError<HttpFailure, oauth2::basic::BasicRevocationErrorResponse>,
) -> OAuthError {
    use oauth2::{RequestTokenError, RevocationErrorResponseType};
    match e {
        RequestTokenError::ServerResponse(resp) => match resp.error() {
            RevocationErrorResponseType::Basic(BasicErrorResponseType::Extension(code))
                if code == "invalid_token" =>
            {
                OAuthError::InvalidGrant {
                    reason: "invalid_token".to_string(),
                }
            }
            RevocationErrorResponseType::Basic(code) => classify_token_error(code),
            RevocationErrorResponseType::UnsupportedTokenType => OAuthError::Config(
                "revocation endpoint rejected the request: unsupported_token_type".into(),
            ),
        },
        RequestTokenError::Request(failure) => failure.into_error("revoke request failed"),
        RequestTokenError::Parse(..) => {
            OAuthError::Transient("revoke request failed: response could not be parsed".into())
        }
        RequestTokenError::Other(_) => {
            OAuthError::Transient("revoke request failed: unusable response".into())
        }
    }
}

/// The token response's `scope` entries, or `None` when the response grants none.
/// `oauth2` splits `scope` on single spaces, so `""` arrives as `[""]`, and a run of
/// spaces gives empty entries. RFC 6749 section 3.3 scope tokens are non-empty, so
/// empty entries are dropped, and a `scope` with no entries left counts as omitted.
pub(crate) fn response_scopes<TE, TT>(
    response: &oauth2::StandardTokenResponse<TE, TT>,
) -> Option<Vec<String>>
where
    TE: oauth2::ExtraTokenFields,
    TT: oauth2::TokenType,
{
    let entries: Vec<String> = response
        .scopes()?
        .iter()
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .collect();
    (!entries.is_empty()).then_some(entries)
}

/// Build an [`AccessGrant`] from an `oauth2` token response. The expiry is
/// `now + expires_in`. When the provider omits `expires_in`, the token counts as
/// due for refresh at once. The code never assumes an unbounded lifetime.
pub(crate) fn grant_from_response<TE, TT>(
    response: &oauth2::StandardTokenResponse<TE, TT>,
    requested_scopes: Vec<String>,
) -> AccessGrant
where
    TE: oauth2::ExtraTokenFields,
    TT: oauth2::TokenType,
{
    let now = now_unix();
    // `expires_in` comes from the network, so any u64 can arrive. Saturate instead
    // of overflowing: a value past the i64 range panics in a debug build and wraps
    // to a past expiry in a release build.
    let expires_at_unix = response.expires_in().map_or(now, |d| {
        now.saturating_add(i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
    });
    AccessGrant {
        access_token: Secret::new(response.access_token().secret().clone()),
        expires_at_unix,
        granted_scopes: requested_scopes,
    }
}

/// Fuzz entry for target F2: parse `body` as a token response and map it to a
/// grant, as an exchange does once `oauth2` accepts the HTTP response. `None` when
/// the body is not a token response.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_token_body(body: &[u8], requested_scopes: Vec<String>) -> Option<AccessGrant> {
    let response: oauth2::basic::BasicTokenResponse = serde_json::from_slice(body).ok()?;
    let grant = grant_from_response(&response, requested_scopes);
    Some(match response_scopes(&response) {
        Some(granted_scopes) => AccessGrant {
            granted_scopes,
            ..grant
        },
        None => grant,
    })
}

/// Fuzz entry for target F2: parse `body` as a token error response and classify
/// it with `classify`. `None` when the body is not an error response.
#[cfg(feature = "fuzzing")]
pub(crate) fn fuzz_error_body(body: &[u8], classify: Classifier) -> Option<OAuthError> {
    let response: oauth2::basic::BasicErrorResponse = serde_json::from_slice(body).ok()?;
    Some(classify(response.error()))
}

/// The current wall-clock time in Unix seconds. An adapter computes the absolute
/// expiry from the relative `expires_in` here. The service still reads its injected
/// [`crate::flow::Clock`] for the refresh check, so tests keep control of expiry.
pub(crate) fn now_unix() -> i64 {
    crate::flow::Clock::now_unix(&crate::flow::SystemClock)
}

/// Map an `oauth2` request error to an [`OAuthError`]. A token-endpoint error code
/// goes to `classify`, a rate limit is `Throttled`, and a transport or parse failure
/// is transient.
pub(crate) fn map_token_error(
    err: oauth2::RequestTokenError<HttpFailure, oauth2::basic::BasicErrorResponse>,
    classify: Classifier,
) -> OAuthError {
    use oauth2::RequestTokenError;
    match err {
        RequestTokenError::ServerResponse(resp) => classify(resp.error()),
        RequestTokenError::Request(failure) => failure.into_error("token request failed"),
        RequestTokenError::Parse(e, _) => {
            let at = known_token_field(&e.path().to_string())
                .map(|field| format!(" at field `{field}`"))
                .unwrap_or_default();
            OAuthError::Transient(format!("token response could not be parsed{at}"))
        }
        RequestTokenError::Other(_) => OAuthError::Transient(
            "token endpoint returned an unusable response (empty body or non-JSON Content-Type)"
                .into(),
        ),
    }
}

/// The default classification of an RFC 6749 section 5.2 token-endpoint error.
///
/// - `invalid_grant`: the grant is dead, so the user must consent again.
/// - `invalid_client`, `invalid_request`, `unauthorized_client`,
///   `unsupported_grant_type`, `invalid_scope`: the request itself is wrong (a bad
///   client id or secret, a bad scope). A retry sends the same request and fails
///   the same way, so these are [`OAuthError::Config`], which is not retryable and
///   does not ask the user for consent.
/// - Any other code is an extension code (for example a provider's server error).
///   It stays retryable.
///
/// Only the allowlisted label leaves this function.
pub(crate) fn classify_token_error(code: &BasicErrorResponseType) -> OAuthError {
    use BasicErrorResponseType as Code;
    let label = allowlisted_token_error(code);
    match code {
        Code::InvalidGrant => OAuthError::InvalidGrant {
            reason: label.to_string(),
        },
        Code::InvalidClient
        | Code::InvalidRequest
        | Code::UnauthorizedClient
        | Code::UnsupportedGrantType
        | Code::InvalidScope => {
            OAuthError::Config(format!("token endpoint rejected the request: {label}"))
        }
        Code::Extension(_) => OAuthError::Transient(format!(
            "token endpoint rejected: {label} (provider description withheld)"
        )),
    }
}

/// The RFC 6749 section 5.2 error-code name. An extension code is provider text,
/// so it becomes the fixed label `unrecognized_error`.
pub(crate) fn allowlisted_token_error(code: &BasicErrorResponseType) -> &'static str {
    use BasicErrorResponseType as Code;
    match code {
        Code::InvalidClient => "invalid_client",
        Code::InvalidGrant => "invalid_grant",
        Code::InvalidRequest => "invalid_request",
        Code::InvalidScope => "invalid_scope",
        Code::UnauthorizedClient => "unauthorized_client",
        Code::UnsupportedGrantType => "unsupported_grant_type",
        Code::Extension(_) => "unrecognized_error",
    }
}

/// The token-response fields a parse error may name. Any other key came from the
/// response, so it is never echoed.
const TOKEN_RESPONSE_FIELDS: [&str; 8] = [
    "access_token",
    "token_type",
    "expires_in",
    "refresh_token",
    "scope",
    "error",
    "error_description",
    "error_uri",
];

/// `path` when it names a known token-response field, else `None`.
fn known_token_field(path: &str) -> Option<&'static str> {
    TOKEN_RESPONSE_FIELDS
        .iter()
        .copied()
        .find(|field| *field == path)
}
