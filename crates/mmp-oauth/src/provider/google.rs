//! `GoogleProvider`: the Google OAuth adapter over `oauth2` 5.0.
//!
//! It issues tokens for any Google resource the host's scopes select (Gmail,
//! Drive, Calendar). It adapts the four methods to the `oauth2` type-state client
//! and owns Google's quirks: a `127.0.0.1` loopback redirect (never `localhost`),
//! PKCE S256, the client secret (see [`GoogleProvider::with_secret`]), and the
//! revoke form.
//!
//! ## Which scopes need Google's app verification
//!
//! Google sorts scopes into non-sensitive, sensitive and restricted. An app that
//! requests a sensitive or restricted scope (a mailbox scope is restricted) must
//! pass Google's app verification before it ships to the public. The email scope
//! (`https://www.googleapis.com/auth/userinfo.email`) is non-sensitive, so a smoke
//! test with only that scope needs no verification. This crate's testbed uses it
//! as its default scope for that reason.
//!
//! The `oauth2` type-state turns "exchange before setting the token URI" into a
//! compile error, so an endpoint mistake cannot ship. The HTTP client is `reqwest`
//! with `redirect::Policy::none()`, the SSRF guard that the `oauth2` docs name.

use async_trait::async_trait;

use super::oauth2_core::{classify_token_error, Core};
#[cfg(test)]
use super::oauth2_core::{map_revoke_error, now_unix, HttpFailure};
use crate::error::OAuthError;
use crate::flow::{AuthSession, PendingExchange};
use crate::provider::{Provider, ProviderKind, ProviderProfile, ScopeRequest};
use crate::token::{RefreshedGrant, TokenPair};
use crate::Secret;

/// The Google OAuth provider. The host's scopes pick the resource.
pub struct GoogleProvider {
    core: Core,
}

impl GoogleProvider {
    /// Build the provider with the application's client id from configuration.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the TLS backend cannot start.
    pub fn new(client_id: impl Into<String>) -> Result<Self, OAuthError> {
        Ok(Self {
            core: Core::new(ProviderProfile::google(client_id), classify_token_error)?,
        })
    }

    /// Attach the OAuth client secret.
    ///
    /// A desktop app is a public client: it cannot keep a secret (RFC 8252 section
    /// 8.5). Google's "Desktop app" client type is the exception to the usual rule:
    /// its token endpoint still requires `client_secret` in the code exchange and the
    /// refresh, even with PKCE, and returns `invalid_request` without it. Google
    /// documents that it does not treat this secret as confidential for an installed
    /// app. Pass `None` for a client type that has no secret.
    #[must_use]
    pub fn with_secret(mut self, client_secret: Option<Secret>) -> Self {
        self.core.client_secret = client_secret;
        self
    }

    /// Build from an explicit profile. The wiremock tests use it to point the
    /// auth, token and revocation endpoints at a local mock server, which tests the
    /// real reqwest and oauth2 code with no call to Google.
    #[cfg(test)]
    pub(crate) fn from_profile(profile: ProviderProfile) -> Result<Self, OAuthError> {
        Ok(Self {
            core: Core::new(profile, classify_token_error)?,
        })
    }
}

#[async_trait]
impl Provider for GoogleProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Google
    }

    fn profile(&self) -> &ProviderProfile {
        &self.core.profile
    }

    fn begin_authorization(&self, scopes: &[ScopeRequest], redirect_uri: &str) -> AuthSession {
        // `access_type=offline` makes Google issue a refresh token, and
        // `prompt=consent` makes it issue one again on re-consent.
        let requested = scopes.iter().map(|s| s.scope.clone()).collect();
        self.core.begin(
            requested,
            redirect_uri,
            &[("access_type", "offline"), ("prompt", "consent")],
        )
    }

    async fn exchange_code(&self, pending: PendingExchange) -> Result<TokenPair, OAuthError> {
        self.core
            .exchange(
                pending,
                "Google returned no refresh token (need access_type=offline + prompt=consent)",
            )
            .await
    }

    async fn refresh(&self, refresh_token: &Secret) -> Result<RefreshedGrant, OAuthError> {
        // Google does not rotate refresh tokens, so the result normally carries none.
        self.core.refresh(refresh_token).await
    }

    async fn revoke(&self, refresh_token: &Secret) -> Result<(), OAuthError> {
        // RFC 7009 revoke. Best effort: the service clears local tokens whatever the result.
        self.core.revoke(refresh_token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// A Google profile whose endpoints point at a local wiremock server. The
    /// exchange and refresh paths do not use the auth URL, but the client needs a
    /// valid one.
    fn mock_profile(base: &str) -> ProviderProfile {
        ProviderProfile {
            kind: ProviderKind::Google,
            auth_url: format!("{base}/authorize"),
            token_url: format!("{base}/token"),
            revocation_url: Some(format!("{base}/revoke")),
            client_id: "test-client-id".into(),
            loopback_host: "127.0.0.1".into(),
            requires_pkce: true,
        }
    }

    fn pending(code: &str) -> PendingExchange {
        PendingExchange {
            code: code.into(),
            pkce_verifier: Secret::new("a-test-pkce-verifier-of-sufficient-length-000"),
            requested_scopes: vec!["https://www.googleapis.com/auth/userinfo.email".into()],
            redirect_uri: "http://127.0.0.1:51219/callback".into(),
        }
    }

    /// The real reqwest and oauth2 code: a code exchange posts to /token and parses
    /// the JSON into a `TokenPair` with both the access and refresh tokens.
    #[tokio::test]
    async fn exchange_code_posts_to_the_token_endpoint_and_parses_the_pair() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.live-access",
                "refresh_token": "1//live-refresh",
                "expires_in": 3599,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/userinfo.email"
            })))
            .mount(&server)
            .await;

        let provider = GoogleProvider::from_profile(mock_profile(&server.uri())).unwrap();
        let pair = provider
            .exchange_code(pending("auth-code-abc"))
            .await
            .expect("exchange must succeed");

        assert_eq!(pair.grant.access_token.expose(), "ya29.live-access");
        assert_eq!(pair.refresh_token.expose(), "1//live-refresh");
        assert!(
            pair.grant.expires_at_unix > now_unix(),
            "expiry is now + expires_in"
        );
    }

    /// Google's granular consent lets the user untick a scope, and the token
    /// response's `scope` then lists only what was granted. The grant must record
    /// that list, not the requested one, so the UI and a reviewer see the live access.
    #[tokio::test]
    async fn exchange_code_records_the_scopes_the_response_granted() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.live-access",
                "refresh_token": "1//live-refresh",
                "expires_in": 3599,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/userinfo.email"
            })))
            .mount(&server)
            .await;

        let mut narrowed = pending("auth-code-abc");
        narrowed
            .requested_scopes
            .push("https://www.googleapis.com/auth/gmail.readonly".into());
        let provider = GoogleProvider::from_profile(mock_profile(&server.uri())).unwrap();
        let pair = provider
            .exchange_code(narrowed)
            .await
            .expect("exchange must succeed");

        assert_eq!(
            pair.grant.granted_scopes,
            vec!["https://www.googleapis.com/auth/userinfo.email"]
        );
    }

    /// A code-exchange response with no `scope` field granted the requested scopes
    /// (RFC 6749 section 5.1), so the grant records the requested list.
    #[tokio::test]
    async fn exchange_code_without_a_scope_field_records_the_requested_scopes() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.live-access",
                "refresh_token": "1//live-refresh",
                "expires_in": 3599,
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let provider = GoogleProvider::from_profile(mock_profile(&server.uri())).unwrap();
        let pair = provider
            .exchange_code(pending("auth-code-abc"))
            .await
            .expect("exchange must succeed");

        assert_eq!(
            pair.grant.granted_scopes,
            vec!["https://www.googleapis.com/auth/userinfo.email"]
        );
    }

    /// A token endpoint that returns `invalid_grant` is a permanent error (the host
    /// must ask for consent again), never a retryable one.
    #[tokio::test]
    async fn an_invalid_grant_from_the_token_endpoint_is_permanent() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Bad authorization code"
            })))
            .mount(&server)
            .await;

        let provider = GoogleProvider::from_profile(mock_profile(&server.uri())).unwrap();
        let err = provider
            .exchange_code(pending("dead-code"))
            .await
            .unwrap_err();

        assert!(
            matches!(err, OAuthError::InvalidGrant { .. }),
            "got {err:?}"
        );
        assert!(err.requires_reconsent());
        assert!(!err.is_retryable());
    }

    /// The refresh path: a refresh-token request posts to /token and yields a new
    /// access grant with an expiry from the response's `expires_in`.
    #[tokio::test]
    async fn refresh_posts_to_the_token_endpoint_and_yields_a_new_grant() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.refreshed-access",
                "expires_in": 3599,
                "token_type": "Bearer",
                "scope": "https://www.googleapis.com/auth/userinfo.email"
            })))
            .mount(&server)
            .await;

        let provider = GoogleProvider::from_profile(mock_profile(&server.uri())).unwrap();
        let refreshed = provider
            .refresh(&Secret::new("1//some-refresh"))
            .await
            .expect("refresh must succeed");

        assert_eq!(
            refreshed.grant.access_token.expose(),
            "ya29.refreshed-access"
        );
        assert_eq!(
            refreshed.grant.granted_scopes,
            vec!["https://www.googleapis.com/auth/userinfo.email"]
        );
        assert!(
            refreshed.refresh_token.is_none(),
            "no refresh_token in the response → None"
        );
    }

    /// A refresh response that carries a `refresh_token` (a rotating provider)
    /// returns it, so the service saves it instead of the token it just sent.
    #[tokio::test]
    async fn refresh_surfaces_a_rotated_refresh_token_from_the_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ya29.refreshed-access",
                "expires_in": 3599,
                "token_type": "Bearer",
                "refresh_token": "1//rotated-refresh"
            })))
            .mount(&server)
            .await;

        let provider = GoogleProvider::from_profile(mock_profile(&server.uri())).unwrap();
        let refreshed = provider
            .refresh(&Secret::new("1//some-refresh"))
            .await
            .expect("refresh must succeed");

        let rotated = refreshed
            .refresh_token
            .expect("the response's refresh_token must be surfaced");
        assert_eq!(rotated.expose(), "1//rotated-refresh");
    }

    /// A revocation error never echoes response text. The test calls the mapping
    /// directly: oauth2 refuses a non-HTTPS revocation URL, so a wiremock round trip
    /// never reaches the response-handling code.
    #[test]
    fn revoke_errors_never_echo_response_text() {
        use oauth2::basic::{BasicErrorResponseType, BasicRevocationErrorResponse};
        use oauth2::{RequestTokenError, RevocationErrorResponseType, StandardErrorResponse};

        let sentinel = "SENTINEL-c0ffee-7f3a";
        let server: RequestTokenError<HttpFailure, BasicRevocationErrorResponse> =
            RequestTokenError::ServerResponse(StandardErrorResponse::new(
                RevocationErrorResponseType::Basic(BasicErrorResponseType::InvalidGrant),
                Some(format!("Rejected token {sentinel}")),
                Some(format!("https://x/{sentinel}")),
            ));
        let other: RequestTokenError<HttpFailure, BasicRevocationErrorResponse> =
            RequestTokenError::Other(format!(
                "unexpected response Content-Type: \"text/{sentinel}\""
            ));
        for err in [map_revoke_error(server), map_revoke_error(other)] {
            assert!(!format!("{err}").contains(sentinel), "Display leaks: {err}");
            assert!(
                !format!("{err:?}").contains(sentinel),
                "Debug leaks: {err:?}"
            );
        }
    }

    /// Revocation errors get the same classes as token errors: a dead token needs new
    /// consent, a client error is a configuration fault, and only a server-side
    /// failure is retryable. The test calls the mapping directly, because oauth2
    /// refuses a non-HTTPS revocation URL, so wiremock cannot reach this code.
    #[test]
    fn revoke_errors_are_classified() {
        use oauth2::basic::BasicErrorResponseType as Code;
        use oauth2::{
            RequestTokenError, RevocationErrorResponseType as Revoke, StandardErrorResponse,
        };

        let server = |code| {
            map_revoke_error(RequestTokenError::<HttpFailure, _>::ServerResponse(
                StandardErrorResponse::new(code, None, None),
            ))
        };
        let invalid_token = Code::Extension("invalid_token".into());
        assert!(matches!(
            server(Revoke::Basic(Code::InvalidGrant)),
            OAuthError::InvalidGrant { .. }
        ));
        assert!(matches!(
            server(Revoke::Basic(invalid_token)),
            OAuthError::InvalidGrant { .. }
        ));
        assert!(matches!(
            server(Revoke::Basic(Code::InvalidClient)),
            OAuthError::Config(_)
        ));
        assert!(matches!(
            server(Revoke::UnsupportedTokenType),
            OAuthError::Config(_)
        ));
        let other = Revoke::Basic(Code::Extension("server_error".into()));
        assert!(server(other).is_retryable());

        let wait = Some(std::time::Duration::from_secs(5));
        let throttled = map_revoke_error(RequestTokenError::Request(HttpFailure::Throttled {
            retry_after: wait,
        }));
        assert!(matches!(throttled, OAuthError::Throttled { retry_after } if retry_after == wait));
    }

    /// `begin_authorization` builds a real Google consent URL with PKCE S256, a state,
    /// and offline access, and carries the verifier in the session.
    #[test]
    fn begin_authorization_builds_a_pkce_consent_url() {
        let provider = GoogleProvider::new("the-client-id").unwrap();
        let scopes = vec![ScopeRequest::at_connect(
            "https://www.googleapis.com/auth/userinfo.email",
            "identify-account",
            "read the connected account's email",
        )];
        let session = provider.begin_authorization(&scopes, "http://127.0.0.1:50505/callback");

        assert!(
            session.authorize_url.contains("code_challenge="),
            "PKCE challenge present"
        );
        assert!(session.authorize_url.contains("code_challenge_method=S256"));
        assert!(
            session.authorize_url.contains("state="),
            "CSRF state present"
        );
        assert!(
            session.authorize_url.contains("access_type=offline"),
            "offline access for a refresh token"
        );
        assert!(session.authorize_url.contains("client_id=the-client-id"));
        assert!(session
            .authorize_url
            .contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A50505%2Fcallback"));
    }
}
