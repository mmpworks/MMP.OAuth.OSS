//! Scenarios for the real `GoogleProvider` over a wiremock token endpoint, from the
//! open-source readiness plan: S2 and S3 (PKCE verifier), S4 and S5 (dead refresh
//! tokens), S6 (error classification), and S10 (single-flight refresh on the real
//! provider). They are unit tests because `GoogleProvider::from_profile`, which
//! points the endpoints at the mock server, is private to the crate.

use std::sync::Arc;

use base64::Engine as _;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

use super::google::GoogleProvider;
use crate::capability::{OAuthCapability, OAuthService};
use crate::error::OAuthError;
use crate::flow::{ManualClock, PendingExchange};
use crate::provider::{Provider, ProviderKind, ProviderProfile, ScopeRequest};
use crate::storage::{AccountKey, InMemoryTokenStore, StoredTokens, TokenStore};
use crate::Secret;

const REDIRECT: &str = "http://127.0.0.1:51219/callback";

fn profile(base: &str) -> ProviderProfile {
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

fn scope() -> ScopeRequest {
    ScopeRequest::at_connect(
        "https://www.googleapis.com/auth/userinfo.email",
        "identify",
        "read the email address",
    )
}

fn token_json(access: &str) -> serde_json::Value {
    serde_json::json!({ "access_token": access, "refresh_token": "1//rt", "expires_in": 3599, "token_type": "Bearer" })
}

/// One query parameter from a URL, percent-decoded.
fn query_param(url: &str, name: &str) -> String {
    let query = url.split_once('?').map_or("", |(_, q)| q);
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map_or_else(|| panic!("no `{name}` in {url}"), |(_, v)| v.into_owned())
}

/// Begin an authorization and turn it into a `PendingExchange`, as the consent flow
/// does. Returns the exchange and the S256 challenge the consent URL carried.
fn begin(provider: &GoogleProvider, code: &str) -> (PendingExchange, String) {
    let session = provider.begin_authorization(&[scope()], REDIRECT);
    let challenge = query_param(&session.authorize_url, "code_challenge");
    let state = query_param(&session.authorize_url, "state");
    (
        session
            .validate_redirect(code.into(), &state)
            .expect("state matches"),
        challenge,
    )
}

/// Matches a token request whose `code_verifier` hashes to `challenge` under S256
/// (RFC 7636 section 4.6), as the provider checks it.
struct VerifierMatches(String);

impl Match for VerifierMatches {
    fn matches(&self, request: &Request) -> bool {
        let verifier = url::form_urlencoded::parse(&request.body)
            .find(|(k, _)| k == "code_verifier")
            .map(|(_, v)| v.into_owned());
        let Some(verifier) = verifier else {
            return false;
        };
        let digest = Sha256::digest(verifier.as_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest) == self.0
    }
}

/// A token endpoint that accepts only the verifier for `challenge`, and answers
/// `invalid_grant` to anything else, as a real provider does on a PKCE mismatch.
async fn pkce_checking_server(challenge: String) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(VerifierMatches(challenge))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json("ya29.ok")))
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(serde_json::json!({ "error": "invalid_grant" })),
        )
        .with_priority(2)
        .mount(&server)
        .await;
    server
}

/// S3: the exchange sends the verifier of the same session whose challenge went into
/// the consent URL, so a PKCE-checking provider accepts it.
#[tokio::test]
async fn the_exchange_sends_the_verifier_for_the_consent_challenge() {
    let placeholder = GoogleProvider::from_profile(profile("http://127.0.0.1:9")).unwrap();
    let (pending, challenge) = begin(&placeholder, "code-1");
    let server = pkce_checking_server(challenge).await;
    let provider = GoogleProvider::from_profile(profile(&server.uri())).unwrap();

    let pair = provider
        .exchange_code(pending)
        .await
        .expect("the matching verifier is accepted");
    assert_eq!(pair.grant.access_token.expose(), "ya29.ok");
}

/// S2: an exchange that carries another session's verifier fails PKCE at the provider
/// and maps to the permanent `InvalidGrant`.
#[tokio::test]
async fn a_verifier_from_another_session_is_rejected_as_invalid_grant() {
    let placeholder = GoogleProvider::from_profile(profile("http://127.0.0.1:9")).unwrap();
    let (_first, first_challenge) = begin(&placeholder, "code-1");
    let (second, second_challenge) = begin(&placeholder, "code-2");
    assert_ne!(
        first_challenge, second_challenge,
        "each session has its own challenge"
    );
    let server = pkce_checking_server(first_challenge).await;
    let provider = GoogleProvider::from_profile(profile(&server.uri())).unwrap();

    let err = provider.exchange_code(second).await.unwrap_err();
    assert!(
        matches!(err, OAuthError::InvalidGrant { .. }),
        "got {err:?}"
    );
    assert!(err.requires_reconsent());
}

/// A service over the real provider and an in-memory store that holds an expired
/// access token and the refresh token `1//old`.
fn service_with_expired_token(
    server: &MockServer,
) -> (OAuthService<GoogleProvider>, Arc<InMemoryTokenStore>) {
    let store = Arc::new(InMemoryTokenStore::new());
    let stored = StoredTokens {
        refresh_token: Secret::new("1//old"),
        access_token: Some(Secret::new("ya29.expired")),
        access_expires_at_unix: Some(1),
        granted_scopes: vec!["scope".into()],
        refresh_scopes: None,
    };
    store
        .save(&AccountKey::new(ProviderKind::Google, "a@x.com"), &stored)
        .unwrap();
    let provider = GoogleProvider::from_profile(profile(&server.uri())).unwrap();
    let service =
        OAuthService::new(provider, store.clone()).with_clock(Arc::new(ManualClock::new(1_000)));
    (service, store)
}

/// S4 and S5: Google answers an expired or a revoked refresh token with 400
/// `invalid_grant` and an `error_description`. Both map to the permanent
/// `InvalidGrant`, the description stays out of the error, and the stored record is
/// left for the host to clear with `revoke`.
#[tokio::test]
async fn an_expired_or_revoked_refresh_token_needs_new_consent_and_keeps_the_record() {
    for description in [
        "Token has been expired or revoked.",
        "Token has been revoked.",
    ] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant", "error_description": description
            })))
            .mount(&server)
            .await;
        let (service, store) = service_with_expired_token(&server);

        let err = service.access_token("a@x.com").await.unwrap_err();
        assert!(
            matches!(err, OAuthError::InvalidGrant { .. }),
            "got {err:?}"
        );
        assert!(err.requires_reconsent() && !err.is_retryable());
        assert!(
            !format!("{err} {err:?}").contains(description),
            "the description must not reach the error"
        );
        let kept = store
            .load(&AccountKey::new(ProviderKind::Google, "a@x.com"))
            .unwrap()
            .unwrap();
        assert_eq!(kept.refresh_token.expose(), "1//old");
    }
}

/// S6: how each token-endpoint failure is classified. A server-side or rate-limit
/// failure is retryable. A client error (`invalid_client`, `invalid_request`,
/// `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`) is a
/// configuration fault: a retry sends the same bad request, so it must not be
/// retryable, and it must not send the user through consent either.
#[tokio::test]
async fn token_endpoint_failures_are_classified_for_retry() {
    let error_body = |code: &str| serde_json::json!({ "error": code });
    let cases: Vec<(u16, Option<serde_json::Value>, bool, &str)> = vec![
        (500, None, true, "a 500 with no body"),
        (
            502,
            Some(serde_json::json!("bad gateway")),
            true,
            "a 502 with a non-object body",
        ),
        (
            503,
            Some(error_body("temporarily_unavailable")),
            true,
            "a 503 temporarily_unavailable",
        ),
        (
            500,
            Some(error_body("server_error")),
            true,
            "a 500 server_error",
        ),
        (429, None, true, "a 429 with no body"),
        (
            401,
            Some(error_body("invalid_client")),
            false,
            "a 401 invalid_client",
        ),
        (
            400,
            Some(error_body("invalid_request")),
            false,
            "a 400 invalid_request",
        ),
        (
            400,
            Some(error_body("unauthorized_client")),
            false,
            "a 400 unauthorized_client",
        ),
        (
            400,
            Some(error_body("unsupported_grant_type")),
            false,
            "a 400 unsupported_grant_type",
        ),
        (
            400,
            Some(error_body("invalid_scope")),
            false,
            "a 400 invalid_scope",
        ),
    ];
    for (status, body, retryable, label) in cases {
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(status);
        if let Some(body) = body {
            response = response.set_body_json(body);
        }
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(response)
            .mount(&server)
            .await;
        let provider = GoogleProvider::from_profile(profile(&server.uri())).unwrap();

        let err = provider.refresh(&Secret::new("1//rt")).await.unwrap_err();
        assert_eq!(err.is_retryable(), retryable, "{label}: got {err:?}");
        assert!(
            !err.requires_reconsent(),
            "{label}: must not ask for consent, got {err:?}"
        );
    }
}

/// S10: concurrent callers on the real provider cause one token request per expiry.
/// wiremock verifies the count of 1 when the server drops.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_callers_cause_one_token_request_on_the_real_provider() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_json("ya29.fresh")))
        .expect(1)
        .mount(&server)
        .await;
    let (service, _store) = service_with_expired_token(&server);
    let service: Arc<dyn OAuthCapability> = Arc::new(service);

    let mut handles = Vec::new();
    for _ in 0..16 {
        let service = Arc::clone(&service);
        handles.push(tokio::spawn(async move {
            service.access_token("a@x.com").await
        }));
    }
    for handle in handles {
        let grant = handle
            .await
            .unwrap()
            .expect("every caller gets the fresh token");
        assert_eq!(grant.access_token.expose(), "ya29.fresh");
    }
    server.verify().await;
}

/// A 429 is `Throttled` and carries the `Retry-After` value in seconds. The header
/// comes from the network, so a huge value is capped at 24 hours, and an HTTP date
/// or a junk value gives `None`. The body and the header never reach the error text.
#[tokio::test]
async fn a_429_is_throttled_with_the_retry_after_value() {
    use std::time::Duration;
    const DAY: Duration = Duration::from_secs(86_400);
    let cases = [
        (Some("120"), Some(Duration::from_secs(120))),
        (Some("0"), Some(Duration::ZERO)),
        (Some("99999999999999"), Some(DAY)),
        (Some("Wed, 21 Oct 2026 07:28:00 GMT"), None),
        (Some("SENTINEL-429-header"), None),
        (None, None),
    ];
    for (header, expected) in cases {
        let server = MockServer::start().await;
        let mut response = ResponseTemplate::new(429)
            .set_body_json(serde_json::json!({ "error": "SENTINEL-429-body" }));
        if let Some(value) = header {
            response = response.insert_header("retry-after", value);
        }
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(response)
            .mount(&server)
            .await;
        let provider = GoogleProvider::from_profile(profile(&server.uri())).unwrap();

        let err = provider.refresh(&Secret::new("1//rt")).await.unwrap_err();
        match &err {
            OAuthError::Throttled { retry_after } => {
                assert_eq!(*retry_after, expected, "header {header:?}");
            }
            other => panic!("header {header:?}: expected Throttled, got {other:?}"),
        }
        assert!(err.is_retryable());
        assert!(!format!("{err} {err:?}").contains("SENTINEL"), "{err:?}");
    }
}

/// A 5xx is a server fault whatever its body says, so a dead-grant code in a 503 body
/// must not cost the user their grant (RFC 7009 section 2.2.1 says the same of revoke).
#[tokio::test]
async fn a_5xx_is_transient_even_with_an_invalid_grant_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(
            ResponseTemplate::new(503)
                .set_body_json(serde_json::json!({ "error": "invalid_grant" })),
        )
        .mount(&server)
        .await;
    let provider = GoogleProvider::from_profile(profile(&server.uri())).unwrap();

    let err = provider.refresh(&Secret::new("1//rt")).await.unwrap_err();
    assert!(matches!(err, OAuthError::Transient(_)), "got {err:?}");
}

/// A 429 stays `Throttled` when its body never arrives. The status and the header
/// come first on the wire, so a body failure must not hide them.
#[tokio::test]
async fn a_429_with_a_truncated_body_is_still_throttled() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = [0_u8; 4096];
        let _ = socket.read(&mut request).await.unwrap();
        let head =
            "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 7\r\nContent-Length: 100\r\n\r\nshort";
        socket.write_all(head.as_bytes()).await.unwrap();
    });
    let provider = GoogleProvider::from_profile(profile(&base)).unwrap();

    let err = provider.refresh(&Secret::new("1//rt")).await.unwrap_err();
    server.await.unwrap();
    let expected = Some(std::time::Duration::from_secs(7));
    assert!(
        matches!(err, OAuthError::Throttled { retry_after } if retry_after == expected),
        "got {err:?}"
    );
}

/// A host's guard can retry: each call of the operation makes one new refresh. Here
/// the first attempt gets a 429 and the second gets a token.
#[tokio::test]
async fn a_host_guard_can_retry_a_throttled_refresh() {
    use crate::flow::resilience::{ResilienceGuard, ResilientOp};
    use crate::token::RefreshedGrant;

    struct RetryOnce;
    #[async_trait::async_trait]
    impl ResilienceGuard for RetryOnce {
        async fn guard<'a>(&'a self, op: ResilientOp<'a>) -> Result<RefreshedGrant, OAuthError> {
            match op().await {
                Err(e) if e.is_retryable() => op().await,
                other => other,
            }
        }
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(429))
        .up_to_n_times(1)
        .with_priority(1)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "fresh", "token_type": "Bearer", "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (service, _store) = service_with_expired_token(&server);
    let service = service.with_resilience(Arc::new(RetryOnce));

    let grant = service.access_token("a@x.com").await.unwrap();
    assert_eq!(grant.access_token.expose(), "fresh");
}
