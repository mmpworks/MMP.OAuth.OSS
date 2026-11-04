//! Tests M1 to M9 for `MicrosoftProvider`, from the open-source readiness plan, over
//! a wiremock token endpoint. They are unit tests because
//! `MicrosoftProvider::from_profile`, which points the endpoints at the mock server,
//! is private to the crate. M10 (the testbed builds this provider) is in
//! `testbed/server.rs`.

use std::sync::Arc;

use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Match, Mock, MockServer, Request, ResponseTemplate};

use super::microsoft::MicrosoftProvider;
use crate::capability::{OAuthCapability, OAuthService};
use crate::error::OAuthError;
use crate::flow::{ManualClock, PendingExchange};
use crate::provider::{Provider, ProviderKind, ProviderProfile, ScopeRequest};
use crate::storage::{AccountKey, InMemoryTokenStore, StoredTokens, TokenStore};
use crate::token::TokenState;
use crate::Secret;

/// A clearly fake application (client) id. Real ids come from configuration.
const FAKE_CLIENT_ID: &str = "00000000-0000-0000-0000-000000000000";
const REDIRECT: &str = "http://127.0.0.1:51219/callback";

fn profile(base: &str) -> ProviderProfile {
    ProviderProfile {
        kind: ProviderKind::Microsoft,
        auth_url: format!("{base}/common/oauth2/v2.0/authorize"),
        token_url: format!("{base}/common/oauth2/v2.0/token"),
        revocation_url: None,
        client_id: FAKE_CLIENT_ID.into(),
        loopback_host: "127.0.0.1".into(),
        requires_pkce: true,
    }
}

fn provider(server: &MockServer) -> MicrosoftProvider {
    MicrosoftProvider::from_profile(profile(&server.uri())).unwrap()
}

fn user_read() -> ScopeRequest {
    ScopeRequest::at_connect("User.Read", "identify", "read the signed-in user's profile")
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?').map_or("", |(_, q)| q);
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.into_owned())
}

fn pending(requested: Vec<String>) -> PendingExchange {
    PendingExchange {
        code: "code-1".into(),
        pkce_verifier: Secret::new("a-test-pkce-verifier-of-sufficient-length-000"),
        requested_scopes: requested,
        redirect_uri: REDIRECT.into(),
    }
}

fn token_body(access: &str, refresh: &str) -> serde_json::Value {
    serde_json::json!({
        "token_type": "Bearer", "scope": "User.Read profile openid email",
        "expires_in": 3599, "access_token": access, "refresh_token": refresh
    })
}

async fn token_server(response: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/common/oauth2/v2.0/token"))
        .respond_with(response)
        .mount(&server)
        .await;
    server
}

/// Matches a form body that has no `client_secret` field at all.
struct NoClientSecret;

impl Match for NoClientSecret {
    fn matches(&self, request: &Request) -> bool {
        !url::form_urlencoded::parse(&request.body).any(|(k, _)| k == "client_secret")
            && !request.headers.contains_key("authorization")
    }
}

// --- M1: the consent URL ---

#[test]
fn m1_the_consent_url_uses_pkce_the_loopback_and_offline_access() {
    let p = MicrosoftProvider::new(FAKE_CLIENT_ID).unwrap();
    let session = p.begin_authorization(&[user_read()], REDIRECT);
    let url = &session.authorize_url;
    assert!(
        url.starts_with("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"),
        "{url}"
    );
    assert_eq!(
        query_param(url, "client_id").as_deref(),
        Some(FAKE_CLIENT_ID)
    );
    assert_eq!(
        query_param(url, "code_challenge_method").as_deref(),
        Some("S256")
    );
    assert!(query_param(url, "code_challenge").is_some_and(|c| c.len() >= 43));
    assert_eq!(query_param(url, "redirect_uri").as_deref(), Some(REDIRECT));
    assert!(query_param(url, "state").is_some_and(|s| !s.is_empty()));
    assert_eq!(
        query_param(url, "scope").as_deref(),
        Some("User.Read offline_access")
    );
    assert!(
        query_param(url, "access_type").is_none(),
        "no Google-only parameter"
    );
}

#[test]
fn m1_offline_access_is_not_added_twice() {
    let p = MicrosoftProvider::new(FAKE_CLIENT_ID).unwrap();
    for spelling in ["offline_access", "Offline_Access"] {
        let offline = ScopeRequest::at_connect(spelling, "refresh", "stay signed in");
        let session = p.begin_authorization(&[offline, user_read()], REDIRECT);
        let expected = format!("{spelling} User.Read");
        assert_eq!(
            query_param(&session.authorize_url, "scope").as_deref(),
            Some(expected.as_str())
        );
    }
}

/// Negative control for the `NoClientSecret` matcher used by M2, M4 and M9: it
/// refuses a body that carries `client_secret`, so those tests can fail.
#[tokio::test]
async fn the_no_client_secret_matcher_rejects_a_secret() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(NoClientSecret)
        .respond_with(ResponseTemplate::new(200))
        .expect(0)
        .mount(&server)
        .await;
    let _ = reqwest::Client::new()
        .post(format!("{}/token", server.uri()))
        .body("grant_type=refresh_token&client_secret=x")
        .send()
        .await;
    server.verify().await;
}

/// The Microsoft re-consent codes reach `status` through the service: after an
/// `interaction_required` refresh, `status` is `NeedsReconsent`.
#[tokio::test]
async fn an_interaction_required_refresh_reports_needs_reconsent() {
    let body =
        serde_json::json!({ "error": "interaction_required", "error_description": "AADSTS50076" });
    let server = token_server(ResponseTemplate::new(400).set_body_json(body)).await;
    let store = store_with_expired("M.r0");
    let service =
        OAuthService::new(provider(&server), store).with_clock(Arc::new(ManualClock::new(1_000)));

    let err = service.access_token("a@x.com").await.unwrap_err();
    assert!(err.requires_reconsent(), "{err:?}");
    assert_eq!(service.status("a@x.com"), TokenState::NeedsReconsent);
}

#[test]
fn with_tenant_changes_both_endpoints_and_rejects_a_path() {
    let p = MicrosoftProvider::new(FAKE_CLIENT_ID)
        .unwrap()
        .with_tenant("organizations")
        .unwrap();
    assert_eq!(
        p.profile().auth_url,
        "https://login.microsoftonline.com/organizations/oauth2/v2.0/authorize"
    );
    assert_eq!(
        p.profile().token_url,
        "https://login.microsoftonline.com/organizations/oauth2/v2.0/token"
    );
    for bad in ["", ".", "..", "-x", "a/b", "a?b", "../x", "a b"] {
        assert!(
            MicrosoftProvider::new(FAKE_CLIENT_ID)
                .unwrap()
                .with_tenant(bad)
                .is_err(),
            "{bad:?}"
        );
    }
}

// --- M2 and M3: the code exchange ---

/// M2: the exchange sends the PKCE verifier and no client secret, and parses the pair.
#[tokio::test]
async fn m2_the_exchange_sends_the_verifier_and_no_secret() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/common/oauth2/v2.0/token"))
        .and(body_string_contains(
            "code_verifier=a-test-pkce-verifier-of-sufficient-length-000",
        ))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(NoClientSecret)
        .respond_with(
            ResponseTemplate::new(200).set_body_json(token_body("eyJ.access", "M.refresh-1")),
        )
        .expect(1)
        .mount(&server)
        .await;

    let pair = provider(&server)
        .exchange_code(pending(vec!["User.Read".into()]))
        .await
        .expect("exchange");
    assert_eq!(pair.grant.access_token.expose(), "eyJ.access");
    assert_eq!(pair.refresh_token.expose(), "M.refresh-1");
    assert_eq!(
        pair.grant.granted_scopes,
        ["User.Read", "profile", "openid", "email"]
    );
    server.verify().await;
}

/// M3: a response with no `scope` field granted the requested scopes (RFC 6749
/// section 5.1). A response with no refresh token names `offline_access`.
#[tokio::test]
async fn m3_a_response_without_scope_records_the_requested_scopes() {
    let body = serde_json::json!({ "token_type": "Bearer", "expires_in": 3599, "access_token": "a", "refresh_token": "r" });
    let server = token_server(ResponseTemplate::new(200).set_body_json(body)).await;
    let requested = vec!["User.Read".to_string(), "offline_access".to_string()];
    let pair = provider(&server)
        .exchange_code(pending(requested.clone()))
        .await
        .unwrap();
    assert_eq!(pair.grant.granted_scopes, requested);

    let no_refresh =
        serde_json::json!({ "token_type": "Bearer", "expires_in": 3599, "access_token": "a" });
    let server = token_server(ResponseTemplate::new(200).set_body_json(no_refresh)).await;
    let err = provider(&server)
        .exchange_code(pending(requested))
        .await
        .unwrap_err();
    assert!(
        matches!(&err, OAuthError::Config(msg) if msg.contains("offline_access")),
        "{err:?}"
    );
}

// --- M4: rotation, through the service ---

fn store_with_expired(refresh: &str) -> Arc<InMemoryTokenStore> {
    let store = Arc::new(InMemoryTokenStore::new());
    let tokens = StoredTokens {
        refresh_token: Secret::new(refresh),
        access_token: Some(Secret::new("old-access")),
        access_expires_at_unix: Some(1),
        granted_scopes: vec!["User.Read".into()],
        refresh_scopes: Some(vec!["User.Read".into(), "offline_access".into()]),
    };
    store
        .save(
            &AccountKey::new(ProviderKind::Microsoft, "a@x.com"),
            &tokens,
        )
        .unwrap();
    store
}

/// M4: Microsoft returns a new refresh token on every refresh; the service saves it,
/// and the next refresh sends the new one.
#[tokio::test]
async fn m4_each_refresh_saves_the_rotated_refresh_token() {
    let server = MockServer::start().await;
    for (sent, issued) in [("M.r0", "M.r1"), ("M.r1", "M.r2")] {
        Mock::given(method("POST"))
            .and(path("/common/oauth2/v2.0/token"))
            .and(body_string_contains(format!("refresh_token={sent}")))
            .and(NoClientSecret)
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(token_body(&format!("access-{issued}"), issued)),
            )
            .expect(1)
            .mount(&server)
            .await;
    }
    let store = store_with_expired("M.r0");
    let clock = Arc::new(ManualClock::new(1_000));
    let service = OAuthService::new(provider(&server), store.clone()).with_clock(clock.clone());

    service
        .access_token("a@x.com")
        .await
        .expect("first refresh");
    // The new token's expiry comes from the wall clock, so move the test clock past it.
    clock.advance(4_000_000_000);
    service
        .access_token("a@x.com")
        .await
        .expect("second refresh sends the rotated token");
    let saved = store
        .load(&AccountKey::new(ProviderKind::Microsoft, "a@x.com"))
        .unwrap()
        .unwrap();
    assert_eq!(saved.refresh_token.expose(), "M.r2");
    server.verify().await;
}

// --- M5 and M6: error classification ---

/// M5: an expired refresh token (AADSTS70008), a revoked one (AADSTS50173), and the
/// three interaction codes all need new consent, and none is retryable.
#[tokio::test]
async fn m5_dead_grants_and_interaction_codes_need_new_consent() {
    let cases = [
        (
            "invalid_grant",
            "AADSTS70008: The refresh token has expired due to inactivity.",
        ),
        (
            "invalid_grant",
            "AADSTS50173: The provided grant has expired due to it being revoked.",
        ),
        (
            "interaction_required",
            "AADSTS50076: multi-factor authentication is required.",
        ),
        (
            "consent_required",
            "AADSTS65001: The user has not consented.",
        ),
        (
            "login_required",
            "AADSTS50058: A silent sign-in request was sent but no user is signed in.",
        ),
    ];
    for (code, description) in cases {
        let body = serde_json::json!({ "error": code, "error_description": description, "error_codes": [70008] });
        let server = token_server(ResponseTemplate::new(400).set_body_json(body)).await;
        let err = provider(&server)
            .refresh(&Secret::new("M.r0"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, OAuthError::InvalidGrant { .. }),
            "{code}: {err:?}"
        );
        assert!(err.requires_reconsent() && !err.is_retryable(), "{code}");
        assert!(
            !format!("{err} {err:?}").contains("AADSTS"),
            "{code}: the description leaked"
        );
    }
}

/// M6: server and rate-limit failures are retryable; client errors are not.
#[tokio::test]
async fn m6_failures_are_classified_for_retry() {
    let cases: [(u16, serde_json::Value, bool); 5] = [
        (
            429,
            serde_json::json!({ "error": "temporarily_unavailable" }),
            true,
        ),
        (500, serde_json::json!({ "error": "server_error" }), true),
        (503, serde_json::json!("busy"), true),
        (401, serde_json::json!({ "error": "invalid_client" }), false),
        (400, serde_json::json!({ "error": "invalid_scope" }), false),
    ];
    for (status, body, retryable) in cases {
        let server = token_server(ResponseTemplate::new(status).set_body_json(body)).await;
        let err = provider(&server)
            .refresh(&Secret::new("M.r0"))
            .await
            .unwrap_err();
        assert_eq!(err.is_retryable(), retryable, "{status}: {err:?}");
        assert!(!err.requires_reconsent(), "{status}: {err:?}");
    }
}

/// M6b: Microsoft's rate limit is `Throttled` with its `Retry-After` value, on the
/// exchange as well as the refresh.
#[tokio::test]
async fn m6b_a_429_is_throttled_with_the_retry_after_value() {
    let response = ResponseTemplate::new(429).insert_header("Retry-After", "30");
    let server = token_server(response).await;
    let expected = Some(std::time::Duration::from_secs(30));
    let err = provider(&server)
        .refresh(&Secret::new("M.r0"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, OAuthError::Throttled { retry_after } if retry_after == expected),
        "{err:?}"
    );
    let err = provider(&server)
        .exchange_code(pending(vec![]))
        .await
        .unwrap_err();
    assert!(
        matches!(err, OAuthError::Throttled { retry_after } if retry_after == expected),
        "{err:?}"
    );
}

// --- M7: revoke ---

/// M7: revoke makes no network call (Microsoft documents no revocation endpoint for
/// a client), and the service still deletes the local tokens.
#[tokio::test]
async fn m7_revoke_clears_local_tokens_with_no_network_call() {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&server)
        .await;
    let store = store_with_expired("M.r0");
    let service = OAuthService::new(provider(&server), store.clone());

    service.revoke("a@x.com").await.expect("revoke");
    assert!(store
        .load(&AccountKey::new(ProviderKind::Microsoft, "a@x.com"))
        .unwrap()
        .is_none());
    assert_eq!(service.status("a@x.com"), TokenState::Unauthorized);
    server.verify().await;
}

// --- M8: no response text reaches an error ---

#[tokio::test]
async fn m8_no_response_text_reaches_an_error() {
    const SENTINEL: &str = "SENTINELm8";
    let bodies = [
        serde_json::json!({ "error": SENTINEL }),
        serde_json::json!({ "error": "invalid_grant", "error_description": SENTINEL }),
        serde_json::json!({ "error": "interaction_required", "error_uri": SENTINEL, "suberror": SENTINEL }),
        serde_json::json!({ "error": "invalid_request", "error_codes": [SENTINEL], "trace_id": SENTINEL }),
        serde_json::json!({ "access_token": SENTINEL, "token_type": 7 }),
    ];
    for status in [200u16, 400, 401, 500] {
        for body in &bodies {
            let server =
                token_server(ResponseTemplate::new(status).set_body_json(body.clone())).await;
            for result in [
                provider(&server)
                    .refresh(&Secret::new("M.r0"))
                    .await
                    .map(|_| ()),
                provider(&server)
                    .exchange_code(pending(vec![]))
                    .await
                    .map(|_| ()),
            ] {
                // Every body here is an error body or a malformed token body, so every
                // call must fail; a success would make the check below vacuous.
                let err = result.expect_err("each body must produce an error");
                assert!(
                    !format!("{err} {err:?}").contains(SENTINEL),
                    "{status} {body}: {err:?}"
                );
            }
        }
    }
}

// --- M9: the full flow over the real loopback ---

/// M9: `OAuthService<MicrosoftProvider>` runs the whole consent flow: a real
/// loopback socket, a simulated browser that follows the redirect, and the wiremock
/// token endpoint. The tokens are saved and the status is Active.
#[cfg(feature = "loopback-flow")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn m9_the_full_flow_runs_over_the_loopback() {
    use crate::flow::{ConsentOpener, LoopbackReceiver, RedirectReceiver};

    /// Reads `state` and `redirect_uri` from the consent URL and sends the redirect
    /// a browser would follow after the user clicks Allow.
    struct Browser;
    impl ConsentOpener for Browser {
        fn open(&self, authorize_url: &str) -> Result<(), OAuthError> {
            let state = query_param(authorize_url, "state").unwrap();
            let redirect = query_param(authorize_url, "redirect_uri").unwrap();
            let url = format!("{redirect}?code=code-1&state={state}");
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                let _ = reqwest::Client::new().get(&url).send().await;
            });
            Ok(())
        }
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/common/oauth2/v2.0/token"))
        .and(body_string_contains("code=code-1"))
        .and(NoClientSecret)
        .respond_with(
            ResponseTemplate::new(200).set_body_json(token_body("eyJ.access", "M.refresh-1")),
        )
        .expect(1)
        .mount(&server)
        .await;
    let receiver = LoopbackReceiver::bind_with_deadline(std::time::Duration::from_secs(5)).unwrap();
    let store = Arc::new(InMemoryTokenStore::new());
    let service = OAuthService::new(provider(&server), store.clone()).with_loopback(
        Arc::new(Browser),
        Arc::new(receiver) as Arc<dyn RedirectReceiver>,
    );

    let grant = service
        .authorize("a@x.com", &[user_read()])
        .await
        .expect("the flow completes");
    assert_eq!(grant.access_token.expose(), "eyJ.access");
    let saved = store
        .load(&AccountKey::new(ProviderKind::Microsoft, "a@x.com"))
        .unwrap()
        .unwrap();
    assert_eq!(saved.refresh_token.expose(), "M.refresh-1");
    assert_eq!(service.status("a@x.com"), TokenState::Active);
    server.verify().await;
}
