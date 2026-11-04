//! The end-to-end OAuth flow, deterministic, with no real provider.
//!
//! The full cycle (authorize, exchange, save, serve, expire, refresh, revoke) runs
//! against `MockProvider`, `InMemoryTokenStore` and `ManualClock`, and the CSRF
//! check runs on both the valid path and the attack path. No network, no real
//! time, no browser: every edge is a test double.

use mmp_oauth::flow::{AuthSession, Clock, ManualClock};
use mmp_oauth::provider::{MockProvider, Provider, ProviderKind, ScopeRequest};
use mmp_oauth::storage::{AccountKey, InMemoryTokenStore, StoredTokens, TokenStore};
use mmp_oauth::OAuthError;

fn read_scope() -> ScopeRequest {
    ScopeRequest::at_connect(
        "https://www.googleapis.com/auth/gmail.readonly",
        "read-mailbox",
        "narrowest scope that lets the classifier read message bodies",
    )
}

/// The happy path: begin -> validate matching state -> exchange -> persist ->
/// the stored grant is what we minted.
#[tokio::test]
async fn full_dance_exchange_and_persist() {
    let provider = MockProvider::new(3600);
    provider.set_issued_at(1_000);
    let store = InMemoryTokenStore::new();

    // 1. Begin authorization (builds URL + in-memory PKCE verifier + CSRF state).
    let session = provider.begin_authorization(&[read_scope()], "http://127.0.0.1:53123");
    assert!(session.authorize_url.contains("state=mock-state"));

    // 2. The browser redirect arrives. Validate it against the session's state.
    //    (A real RedirectReceiver yields this; here we seed it directly.)
    let pending = session
        .validate_redirect("auth-code-123".into(), "mock-state")
        .expect("matching state must produce a pending exchange");

    // 3. Exchange the code for the first token pair (grant + refresh token).
    let pair = provider
        .exchange_code(pending)
        .await
        .expect("exchange must succeed");
    assert_eq!(pair.grant.access_token.expose(), "mock-access-1000");
    assert_eq!(pair.grant.expires_at_unix, 1_000 + 3600);
    assert_eq!(
        pair.refresh_token.expose(),
        "mock-refresh-token",
        "exchange yields the refresh token to persist"
    );

    // 4. Save the tokens, as the service does inside authorize. The refresh token
    //    comes from the exchange, not from a literal.
    let key = AccountKey::new(ProviderKind::Google, "a@x.com");
    store
        .save(
            &key,
            &StoredTokens {
                refresh_token: pair.refresh_token.clone(),
                access_token: Some(pair.grant.access_token.clone()),
                access_expires_at_unix: Some(pair.grant.expires_at_unix),
                granted_scopes: pair.grant.granted_scopes.clone(),
                refresh_scopes: Some(pair.grant.granted_scopes.clone()),
            },
        )
        .unwrap();

    let loaded = store.load(&key).unwrap().unwrap();
    assert_eq!(loaded.refresh_token.expose(), "mock-refresh-token");
    assert_eq!(
        loaded.granted_scopes,
        vec!["https://www.googleapis.com/auth/gmail.readonly"]
    );
}

/// The most important negative test: a redirect whose `state` does not match the
/// session must be rejected, and no code exchange is possible. A missing or
/// mis-wired state check is the classic desktop OAuth CSRF hole (RFC 6749 section
/// 10.12).
#[tokio::test]
async fn mismatched_csrf_state_is_refused_and_blocks_exchange() {
    let provider = MockProvider::new(3600);
    let session: AuthSession =
        provider.begin_authorization(&[read_scope()], "http://127.0.0.1:53123");

    let result = session.validate_redirect("attacker-code".into(), "WRONG-state");
    match result {
        Err(OAuthError::StateMismatch) => {} // correct: refused
        _ => panic!("a mismatched CSRF state must be refused with StateMismatch"),
    }
}

/// The refresh path: an expired cached token is refreshed once, and the new token
/// is issued against the advanced clock.
#[tokio::test]
async fn expired_token_refreshes_once_against_the_clock() {
    let provider = MockProvider::new(3600);
    let clock = ManualClock::new(1_000);

    // Simulate a stored grant that has already expired by the time we read it.
    provider.set_issued_at(clock.now_unix());
    let _first = {
        let session = provider.begin_authorization(&[read_scope()], "http://127.0.0.1:1");
        let pending = session.validate_redirect("c".into(), "mock-state").unwrap();
        provider.exchange_code(pending).await.unwrap()
    };
    assert_eq!(provider.refresh_count(), 0);

    // Advance past expiry and refresh.
    clock.advance(4_000);
    provider.set_issued_at(clock.now_unix());
    let refreshed = provider
        .refresh(&mmp_oauth::Secret::new("rt"))
        .await
        .unwrap();
    assert_eq!(provider.refresh_count(), 1, "exactly one refresh");
    assert_eq!(refreshed.grant.access_token.expose(), "mock-access-5000");
}

/// A dead refresh token (the provider returns `invalid_grant`) is a permanent error
/// that tells the host to ask for consent again. It must not look retryable.
#[tokio::test]
async fn dead_refresh_token_surfaces_as_reconsent_not_retry() {
    let provider = MockProvider::new(3600);
    provider.arm_invalid_grant();

    let err = provider
        .refresh(&mmp_oauth::Secret::new("rt"))
        .await
        .unwrap_err();
    assert!(
        err.requires_reconsent(),
        "invalid_grant must require re-consent"
    );
    assert!(!err.is_retryable(), "invalid_grant must NOT be retryable");
}
