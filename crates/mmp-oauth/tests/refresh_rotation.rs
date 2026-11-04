//! Refresh-token rotation, end to end through the Facade.
//!
//! A rotating provider issues a new refresh token on every refresh and invalidates
//! the one it was sent (RFC 6749 §6). The Facade must persist the new token, or the
//! SECOND refresh presents a dead token, fails with `invalid_grant`, and forces the
//! user back through consent. A non-rotating provider (Google) sends no refresh
//! token on refresh, and the Facade must keep the one it already stores.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mmp_oauth::flow::{AuthSession, Clock, ManualClock, PendingExchange};
use mmp_oauth::provider::{MockProvider, Provider, ProviderKind, ProviderProfile, ScopeRequest};
use mmp_oauth::storage::{AccountKey, InMemoryTokenStore, StoredTokens, TokenStore};
use mmp_oauth::{OAuthCapability, OAuthError, OAuthService, RefreshedGrant, Secret, TokenPair};

const ACCOUNT: &str = "a@x.com";
const TTL: i64 = 3600;
const FIRST_REFRESH_TOKEN: &str = "rt-0";

/// A provider that rotates the refresh token on EVERY refresh. It honours only the
/// most recently issued refresh token; any other token is `invalid_grant`, as a real
/// rotating provider answers. Everything except `refresh` delegates to `MockProvider`.
struct RotatingProvider {
    inner: MockProvider,
    /// The one refresh token this provider still accepts.
    live: Mutex<String>,
    issued: AtomicUsize,
}

impl RotatingProvider {
    fn new() -> Self {
        Self {
            inner: MockProvider::new(TTL),
            live: Mutex::new(FIRST_REFRESH_TOKEN.into()),
            issued: AtomicUsize::new(0),
        }
    }

    /// Accept `presented` only if it is the live token; then rotate to a new one.
    fn rotate(&self, presented: &Secret) -> Result<String, OAuthError> {
        let mut live = self.live.lock().unwrap();
        if presented.expose() != live.as_str() {
            return Err(OAuthError::InvalidGrant {
                reason: "refresh token was rotated out".into(),
            });
        }
        let n = self.issued.fetch_add(1, Ordering::SeqCst) + 1;
        *live = format!("rt-{n}");
        Ok(live.clone())
    }
}

#[async_trait]
impl Provider for RotatingProvider {
    fn kind(&self) -> ProviderKind {
        self.inner.kind()
    }
    fn profile(&self) -> &ProviderProfile {
        self.inner.profile()
    }
    fn begin_authorization(&self, scopes: &[ScopeRequest], redirect_uri: &str) -> AuthSession {
        self.inner.begin_authorization(scopes, redirect_uri)
    }
    async fn exchange_code(&self, pending: PendingExchange) -> Result<TokenPair, OAuthError> {
        self.inner.exchange_code(pending).await
    }
    async fn refresh(&self, refresh_token: &Secret) -> Result<RefreshedGrant, OAuthError> {
        let next = self.rotate(refresh_token)?;
        let refreshed = self.inner.refresh(refresh_token).await?;
        Ok(RefreshedGrant {
            grant: refreshed.grant,
            refresh_token: Some(Secret::new(next)),
        })
    }
    async fn revoke(&self, refresh_token: &Secret) -> Result<(), OAuthError> {
        self.inner.revoke(refresh_token).await
    }
}

fn key() -> AccountKey {
    AccountKey::new(ProviderKind::Google, ACCOUNT)
}

/// Store a connected account whose cached access token expired at `expired_at`.
fn seed_expired(store: &InMemoryTokenStore, expired_at: i64) {
    store
        .save(
            &key(),
            &StoredTokens {
                refresh_token: Secret::new(FIRST_REFRESH_TOKEN),
                access_token: Some(Secret::new("stale-at")),
                access_expires_at_unix: Some(expired_at),
                granted_scopes: vec!["gmail.readonly".into()],
                refresh_scopes: None,
            },
        )
        .unwrap();
}

fn stored_refresh_token(store: &InMemoryTokenStore) -> String {
    store
        .load(&key())
        .unwrap()
        .expect("account stays connected")
        .refresh_token
        .expose()
        .to_string()
}

#[tokio::test]
async fn second_refresh_succeeds_against_a_rotating_provider() {
    let store = Arc::new(InMemoryTokenStore::new());
    seed_expired(&store, 1_000);
    let clock = Arc::new(ManualClock::new(2_000));
    let provider = RotatingProvider::new();
    provider.inner.set_issued_at(clock.now_unix());
    let svc = OAuthService::new(provider, store.clone()).with_clock(clock.clone());

    // First refresh: presents rt-0, the provider rotates to rt-1.
    let first = svc
        .access_token(ACCOUNT)
        .await
        .expect("first refresh must succeed");
    assert_eq!(first.access_token.expose(), "mock-access-2000");

    // Expire the new access token, then refresh again. It must present rt-1, not rt-0.
    clock.advance(TTL + 1);
    let second = svc
        .access_token(ACCOUNT)
        .await
        .expect("second refresh must succeed against a rotating provider");
    assert_eq!(second.access_token.expose(), "mock-access-2000");
    assert_eq!(
        stored_refresh_token(&store),
        "rt-2",
        "each rotated refresh token must be persisted"
    );
}

#[tokio::test]
async fn refresh_without_a_new_refresh_token_keeps_the_stored_one() {
    let store = Arc::new(InMemoryTokenStore::new());
    seed_expired(&store, 1_000);
    let clock = Arc::new(ManualClock::new(2_000));
    let provider = MockProvider::new(TTL); // Google-shaped: refresh carries no refresh token.
    provider.set_issued_at(clock.now_unix());
    let svc = OAuthService::new(provider, store.clone()).with_clock(clock);

    svc.access_token(ACCOUNT)
        .await
        .expect("refresh must succeed");
    assert_eq!(
        stored_refresh_token(&store),
        FIRST_REFRESH_TOKEN,
        "no rotation → the stored refresh token stays"
    );
}
