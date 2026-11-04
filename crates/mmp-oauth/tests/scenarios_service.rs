//! Service scenarios from the open-source readiness plan, run through the public
//! API with test doubles: S7 (a failed provider revoke), S8 (the refresh-margin
//! boundary), S11 (concurrent refresh for two accounts), and S12 to S14
//! (token-store failures).

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use mmp_oauth::flow::{
    AuthSession, ConsentOpener, ManualClock, PendingExchange, RedirectOutcome, RedirectReceiver,
};
use mmp_oauth::provider::MockProvider;
use mmp_oauth::storage::InMemoryTokenStore;
use mmp_oauth::{
    AccountKey, OAuthCapability, OAuthError, OAuthService, Provider, ProviderKind, ProviderProfile,
    RefreshedGrant, ScopeRequest, Secret, StoredTokens, TokenPair, TokenState, TokenStore,
};

const NOW: i64 = 10_000;

fn stored(expires_at: i64) -> StoredTokens {
    StoredTokens {
        refresh_token: Secret::new("rt"),
        access_token: Some(Secret::new("cached-at")),
        access_expires_at_unix: Some(expires_at),
        granted_scopes: vec!["scope".into()],
        refresh_scopes: None,
    }
}

fn key(account: &str) -> AccountKey {
    AccountKey::new(ProviderKind::Google, account)
}

fn service_at(now: i64, store: Arc<dyn TokenStore>) -> OAuthService<MockProvider> {
    let provider = MockProvider::new(3600);
    provider.set_issued_at(now);
    OAuthService::new(provider, store).with_clock(Arc::new(ManualClock::new(now)))
}

// --- S8: the refresh margin is 60 seconds, and its boundary is strict ---

/// A token expiring 61 s from now is outside the margin and is served from the
/// cache. At 60 s it is inside the margin, and at 59 s too; both refresh.
#[tokio::test]
async fn the_sixty_second_margin_boundary_is_strict() {
    let cases = [
        (61, TokenState::Active, true),
        (60, TokenState::Expired, false),
        (59, TokenState::Expired, false),
    ];
    for (ahead, state, cached) in cases {
        let store = Arc::new(InMemoryTokenStore::new());
        store.save(&key("a@x.com"), &stored(NOW + ahead)).unwrap();
        let service = service_at(NOW, store);

        assert_eq!(
            service.status("a@x.com"),
            state,
            "status with expiry now+{ahead}"
        );
        let grant = service.access_token("a@x.com").await.unwrap();
        assert_eq!(
            grant.access_token.expose() == "cached-at",
            cached,
            "cache use with expiry now+{ahead}"
        );
    }
}

// --- S11: two accounts refresh in parallel, one refresh each ---

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_accounts_each_refresh_once_under_concurrent_callers() {
    let store = Arc::new(InMemoryTokenStore::new());
    store.save(&key("a@x.com"), &stored(NOW - 1)).unwrap();
    store.save(&key("b@x.com"), &stored(NOW - 1)).unwrap();

    let refreshes = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&refreshes);
    let service: Arc<dyn OAuthCapability> = Arc::new(service_at(NOW, store).with_refresh_observer(
        Arc::new(move |_key| {
            seen.fetch_add(1, Ordering::SeqCst);
        }),
    ));

    let mut handles = Vec::new();
    for i in 0..16 {
        let service = Arc::clone(&service);
        let account = if i % 2 == 0 { "a@x.com" } else { "b@x.com" };
        handles.push(tokio::spawn(
            async move { service.access_token(account).await },
        ));
    }
    for handle in handles {
        handle.await.unwrap().expect("every caller gets a token");
    }
    assert_eq!(
        refreshes.load(Ordering::SeqCst),
        2,
        "one refresh per account, not one per caller"
    );
}

// --- S12 to S14: token-store failures surface as Storage and lose nothing ---

/// An in-memory store whose `load` or `save` fails on demand.
#[derive(Default)]
struct FailingStore {
    inner: InMemoryTokenStore,
    fail_load: AtomicBool,
    fail_save: AtomicBool,
}

impl TokenStore for FailingStore {
    fn load(&self, key: &AccountKey) -> Result<Option<StoredTokens>, OAuthError> {
        if self.fail_load.load(Ordering::SeqCst) {
            return Err(OAuthError::Storage("vault locked".into()));
        }
        self.inner.load(key)
    }
    fn save(&self, key: &AccountKey, tokens: &StoredTokens) -> Result<(), OAuthError> {
        if self.fail_save.load(Ordering::SeqCst) {
            return Err(OAuthError::Storage("vault locked".into()));
        }
        self.inner.save(key, tokens)
    }
    fn delete(&self, key: &AccountKey) -> Result<(), OAuthError> {
        self.inner.delete(key)
    }
}

/// S13: a load failure is a Storage error from `access_token`, never `NotConnected`
/// (which would tell the host to ask for consent). `status` cannot return an error,
/// so it reports Unauthorized.
#[tokio::test]
async fn a_load_failure_is_a_storage_error_not_a_missing_account() {
    let store = Arc::new(FailingStore::default());
    store
        .inner
        .save(&key("a@x.com"), &stored(NOW + 3600))
        .unwrap();
    store.fail_load.store(true, Ordering::SeqCst);
    let service = service_at(NOW, store);

    let err = service.access_token("a@x.com").await.unwrap_err();
    assert!(matches!(err, OAuthError::Storage(_)), "got {err:?}");
    assert!(
        !err.requires_reconsent(),
        "a locked vault must not send the user through consent"
    );
    assert_eq!(service.status("a@x.com"), TokenState::Unauthorized);
}

/// S14: a save failure after a refresh surfaces as Storage. The stored record keeps
/// the old refresh token, so the next call can refresh again once the store works.
#[tokio::test]
async fn a_save_failure_after_refresh_surfaces_and_keeps_the_old_record() {
    let store = Arc::new(FailingStore::default());
    store.inner.save(&key("a@x.com"), &stored(NOW - 1)).unwrap();
    store.fail_save.store(true, Ordering::SeqCst);
    let service = service_at(NOW, store.clone());

    let err = service.access_token("a@x.com").await.unwrap_err();
    assert!(matches!(err, OAuthError::Storage(_)), "got {err:?}");
    let kept = store.inner.load(&key("a@x.com")).unwrap().unwrap();
    assert_eq!(
        kept.refresh_token.expose(),
        "rt",
        "the old refresh token is still stored"
    );

    store.fail_save.store(false, Ordering::SeqCst);
    let grant = service
        .access_token("a@x.com")
        .await
        .expect("the next call refreshes again");
    assert_eq!(grant.access_token.expose(), format!("mock-access-{NOW}"));
}

// --- S7: a provider that fails to revoke still leaves no local token ---

/// Delegates to `MockProvider`, except that `revoke` fails like a provider outage.
struct RevokeFails(MockProvider);

#[async_trait]
impl Provider for RevokeFails {
    fn kind(&self) -> ProviderKind {
        self.0.kind()
    }
    fn profile(&self) -> &ProviderProfile {
        self.0.profile()
    }
    fn begin_authorization(&self, scopes: &[ScopeRequest], redirect_uri: &str) -> AuthSession {
        self.0.begin_authorization(scopes, redirect_uri)
    }
    async fn exchange_code(&self, pending: PendingExchange) -> Result<TokenPair, OAuthError> {
        self.0.exchange_code(pending).await
    }
    async fn refresh(&self, refresh_token: &Secret) -> Result<RefreshedGrant, OAuthError> {
        self.0.refresh(refresh_token).await
    }
    async fn revoke(&self, _refresh_token: &Secret) -> Result<(), OAuthError> {
        Err(OAuthError::Transient(
            "revocation endpoint returned 500".into(),
        ))
    }
}

/// `revoke` is best effort at the provider. When the provider fails, the local
/// tokens are still deleted and the call succeeds, so a disconnect never leaves a
/// refresh token on the machine.
#[tokio::test]
async fn a_failed_provider_revoke_still_clears_local_tokens() {
    let store = Arc::new(InMemoryTokenStore::new());
    store.save(&key("a@x.com"), &stored(NOW + 3600)).unwrap();
    let service = OAuthService::new(RevokeFails(MockProvider::new(3600)), store.clone());

    service
        .revoke("a@x.com")
        .await
        .expect("revoke succeeds locally");
    assert!(
        store.load(&key("a@x.com")).unwrap().is_none(),
        "no token is left behind"
    );
    assert_eq!(service.status("a@x.com"), TokenState::Unauthorized);
}

// --- S12: a save failure at the end of authorize returns no grant ---

struct NoBrowser;

impl ConsentOpener for NoBrowser {
    fn open(&self, _authorize_url: &str) -> Result<(), OAuthError> {
        Ok(())
    }
}

/// Returns the redirect `MockProvider` expects (state `mock-state`).
struct Redirect;

#[async_trait]
impl RedirectReceiver for Redirect {
    fn redirect_uri(&self) -> String {
        "http://127.0.0.1:50000/callback".into()
    }
    async fn wait_for_redirect(&self) -> Result<RedirectOutcome, OAuthError> {
        Ok(RedirectOutcome {
            code: "code".into(),
            state: "mock-state".into(),
        })
    }
}

/// When the store cannot save the new tokens, `authorize` returns Storage instead of
/// a grant. A grant the host received but the store never saved would vanish at the
/// next launch.
#[tokio::test]
async fn a_save_failure_at_the_end_of_authorize_returns_storage_and_no_grant() {
    let store = Arc::new(FailingStore::default());
    store.fail_save.store(true, Ordering::SeqCst);
    let service =
        service_at(NOW, store.clone()).with_loopback(Arc::new(NoBrowser), Arc::new(Redirect));
    let scope = ScopeRequest::at_connect(
        "https://www.googleapis.com/auth/userinfo.email",
        "identify",
        "email",
    );

    let err = service.authorize("a@x.com", &[scope]).await.unwrap_err();
    assert!(matches!(err, OAuthError::Storage(_)), "got {err:?}");
    assert!(store.inner.load(&key("a@x.com")).unwrap().is_none());
}

// --- NeedsReconsent: status reports a dead grant ---

/// After a refresh fails with `invalid_grant`, `status` reports `NeedsReconsent`, so a
/// UI can show "reconnect" without calling the network again. A new `authorize`
/// clears it.
#[tokio::test]
async fn status_reports_needs_reconsent_after_a_dead_refresh_token() {
    let store = Arc::new(InMemoryTokenStore::new());
    store.save(&key("a@x.com"), &stored(NOW - 1)).unwrap();
    let provider = MockProvider::new(3600);
    provider.set_issued_at(NOW);
    provider.arm_invalid_grant();
    let service = OAuthService::new(provider, store.clone())
        .with_clock(Arc::new(ManualClock::new(NOW)))
        .with_loopback(Arc::new(NoBrowser), Arc::new(Redirect));

    let err = service.access_token("a@x.com").await.unwrap_err();
    assert!(err.requires_reconsent());
    assert_eq!(service.status("a@x.com"), TokenState::NeedsReconsent);

    let scope = ScopeRequest::at_connect(
        "https://www.googleapis.com/auth/userinfo.email",
        "identify",
        "email",
    );
    service
        .authorize("a@x.com", &[scope])
        .await
        .expect("re-consent");
    assert_eq!(service.status("a@x.com"), TokenState::Active);
}

/// A provider whose refresh, while in flight, sees a new consent save a new refresh
/// token (as `authorize` on another task would), and then fails with the old token.
struct ConsentDuringRefresh {
    inner: MockProvider,
    store: Arc<InMemoryTokenStore>,
}

#[async_trait]
impl Provider for ConsentDuringRefresh {
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
    async fn refresh(&self, _refresh_token: &Secret) -> Result<RefreshedGrant, OAuthError> {
        let fresh = StoredTokens {
            refresh_token: Secret::new("rt-after-consent"),
            ..stored(NOW + 3600)
        };
        self.store.save(&key("a@x.com"), &fresh).unwrap();
        Err(OAuthError::InvalidGrant {
            reason: "invalid_grant".into(),
        })
    }
    async fn revoke(&self, refresh_token: &Secret) -> Result<(), OAuthError> {
        self.inner.revoke(refresh_token).await
    }
}

/// The old token's failure must not mark the new grant dead: `status` reports the
/// new grant as Active.
#[tokio::test]
async fn a_new_consent_during_a_failing_refresh_is_not_marked_dead() {
    let store = Arc::new(InMemoryTokenStore::new());
    store.save(&key("a@x.com"), &stored(NOW - 1)).unwrap();
    let provider = ConsentDuringRefresh {
        inner: MockProvider::new(3600),
        store: store.clone(),
    };
    let service = OAuthService::new(provider, store).with_clock(Arc::new(ManualClock::new(NOW)));

    let err = service.access_token("a@x.com").await.unwrap_err();
    assert!(err.requires_reconsent());
    assert_eq!(
        service.status("a@x.com"),
        TokenState::Active,
        "the new grant is live"
    );
}
