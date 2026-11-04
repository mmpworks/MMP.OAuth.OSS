//! The capability interface: the facade over the whole OAuth subsystem.
//!
//! [`OAuthCapability`] is the four-method entry point. [`OAuthService`] implements
//! it by coordinating the injected parts: a [`Provider`], a [`TokenStore`], a
//! [`Clock`], and a [`ResilienceGuard`].
//! A host calls only these methods and never handles a provider profile, a token
//! endpoint, or a keystore.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex as StdMutex};

use async_trait::async_trait;
use tokio::sync::Mutex as AsyncMutex;

use crate::error::OAuthError;
use crate::flow::resilience::{Passthrough, ResilienceGuard, ResilientAttempt};
use crate::flow::{run_consent_flow, Clock, ConsentOpener, RedirectReceiver, SystemClock};
use crate::provider::{Provider, ScopeRequest};
use crate::storage::{AccountKey, StoredTokens, TokenStore};
use crate::token::grant::is_due;
use crate::token::{AccessGrant, TokenState};

/// Refresh a token this many seconds before the expiry the provider reported.
/// The margin covers clock drift between this host and the provider, and the
/// time a request spends in flight. A request that lasts longer than the margin
/// can still arrive after expiry; the API then answers 401 and the host calls
/// `access_token` again.
const REFRESH_SKEW_SECS: i64 = 60;

/// True while a token that expires at `expires_at` is still outside the refresh
/// margin at `now`. Both the token cache and `status` call this one predicate. The
/// expiry rule itself, with its saturating arithmetic, lives in
/// [`crate::token::grant::is_due`].
fn is_outside_refresh_margin(now: i64, expires_at: i64) -> bool {
    !is_due(now, expires_at, REFRESH_SKEW_SECS)
}

/// The capability surface a host depends on: four methods over the whole OAuth
/// subsystem. The four signatures change only in a breaking release (a new 0.x
/// minor version). New providers, scopes and stores arrive without changing them.
///
/// # Example
///
/// The mock provider and the in-memory store run with no network. A real host
/// passes a `GoogleProvider` or `MicrosoftProvider` and a persistent `TokenStore`.
///
/// ```
/// use std::sync::Arc;
/// use mmp_oauth::provider::MockProvider;
/// use mmp_oauth::storage::InMemoryTokenStore;
/// use mmp_oauth::{OAuthCapability, OAuthError, OAuthService, TokenState};
///
/// # tokio_test_block_on(async {
/// let service = OAuthService::new(MockProvider::new(3600), Arc::new(InMemoryTokenStore::new()));
///
/// // No consent has run yet, so there is no token to serve.
/// assert_eq!(service.status("user@example.com"), TokenState::Unauthorized);
/// let err = service.access_token("user@example.com").await.unwrap_err();
/// assert!(matches!(err, OAuthError::NotConnected));
/// # });
/// # fn tokio_test_block_on<F: std::future::Future>(f: F) -> F::Output {
/// #     tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
/// # }
/// ```
#[async_trait]
pub trait OAuthCapability: Send + Sync {
    /// Run the consent flow for `scopes` and return the first live grant.
    ///
    /// Use it once per account, when the user connects, and again after any
    /// error where [`OAuthError::requires_reconsent`] is true. The service opens
    /// the system browser, waits for the loopback redirect, checks the CSRF
    /// `state`, exchanges the code with PKCE, and saves the tokens. The browser
    /// opener and the loopback listener come from
    /// [`OAuthService::with_loopback`], so this method takes no runtime or HTTP
    /// types.
    ///
    /// # Errors
    ///
    /// - [`OAuthError::Config`] when the loopback edges are not wired.
    /// - [`OAuthError::ConsentAbandoned`] when the user closes the consent page
    ///   or the deadline passes.
    /// - [`OAuthError::StateMismatch`] when the redirect's `state` does not match.
    ///   Nothing is exchanged or saved.
    /// - [`OAuthError::InvalidGrant`], [`OAuthError::Transient`] or
    ///   [`OAuthError::Throttled`] from the code exchange.
    /// - [`OAuthError::Config`] when the token endpoint rejects the request itself
    ///   (for example `invalid_client`: a wrong client id or secret). A retry fails
    ///   the same way.
    /// - [`OAuthError::Storage`] when the token store cannot save.
    ///
    /// # Example
    ///
    /// A production host passes `SystemBrowserOpener` and `LoopbackReceiver::bind()`.
    /// This example passes two small doubles, so it runs with no browser and no socket.
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use async_trait::async_trait;
    /// # use mmp_oauth::flow::{ConsentOpener, RedirectOutcome, RedirectReceiver};
    /// # use mmp_oauth::provider::MockProvider;
    /// # use mmp_oauth::storage::InMemoryTokenStore;
    /// # use mmp_oauth::{OAuthCapability, OAuthError, OAuthService, ScopeRequest, TokenState};
    /// # struct NoBrowser;
    /// # impl ConsentOpener for NoBrowser {
    /// #     fn open(&self, _url: &str) -> Result<(), OAuthError> { Ok(()) }
    /// # }
    /// # struct Redirect;
    /// # #[async_trait]
    /// # impl RedirectReceiver for Redirect {
    /// #     fn redirect_uri(&self) -> String { "http://127.0.0.1:50000/callback".into() }
    /// #     async fn wait_for_redirect(&self) -> Result<RedirectOutcome, OAuthError> {
    /// #         Ok(RedirectOutcome { code: "code".into(), state: "mock-state".into() })
    /// #     }
    /// # }
    /// # tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(async {
    /// let service = OAuthService::new(MockProvider::new(3600), Arc::new(InMemoryTokenStore::new()))
    ///     .with_loopback(Arc::new(NoBrowser), Arc::new(Redirect));
    ///
    /// let scope = ScopeRequest::at_connect(
    ///     "https://www.googleapis.com/auth/userinfo.email",
    ///     "identify-account",
    ///     "read the connected account's email address",
    /// );
    /// let grant = service.authorize("user@example.com", &[scope]).await?;
    /// assert!(!grant.access_token.expose().is_empty());
    /// assert!(service.status("user@example.com").can_serve_token());
    /// # Ok::<(), OAuthError>(())
    /// # }).unwrap();
    /// ```
    async fn authorize(
        &self,
        account: &str,
        scopes: &[ScopeRequest],
    ) -> Result<AccessGrant, OAuthError>;

    /// The current access token for `account`, refreshed first if it is within
    /// the refresh margin (60 seconds, `REFRESH_SKEW_SECS`) of expiry.
    ///
    /// Call it before every API request. Concurrent calls for one account cause
    /// at most one refresh; the other callers wait and then read the new token.
    ///
    /// # Errors
    ///
    /// - [`OAuthError::NotConnected`] when no tokens are stored for `account`.
    /// - [`OAuthError::InvalidGrant`] when the provider rejects the refresh
    ///   token (expired or revoked). The host must run `authorize` again.
    /// - [`OAuthError::Transient`] or [`OAuthError::Throttled`] when the refresh
    ///   fails in a way a retry can fix.
    /// - [`OAuthError::Config`] when the token endpoint rejects the request itself
    ///   (for example `invalid_client` or `invalid_scope`).
    /// - [`OAuthError::Storage`] when the token store cannot load or save.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mmp_oauth::{OAuthCapability, OAuthError};
    /// # async fn call_api(service: &dyn OAuthCapability) -> Result<(), OAuthError> {
    /// let grant = service.access_token("user@example.com").await?;
    /// let header = format!("Bearer {}", grant.access_token.expose());
    /// // Send `header` as the Authorization header of the API request.
    /// # let _ = header;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// When the error requires new consent, run `authorize` again:
    ///
    /// ```no_run
    /// # use mmp_oauth::{OAuthCapability, OAuthError};
    /// # async fn call_api(service: &dyn OAuthCapability) -> Result<(), OAuthError> {
    /// match service.access_token("user@example.com").await {
    ///     Ok(grant) => { /* call the API with grant.access_token */ }
    ///     Err(e) if e.requires_reconsent() => { /* show "reconnect" and run authorize */ }
    ///     Err(e) if e.is_retryable() => { /* retry later */ }
    ///     Err(e) => return Err(e),
    /// }
    /// # Ok(())
    /// # }
    /// ```
    async fn access_token(&self, account: &str) -> Result<AccessGrant, OAuthError>;

    /// Disconnect `account`: revoke the refresh token at the provider, then
    /// delete the stored tokens.
    ///
    /// The provider call is best effort. Its result is ignored, so a provider
    /// outage never leaves a token on this machine after the user disconnects.
    ///
    /// # Errors
    ///
    /// - [`OAuthError::Storage`] when the token store cannot load or delete.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mmp_oauth::{OAuthCapability, OAuthError, TokenState};
    /// # async fn disconnect(service: &dyn OAuthCapability) -> Result<(), OAuthError> {
    /// service.revoke("user@example.com").await?;
    /// assert_eq!(service.status("user@example.com"), TokenState::Unauthorized);
    /// # Ok(())
    /// # }
    /// ```
    async fn revoke(&self, account: &str) -> Result<(), OAuthError>;

    /// The lifecycle state of `account` for a UI. Reads the token store and the
    /// clock only, with no network I/O.
    ///
    /// Returns [`TokenState::Unauthorized`] when no tokens are stored and when
    /// the store cannot be read. Returns [`TokenState::Active`] while the cached
    /// access token is outside the refresh margin, and
    /// [`TokenState::Expired`] otherwise (the next `access_token` call refreshes it).
    /// Returns [`TokenState::NeedsReconsent`] after a refresh in this process failed
    /// with a dead grant, until `authorize` or `revoke` runs.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use mmp_oauth::{OAuthCapability, TokenState};
    /// # fn label(service: &dyn OAuthCapability) -> &'static str {
    /// match service.status("user@example.com") {
    ///     TokenState::Active | TokenState::Expired => "Connected",
    ///     TokenState::NeedsReconsent => "Reconnect needed",
    ///     _ => "Not connected",
    /// }
    /// # }
    /// ```
    fn status(&self, account: &str) -> TokenState;
}

/// A callback that runs after a silent refresh, with the account it refreshed.
/// A host wires it to a UI update or an audit log. The service works with none
/// wired.
pub type RefreshObserver = Arc<dyn Fn(&AccountKey) + Send + Sync>;

/// The facade implementation. It is generic over the provider, so tests drive it
/// with `MockProvider` and production drives it with `GoogleProvider` or
/// `MicrosoftProvider`, through the same code.
pub struct OAuthService<P: Provider> {
    provider: P,
    store: Arc<dyn TokenStore>,
    clock: Arc<dyn Clock>,
    resilience: Arc<dyn ResilienceGuard>,
    on_refresh: Option<RefreshObserver>,
    /// The browser opener and the loopback listener. Optional, because only
    /// `authorize` needs them. A host that refreshes an already-stored grant
    /// wires neither.
    consent: Option<ConsentEdges>,
    /// Per-account single-flight refresh locks. When several `access_token` calls find
    /// the cached token expired, one of them takes the account's async lock, refreshes,
    /// and saves. The others wait on the lock and then read the new token. The provider
    /// sees one refresh, not one per caller.
    ///
    /// The outer `std::sync::Mutex` guards only the map, for a short insert-or-get with
    /// no await. The inner `tokio::sync::Mutex` is held across the refresh and the
    /// save, which is the one place that awaits.
    ///
    /// The locks are per account, so one account's refresh never blocks another's.
    ///
    /// A `tokio::sync::Mutex` is used instead of a shared future, because it is
    /// cancellation-safe. A cancelled holder drops the guard, and the next waiter
    /// proceeds. A shared future would hand the cancellation to every waiter.
    refresh_locks: StdMutex<HashMap<AccountKey, Arc<AsyncMutex<()>>>>,
    /// Accounts whose last refresh failed with a dead grant (`invalid_grant` or a
    /// re-consent code). `status` reports them as `NeedsReconsent`. The set lives in
    /// memory only: after a restart, `status` reports `Expired` until the next
    /// `access_token` call fails again. `authorize` and `revoke` clear an entry.
    dead_grants: StdMutex<HashSet<AccountKey>>,
}

/// The two edges the consent flow drives. They are bundled so `authorize` has
/// both or neither, never one.
struct ConsentEdges {
    opener: Arc<dyn ConsentOpener>,
    receiver: Arc<dyn RedirectReceiver>,
}

impl<P: Provider> OAuthService<P> {
    /// Build a service from a provider and a token store.
    ///
    /// Defaults: the system clock, no resilience policy ([`Passthrough`]), no
    /// refresh observer, and no loopback edges. The `with_*` methods replace them.
    pub fn new(provider: P, store: Arc<dyn TokenStore>) -> Self {
        Self {
            provider,
            store,
            clock: Arc::new(SystemClock),
            resilience: Arc::new(Passthrough),
            on_refresh: None,
            consent: None,
            refresh_locks: StdMutex::new(HashMap::new()),
            dead_grants: StdMutex::new(HashSet::new()),
        }
    }

    /// Replace the clock. Tests pass a `ManualClock` to control expiry.
    #[must_use]
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Replace the resilience policy that wraps each background refresh (retry,
    /// backoff, circuit breaking). The default, [`Passthrough`], calls once.
    #[must_use]
    pub fn with_resilience(mut self, guard: Arc<dyn ResilienceGuard>) -> Self {
        self.resilience = guard;
        self
    }

    /// Set the callback that runs after each silent refresh.
    #[must_use]
    pub fn with_refresh_observer(mut self, observer: RefreshObserver) -> Self {
        self.on_refresh = Some(observer);
        self
    }

    /// Wire the consent-flow edges that `authorize` needs: the browser opener and
    /// the loopback redirect receiver. They are supplied together. Without them,
    /// `authorize` returns [`OAuthError::Config`].
    #[must_use]
    pub fn with_loopback(
        mut self,
        opener: Arc<dyn ConsentOpener>,
        receiver: Arc<dyn RedirectReceiver>,
    ) -> Self {
        self.consent = Some(ConsentEdges { opener, receiver });
        self
    }

    fn key(&self, account: &str) -> AccountKey {
        AccountKey::new(self.provider.kind(), account)
    }

    /// The dead-grant set, locked. A poisoned lock means another thread panicked
    /// while it held the set; the set is still valid data, so the guard is recovered
    /// instead of failing the caller.
    ///
    /// The lock also orders the token writes that change whether a grant is dead:
    /// `authorize` saves and clears under it, `revoke` deletes and clears under it,
    /// and a failed refresh checks the store and marks under it. So a refresh that
    /// fails with an old token cannot mark a grant that a new consent just saved.
    /// The store calls are synchronous and short, and no `.await` runs under it.
    fn dead_grants(&self) -> std::sync::MutexGuard<'_, HashSet<AccountKey>> {
        self.dead_grants
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Mark `key`'s grant dead after `sent` was refused, but only if `sent` is still
    /// the stored refresh token (see [`Self::dead_grants`] for the ordering). A store
    /// that cannot be read leaves the grant unmarked; `status` then reports
    /// `Expired`, and the next `access_token` call fails again.
    fn mark_dead_if_still_stored(&self, key: &AccountKey, sent: &crate::Secret) {
        let mut dead = self.dead_grants();
        if matches!(self.store.load(key), Ok(Some(now)) if now.refresh_token.expose() == sent.expose())
        {
            dead.insert(key.clone());
        }
    }

    fn is_dead_grant(&self, key: &AccountKey) -> bool {
        self.dead_grants().contains(key)
    }

    /// The account's single-flight refresh lock. It is fetched or inserted under the
    /// map mutex, with no await, and returned as an `Arc`, so the caller awaits it
    /// after the map lock is released.
    fn refresh_lock(&self, key: &AccountKey) -> Arc<AsyncMutex<()>> {
        // A poisoned lock means another thread panicked in the short insert-or-get
        // below. The map still holds valid locks, so recover it: a caller's token
        // request must not panic because of an unrelated panic.
        let mut map = self
            .refresh_locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Arc::clone(map.entry(key.clone()).or_default())
    }

    /// The cached access token, if it is outside the refresh margin. A pure read of
    /// `stored` against the clock, with no I/O and no lock. `None` means a refresh is
    /// due. Both the lock-free path and the check inside the lock call it.
    fn cached_if_valid(&self, stored: &StoredTokens) -> Option<AccessGrant> {
        match (stored.access_token.clone(), stored.access_expires_at_unix) {
            (Some(at), Some(exp)) if is_outside_refresh_margin(self.clock.now_unix(), exp) => {
                Some(AccessGrant {
                    access_token: at,
                    expires_at_unix: exp,
                    granted_scopes: stored.granted_scopes.clone(),
                })
            }
            _ => None,
        }
    }

    fn persist(
        &self,
        key: &AccountKey,
        refresh_token: crate::Secret,
        refresh_scopes: Option<Vec<String>>,
        grant: &AccessGrant,
    ) -> Result<(), OAuthError> {
        let stored = StoredTokens {
            refresh_token,
            access_token: Some(grant.access_token.clone()),
            access_expires_at_unix: Some(grant.expires_at_unix),
            granted_scopes: grant.granted_scopes.clone(),
            refresh_scopes,
        };
        self.store.save(key, &stored)
    }
}

#[async_trait]
impl<P: Provider> OAuthCapability for OAuthService<P> {
    async fn authorize(
        &self,
        account: &str,
        scopes: &[ScopeRequest],
    ) -> Result<AccessGrant, OAuthError> {
        // Fail fast when the consent edges are missing, before any part of the
        // flow runs.
        let edges = self.consent.as_ref().ok_or_else(|| {
            OAuthError::Config(
                "authorize requires the consent edges; call with_loopback(opener, receiver)".into(),
            )
        })?;

        // Run the loopback flow: begin, open the browser, wait for the redirect,
        // and check the CSRF state. Only a matching state yields a PendingExchange,
        // so a CSRF failure cannot reach the exchange below.
        let pending = run_consent_flow(
            &self.provider,
            edges.opener.as_ref(),
            edges.receiver.as_ref(),
            scopes,
        )
        .await?;

        // Exchange the code for the first token pair. This call is interactive (the
        // user is at the consent page), so it skips the ResilienceGuard, whose retry
        // and backoff serve the background refresh in `access_token`. A failed
        // exchange returns its error to the host, which runs authorize again.
        let pair = self.provider.exchange_code(pending).await?;

        // Save the refresh token and the cached access token, then return the grant.
        // The scope granted at consent is the refresh token's scope for the life of
        // the grant (RFC 6749 section 6).
        let key = self.key(account);
        let refresh_scopes = Some(pair.grant.granted_scopes.clone());
        // Save and clear under the dead-grant lock (see `dead_grants`).
        let mut dead = self.dead_grants();
        self.persist(&key, pair.refresh_token, refresh_scopes, &pair.grant)?;
        dead.remove(&key);
        drop(dead);
        Ok(pair.grant)
    }

    async fn access_token(&self, account: &str) -> Result<AccessGrant, OAuthError> {
        let key = self.key(account);

        // Lock-free path: serve the cached token if it is outside the refresh margin.
        let stored = self.store.load(&key)?.ok_or(OAuthError::NotConnected)?;
        if let Some(grant) = self.cached_if_valid(&stored) {
            return Ok(grant);
        }

        // Single-flight: take the account lock, so only one caller refreshes. The lock
        // covers the re-check, the refresh, and the save.
        let lock = self.refresh_lock(&key);
        let _guard = lock.lock().await;

        // 1. Re-check inside the lock.
        // 2. If an earlier holder refreshed, serve its token: one refresh per expiry.
        // 3. If that refresh failed, the next waiter finds the token still expired and
        //    tries once more, so retries run one at a time.
        let stored = self.store.load(&key)?.ok_or(OAuthError::NotConnected)?;
        if let Some(grant) = self.cached_if_valid(&stored) {
            return Ok(grant);
        }

        // This caller is the one refresher. The host's resilience policy wraps the
        // call. A dead refresh token returns InvalidGrant, and the host then runs
        // authorize again.
        let provider = &self.provider;
        let refresh_token = &stored.refresh_token;
        let op = || -> ResilientAttempt<'_> { Box::pin(provider.refresh(refresh_token)) };
        let refreshed = self.resilience.guard(&op).await.inspect_err(|e| {
            if matches!(e, OAuthError::InvalidGrant { .. }) {
                self.mark_dead_if_still_stored(&key, &stored.refresh_token);
            }
        })?;
        // A response with no scope grants the refresh token's consent scope (RFC 6749
        // section 6). A record saved before refresh scopes were stored falls back to
        // the previous access token's scope.
        let omitted_means = stored
            .refresh_scopes
            .as_deref()
            .unwrap_or(&stored.granted_scopes);
        let grant = scopes_or_omitted_default(refreshed.grant, omitted_means);

        // A provider that rotates refresh tokens has invalidated the one just sent,
        // so save the new one. A response with no refresh token (Google), or an
        // empty one, keeps the stored token: an empty string is not a credential.
        let refresh_token = refreshed
            .refresh_token
            .filter(|rt| !rt.expose().is_empty())
            .unwrap_or(stored.refresh_token);
        // RFC 6749 section 6: a rotated refresh token keeps the old one's scope.
        // Save and clear under the dead-grant lock (see `dead_grants`).
        let mut dead = self.dead_grants();
        self.persist(&key, refresh_token, stored.refresh_scopes, &grant)?;
        dead.remove(&key);
        drop(dead);
        if let Some(observer) = &self.on_refresh {
            observer(&key);
        }
        Ok(grant)
        // `_guard` drops here and releases the account lock. Waiting callers then hit
        // the re-check above and serve the token this refresh saved.
    }

    async fn revoke(&self, account: &str) -> Result<(), OAuthError> {
        let key = self.key(account);
        if let Some(stored) = self.store.load(&key)? {
            let _ = self.provider.revoke(&stored.refresh_token).await; // best-effort
        }
        // Delete and clear under the dead-grant lock (see `dead_grants`).
        let mut dead = self.dead_grants();
        self.store.delete(&key)?;
        dead.remove(&key);
        Ok(())
    }

    fn status(&self, account: &str) -> TokenState {
        let key = self.key(account);
        match self.store.load(&key) {
            Ok(None) | Err(_) => TokenState::Unauthorized,
            Ok(Some(_)) if self.is_dead_grant(&key) => TokenState::NeedsReconsent,
            Ok(Some(stored)) => {
                let now = self.clock.now_unix();
                match stored.access_expires_at_unix {
                    Some(exp) if is_outside_refresh_margin(now, exp) => TokenState::Active,
                    _ => TokenState::Expired,
                }
            }
        }
    }
}

/// RFC 6749 section 5.1: a token response that omits `scope` granted the requested
/// scope. A refresh sends no `scope`, so section 6 makes the request equal to the
/// consent scope. The provider reports an omitted scope as an empty list, so an
/// empty list becomes `omitted_means`; a non-empty list is what the provider granted.
fn scopes_or_omitted_default(grant: AccessGrant, omitted_means: &[String]) -> AccessGrant {
    if !grant.granted_scopes.is_empty() {
        return grant;
    }
    AccessGrant {
        granted_scopes: omitted_means.to_vec(),
        ..grant
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::{ManualClock, RedirectOutcome};
    use crate::provider::{MockProvider, ProviderKind};
    use crate::storage::InMemoryTokenStore;
    use async_trait::async_trait;

    fn seed_connected(store: &InMemoryTokenStore, expires_at: i64) {
        let key = AccountKey::new(ProviderKind::Google, "a@x.com");
        store
            .save(
                &key,
                &StoredTokens {
                    refresh_token: crate::Secret::new("rt"),
                    access_token: Some(crate::Secret::new("cached-at")),
                    access_expires_at_unix: Some(expires_at),
                    granted_scopes: vec!["gmail.readonly".into()],
                    refresh_scopes: None,
                },
            )
            .unwrap();
    }

    #[tokio::test]
    async fn access_token_serves_cached_when_valid() {
        let store = Arc::new(InMemoryTokenStore::new());
        seed_connected(&store, 10_000);
        let clock = Arc::new(ManualClock::new(1_000));
        let provider = MockProvider::new(3600);
        let svc = OAuthService::new(provider, store.clone()).with_clock(clock);

        let grant = svc.access_token("a@x.com").await.unwrap();
        assert_eq!(
            grant.access_token.expose(),
            "cached-at",
            "valid cache served, no refresh"
        );
    }

    #[tokio::test]
    async fn access_token_refreshes_when_expired() {
        let store = Arc::new(InMemoryTokenStore::new());
        seed_connected(&store, 1_500);
        let clock = Arc::new(ManualClock::new(2_000));
        let provider = MockProvider::new(3600);
        provider.set_issued_at(2_000);
        let svc = OAuthService::new(provider, store.clone()).with_clock(clock);

        let grant = svc.access_token("a@x.com").await.unwrap();
        assert_eq!(
            grant.access_token.expose(),
            "mock-access-2000",
            "expired cache triggers refresh"
        );
        assert_eq!(grant.expires_at_unix, 2_000 + 3600);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn access_token_is_single_flight_under_concurrent_expiry() {
        // N concurrent callers find the cached token expired at the same instant. One
        // refresh must fire; the others wait for it and read the new token. The refresh
        // observer counts refreshes. MockProvider::refresh yields like a network call,
        // so on the multi-thread runtime the callers race. The property is one refresh
        // per expiry, and this test crosses one expiry.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let store = Arc::new(InMemoryTokenStore::new());
        seed_connected(&store, 1_500); // expires at 1_500…
        let clock = Arc::new(ManualClock::new(2_000)); // …and now is 2_000 (> exp - skew) → refresh.
        let provider = MockProvider::new(3600);
        provider.set_issued_at(2_000);

        let refreshes = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&refreshes);
        let svc: Arc<dyn OAuthCapability> = Arc::new(
            OAuthService::new(provider, store.clone())
                .with_clock(clock)
                .with_refresh_observer(Arc::new(move |_key| {
                    seen.fetch_add(1, Ordering::SeqCst);
                })),
        );

        // 16 concurrent access_token() calls at the single expiry boundary.
        let mut handles = Vec::new();
        for _ in 0..16 {
            let svc = Arc::clone(&svc);
            handles.push(tokio::spawn(
                async move { svc.access_token("a@x.com").await },
            ));
        }
        for h in handles {
            let grant = h.await.unwrap().unwrap();
            assert_eq!(
                grant.access_token.expose(),
                "mock-access-2000",
                "all callers get the fresh token"
            );
        }

        assert_eq!(
            refreshes.load(Ordering::SeqCst),
            1,
            "single-flight: exactly ONE refresh fired across 16 concurrent callers at one expiry crossing"
        );
    }

    #[tokio::test]
    async fn access_token_on_unconnected_account_is_not_connected() {
        let store = Arc::new(InMemoryTokenStore::new());
        let provider = MockProvider::new(3600);
        let svc = OAuthService::new(provider, store);
        let err = svc.access_token("nobody@x.com").await.unwrap_err();
        assert!(matches!(err, OAuthError::NotConnected));
    }

    #[tokio::test]
    async fn revoke_clears_local_tokens() {
        let store = Arc::new(InMemoryTokenStore::new());
        seed_connected(&store, 10_000);
        let provider = MockProvider::new(3600);
        let svc = OAuthService::new(provider, store.clone());
        svc.revoke("a@x.com").await.unwrap();
        assert!(store
            .load(&AccountKey::new(ProviderKind::Google, "a@x.com"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn status_reflects_the_lifecycle_without_io() {
        let store = Arc::new(InMemoryTokenStore::new());
        let clock = Arc::new(ManualClock::new(1_000));
        let provider = MockProvider::new(3600);
        let svc = OAuthService::new(provider, store.clone()).with_clock(clock.clone());

        assert_eq!(svc.status("a@x.com"), TokenState::Unauthorized);
        seed_connected(&store, 10_000);
        assert_eq!(svc.status("a@x.com"), TokenState::Active);
        clock.advance(20_000);
        assert_eq!(svc.status("a@x.com"), TokenState::Expired);
    }

    // --- authorize() consent-flow wiring tests, with test doubles for the edges ---

    /// Records the opened URL instead of launching a browser.
    #[derive(Default)]
    struct RecordingOpener {
        opened: std::sync::Mutex<Vec<String>>,
    }
    impl ConsentOpener for RecordingOpener {
        fn open(&self, authorize_url: &str) -> Result<(), OAuthError> {
            self.opened.lock().unwrap().push(authorize_url.to_string());
            Ok(())
        }
    }

    /// Returns a canned `(code, state)` instead of binding a socket.
    struct SeededReceiver {
        state: String,
    }
    #[async_trait]
    impl RedirectReceiver for SeededReceiver {
        fn redirect_uri(&self) -> String {
            "http://127.0.0.1:50001/callback".into()
        }
        async fn wait_for_redirect(&self) -> Result<RedirectOutcome, OAuthError> {
            Ok(RedirectOutcome {
                code: "auth-code-789".into(),
                state: self.state.clone(),
            })
        }
    }

    fn scope() -> ScopeRequest {
        ScopeRequest::at_connect(
            "https://www.googleapis.com/auth/userinfo.email",
            "identify-account",
            "read the connected account's email address",
        )
    }

    #[tokio::test]
    async fn authorize_runs_the_dance_and_persists_the_refresh_token() {
        let store = Arc::new(InMemoryTokenStore::new());
        let provider = MockProvider::new(3600);
        provider.set_issued_at(5_000);
        let opener: Arc<dyn ConsentOpener> = Arc::new(RecordingOpener::default());
        // MockProvider mints "mock-state"; the receiver must echo it.
        let receiver: Arc<dyn RedirectReceiver> = Arc::new(SeededReceiver {
            state: "mock-state".into(),
        });
        let svc = OAuthService::new(provider, store.clone()).with_loopback(opener, receiver);

        let grant = svc
            .authorize("a@x.com", &[scope()])
            .await
            .expect("authorize must succeed");
        assert_eq!(grant.access_token.expose(), "mock-access-5000");

        // The refresh token from the exchange was persisted under the account key.
        let stored = store
            .load(&AccountKey::new(ProviderKind::Google, "a@x.com"))
            .unwrap()
            .expect("authorize must persist tokens");
        assert_eq!(stored.refresh_token.expose(), "mock-refresh-token");
        assert_eq!(stored.access_token.unwrap().expose(), "mock-access-5000");
    }

    #[tokio::test]
    async fn authorize_with_a_mismatched_state_is_refused_and_persists_nothing() {
        let store = Arc::new(InMemoryTokenStore::new());
        let provider = MockProvider::new(3600);
        let opener: Arc<dyn ConsentOpener> = Arc::new(RecordingOpener::default());
        // Attacker state that does NOT match the session's "mock-state".
        let receiver: Arc<dyn RedirectReceiver> = Arc::new(SeededReceiver {
            state: "attacker".into(),
        });
        let svc = OAuthService::new(provider, store.clone()).with_loopback(opener, receiver);

        let err = svc.authorize("a@x.com", &[scope()]).await.unwrap_err();
        assert!(matches!(err, OAuthError::StateMismatch));
        // Nothing was saved: the CSRF check stopped the flow before the exchange.
        assert!(store
            .load(&AccountKey::new(ProviderKind::Google, "a@x.com"))
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn authorize_without_loopback_edges_fails_with_a_clear_config_error() {
        let store = Arc::new(InMemoryTokenStore::new());
        let provider = MockProvider::new(3600);
        let svc = OAuthService::new(provider, store);

        let err = svc.authorize("a@x.com", &[scope()]).await.unwrap_err();
        match err {
            OAuthError::Config(msg) => assert!(
                msg.contains("with_loopback"),
                "error must name the missing wiring"
            ),
            other => panic!("expected a Config error naming with_loopback, got {other:?}"),
        }
    }

    // --- S9: a corrupt stored expiry must not overflow the skew subtraction ---

    /// A record whose expiry is `i64::MIN` (a corrupt or hostile store) is a token
    /// that expired long ago. `access_token` must refresh it, not panic in a debug
    /// build or wrap to "valid until the far future" in a release build.
    #[tokio::test]
    async fn access_token_with_an_expiry_at_i64_min_refreshes_instead_of_overflowing() {
        let store = Arc::new(InMemoryTokenStore::new());
        seed_connected(&store, i64::MIN);
        let provider = MockProvider::new(3600);
        provider.set_issued_at(2_000);
        let svc = OAuthService::new(provider, store).with_clock(Arc::new(ManualClock::new(2_000)));

        let grant = svc
            .access_token("a@x.com")
            .await
            .expect("an ancient expiry refreshes");
        assert_eq!(
            grant.access_token.expose(),
            "mock-access-2000",
            "a refresh ran"
        );
    }

    /// `status` reads the same expiry. It must report `Expired`, not panic.
    #[test]
    fn status_with_an_expiry_at_i64_min_is_expired_instead_of_overflowing() {
        let store = Arc::new(InMemoryTokenStore::new());
        seed_connected(&store, i64::MIN);
        let svc = OAuthService::new(MockProvider::new(3600), store)
            .with_clock(Arc::new(ManualClock::new(2_000)));

        assert_eq!(svc.status("a@x.com"), TokenState::Expired);
    }
}
