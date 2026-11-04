//! Granted scopes across a refresh, end to end through the Facade.
//!
//! A refresh response that omits `scope` is reported by the provider adapter as an
//! empty scope list, and the Facade must never write that empty list. This file pins
//! the LEGACY case: a record with no `refresh_scopes` falls back to the previous
//! token's `granted_scopes`. The consent-scope case (`refresh_scopes` present, RFC 6749
//! §5.1 and §6) is pinned in `refresh_scope_inheritance.rs`.

use std::sync::Arc;

use async_trait::async_trait;
use mmp_oauth::flow::{AuthSession, Clock, ManualClock, PendingExchange};
use mmp_oauth::provider::{MockProvider, Provider, ProviderKind, ProviderProfile, ScopeRequest};
use mmp_oauth::storage::{AccountKey, InMemoryTokenStore, StoredTokens, TokenStore};
use mmp_oauth::{OAuthCapability, OAuthError, OAuthService, RefreshedGrant, Secret, TokenPair};

const ACCOUNT: &str = "a@x.com";
const STORED_SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";

/// A provider whose refresh response omits `scope`. Everything else delegates to
/// `MockProvider`.
struct ScopelessRefreshProvider {
    inner: MockProvider,
}

#[async_trait]
impl Provider for ScopelessRefreshProvider {
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
        let refreshed = self.inner.refresh(refresh_token).await?;
        let grant = mmp_oauth::AccessGrant {
            granted_scopes: Vec::new(),
            ..refreshed.grant
        };
        Ok(RefreshedGrant {
            grant,
            refresh_token: refreshed.refresh_token,
        })
    }
    async fn revoke(&self, refresh_token: &Secret) -> Result<(), OAuthError> {
        self.inner.revoke(refresh_token).await
    }
}

#[tokio::test]
async fn refresh_response_without_scope_keeps_the_stored_scopes() {
    let key = AccountKey::new(ProviderKind::Google, ACCOUNT);
    let store = Arc::new(InMemoryTokenStore::new());
    store
        .save(
            &key,
            &StoredTokens {
                refresh_token: Secret::new("rt"),
                access_token: Some(Secret::new("stale-at")),
                access_expires_at_unix: Some(1_000),
                granted_scopes: vec![STORED_SCOPE.into()],
                refresh_scopes: None,
            },
        )
        .unwrap();
    let clock = Arc::new(ManualClock::new(2_000));
    let provider = ScopelessRefreshProvider {
        inner: MockProvider::new(3600),
    };
    provider.inner.set_issued_at(clock.now_unix());
    let svc = OAuthService::new(provider, store.clone()).with_clock(clock);

    let grant = svc
        .access_token(ACCOUNT)
        .await
        .expect("refresh must succeed");

    assert_eq!(
        grant.granted_scopes,
        vec![STORED_SCOPE],
        "legacy record: the returned grant keeps the previous scopes"
    );
    let stored = store.load(&key).unwrap().expect("account stays connected");
    assert_eq!(
        stored.granted_scopes,
        vec![STORED_SCOPE],
        "the persisted scopes are not wiped"
    );
}
