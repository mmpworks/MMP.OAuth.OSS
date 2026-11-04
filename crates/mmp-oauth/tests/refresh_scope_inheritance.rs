//! A refresh response that omits `scope` grants the refresh token's scope.
//!
//! RFC 6749 §6: a refresh request without `scope` asks for the scope the resource
//! owner originally granted. §5.1: a response without `scope` granted what was
//! requested. `GoogleProvider` sends no `scope` on refresh, so an omitted scope
//! means the CONSENT scope, never the previous access token's (possibly narrower) one.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mmp_oauth::flow::{AuthSession, ManualClock, PendingExchange};
use mmp_oauth::provider::{MockProvider, Provider, ProviderKind, ProviderProfile, ScopeRequest};
use mmp_oauth::storage::{AccountKey, InMemoryTokenStore, StoredTokens, TokenStore};
use mmp_oauth::{
    AccessGrant, OAuthCapability, OAuthError, OAuthService, RefreshedGrant, Secret, TokenPair,
};

const ACCOUNT: &str = "a@x.com";
const TTL: i64 = 3600;

/// Answers each refresh with the next scope list from a script (empty = omitted).
struct ScriptedScopeProvider {
    inner: MockProvider,
    scopes: Mutex<VecDeque<Vec<String>>>,
}

#[async_trait]
impl Provider for ScriptedScopeProvider {
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
        let scopes = self
            .scopes
            .lock()
            .unwrap()
            .pop_front()
            .expect("script covers every refresh");
        let minted = self.inner.refresh(refresh_token).await?.grant;
        Ok(RefreshedGrant {
            grant: AccessGrant {
                granted_scopes: scopes,
                ..minted
            },
            refresh_token: None,
        })
    }
    async fn revoke(&self, refresh_token: &Secret) -> Result<(), OAuthError> {
        self.inner.revoke(refresh_token).await
    }
}

fn strings(items: &[&str]) -> Vec<String> {
    items.iter().map(std::string::ToString::to_string).collect()
}

#[tokio::test]
async fn an_omitted_scope_after_a_narrowed_refresh_reports_the_consent_scope() {
    let key = AccountKey::new(ProviderKind::Google, ACCOUNT);
    let store = Arc::new(InMemoryTokenStore::new());
    // As authorize() leaves it: consent granted `read write`.
    store
        .save(
            &key,
            &StoredTokens {
                refresh_token: Secret::new("rt"),
                access_token: Some(Secret::new("stale-at")),
                access_expires_at_unix: Some(0),
                granted_scopes: strings(&["read", "write"]),
                refresh_scopes: Some(strings(&["read", "write"])),
            },
        )
        .unwrap();
    let clock = Arc::new(ManualClock::new(1_000));
    let provider = ScriptedScopeProvider {
        inner: MockProvider::new(TTL),
        // Refresh 1 narrows to `read`; refresh 2 omits `scope`.
        scopes: Mutex::new(VecDeque::from([strings(&["read"]), Vec::new()])),
    };
    let svc = OAuthService::new(provider, store.clone()).with_clock(clock.clone());

    let first = svc.access_token(ACCOUNT).await.expect("refresh 1");
    assert_eq!(
        first.granted_scopes,
        strings(&["read"]),
        "refresh 1 reports the narrowed scope"
    );

    clock.advance(TTL + 1);
    let second = svc.access_token(ACCOUNT).await.expect("refresh 2");
    assert_eq!(
        second.granted_scopes,
        strings(&["read", "write"]),
        "omitted scope = the consent scope"
    );

    let stored = store.load(&key).unwrap().expect("account stays connected");
    assert_eq!(stored.granted_scopes, strings(&["read", "write"]));
    assert_eq!(
        stored.refresh_scopes,
        Some(strings(&["read", "write"])),
        "the refresh scope never changes"
    );
}
