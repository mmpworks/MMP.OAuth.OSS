//! [`MockProvider`]: a deterministic [`Provider`] with no I/O. Tests use it to run
//! the whole OAuth flow (authorize, exchange, refresh, revoke) with no real
//! provider. It is also the reference for what a provider does.

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};

use async_trait::async_trait;

use crate::error::OAuthError;
use crate::flow::{AuthSession, PendingExchange};
use crate::provider::{Provider, ProviderKind, ProviderProfile, ScopeRequest};
use crate::token::{AccessGrant, RefreshedGrant, TokenPair};
use crate::Secret;

/// A scripted provider for tests and examples. It returns predictable tokens,
/// counts refreshes, and can fail the next refresh with `invalid_grant`.
pub struct MockProvider {
    profile: ProviderProfile,
    /// The lifetime, in seconds, of each access token it issues.
    token_ttl: i64,
    /// The clock value tokens are issued against, so expiry is deterministic.
    issued_at: AtomicI64,
    refresh_count: AtomicUsize,
    fail_next_refresh_invalid_grant: std::sync::atomic::AtomicBool,
}

impl MockProvider {
    /// A mock provider that reports itself as Google, with the given access-token
    /// lifetime in seconds.
    #[must_use]
    pub fn new(token_ttl: i64) -> Self {
        Self {
            profile: ProviderProfile::google("mock-client-id"),
            token_ttl,
            issued_at: AtomicI64::new(0),
            refresh_count: AtomicUsize::new(0),
            fail_next_refresh_invalid_grant: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Set the clock value that later tokens are issued against.
    pub fn set_issued_at(&self, now: i64) {
        self.issued_at.store(now, Ordering::SeqCst);
    }

    /// Make the next `refresh` fail with `invalid_grant`, as a dead refresh token does.
    pub fn arm_invalid_grant(&self) {
        self.fail_next_refresh_invalid_grant
            .store(true, Ordering::SeqCst);
    }

    /// How many times `refresh` has run. A test uses it to check that an expired
    /// token caused a refresh.
    pub fn refresh_count(&self) -> usize {
        self.refresh_count.load(Ordering::SeqCst)
    }

    fn mint(&self, scopes: Vec<String>) -> AccessGrant {
        let issued = self.issued_at.load(Ordering::SeqCst);
        AccessGrant {
            access_token: Secret::new(format!("mock-access-{issued}")),
            expires_at_unix: issued.saturating_add(self.token_ttl),
            granted_scopes: scopes,
        }
    }
}

#[async_trait]
impl Provider for MockProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Google
    }

    fn profile(&self) -> &ProviderProfile {
        &self.profile
    }

    fn begin_authorization(&self, scopes: &[ScopeRequest], redirect_uri: &str) -> AuthSession {
        let scope_strs: Vec<String> = scopes.iter().map(|s| s.scope.clone()).collect();
        AuthSession::new(
            format!("https://mock/authorize?redirect_uri={redirect_uri}&state=mock-state"),
            redirect_uri,
            "mock-state",
            Secret::new("mock-verifier"),
            scope_strs,
        )
    }

    async fn exchange_code(&self, pending: PendingExchange) -> Result<TokenPair, OAuthError> {
        // The mock checks that the verifier came from the session.
        debug_assert_eq!(pending.pkce_verifier.expose(), "mock-verifier");
        Ok(TokenPair {
            grant: self.mint(pending.requested_scopes),
            refresh_token: Secret::new("mock-refresh-token"),
        })
    }

    async fn refresh(&self, _refresh_token: &Secret) -> Result<RefreshedGrant, OAuthError> {
        // An await point before the count increases. A real refresh is a network
        // call, so yielding here lets concurrent refreshers interleave on a
        // multi-thread runtime. Without it, the single-flight test could pass only
        // because nothing raced.
        tokio::task::yield_now().await;
        self.refresh_count.fetch_add(1, Ordering::SeqCst);
        if self
            .fail_next_refresh_invalid_grant
            .swap(false, Ordering::SeqCst)
        {
            return Err(OAuthError::InvalidGrant {
                reason: "invalid_grant".into(),
            });
        }
        // Like Google: no refresh-token rotation, so the response carries none.
        Ok(RefreshedGrant {
            grant: self.mint(vec!["gmail.readonly".into()]),
            refresh_token: None,
        })
    }

    async fn revoke(&self, _refresh_token: &Secret) -> Result<(), OAuthError> {
        Ok(())
    }
}
