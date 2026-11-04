//! Property tests for the Facade's refresh path (`access_token`).
//!
//! Each case scripts a sequence of refresh responses from a ROTATING provider and
//! drives one refresh per response. The provider honours only the newest refresh
//! token it issued, so a Facade that persists the wrong token fails the next refresh.
//!
//! Rules pinned here:
//! 1. Refresh token: a non-empty token in a response replaces the stored one. An
//!    absent token, or an EMPTY one, leaves the stored token in force.
//! 2. Scopes: a non-empty scope list from the provider is the new token's scope.
//!    An empty list means the response omitted `scope`, so the new token holds the
//!    refresh token's consent scope (RFC 6749 §5.1, §6), never the previous token's.
//!    A legacy record with no stored refresh scope falls back to the previous token's.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use mmp_oauth::flow::{AuthSession, Clock, ManualClock, PendingExchange};
use mmp_oauth::provider::{MockProvider, Provider, ProviderKind, ProviderProfile, ScopeRequest};
use mmp_oauth::storage::{AccountKey, InMemoryTokenStore, StoredTokens, TokenStore};
use mmp_oauth::{
    AccessGrant, OAuthCapability, OAuthError, OAuthService, RefreshedGrant, Secret, TokenPair,
};
use proptest::collection::vec;
use proptest::prelude::*;

const ACCOUNT: &str = "a@x.com";
const TTL: i64 = 3600;
const ORIGINAL_TOKEN: &str = "rt-original";
const ORIGINAL_SCOPE: &str = "scope-original";
const CASES: u32 = 1_000;

/// One scripted refresh response.
#[derive(Clone, Debug)]
struct Step {
    refresh_token: Option<String>,
    scopes: Vec<String>,
}

/// A rotating provider that answers each refresh from a script. It accepts only the
/// newest non-empty token it issued (an empty token is not a token, so it does not
/// rotate on one). Everything except `refresh` delegates to `MockProvider`.
struct ScriptedRotatingProvider {
    inner: MockProvider,
    live: Mutex<String>,
    script: Mutex<VecDeque<Step>>,
}

#[async_trait]
impl Provider for ScriptedRotatingProvider {
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
    async fn refresh(&self, presented: &Secret) -> Result<RefreshedGrant, OAuthError> {
        let step = {
            let mut live = self.live.lock().unwrap();
            if presented.expose() != live.as_str() {
                return Err(OAuthError::InvalidGrant {
                    reason: "refresh token was rotated out".into(),
                });
            }
            let step = self
                .script
                .lock()
                .unwrap()
                .pop_front()
                .expect("script covers every refresh");
            if let Some(token) = step.refresh_token.as_ref().filter(|t| !t.is_empty()) {
                live.clone_from(token);
            }
            step
        };
        let minted = self.inner.refresh(presented).await?.grant;
        Ok(RefreshedGrant {
            grant: AccessGrant {
                granted_scopes: step.scopes,
                ..minted
            },
            refresh_token: step.refresh_token.map(Secret::new),
        })
    }
    async fn revoke(&self, refresh_token: &Secret) -> Result<(), OAuthError> {
        self.inner.revoke(refresh_token).await
    }
}

/// Arbitrary token strings: absent, empty, short arbitrary Unicode, or very long.
fn token_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some(String::new())),
        any::<String>().prop_map(Some),
        "[A-Za-z0-9._/-]{1000,8192}".prop_map(Some),
    ]
}

/// A provider scope list: empty (the response omitted `scope`) or arbitrary entries.
fn scopes_strategy() -> impl Strategy<Value = Vec<String>> {
    prop_oneof![Just(Vec::new()), vec(any::<String>(), 1..5)]
}

fn steps_strategy() -> impl Strategy<Value = Vec<Step>> {
    vec(
        (token_strategy(), scopes_strategy()).prop_map(|(refresh_token, scopes)| Step {
            refresh_token,
            scopes,
        }),
        2..10,
    )
}

/// The model: what the store must hold after each step.
fn expected_after(
    step: &Step,
    token: &mut String,
    scopes: &mut Vec<String>,
    refresh_scopes: Option<&Vec<String>>,
) {
    if let Some(t) = step.refresh_token.as_ref().filter(|t| !t.is_empty()) {
        token.clone_from(t);
    }
    if !step.scopes.is_empty() {
        scopes.clone_from(&step.scopes);
    } else if let Some(consent) = refresh_scopes {
        scopes.clone_from(consent);
    }
}

/// The consent scope a fresh `authorize` leaves behind: both the cached token's
/// scope and the refresh token's scope.
fn consent_scopes() -> Vec<String> {
    vec![ORIGINAL_SCOPE.to_string(), "scope-write".to_string()]
}

fn run_case(steps: Vec<Step>, legacy_record: bool) -> Result<(), TestCaseError> {
    let refresh_scopes = (!legacy_record).then(consent_scopes);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async move {
        let key = AccountKey::new(ProviderKind::Google, ACCOUNT);
        let store = Arc::new(InMemoryTokenStore::new());
        store
            .save(
                &key,
                &StoredTokens {
                    refresh_token: Secret::new(ORIGINAL_TOKEN),
                    access_token: Some(Secret::new("stale-at")),
                    access_expires_at_unix: Some(0),
                    granted_scopes: consent_scopes(),
                    refresh_scopes: refresh_scopes.clone(),
                },
            )
            .unwrap();
        let clock = Arc::new(ManualClock::new(1_000));
        let provider = Arc::new(ScriptedRotatingProvider {
            inner: MockProvider::new(TTL),
            live: Mutex::new(ORIGINAL_TOKEN.into()),
            script: Mutex::new(steps.iter().cloned().collect()),
        });
        let svc = OAuthService::new(ArcProvider(Arc::clone(&provider)), store.clone())
            .with_clock(clock.clone());

        let (mut token, mut scopes) = (ORIGINAL_TOKEN.to_string(), consent_scopes());
        for (n, step) in steps.iter().enumerate() {
            provider.inner.set_issued_at(clock.now_unix());
            let grant = svc.access_token(ACCOUNT).await;
            prop_assert!(
                grant.is_ok(),
                "refresh #{} failed against a rotating provider: {:?}",
                n + 1,
                grant.err()
            );
            expected_after(step, &mut token, &mut scopes, refresh_scopes.as_ref());

            let stored = store.load(&key).unwrap().expect("account stays connected");
            prop_assert_eq!(
                stored.refresh_token.expose(),
                token.as_str(),
                "stored refresh token after refresh #{}",
                n + 1
            );
            prop_assert_eq!(
                &stored.granted_scopes,
                &scopes,
                "stored scopes after refresh #{}",
                n + 1
            );
            prop_assert_eq!(
                &grant.unwrap().granted_scopes,
                &scopes,
                "returned scopes after refresh #{}",
                n + 1
            );
            prop_assert_eq!(
                &stored.refresh_scopes,
                &refresh_scopes,
                "the refresh scope never changes (refresh #{})",
                n + 1
            );
            clock.advance(TTL + 1);
        }
        Ok(())
    })
}

/// `OAuthService` owns its provider; the test keeps a handle to read the mock.
struct ArcProvider(Arc<ScriptedRotatingProvider>);

#[async_trait]
impl Provider for ArcProvider {
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
    async fn revoke(&self, refresh_token: &Secret) -> Result<(), OAuthError> {
        self.0.revoke(refresh_token).await
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    /// Rules 1 and 2: after every refresh in any scripted sequence, the store
    /// holds the newest non-empty refresh token (else the original) and the newest
    /// non-empty scope list (else the consent scope; for a legacy record, the previous
    /// one), and every refresh succeeds.
    #[test]
    fn every_refresh_in_a_rotating_sequence_succeeds_and_persists_the_newest_token(
        steps in steps_strategy(),
        legacy_record in any::<bool>(),
    ) {
        run_case(steps, legacy_record)?;
    }
}
