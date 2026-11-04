//! Fuzz target F6: the token lifecycle over arbitrary stored values.
//!
//! A `TokenStore` is host code, so a stored record can hold any expiry, including
//! values a provider would never send. The harness seeds the in-memory store with an
//! arbitrary cached-token expiry (or none) and an arbitrary clock value, then calls
//! `status` and `access_token` through the public service.
//!
//! Oracle:
//! 1. No input panics.
//! 2. `status` is `Active` if and only if a cached expiry exists and
//!    `now < expiry - 60` in wide (`i128`) arithmetic, which cannot overflow.
//! 3. `access_token` succeeds, and serves the cached token when `status` was
//!    `Active`, else a refreshed token.
//!
//! Under `cargo test` bolero runs random inputs. Under libFuzzer:
//! `cargo bolero test -p mmp-oauth --all-features --toolchain nightly -T 1800s stored_expiry_never_panics_and_matches_the_model`.

use std::sync::Arc;

use mmp_oauth::flow::ManualClock;
use mmp_oauth::provider::MockProvider;
use mmp_oauth::storage::InMemoryTokenStore;
use mmp_oauth::{
    AccountKey, OAuthCapability, OAuthService, ProviderKind, Secret, StoredTokens, TokenState,
    TokenStore,
};

/// The refresh margin the service uses, in seconds.
const SKEW: i128 = 60;

fn seeded_store(expiry: Option<i64>) -> Arc<InMemoryTokenStore> {
    let store = Arc::new(InMemoryTokenStore::new());
    let tokens = StoredTokens {
        refresh_token: Secret::new("rt"),
        access_token: Some(Secret::new("cached-at")),
        access_expires_at_unix: expiry,
        granted_scopes: vec!["scope".into()],
        refresh_scopes: None,
    };
    store
        .save(&AccountKey::new(ProviderKind::Google, "a@x.com"), &tokens)
        .unwrap();
    store
}

fn check(expiry: Option<i64>, now: i64, runtime: &tokio::runtime::Runtime) {
    let provider = MockProvider::new(3600);
    provider.set_issued_at(now);
    let service = OAuthService::new(provider, seeded_store(expiry))
        .with_clock(Arc::new(ManualClock::new(now)));

    let model_active = expiry.is_some_and(|exp| i128::from(now) < i128::from(exp) - SKEW);
    let state = service.status("a@x.com");
    assert_eq!(
        state == TokenState::Active,
        model_active,
        "status for expiry={expiry:?} now={now}"
    );

    let grant = runtime
        .block_on(service.access_token("a@x.com"))
        .expect("a stored account always yields a token");
    let served_cache = grant.access_token.expose() == "cached-at";
    assert_eq!(
        served_cache, model_active,
        "cache use for expiry={expiry:?} now={now}"
    );
}

#[test]
fn stored_expiry_never_panics_and_matches_the_model() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    bolero::check!()
        .with_type::<(Option<i64>, i64)>()
        .for_each(|(expiry, now)| check(*expiry, *now, &runtime));
}

/// The extremes the random run may not reach.
#[test]
fn extreme_expiries_and_clocks_match_the_model() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let edges = [
        i64::MIN,
        i64::MIN + 59,
        i64::MIN + 60,
        -1,
        0,
        59,
        60,
        61,
        i64::MAX - 60,
        i64::MAX,
    ];
    for &now in &edges {
        check(None, now, &runtime);
        for &exp in &edges {
            check(Some(exp), now, &runtime);
        }
    }
}
