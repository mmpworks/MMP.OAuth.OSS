//! Automatic refresh: `access_token` refreshes an expired token once, and a refresh
//! observer reports it.
//!
//! A `ManualClock` stands in for time, so the example moves past the token's
//! expiry in one call instead of waiting an hour. It needs no network and no
//! credentials.
//!
//! Run it with `cargo run -p mmp-oauth --example auto_refresh`.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use mmp_oauth::flow::ManualClock;
use mmp_oauth::provider::MockProvider;
use mmp_oauth::storage::InMemoryTokenStore;
use mmp_oauth::{
    AccountKey, OAuthCapability, OAuthError, OAuthService, ProviderKind, Secret, StoredTokens,
    TokenStore,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), OAuthError> {
    let account = "user@example.com";
    let start = 1_800_000_000;

    // A store that already holds a connected account, as after `authorize`. The
    // cached access token expires one hour after `start`.
    let store = Arc::new(InMemoryTokenStore::new());
    store.save(
        &AccountKey::new(ProviderKind::Google, account),
        &StoredTokens {
            refresh_token: Secret::new("refresh-token"),
            access_token: Some(Secret::new("first-access-token")),
            access_expires_at_unix: Some(start + 3600),
            granted_scopes: vec!["https://www.googleapis.com/auth/userinfo.email".into()],
            refresh_scopes: None,
        },
    )?;

    let clock = Arc::new(ManualClock::new(start));
    let refreshes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&refreshes);
    let provider = MockProvider::new(3600);
    provider.set_issued_at(start + 3600);
    let service = OAuthService::new(provider, store)
        .with_clock(clock.clone())
        .with_refresh_observer(Arc::new(move |key| {
            counter.fetch_add(1, Ordering::SeqCst);
            println!("   observer: refreshed {}", key.storage_ref());
        }));

    let token = service.access_token(account).await?;
    println!(
        "1. at start          : {:?}, status {:?}",
        token.access_token,
        service.status(account)
    );

    // Move to 30 seconds before expiry, inside the 60-second refresh margin.
    clock.advance(3600 - 30);
    println!(
        "2. 30 s before expiry: status {:?}",
        service.status(account)
    );
    let token = service.access_token(account).await?;
    println!(
        "3. access_token      : {:?}, expires at {}",
        token.access_token, token.expires_at_unix
    );

    // A second call serves the new cached token, with no second refresh.
    service.access_token(account).await?;
    println!(
        "4. refreshes in total: {}",
        refreshes.load(Ordering::SeqCst)
    );
    assert_eq!(refreshes.load(Ordering::SeqCst), 1);
    Ok(())
}
