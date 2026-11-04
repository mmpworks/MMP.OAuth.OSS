//! Quick start: the four methods end to end, with no network and no credentials.
//!
//! It uses `MockProvider` for the provider, `InMemoryTokenStore` for storage, and
//! two small doubles for the browser and the loopback redirect. A real host swaps
//! in `GoogleProvider`, a persistent `TokenStore`, `SystemBrowserOpener` and
//! `LoopbackReceiver`; the four calls stay the same.
//!
//! Run it with `cargo run -p mmp-oauth --example quickstart_mock`.

use std::sync::Arc;

use async_trait::async_trait;
use mmp_oauth::flow::{ConsentOpener, ManualClock, RedirectOutcome, RedirectReceiver};
use mmp_oauth::provider::MockProvider;
use mmp_oauth::storage::InMemoryTokenStore;
use mmp_oauth::{OAuthCapability, OAuthError, OAuthService, ScopeRequest, TokenState};

/// Stands in for the system browser. It prints the consent URL instead of opening it.
struct PrintingOpener;

impl ConsentOpener for PrintingOpener {
    fn open(&self, authorize_url: &str) -> Result<(), OAuthError> {
        println!("1. consent URL : {authorize_url}");
        Ok(())
    }
}

/// Stands in for the loopback listener. It returns the redirect a provider would
/// send after the user clicks Allow. `MockProvider` issues the state `mock-state`.
struct InstantRedirect;

#[async_trait]
impl RedirectReceiver for InstantRedirect {
    fn redirect_uri(&self) -> String {
        "http://127.0.0.1:50000/callback".into()
    }

    async fn wait_for_redirect(&self) -> Result<RedirectOutcome, OAuthError> {
        Ok(RedirectOutcome {
            code: "example-code".into(),
            state: "mock-state".into(),
        })
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), OAuthError> {
    let account = "user@example.com";
    // A fixed clock, so the output is the same on every run. The mock issues its
    // tokens against the same time.
    let now = 1_800_000_000;
    let provider = MockProvider::new(3600);
    provider.set_issued_at(now);
    let service = OAuthService::new(provider, Arc::new(InMemoryTokenStore::new()))
        .with_clock(Arc::new(ManualClock::new(now)))
        .with_loopback(Arc::new(PrintingOpener), Arc::new(InstantRedirect));

    assert_eq!(service.status(account), TokenState::Unauthorized);

    // authorize: consent, CSRF check, code exchange, save.
    let scope = ScopeRequest::at_connect(
        "https://www.googleapis.com/auth/userinfo.email",
        "identify-account",
        "read the connected account's email address",
    );
    let grant = service.authorize(account, &[scope]).await?;
    println!(
        "2. authorize   : granted {:?}, token {:?}",
        grant.granted_scopes, grant.access_token
    );

    // access_token: the call a resource adapter makes before each API request.
    let token = service.access_token(account).await?;
    println!(
        "3. access_token: {:?}, expires at {}",
        token.access_token, token.expires_at_unix
    );

    // status: for a UI, with no I/O.
    println!("4. status      : {:?}", service.status(account));

    // revoke: disconnect and clear local tokens.
    service.revoke(account).await?;
    println!(
        "5. revoke      : status is now {:?}",
        service.status(account)
    );
    assert_eq!(service.status(account), TokenState::Unauthorized);
    Ok(())
}
