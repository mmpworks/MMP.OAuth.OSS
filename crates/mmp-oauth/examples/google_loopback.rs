//! The real desktop flow with Google: the system browser, a `127.0.0.1` loopback
//! listener, PKCE, and a token you can refresh.
//!
//! This example needs a Google OAuth client of type "Desktop app". Create one in
//! the Google Cloud console under APIs and Services, Credentials. It reads the
//! client id from `GOOGLE_CLIENT_ID` and the client secret from
//! `GOOGLE_CLIENT_SECRET`. Google's Desktop client type sends the secret in the
//! token exchange even with PKCE; Google does not treat it as confidential for an
//! installed app.
//!
//! Tokens are kept in memory, so the account is gone when the program exits. A
//! real application passes a persistent `TokenStore` (see `custom_token_store`).
//!
//! Run it with:
//!
//! ```text
//! GOOGLE_CLIENT_ID=... GOOGLE_CLIENT_SECRET=... \
//!   cargo run -p mmp-oauth --features reqwest-transport,loopback-flow --example google_loopback
//! ```

use std::sync::Arc;

use mmp_oauth::flow::{LoopbackReceiver, SystemBrowserOpener};
use mmp_oauth::provider::GoogleProvider;
use mmp_oauth::storage::InMemoryTokenStore;
use mmp_oauth::{OAuthCapability, OAuthError, OAuthService, ScopeRequest, Secret};

#[tokio::main]
async fn main() -> Result<(), OAuthError> {
    let Ok(client_id) = std::env::var("GOOGLE_CLIENT_ID") else {
        eprintln!("Set GOOGLE_CLIENT_ID (and GOOGLE_CLIENT_SECRET) to a Google \"Desktop app\" OAuth client.");
        return Ok(());
    };
    let mut provider = GoogleProvider::new(client_id)?;
    if let Ok(secret) = std::env::var("GOOGLE_CLIENT_SECRET") {
        provider = provider.with_secret(Some(Secret::new(secret)));
    }

    let receiver = LoopbackReceiver::bind()?;
    let service = OAuthService::new(provider, Arc::new(InMemoryTokenStore::new()))
        .with_loopback(Arc::new(SystemBrowserOpener), Arc::new(receiver));

    let scope = ScopeRequest::at_connect(
        "https://www.googleapis.com/auth/userinfo.email",
        "identify-account",
        "read the connected account's email address",
    );
    println!("Opening the consent page in your browser...");
    let grant = service.authorize("me", &[scope]).await?;
    println!(
        "Connected. Token {:?}, granted {:?}",
        grant.access_token, grant.granted_scopes
    );

    let token = service.access_token("me").await?;
    println!(
        "access_token serves {:?}, expires at {}",
        token.access_token, token.expires_at_unix
    );

    service.revoke("me").await?;
    println!("Revoked and cleared.");
    Ok(())
}
