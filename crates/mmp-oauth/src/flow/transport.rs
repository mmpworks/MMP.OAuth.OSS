//! The HTTP, browser-opener, and loopback-listener edges as injectable traits.
//! The production implementations sit behind the `reqwest-transport` and
//! `loopback-flow` features. Tests supply test doubles, so no port is bound and no
//! browser opens.

use async_trait::async_trait;

use crate::error::OAuthError;

/// A minimal HTTP response: status and body. The token and revocation endpoints
/// need nothing more.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: u16,
    /// The response body bytes (token JSON or error JSON).
    pub body: Vec<u8>,
}

/// The HTTP edge to the provider's token and revocation endpoints. It is injected
/// so tests can drive the token flow with a fake or with `wiremock`. OAuth token
/// and revocation endpoints take a form POST and nothing else (RFC 6749 section
/// 4.1.3, RFC 7009 section 2.1).
#[async_trait]
pub trait HttpTransport: Send + Sync {
    /// POST `form` to `url` as `application/x-www-form-urlencoded` pairs.
    async fn post_form(&self, url: &str, form: &[(&str, &str)])
        -> Result<HttpResponse, OAuthError>;
}

/// Opens the consent URL in the user's browser. It is injected so a test can
/// record the URL instead of launching a browser.
pub trait ConsentOpener: Send + Sync {
    /// Open `authorize_url`. Production opens the system browser.
    ///
    /// # Errors
    ///
    /// Any [`OAuthError`] the opener reports, for example when the browser cannot
    /// be launched.
    fn open(&self, authorize_url: &str) -> Result<(), OAuthError>;
}

/// The result of waiting on the loopback redirect.
///
/// `Debug` redacts `code`. An authorization code is a credential until it is
/// exchanged (RFC 6749 section 10.5), so it must not reach a log line.
#[derive(Clone)]
pub struct RedirectOutcome {
    /// The authorization code from the query string.
    pub code: String,
    /// The `state` the provider returned. The session checks it.
    pub state: String,
}

impl std::fmt::Debug for RedirectOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedirectOutcome")
            .field("code", &crate::flow::session::RedactedCode(&self.code))
            .field("state", &self.state)
            .finish()
    }
}

/// Listens on the loopback interface for the provider's redirect and returns
/// `(code, state)`. Production binds `127.0.0.1:0`, so the OS picks a free port,
/// with a one-shot listener and a deadline (RFC 8252 section 7.3). A test supplies
/// the outcome directly.
#[async_trait]
pub trait RedirectReceiver: Send + Sync {
    /// The redirect URI this receiver listens on, built from the bound port.
    fn redirect_uri(&self) -> String;
    /// Wait for the one redirect.
    ///
    /// # Errors
    ///
    /// [`OAuthError::ConsentAbandoned`] when the deadline passes or the user
    /// denies consent.
    async fn wait_for_redirect(&self) -> Result<RedirectOutcome, OAuthError>;
}
