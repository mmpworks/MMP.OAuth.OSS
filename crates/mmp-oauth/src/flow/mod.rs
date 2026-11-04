//! The flow edges: injected traits that make the OAuth flow deterministic.
//!
//! Each edge has a production implementation behind a feature flag and a test
//! double, so the whole flow (authorize, token, refresh, revoke) runs in tests
//! with no real provider:
//!
//! | Edge | Trait | Production implementation (feature) | Test double |
//! |---|---|---|---|
//! | HTTP | [`HttpTransport`] | `ReqwestTransport` (`reqwest-transport`) | a test double for HTTP |
//! | Clock | [`Clock`] | [`SystemClock`] | [`ManualClock`] |
//! | Browser opener | [`ConsentOpener`] | system browser (`loopback-flow`) | a test double that records the URL |
//! | Loopback listener | [`RedirectReceiver`] | `tiny_http` (`loopback-flow`) | a test double that returns a set redirect |
//!
//! `HttpTransport` is defined, with a reqwest implementation, for a provider that
//! takes its HTTP client as a parameter. `GoogleProvider` holds its own reqwest
//! client today; its tests point that client at a `wiremock` server.
//!
//! [`AuthSession`] holds the PKCE verifier (RFC 7636) and the CSRF `state` for one
//! pending authorization, in memory only. The verifier is never saved, and the
//! `state` is compared before the code exchange. That comparison blocks login
//! CSRF: without it, an attacker could hand the app a code from the attacker's
//! own account.

mod clock;
mod consent;
pub mod resilience;
mod session;
mod transport;

// The production loopback edges (browser opener and tiny_http listener) and the
// reqwest HTTP transport sit behind feature flags. The default build has none.
#[cfg(feature = "loopback-flow")]
pub(crate) mod loopback;
#[cfg(feature = "reqwest-transport")]
mod reqwest_transport;

pub use clock::{Clock, ManualClock, SystemClock};
pub use consent::run_consent_flow;
pub use session::{AuthSession, PendingExchange};
pub use transport::{
    ConsentOpener, HttpResponse, HttpTransport, RedirectOutcome, RedirectReceiver,
};

#[cfg(feature = "loopback-flow")]
pub use loopback::{LoopbackReceiver, SystemBrowserOpener};
#[cfg(feature = "reqwest-transport")]
pub use reqwest_transport::ReqwestTransport;
