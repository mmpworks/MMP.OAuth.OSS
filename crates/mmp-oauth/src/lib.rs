//! # mmp-oauth
//!
//! A small OAuth 2.0 client for desktop applications. It turns a user's consent
//! into a live access token that refreshes itself, through four methods on
//! [`OAuthCapability`]. The provider, the token store, the clock, the browser and
//! the loopback listener are injected traits, so the whole flow runs in tests with
//! a mock provider and no network.
//!
//! ## Scope
//!
//! The crate wraps the [`oauth2`] crate (5.0), which implements the RFC 6749 flows,
//! PKCE (RFC 7636) and token revocation (RFC 7009). It adds the four things
//! `oauth2` leaves to the caller: provider profiles, token persistence, automatic
//! refresh, and the desktop loopback flow (RFC 8252). It stops at the access token:
//! mail, identity, and single sign-on belong to the host.
//!
//! ## Terms
//!
//! - **Access token**: a short-lived key the app sends with each API call.
//! - **Refresh token**: a long-lived key that gets a new access token without
//!   asking the user again.
//! - **Scope**: one permission, as a string the provider defines.
//! - **Consent**: the browser page where the user signs in and clicks Allow.
//! - **Authorization code**: the one-time value the provider returns after consent.
//!   The app exchanges it for the first tokens.
//! - **Loopback redirect**: after consent, the provider sends the browser to
//!   `http://127.0.0.1:<port>`, where this crate listens for one request.
//! - **PKCE** (RFC 7636): a one-time secret the app creates per sign-in. The
//!   provider exchanges the code only for the app that holds it, so a stolen code
//!   is useless.
//! - **CSRF `state`**: a random value the redirect must return unchanged. It stops
//!   an attacker from handing the app a code from the attacker's own account.
//! - **Edge**: a trait for something outside the process (the provider, the token
//!   store, the clock, the browser, the loopback listener). The host passes in the
//!   real one. A test passes in a test double.
//! - **Test double**: a stand-in for an edge in tests. [`provider::MockProvider`] is
//!   the test double for a provider.
//!
//! ## Resource-agnostic
//!
//! OAuth authorizes an application to access a user's data at a provider. This
//! crate ends at the access token. What the host does with the token is the
//! host's choice. The same four methods serve Gmail, Google Drive, Google
//! Calendar, or Microsoft Graph. A [`provider::Provider`] exposes the scopes it
//! supports, and the host requests the ones a feature needs as
//! [`provider::ScopeRequest`] values. A new resource is a new scope string, with no
//! change to this crate. Resource base URLs and API calls belong to the host.
//!
//! ## The four methods
//!
//! - [`OAuthCapability::authorize`]: run the consent flow for a provider and a
//!   set of scopes. Returns a saved, live [`token::AccessGrant`].
//! - [`OAuthCapability::access_token`]: the current access token, refreshed
//!   first if it is due. A resource adapter calls it before every API request.
//! - [`OAuthCapability::revoke`]: disconnect. Revokes at the provider and clears
//!   the stored tokens.
//! - [`OAuthCapability::status`]: the lifecycle state for a UI ("connected",
//!   "needs re-consent"). No I/O.
//!
//! The host wires the edges once. [`OAuthService`] coordinates them.
//!
//! ## Modules
//!
//! | Module | Holds |
//! |---|---|
//! | [`provider`] | One type per OAuth provider, and the `Provider` trait |
//! | [`storage`] | Where tokens rest: the `TokenStore` trait and its implementations |
//! | [`flow`] | The browser opener, the loopback listener, the clock, and the retry hook |
//! | [`token`] | The token values and the lifecycle state |
//! | [`error`] | `OAuthError` and its retry classification |
//!
//! ## Feature flags
//!
//! The default build is the pure core: the traits, the token state machine, the
//! mock provider, and the in-memory store. It has no network, no OS keystore, and
//! no async runtime.
//!
//! | Feature | Adds |
//! |---|---|
//! | `reqwest-transport` | `GoogleProvider`, `MicrosoftProvider`, and `ReqwestTransport` |
//! | `loopback-flow` | `LoopbackReceiver` and `SystemBrowserOpener`, the desktop consent edges |
//! | `keyring-store` | `KeyringTokenStore`, a `TokenStore` over the OS keystore |
//! | `testbed` | the `testbed` module and, with the two features above, the `oauth_testbed` binary |
//!
//! A desktop application usually enables `reqwest-transport` and `loopback-flow`,
//! and either `keyring-store` or its own `TokenStore`.
//!
//! ## Versioning
//!
//! The crate is at 0.x. A breaking change raises the minor version (0.1 to 0.2),
//! and a fix raises the patch version. The minimum supported Rust version is the
//! `rust-version` in the workspace manifest. Anything marked `#[doc(hidden)]` is
//! outside this promise.
//!
//! ## Example
//!
//! The mock provider and the in-memory store need no network:
//!
//! ```
//! use std::sync::Arc;
//! use mmp_oauth::provider::MockProvider;
//! use mmp_oauth::storage::InMemoryTokenStore;
//! use mmp_oauth::{OAuthCapability, OAuthService, TokenState};
//!
//! let service = OAuthService::new(MockProvider::new(3600), Arc::new(InMemoryTokenStore::new()));
//! assert_eq!(service.status("user@example.com"), TokenState::Unauthorized);
//! ```
//!
//! The design notes (the design patterns used, and the designs considered and
//! not used) are in the repository's `docs/design/` folder.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod flow;
pub mod provider;
pub mod storage;
#[cfg(feature = "testbed")]
pub mod testbed;
pub mod token;

mod capability;

pub use capability::{OAuthCapability, OAuthService};
pub use error::OAuthError;
pub use provider::{Provider, ProviderKind, ProviderProfile, ScopeRequest};
// `Secret` is defined in the `mmp-secret` leaf crate and re-exported here, so a
// host can name it as `mmp_oauth::Secret` without a second dependency. Internal
// modules refer to it as `crate::Secret`.
pub use mmp_secret::Secret;
pub use storage::{AccountKey, StoredTokens, TokenStore};
pub use token::{AccessGrant, RefreshedGrant, TokenPair, TokenState};

/// Entry points for the fuzz and property harnesses. Not part of the public API:
/// it is hidden from the docs, exists only with the `fuzzing` feature, and carries
/// no semver promise. It wraps private parsers so a harness outside the crate can
/// call them.
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod __fuzz {
    /// Split a loopback request target and parse its redirect query, as the
    /// loopback receiver does for one request.
    #[cfg(feature = "loopback-flow")]
    pub fn redirect_target(url: &str) -> Result<crate::flow::RedirectOutcome, crate::OAuthError> {
        let (_path, query) = crate::flow::loopback::split_path_query(url);
        crate::flow::loopback::parse_redirect_query(query)
    }

    /// Parse a token response body and map it to a grant, as `GoogleProvider` does.
    #[cfg(feature = "reqwest-transport")]
    #[must_use]
    pub fn token_body(body: &[u8], requested_scopes: Vec<String>) -> Option<crate::AccessGrant> {
        crate::provider::oauth2_core::fuzz_token_body(body, requested_scopes)
    }

    /// Parse a token error body and classify it, as `GoogleProvider` does.
    #[cfg(feature = "reqwest-transport")]
    pub fn error_body(body: &[u8]) -> Option<crate::OAuthError> {
        crate::provider::oauth2_core::fuzz_error_body(
            body,
            crate::provider::oauth2_core::classify_token_error,
        )
    }

    /// Parse a token error body and classify it, as `MicrosoftProvider` does.
    #[cfg(feature = "reqwest-transport")]
    pub fn error_body_microsoft(body: &[u8]) -> Option<crate::OAuthError> {
        crate::provider::oauth2_core::fuzz_error_body(
            body,
            crate::provider::microsoft::classify_microsoft_error,
        )
    }
}
