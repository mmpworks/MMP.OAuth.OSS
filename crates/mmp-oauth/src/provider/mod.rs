//! Providers: one OAuth provider per implementation, behind one trait.
//!
//! A [`Provider`] holds one provider's flow, endpoints and quirks. Each concrete
//! provider (`GoogleProvider`, `MicrosoftProvider`) adapts the four methods to that
//! provider's wire format. A provider is identified by the authorization server it
//! talks to, never by the resource a host reads: the same provider mints tokens
//! for Gmail, Drive, or Calendar. The quirks that do vary by provider are data in
//! [`ProviderProfile`]:
//!   - Google: a `127.0.0.1` loopback redirect, not `localhost`. Restricted scopes
//!     (for example a mailbox scope) need Google's app verification before release.
//!   - Microsoft: the v2 `common` endpoints, which accept personal and work
//!     accounts, and HTTP 429 throttling.
//!
//! The endpoint and scope differences live in a [`ProviderProfile`] value. A new
//! provider is a new profile and a thin adapter, with no change to the service or
//! to any host. [`ProviderKind`] selects which provider to build.
//!
//! ## Holding a provider as `dyn Provider`
//!
//! `Provider` uses `#[async_trait]`, so a host can hold it as `dyn Provider`. The
//! OAuth flow runs at human speed (seconds between steps), so the allocation per
//! call has no measurable cost.

use async_trait::async_trait;

use crate::error::OAuthError;
use crate::flow::{AuthSession, PendingExchange};
use crate::token::{RefreshedGrant, TokenPair};

mod mock;
mod profile;

#[cfg(feature = "reqwest-transport")]
pub(crate) mod google;
#[cfg(all(test, feature = "reqwest-transport"))]
mod google_props;
#[cfg(all(test, feature = "reqwest-transport"))]
mod google_scenarios;
#[cfg(feature = "reqwest-transport")]
pub(crate) mod microsoft;
#[cfg(all(test, feature = "reqwest-transport"))]
mod microsoft_scenarios;
#[cfg(feature = "reqwest-transport")]
pub(crate) mod oauth2_core;

pub use mock::MockProvider;
pub use profile::{ProviderProfile, ScopeRequest};

#[cfg(feature = "reqwest-transport")]
pub use google::GoogleProvider;
#[cfg(feature = "reqwest-transport")]
pub use microsoft::MicrosoftProvider;

/// The known providers. A closed enum, so every `match` on it must handle a new
/// provider. A free string would compile and fail at run time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProviderKind {
    /// Google (Gmail, Drive, Calendar, and any other Google API the host requests
    /// scopes for).
    Google,
    /// Microsoft (Graph mail, files, calendar, and any other Graph resource the
    /// host requests scopes for).
    Microsoft,
}

impl ProviderKind {
    /// A stable lowercase name, used in storage references and logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            ProviderKind::Google => "google",
            ProviderKind::Microsoft => "microsoft",
        }
    }
}

/// One OAuth provider's behaviour behind one trait. Each method is a step the
/// service runs. The provider adapter owns the wire detail.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Which provider this is.
    fn kind(&self) -> ProviderKind;

    /// The provider's static profile: endpoints, client id, and quirks.
    fn profile(&self) -> &ProviderProfile;

    /// Begin authorization. Build the consent URL that the browser opens, with a
    /// PKCE S256 challenge (RFC 7636) and a CSRF `state`, and return the
    /// [`AuthSession`] that holds the verifier and the `state` in memory. The
    /// provider owns its redirect-host and scope-encoding rules here.
    fn begin_authorization(&self, scopes: &[ScopeRequest], redirect_uri: &str) -> AuthSession;

    /// Exchange an authorization code for the first token pair: the live grant and
    /// the refresh token to save. The `PendingExchange` type proves the CSRF
    /// `state` already matched.
    ///
    /// # Errors
    ///
    /// [`OAuthError::InvalidGrant`] when the provider rejects the code,
    /// [`OAuthError::Transient`] or [`OAuthError::Throttled`] on a retryable
    /// failure, and [`OAuthError::Config`] on a bad endpoint URL or when the token
    /// endpoint rejects the request itself (`invalid_client`, `invalid_request`,
    /// `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`).
    async fn exchange_code(&self, pending: PendingExchange) -> Result<TokenPair, OAuthError>;

    /// Get a new access token from a refresh token. Returns the new grant and the
    /// refresh token the response carried, if any. A rotating provider issues a new
    /// one and invalidates `refresh_token`. When the response omits `scope`,
    /// `granted_scopes` is empty, and the service applies the refresh token's
    /// consent scope (`StoredTokens.refresh_scopes`). It falls back to the previous
    /// token's `granted_scopes` only for an older record that has no refresh scopes.
    ///
    /// # Errors
    ///
    /// The provider classifies its own errors. A dead refresh token is
    /// [`OAuthError::InvalidGrant`]. A 429 is [`OAuthError::Throttled`]. A network
    /// failure or 5xx is [`OAuthError::Transient`]. A client error (`invalid_client`
    /// and the others above) is [`OAuthError::Config`].
    async fn refresh(&self, refresh_token: &crate::Secret) -> Result<RefreshedGrant, OAuthError>;

    /// Revoke a token at the provider (RFC 7009 where the provider supports it).
    /// The service treats this as best effort: it clears the local tokens whatever
    /// the result.
    async fn revoke(&self, refresh_token: &crate::Secret) -> Result<(), OAuthError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_kind_str_is_stable() {
        assert_eq!(ProviderKind::Google.as_str(), "google");
        assert_eq!(ProviderKind::Microsoft.as_str(), "microsoft");
    }
}
