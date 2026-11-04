//! The error type for every OAuth operation.
//!
//! The classification drives the retry choice (see `flow::resilience`).
//! [`OAuthError::InvalidGrant`] is permanent: the refresh token is dead, the user
//! must consent again, and a retry cannot help. [`OAuthError::Transient`] and
//! [`OAuthError::Throttled`] are worth a retry with backoff. A host branches on
//! [`OAuthError::is_retryable`] and [`OAuthError::requires_reconsent`], never on
//! the message text.

use thiserror::Error;

/// Everything that can go wrong while getting or refreshing a token. The service
/// returns every error to the host.
///
/// No variant carries text from a provider's response body. Provider error codes
/// pass through an allowlist, so a hostile or verbose response cannot place its
/// content in a log line.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OAuthError {
    /// The user closed the consent page, or the loopback deadline passed before a
    /// code arrived. The host can offer "connection cancelled, try again".
    #[error("consent was abandoned before a code arrived")]
    ConsentAbandoned,

    /// The redirect's `state` did not match the value this session generated.
    /// This is the CSRF (cross-site request forgery) check from RFC 6749 section
    /// 10.12. On a mismatch the crate does not exchange the code.
    #[error("CSRF state mismatch: refusing to exchange the authorization code")]
    StateMismatch,

    /// The provider rejected the grant, for example a revoked or expired refresh
    /// token. Permanent: do not retry. The host must run `authorize` again.
    #[error("provider rejected the grant ({reason}); re-consent required")]
    InvalidGrant {
        /// The provider's error code from an allowlist (for example `invalid_grant`).
        reason: String,
    },

    /// A failure a retry can fix: a network error, a reset connection, or an HTTP
    /// 5xx response.
    #[error("transient transport failure: {0}")]
    Transient(String),

    /// The provider asked the client to slow down (HTTP 429). Retry after a backoff.
    #[error("throttled by the provider")]
    Throttled {
        /// How long the provider asked the client to wait: its `Retry-After` header
        /// in seconds, capped at 24 hours because the value comes from the network.
        /// `None` when the header is absent or holds an HTTP date.
        retry_after: Option<std::time::Duration>,
    },

    /// No tokens are stored for this account. `authorize` never ran, or the account
    /// was revoked.
    #[error("no stored credentials for this account")]
    NotConnected,

    /// The token store failed, for example a locked vault or an unavailable keystore.
    #[error("token storage failure: {0}")]
    Storage(String),

    /// A configuration error: a bad provider profile, an invalid URL, or a missing
    /// edge such as the loopback receiver.
    #[error("configuration error: {0}")]
    Config(String),
}

impl OAuthError {
    /// True when a retry of the same operation can succeed ([`OAuthError::Transient`]
    /// and [`OAuthError::Throttled`]). A host's retry policy reads this.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            OAuthError::Transient(_) | OAuthError::Throttled { .. }
        )
    }

    /// True when the user must consent again ([`OAuthError::InvalidGrant`] and
    /// [`OAuthError::NotConnected`]).
    #[must_use]
    pub fn requires_reconsent(&self) -> bool {
        matches!(
            self,
            OAuthError::InvalidGrant { .. } | OAuthError::NotConnected
        )
    }
}
