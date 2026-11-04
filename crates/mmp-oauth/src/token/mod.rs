//! The token lifecycle as a named state.
//!
//! An account with OAuth credentials moves through a small state machine.
//! [`TokenState`] is its public readout. The state names live in one place, and
//! the service, a UI status label, and an audit log all read the same names.
//!
//! ```text
//!   Unauthorized ──authorize()──▶ Active ──(clock passes expiry)──▶ Expired
//!        ▲                          │                                  │
//!        │                          │ revoke()              access_token() triggers
//!        └──────────revoke()────────┴──◀── Revoked            Refreshing ──┐
//!                                                                  │       │
//!                                          Active ◀──refresh ok────┘       │
//!                                                                          │
//!                          NeedsReconsent ◀──refresh = InvalidGrant────────┘
//! ```
//!
//! The readout is an enum, not one struct per state. The transitions are few and
//! the behaviour differences are small: `Active` and `Expired` both hold an access
//! token, and the only question is whether it is still valid. An enum gives one
//! named state with no scattered boolean flags.

pub(crate) mod grant;

pub use grant::{AccessGrant, RefreshedGrant, TokenPair};

/// The lifecycle state of an account's OAuth credentials. The service reads it to
/// pick the next action, and a UI reads it to show the connection state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenState {
    /// No tokens are stored. `authorize` never ran, or the account was revoked.
    Unauthorized,
    /// An access token is stored and is outside the refresh margin.
    Active,
    /// An access token is stored but is inside the refresh margin or past expiry.
    /// The next `access_token()` call refreshes it.
    Expired,
    /// A refresh is in progress.
    Refreshing,
    /// The refresh token is dead (the provider returned `invalid_grant`). The user
    /// must consent again. The state holds until `authorize` runs.
    NeedsReconsent,
    /// The user disconnected. The tokens were revoked at the provider and cleared.
    Revoked,
}

impl TokenState {
    /// True when an API call can proceed without new consent. `Expired` counts,
    /// because `access_token()` refreshes it.
    #[must_use]
    pub fn can_serve_token(self) -> bool {
        matches!(self, TokenState::Active | TokenState::Expired)
    }

    /// True when the host must show a "reconnect" prompt.
    #[must_use]
    pub fn needs_user_action(self) -> bool {
        matches!(
            self,
            TokenState::Unauthorized | TokenState::NeedsReconsent | TokenState::Revoked
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_and_expired_can_serve_a_token() {
        assert!(TokenState::Active.can_serve_token());
        assert!(
            TokenState::Expired.can_serve_token(),
            "expired refreshes transparently"
        );
    }

    #[test]
    fn dead_states_need_user_action() {
        assert!(TokenState::NeedsReconsent.needs_user_action());
        assert!(TokenState::Unauthorized.needs_user_action());
        assert!(TokenState::Revoked.needs_user_action());
        assert!(!TokenState::Active.needs_user_action());
    }
}
