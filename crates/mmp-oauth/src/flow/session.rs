//! [`AuthSession`] is the in-memory state of a pending authorization.
//! [`PendingExchange`] is a session whose redirect arrived with a matching CSRF
//! `state`, ready to exchange.
//!
//! The two types make the CSRF check a type-state check: one the compiler
//! enforces. No `PendingExchange` value exists until the `state` matched, and
//! `Provider::exchange_code` takes only a `PendingExchange`, so code that skips the
//! check does not compile. The only way to get one is
//! [`AuthSession::validate_redirect`], which rejects a mismatched `state`.

use crate::error::OAuthError;
use crate::Secret;

/// A pending authorization: the consent URL is built and the browser is open. It
/// holds the PKCE verifier and the CSRF `state` in memory only. Neither is saved.
#[derive(Debug)]
pub struct AuthSession {
    /// The URL to open in the system browser.
    pub authorize_url: String,
    /// The loopback redirect URI that the provider calls back.
    pub redirect_uri: String,
    /// The CSRF `state` this session generated. The redirect must return it.
    csrf_state: String,
    /// The PKCE code verifier (RFC 7636). It is sent with the code exchange and
    /// never stored.
    pkce_verifier: Secret,
    /// The requested scopes. They become the grant's scopes when the response
    /// omits `scope`.
    requested_scopes: Vec<String>,
}

/// A redirect that arrived and matched the CSRF `state`. It is the only value
/// that can be exchanged, so holding one proves the `state` check passed.
///
/// `Debug` redacts `code`. An authorization code is a credential until it is
/// exchanged (RFC 6749 section 10.5), so it must not reach a log line.
pub struct PendingExchange {
    /// The authorization code from the provider.
    pub code: String,
    /// The PKCE code verifier to send with the exchange.
    pub pkce_verifier: Secret,
    /// The scopes requested at authorization.
    pub requested_scopes: Vec<String>,
    /// The redirect URI from the authorization request, with its real loopback
    /// port. RFC 6749 section 4.1.3 requires the token request to send the same
    /// value, and Google rejects a mismatch with `invalid_request`. It is carried
    /// from the session, never rebuilt.
    pub redirect_uri: String,
}

impl std::fmt::Debug for PendingExchange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingExchange")
            .field("code", &RedactedCode(&self.code))
            .field("pkce_verifier", &self.pkce_verifier)
            .field("requested_scopes", &self.requested_scopes)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

/// Formats an authorization code as its length only, in the same shape as the
/// `Secret` redaction. Shared by every type that holds a code.
pub(crate) struct RedactedCode<'a>(pub(crate) &'a str);

impl std::fmt::Debug for RedactedCode<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "<redacted len={}>", self.0.len())
    }
}

impl AuthSession {
    /// Build a session. `Provider::begin_authorization` calls this.
    pub fn new(
        authorize_url: impl Into<String>,
        redirect_uri: impl Into<String>,
        csrf_state: impl Into<String>,
        pkce_verifier: Secret,
        requested_scopes: Vec<String>,
    ) -> Self {
        Self {
            authorize_url: authorize_url.into(),
            redirect_uri: redirect_uri.into(),
            csrf_state: csrf_state.into(),
            pkce_verifier,
            requested_scopes,
        }
    }

    /// Check a redirect's `(code, state)` against this session.
    ///
    /// # Errors
    ///
    /// [`OAuthError::StateMismatch`] when `returned_state` differs from the
    /// session's `state`. The session is consumed, so no exchange is possible.
    pub fn validate_redirect(
        self,
        code: String,
        returned_state: &str,
    ) -> Result<PendingExchange, OAuthError> {
        if !constant_time_eq(self.csrf_state.as_bytes(), returned_state.as_bytes()) {
            return Err(OAuthError::StateMismatch);
        }
        Ok(PendingExchange {
            code,
            pkce_verifier: self.pkce_verifier,
            requested_scopes: self.requested_scopes,
            redirect_uri: self.redirect_uri,
        })
    }
}

/// Compare two byte strings. Strings of different lengths return `false` at once;
/// the generated `state` has a fixed length, so the length reveals nothing. For
/// equal lengths, the loop visits every byte, so the time does not reveal the
/// position of the first difference.
///
/// This is not a full constant-time primitive, and it does not need to be. The
/// loopback listener serves one request, and the check consumes the session, so an
/// attacker gets one guess per sign-in and cannot repeat guesses to measure timing.
/// That avoids a cryptography dependency for one comparison.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> AuthSession {
        AuthSession::new(
            "https://accounts.google.com/...",
            "http://127.0.0.1:53123",
            "the-real-state",
            Secret::new("verifier"),
            vec!["gmail.readonly".into()],
        )
    }

    #[test]
    fn matching_state_yields_a_pending_exchange() {
        let pending = session()
            .validate_redirect("auth-code".into(), "the-real-state")
            .unwrap();
        assert_eq!(pending.code, "auth-code");
        assert_eq!(pending.pkce_verifier.expose(), "verifier");
        // Check: the redirect URI sent at exchange equals the one sent at
        // authorization. Google rejects a mismatch with `invalid_request` (RFC 6749
        // section 4.1.3).
        assert_eq!(pending.redirect_uri, "http://127.0.0.1:53123");
    }

    #[test]
    fn mismatched_state_is_rejected_and_cannot_exchange() {
        let err = session()
            .validate_redirect("auth-code".into(), "attacker-state")
            .unwrap_err();
        assert!(matches!(err, OAuthError::StateMismatch));
    }
}
