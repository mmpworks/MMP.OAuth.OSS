//! The consent-flow driver: the one-shot loopback sequence, with every edge injected.
//!
//! [`run_consent_flow`] is the body that the service's `authorize` calls. It runs
//! the desktop flow (RFC 8252) through injected edges, so tests run the whole
//! sequence with test doubles, with no browser and no socket:
//!
//! 1. Ask the [`RedirectReceiver`] for its loopback redirect URI. The port is
//!    already bound.
//! 2. [`Provider::begin_authorization`] builds the consent URL (PKCE S256 and a
//!    CSRF `state`) and the in-memory [`AuthSession`].
//! 3. [`ConsentOpener::open`] opens the browser at that URL.
//! 4. [`RedirectReceiver::wait_for_redirect`] captures `(code, state)`. Then
//!    [`AuthSession::validate_redirect`] checks the `state`. A mismatched or
//!    missing `state` returns [`OAuthError::StateMismatch`] and cannot produce the
//!    [`PendingExchange`] that the exchange needs.
//!
//! It is a free function, not a service method, so one place owns the order of
//! the steps, every edge is a parameter, and the type-state check is the only
//! path to an exchange.

use crate::error::OAuthError;
use crate::flow::transport::{ConsentOpener, RedirectReceiver};
use crate::flow::PendingExchange;
use crate::provider::{Provider, ScopeRequest};

/// Run the consent flow through the injected edges and return a checked
/// [`PendingExchange`]. The caller exchanges it for tokens.
///
/// This function never compares `state` values itself. It passes the receiver's
/// outcome to [`crate::flow::AuthSession::validate_redirect`], so the CSRF check
/// lives in one place.
///
/// # Errors
///
/// - [`OAuthError::ConsentAbandoned`] when the user denies consent or the
///   receiver's deadline passes.
/// - [`OAuthError::StateMismatch`] when the redirect's `state` does not match.
/// - Any error from the opener (for example the browser fails to launch).
pub async fn run_consent_flow(
    provider: &dyn Provider,
    opener: &dyn ConsentOpener,
    receiver: &dyn RedirectReceiver,
    scopes: &[ScopeRequest],
) -> Result<PendingExchange, OAuthError> {
    let redirect_uri = receiver.redirect_uri();

    // The session holds the PKCE verifier and the CSRF state, in memory only.
    let session = provider.begin_authorization(scopes, &redirect_uri);

    // Open the system browser at the consent URL.
    opener.open(&session.authorize_url)?;

    // Wait for the one loopback redirect, up to the receiver's deadline.
    let outcome = receiver.wait_for_redirect().await?;

    // The only path to a PendingExchange: a redirect whose state matched. A
    // mismatch returns StateMismatch here, and no exchange is reachable.
    session.validate_redirect(outcome.code, &outcome.state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::transport::RedirectOutcome;
    use crate::provider::MockProvider;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// A test double that records the URL it was asked to open instead of launching
    /// a browser.
    #[derive(Default)]
    struct RecordingOpener {
        opened: Mutex<Vec<String>>,
    }
    impl ConsentOpener for RecordingOpener {
        fn open(&self, authorize_url: &str) -> Result<(), OAuthError> {
            self.opened.lock().unwrap().push(authorize_url.to_string());
            Ok(())
        }
    }

    /// A test double that returns a canned `(code, state)` and a fixed redirect URI,
    /// standing in for the real loopback listener.
    struct SeededReceiver {
        redirect_uri: String,
        outcome: Result<RedirectOutcome, OAuthError>,
    }
    impl SeededReceiver {
        fn ok(code: &str, state: &str) -> Self {
            Self {
                redirect_uri: "http://127.0.0.1:53999/callback".into(),
                outcome: Ok(RedirectOutcome {
                    code: code.into(),
                    state: state.into(),
                }),
            }
        }
        fn abandoned() -> Self {
            Self {
                redirect_uri: "http://127.0.0.1:53999/callback".into(),
                outcome: Err(OAuthError::ConsentAbandoned),
            }
        }
    }
    #[async_trait]
    impl RedirectReceiver for SeededReceiver {
        fn redirect_uri(&self) -> String {
            self.redirect_uri.clone()
        }
        async fn wait_for_redirect(&self) -> Result<RedirectOutcome, OAuthError> {
            // Rebuild the canned result by hand, because OAuthError does not
            // implement Clone (RedirectOutcome does).
            match &self.outcome {
                Ok(o) => Ok(o.clone()),
                Err(OAuthError::ConsentAbandoned) => Err(OAuthError::ConsentAbandoned),
                Err(_) => Err(OAuthError::Transient("seeded".into())),
            }
        }
    }

    fn scope() -> ScopeRequest {
        ScopeRequest::at_connect(
            "https://www.googleapis.com/auth/userinfo.email",
            "identify-account",
            "read the connected account's email address",
        )
    }

    #[tokio::test]
    async fn happy_path_opens_the_browser_and_yields_a_pending_exchange() {
        let provider = MockProvider::new(3600);
        let opener = RecordingOpener::default();
        // MockProvider mints state "mock-state"; the receiver must echo it.
        let receiver = SeededReceiver::ok("auth-code-xyz", "mock-state");

        let pending = run_consent_flow(&provider, &opener, &receiver, &[scope()])
            .await
            .expect("matching state must produce a pending exchange");

        assert_eq!(pending.code, "auth-code-xyz");
        assert_eq!(
            pending.pkce_verifier.expose(),
            "mock-verifier",
            "verifier round-trips"
        );
        // The browser opened once, at the consent URL that carries the state.
        let urls = opener.opened.lock().unwrap();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].contains("state=mock-state"));
        assert!(urls[0].contains("redirect_uri=http://127.0.0.1:53999/callback"));
    }

    #[tokio::test]
    async fn mismatched_state_is_refused_and_no_exchange_is_reachable() {
        let provider = MockProvider::new(3600);
        let opener = RecordingOpener::default();
        // An attacker-controlled state that does not match the session's "mock-state".
        let receiver = SeededReceiver::ok("attacker-code", "attacker-state");

        let result = run_consent_flow(&provider, &opener, &receiver, &[scope()]).await;

        // The type-state check rejects it. The function returns StateMismatch, and
        // the caller never gets a PendingExchange.
        assert!(matches!(result, Err(OAuthError::StateMismatch)));
        // The browser did open, which proves the rejection happens at validation,
        // after consent started.
        assert_eq!(opener.opened.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn an_abandoned_consent_surfaces_cleanly() {
        let provider = MockProvider::new(3600);
        let opener = RecordingOpener::default();
        let receiver = SeededReceiver::abandoned();

        let result = run_consent_flow(&provider, &opener, &receiver, &[scope()]).await;
        assert!(matches!(result, Err(OAuthError::ConsentAbandoned)));
    }
}
