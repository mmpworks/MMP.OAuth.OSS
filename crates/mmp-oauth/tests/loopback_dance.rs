//! The end-to-end consent flow over the real loopback listener, with no live
//! provider.
//!
//! It drives the production `LoopbackReceiver`, which binds a real `127.0.0.1:0`
//! socket, and a `ConsentOpener` double that sends a real HTTP GET to the loopback
//! callback instead of launching a browser. That GET is what a provider's redirect
//! does. The tests prove that the listener:
//!   - parses a real `?code=...&state=...` query from the wire,
//!   - replies with the short 200 browser-close page,
//!   - hands `(code, state)` to the CSRF type-state check.
//!
//! Requires the `loopback-flow` + `reqwest-transport` features (the test injects a
//! reqwest client to play the browser). Run with:
//!   `cargo test -p mmp-oauth --features loopback-flow,reqwest-transport --test loopback_dance`

#![cfg(all(feature = "loopback-flow", feature = "reqwest-transport"))]

use std::sync::Arc;
use std::time::Duration;

use mmp_oauth::flow::{run_consent_flow, ConsentOpener, LoopbackReceiver, RedirectReceiver};
use mmp_oauth::provider::{MockProvider, ScopeRequest};
use mmp_oauth::OAuthError;

/// A `ConsentOpener` that spawns a task to GET the loopback callback with a chosen
/// `code` and `state`, instead of opening a browser. It stands in for the provider
/// redirect that a real browser would follow.
struct BrowserSimulator {
    redirect_uri: String,
    state_to_send: String,
    code_to_send: String,
}

impl ConsentOpener for BrowserSimulator {
    fn open(&self, _authorize_url: &str) -> Result<(), OAuthError> {
        // Build the callback URL the browser would be redirected to.
        let callback = format!(
            "{}?code={}&state={}",
            self.redirect_uri, self.code_to_send, self.state_to_send
        );
        // Send it after a short delay, so the receiver is already waiting. The
        // receiver runs the blocking accept on tokio's blocking pool, so a spawned
        // task here races it correctly.
        tokio::spawn(async move {
            // A brief yield lets wait_for_redirect reach its accept loop first.
            tokio::time::sleep(Duration::from_millis(50)).await;
            let _ = reqwest::Client::new().get(&callback).send().await;
        });
        Ok(())
    }
}

fn scope() -> ScopeRequest {
    ScopeRequest::at_connect(
        "https://www.googleapis.com/auth/userinfo.email",
        "identify-account",
        "read the connected account's email address",
    )
}

/// The valid path over a real socket: the simulated browser calls the loopback with
/// the matching state, the listener parses it, and the type-state check yields a
/// `PendingExchange` that carries the PKCE verifier.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_loopback_captures_a_redirect_and_validates_state() {
    let provider = MockProvider::new(3600); // mints state "mock-state"
    let receiver = LoopbackReceiver::bind_with_deadline(Duration::from_secs(5))
        .expect("binding the loopback listener must succeed");

    let opener = BrowserSimulator {
        redirect_uri: receiver.redirect_uri(),
        state_to_send: "mock-state".into(), // matches the session
        code_to_send: "4%2F0Areal-loopback-code".into(),
    };

    let pending = run_consent_flow(&provider, &opener, &receiver, &[scope()])
        .await
        .expect("a matching-state redirect over the real socket must yield a pending exchange");

    assert_eq!(
        pending.code, "4/0Areal-loopback-code",
        "percent-decoded off the wire"
    );
    assert_eq!(pending.pkce_verifier.expose(), "mock-verifier");
}

/// The attack path over a real socket: the simulated browser sends a state that does
/// not match. The listener parses it, the CSRF type-state check refuses it, and no
/// exchange is reachable.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_loopback_rejects_a_mismatched_state() {
    let provider = MockProvider::new(3600);
    let receiver = LoopbackReceiver::bind_with_deadline(Duration::from_secs(5))
        .expect("binding the loopback listener must succeed");

    let opener = BrowserSimulator {
        redirect_uri: receiver.redirect_uri(),
        state_to_send: "attacker-state".into(), // does NOT match "mock-state"
        code_to_send: "attacker-code".into(),
    };

    let result = run_consent_flow(&provider, &opener, &receiver, &[scope()]).await;
    assert!(
        matches!(result, Err(OAuthError::StateMismatch)),
        "a mismatched state over the real socket must be refused, got {result:?}"
    );
}

/// The deadline path: no redirect arrives, so the listener times out as
/// `ConsentAbandoned` instead of waiting forever.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_loopback_times_out_as_abandoned_when_no_redirect_arrives() {
    // An opener that does nothing: the browser never sends a redirect.
    struct SilentOpener;
    impl ConsentOpener for SilentOpener {
        fn open(&self, _url: &str) -> Result<(), OAuthError> {
            Ok(())
        }
    }

    let receiver = LoopbackReceiver::bind_with_deadline(Duration::from_millis(150))
        .expect("binding the loopback listener must succeed");

    let provider = MockProvider::new(3600);
    let result = run_consent_flow(&provider, &SilentOpener, &receiver, &[scope()]).await;
    assert!(
        matches!(result, Err(OAuthError::ConsentAbandoned)),
        "no redirect before the deadline must surface as ConsentAbandoned, got {result:?}"
    );
}

/// The bound receiver gives a `127.0.0.1` URI on a free port, and an `Arc`-shared
/// receiver returns the same URI.
#[test]
fn bound_receiver_exposes_a_stable_loopback_uri() {
    let receiver: Arc<dyn RedirectReceiver> =
        Arc::new(LoopbackReceiver::bind().expect("bind must succeed"));
    let uri = receiver.redirect_uri();
    assert!(uri.starts_with("http://127.0.0.1:"));
    assert!(uri.ends_with("/callback"));
}
