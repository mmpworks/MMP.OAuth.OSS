//! Loopback scenarios from the open-source readiness plan, over a real socket:
//! S1 (a CSRF mismatch through the full `authorize` call) and S16 (malformed
//! redirect requests).
//!
//! Requires the `loopback-flow` and `reqwest-transport` features. The test uses a
//! reqwest client in place of the browser.

#![cfg(all(feature = "loopback-flow", feature = "reqwest-transport"))]

use std::sync::Arc;
use std::time::Duration;

use mmp_oauth::flow::{ConsentOpener, LoopbackReceiver, RedirectReceiver};
use mmp_oauth::provider::MockProvider;
use mmp_oauth::storage::InMemoryTokenStore;
use mmp_oauth::{
    AccountKey, OAuthCapability, OAuthError, OAuthService, ProviderKind, ScopeRequest, TokenStore,
};

/// Stands in for the browser: after a short delay it sends GET requests to the
/// loopback receiver, one per suffix, in order.
struct BrowserSimulator {
    base: String,
    suffixes: Vec<String>,
}

impl ConsentOpener for BrowserSimulator {
    fn open(&self, _authorize_url: &str) -> Result<(), OAuthError> {
        let urls: Vec<String> = self
            .suffixes
            .iter()
            .map(|s| format!("{}{s}", self.base))
            .collect();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let client = reqwest::Client::new();
            for url in urls {
                let _ = client.get(&url).send().await;
            }
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

/// Run `authorize` with a real loopback receiver that receives the given requests.
async fn authorize_with(suffixes: &[&str]) -> (Result<(), OAuthError>, Arc<InMemoryTokenStore>) {
    let receiver =
        LoopbackReceiver::bind_with_deadline(Duration::from_secs(3)).expect("bind loopback");
    let base = receiver.redirect_uri();
    let opener = BrowserSimulator {
        base,
        suffixes: suffixes
            .iter()
            .map(std::string::ToString::to_string)
            .collect(),
    };
    let store = Arc::new(InMemoryTokenStore::new());
    let service = OAuthService::new(MockProvider::new(3600), store.clone())
        .with_loopback(Arc::new(opener), Arc::new(receiver));
    let result = service.authorize("a@x.com", &[scope()]).await.map(|_| ());
    (result, store)
}

fn nothing_saved(store: &InMemoryTokenStore) -> bool {
    store
        .load(&AccountKey::new(ProviderKind::Google, "a@x.com"))
        .unwrap()
        .is_none()
}

/// S1: a mismatched `state` on the real wire, through the full `authorize` call,
/// returns `StateMismatch` and saves nothing. `MockProvider` issues `mock-state`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mismatched_state_through_authorize_saves_nothing() {
    let (result, store) = authorize_with(&["?code=c&state=attacker"]).await;
    assert!(
        matches!(result, Err(OAuthError::StateMismatch)),
        "got {result:?}"
    );
    assert!(nothing_saved(&store));
}

/// The valid path over the same harness, so the S1 and S16 failures are not
/// caused by the harness itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_matching_state_through_authorize_saves_the_tokens() {
    let (result, store) = authorize_with(&["?code=c&state=mock-state"]).await;
    assert!(result.is_ok(), "got {result:?}");
    assert!(!nothing_saved(&store));
}

/// S16: a request to another path (a favicon) is answered 404 and the receiver
/// keeps waiting for the callback.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_favicon_request_before_the_callback_is_ignored() {
    let (result, _store) = authorize_with(&["/../favicon.ico", "?code=c&state=mock-state"]).await;
    assert!(result.is_ok(), "got {result:?}");
}

/// S16: malformed redirect queries fail without saving anything, and never panic.
/// RFC 6749 section 3.1 says a parameter must not appear more than once, so a
/// duplicated `code` or `state` is rejected instead of last-one-wins.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_redirect_queries_fail_and_save_nothing() {
    let long = "a".repeat(16_384);
    let cases = [
        String::new(),
        "?".into(),
        "?state=mock-state".into(),
        "?code=c".into(),
        "?code=c&code=d&state=mock-state".into(),
        "?code=c&state=mock-state&state=mock-state".into(),
        "?code=%ZZ&state=%".into(),
        format!("?code={long}&state=other"),
    ];
    for case in &cases {
        let (result, store) = authorize_with(&[case.as_str()]).await;
        assert!(
            result.is_err(),
            "query {case:.40}: expected an error, got Ok"
        );
        assert!(
            nothing_saved(&store),
            "query {case:.40}: nothing may be saved"
        );
    }
}
