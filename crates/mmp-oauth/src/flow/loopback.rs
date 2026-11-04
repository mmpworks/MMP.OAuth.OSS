//! The production desktop loopback edges (feature `loopback-flow`).
//!
//! Two implementations of the injected flow traits:
//!   - [`SystemBrowserOpener`] opens the consent URL in the OS default browser.
//!   - [`LoopbackReceiver`] binds `127.0.0.1:0` (the OS picks a free port), serves
//!     one redirect, parses `(code, state)` from the query string, replies with a
//!     short "you can close this tab" page, and stops.
//!
//! This is the RFC 8252 loopback redirect for native apps: bind port 0, open the
//! browser, run a one-shot listener with a deadline, and hand `(code, state)` to
//! the CSRF type-state check. These types own the real port and the real timeout,
//! so the consent flow runs end to end.
//!
//! GEM:replaceable-seam — these are the production layer behind the `ConsentOpener`
//! and `RedirectReceiver` traits; a test supplies test doubles instead.

use std::sync::Arc;
use std::time::Duration;

use crate::error::OAuthError;
use crate::flow::transport::{ConsentOpener, RedirectOutcome, RedirectReceiver};

use async_trait::async_trait;

/// The HTML returned to the browser after the redirect is captured. It has no
/// external assets, so it renders with no network.
const BROWSER_CLOSE_PAGE: &str = "<!doctype html><html><head><meta charset=\"utf-8\">\
<title>Connected</title></head><body style=\"font-family:sans-serif;text-align:center;\
margin-top:4rem\"><h2>You're connected.</h2><p>You can close this tab and return to \
the app.</p></body></html>";

/// Opens the consent URL in the user's default system browser.
///
/// It calls the platform launcher directly instead of adding a crate, because
/// opening one URL is one platform call.
pub struct SystemBrowserOpener;

impl ConsentOpener for SystemBrowserOpener {
    fn open(&self, authorize_url: &str) -> Result<(), OAuthError> {
        open_in_browser(authorize_url)
    }
}

/// Spawn the OS browser launcher for `url`. The URL is one separate argument to a
/// protocol handler and is never placed in a shell string, so the `&` separators in
/// a consent URL survive.
fn open_in_browser(url: &str) -> Result<(), OAuthError> {
    browser_command(url)
        .spawn()
        .map(|_child| ())
        .map_err(|e| OAuthError::Config(format!("could not launch system browser: {e}")))
}

/// Build the OS browser-launch command for `url`. It is a separate function so a
/// test can check that the launcher never runs through `cmd.exe`.
///
/// Windows uses `rundll32 url.dll,FileProtocolHandler <url>`, not `cmd /C start`.
/// `cmd` treats `&` as a command separator, and a consent URL holds many `&`
/// characters (`...auth?response_type=code&client_id=...`). `rundll32` receives
/// the URL as one argument with no shell parsing, so every `&` survives.
fn browser_command(url: &str) -> std::process::Command {
    use std::process::Command;

    if cfg!(target_os = "windows") {
        let mut c = Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    } else if cfg!(target_os = "macos") {
        let mut c = Command::new("open");
        c.arg(url);
        c
    } else {
        let mut c = Command::new("xdg-open");
        c.arg(url);
        c
    }
}

/// A one-shot loopback HTTP listener bound to `127.0.0.1:0`.
///
/// It binds a free port when it is built, so the redirect URI is known before the
/// browser opens. [`RedirectReceiver::wait_for_redirect`] then serves one request,
/// extracts `(code, state)`, and returns. A deadline bounds the wait, so a user who
/// closes the tab does not leave the application waiting.
pub struct LoopbackReceiver {
    /// An `Arc`, so the blocking one-shot accept can move onto a blocking task
    /// (`spawn_blocking` needs `'static`). There is still one listener.
    server: Arc<tiny_http::Server>,
    redirect_uri: String,
    /// The path the provider redirects to (for example `/callback`). The provider's
    /// `begin_authorization` builds the same URI from `redirect_uri()`.
    callback_path: String,
    /// How long to wait for the redirect before the consent counts as abandoned.
    deadline: Duration,
}

/// The default consent deadline: 300 seconds. Long enough for a person to read a
/// consent page and click Allow, short enough that an abandoned flow ends.
const DEFAULT_CONSENT_DEADLINE: Duration = Duration::from_secs(300);

impl LoopbackReceiver {
    /// Bind `127.0.0.1:0` and record the port the OS assigned. The redirect URI is
    /// `http://127.0.0.1:<port>/callback`. RFC 8252 section 7.3 asks a provider to
    /// accept any port on a loopback redirect, and Google does, so no port is
    /// registered in advance. The IP literal is used instead of `localhost`, because
    /// `localhost` can resolve to IPv6 or be caught by a local firewall (RFC 8252
    /// section 8.3).
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the listener cannot bind.
    pub fn bind() -> Result<Self, OAuthError> {
        Self::bind_with_deadline(DEFAULT_CONSENT_DEADLINE)
    }

    /// Bind with an explicit deadline. The testbed passes a shorter one.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the listener cannot bind.
    pub fn bind_with_deadline(deadline: Duration) -> Result<Self, OAuthError> {
        let server = tiny_http::Server::http("127.0.0.1:0")
            .map_err(|e| OAuthError::Config(format!("could not bind loopback listener: {e}")))?;
        let port = server
            .server_addr()
            .to_ip()
            .ok_or_else(|| OAuthError::Config("loopback listener has no IP address".into()))?
            .port();
        Ok(Self {
            server: Arc::new(server),
            redirect_uri: format!("http://127.0.0.1:{port}/callback"),
            callback_path: "/callback".to_string(),
            deadline,
        })
    }

    /// Use `localhost` instead of `127.0.0.1` as the host in the redirect URI. The
    /// listener still binds `127.0.0.1`; a browser resolves `localhost` to it.
    ///
    /// Use it only for a provider that matches the port of a `127.0.0.1` redirect URI
    /// and ignores it only for `localhost`. RFC 8252 section 8.3 prefers the IP
    /// literal, because `localhost` can resolve to IPv6 first or be caught by a
    /// firewall, so the default stays `127.0.0.1`.
    #[must_use]
    pub fn with_localhost_redirect(mut self) -> Self {
        self.redirect_uri = self
            .redirect_uri
            .replacen("http://127.0.0.1:", "http://localhost:", 1);
        self
    }
}

#[async_trait]
impl RedirectReceiver for LoopbackReceiver {
    fn redirect_uri(&self) -> String {
        self.redirect_uri.clone()
    }

    async fn wait_for_redirect(&self) -> Result<RedirectOutcome, OAuthError> {
        // tiny_http blocks, so the one-shot accept runs on the blocking pool and never
        // stalls the async runtime. `spawn_blocking` works on both the current-thread
        // and multi-thread tokio runtimes, unlike `block_in_place`. `recv_timeout`
        // inside the blocking task enforces the deadline.
        let server = Arc::clone(&self.server);
        let deadline = self.deadline;
        let expected_path = self.callback_path.clone();
        tokio::task::spawn_blocking(move || accept_one(&server, &expected_path, deadline))
            .await
            .map_err(|e| OAuthError::Transient(format!("loopback task failed to join: {e}")))?
    }
}

/// Block until the one redirect arrives or the deadline passes, reply with the
/// close page, and return the parsed `(code, state)`.
///
/// The loop has two exits: a request to the callback path (success) or the
/// deadline (abandoned). Other requests (a favicon, a probe) get a 404, and the
/// loop continues with the remaining time.
fn accept_one(
    server: &tiny_http::Server,
    expected_path: &str,
    deadline: Duration,
) -> Result<RedirectOutcome, OAuthError> {
    let started = std::time::Instant::now();

    loop {
        let remaining = deadline
            .checked_sub(started.elapsed())
            .ok_or(OAuthError::ConsentAbandoned)?;

        let Some(request) = server
            .recv_timeout(remaining)
            .map_err(|e| OAuthError::Transient(format!("loopback receive failed: {e}")))?
        else {
            return Err(OAuthError::ConsentAbandoned); // deadline elapsed
        };

        let url = request.url().to_string();
        let (path, query) = split_path_query(&url);

        if path != expected_path {
            // Not the callback path (for example a favicon request). Answer 404 and wait on.
            let _ = request.respond(tiny_http::Response::empty(404));
            continue;
        }

        let outcome = parse_redirect_query(query);
        // Always answer the browser, so the tab shows the close page, even after a
        // provider error redirect. Then return the parse result.
        let response = tiny_http::Response::from_string(BROWSER_CLOSE_PAGE).with_header(
            // Cannot fail: the input is this fixed ASCII literal, in `Name: value` form.
            "Content-Type: text/html; charset=utf-8"
                .parse::<tiny_http::Header>()
                .expect("static header is always valid"),
        );
        let _ = request.respond(response);
        return outcome;
    }
}

/// Split a request target into `(path, query)`. The query excludes the `?`.
pub(crate) fn split_path_query(url: &str) -> (&str, &str) {
    match url.split_once('?') {
        Some((path, query)) => (path, query),
        None => (url, ""),
    }
}

/// Parse `code` and `state` from a redirect query string, or map the provider's
/// `error=` parameter to an [`OAuthError`].
///
/// A provider error redirect (the user clicked Deny, or consent failed) carries
/// `error=access_denied` instead of a code. That is [`OAuthError::ConsentAbandoned`],
/// not a transport failure.
pub(crate) fn parse_redirect_query(query: &str) -> Result<RedirectOutcome, OAuthError> {
    let mut code = None;
    let mut state = None;
    let mut provider_error = None;

    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
        let slot = match key.as_ref() {
            "code" => &mut code,
            "state" => &mut state,
            "error" => &mut provider_error,
            _ => continue,
        };
        // RFC 6749 section 3.1: a parameter must not appear more than once. A
        // second `code` or `state` is not a choice to make (first or last wins);
        // it is a malformed redirect, so reject it.
        if slot.replace(value.into_owned()).is_some() {
            return Err(OAuthError::Transient(
                "redirect repeats a code, state or error parameter".into(),
            ));
        }
    }

    if let Some(err) = provider_error {
        // `access_denied` means the user declined, which is an abandonment.
        return if err == "access_denied" {
            Err(OAuthError::ConsentAbandoned)
        } else {
            Err(OAuthError::InvalidGrant {
                reason: allowlisted_redirect_error(&err).to_string(),
            })
        };
    }

    match (code, state) {
        (Some(code), Some(state)) => Ok(RedirectOutcome { code, state }),
        _ => Err(OAuthError::Transient(
            "redirect missing code or state parameter".into(),
        )),
    }
}

/// The RFC 6749 section 4.1.2.1 error-code name for a redirect `error=` value. Any
/// local page can send a request to the loopback port, so any other value is
/// attacker-controlled text and becomes the fixed label `unrecognized_error`.
fn allowlisted_redirect_error(code: &str) -> &'static str {
    const CODES: [&str; 7] = [
        "invalid_request",
        "unauthorized_client",
        "access_denied",
        "unsupported_response_type",
        "invalid_scope",
        "server_error",
        "temporarily_unavailable",
    ];
    CODES
        .iter()
        .copied()
        .find(|known| *known == code)
        .unwrap_or("unrecognized_error")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The redirect's `error` parameter is attacker-controlled text, because any
    /// local page can reach the loopback port. It must never appear in the error's
    /// Display or Debug output.
    #[test]
    fn a_redirect_error_parameter_is_never_echoed_into_the_error() {
        let sentinel = "SENTINEL-c0ffee-7f3a";
        for query in [
            format!("error={sentinel}"),
            format!("error=invalid_scope{sentinel}&state=s"),
        ] {
            let err = parse_redirect_query(&query).unwrap_err();
            assert!(!format!("{err}").contains(sentinel), "Display leaks: {err}");
            assert!(
                !format!("{err:?}").contains(sentinel),
                "Debug leaks: {err:?}"
            );
        }
    }

    #[test]
    fn parses_code_and_state_from_a_real_query() {
        let q = "state=xyz-state&code=4%2F0Aauth-code&scope=email";
        let out = parse_redirect_query(q).expect("a code+state query must parse");
        assert_eq!(
            out.code, "4/0Aauth-code",
            "percent-decoding must round-trip"
        );
        assert_eq!(out.state, "xyz-state");
    }

    #[test]
    fn user_denied_consent_is_abandonment_not_a_hard_error() {
        let err = parse_redirect_query("error=access_denied&state=xyz").unwrap_err();
        assert!(matches!(err, OAuthError::ConsentAbandoned));
    }

    #[test]
    fn a_provider_error_other_than_denial_is_invalid_grant() {
        let err = parse_redirect_query("error=invalid_scope").unwrap_err();
        assert!(matches!(err, OAuthError::InvalidGrant { .. }));
    }

    #[test]
    fn a_redirect_missing_the_code_is_a_transport_error() {
        let err = parse_redirect_query("state=only-state").unwrap_err();
        assert!(matches!(err, OAuthError::Transient(_)));
    }

    #[test]
    fn split_path_query_handles_a_bare_path() {
        assert_eq!(split_path_query("/callback"), ("/callback", ""));
        assert_eq!(
            split_path_query("/callback?code=1"),
            ("/callback", "code=1")
        );
    }

    #[test]
    fn browser_launcher_never_routes_through_cmd_and_keeps_the_url_whole() {
        // Check: the launcher must not run through cmd, because cmd splits the consent
        // URL at the first `&` (the browser then gets no client_id, and Google answers
        // "Missing required parameter: client_id"). It must pass the whole URL as one
        // argument.
        let url = "https://accounts.google.com/o/oauth2/v2/auth?response_type=code\
                   &client_id=abc.apps.googleusercontent.com&state=xyz&scope=email";
        let cmd = browser_command(url);

        assert_ne!(
            cmd.get_program().to_string_lossy(),
            "cmd",
            "must not route through cmd.exe — it re-parses `&` as a command separator"
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            args.iter().any(|a| a == url),
            "the full consent URL must be a single argv element, got: {args:?}"
        );
    }

    #[test]
    fn binding_yields_a_127_loopback_uri_on_an_ephemeral_port() {
        let recv = LoopbackReceiver::bind().expect("binding 127.0.0.1:0 must succeed");
        let uri = recv.redirect_uri();
        assert!(
            uri.starts_with("http://127.0.0.1:"),
            "must be the IP literal, not localhost"
        );
        assert!(uri.ends_with("/callback"));
        // Port is ephemeral and non-zero.
        let port: u16 = uri
            .trim_start_matches("http://127.0.0.1:")
            .trim_end_matches("/callback")
            .parse()
            .expect("ephemeral port must be numeric");
        assert!(port > 0);
    }

    #[test]
    fn the_localhost_redirect_keeps_the_port_and_the_path() {
        let recv = LoopbackReceiver::bind().expect("bind");
        let ip_uri = recv.redirect_uri();
        let recv = recv.with_localhost_redirect();
        assert_eq!(
            recv.redirect_uri(),
            ip_uri.replace("127.0.0.1", "localhost")
        );
    }
}
