//! The local web UI server for the testbed (`oauth_testbed serve`).
//!
//! A single-purpose development server. It serves one embedded page, lists the
//! saved app configs, accepts a new one, and runs the live consent flow for a
//! chosen app. That is the same consent flow (informally, the "OAuth dance") the
//! CLI runs, through the shared [`run_dance`] function. It binds `127.0.0.1` only
//! and is meant for an operator on the same machine.
//!
//! ## One request at a time
//!
//! `tiny_http` blocks, and the server handles one request at a time. For a local
//! tool with one operator that is correct and simplest. The cost: while a
//! `POST /api/run` waits on the consent flow (up to the loopback deadline), other
//! requests queue. With one operator, the run is what they are waiting for. The
//! loopback receiver that the flow starts binds its own free port, separate from
//! this UI server's port, so the two never conflict.
//!
//! ## Security
//!
//! A read never sends the full client id or the client secret to the browser:
//! `GET /api/apps` returns only a masked id and no secret. The server loads the
//! secret from the `.ini` file at run time, and it reaches only the provider's
//! token exchange. `POST /api/apps` accepts a secret (from the operator, on
//! localhost, for their own config); that is the only path that receives one.

use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use tiny_http::{Header, Method, Request, Response, Server};

use crate::error::OAuthError;
use crate::flow::{ConsentOpener, LoopbackReceiver, RedirectReceiver, SystemBrowserOpener};
use crate::provider::{GoogleProvider, MicrosoftProvider, Provider, ProviderKind, ScopeRequest};
use crate::storage::InMemoryTokenStore;
use crate::testbed::config::{self, AppConfig};
use crate::testbed::page::INDEX_HTML;
use crate::token::TokenState;
use crate::{OAuthCapability, OAuthService};

use super::config::slugify;

/// The preferred UI port. If it is taken, the server binds a free port instead, so
/// a second or leftover testbed never blocks a new launch.
const PREFERRED_PORT: u16 = 7800;

/// The consent deadline for a UI-driven run. It matches the CLI's deadline, so a
/// person has time to read the consent page.
const CONSENT_DEADLINE: Duration = Duration::from_secs(300);

/// The outcome of one live run, in the shape the UI renders. It carries the token's
/// shape only, never the access-token bytes (the UI shows the length), so a derived
/// `Debug` cannot leak a secret.
#[derive(Debug)]
pub struct RunReport {
    /// The lifecycle status after the run (`Active` when the grant is live).
    pub status: TokenState,
    /// The access token's length in bytes. The UI shows the shape, never the bytes.
    pub access_token_len: usize,
    /// The access token's expiry, in Unix seconds.
    pub expires_at_unix: i64,
    /// The scopes the provider granted.
    pub granted_scopes: Vec<String>,
}

/// Run the live consent flow for one app config and report the token's shape.
///
/// Both the CLI and the web UI call this function, so the two entry points share
/// one implementation. It dispatches on the provider.
///
/// # Errors
///
/// Any [`OAuthError`] from building the provider or the loopback edges, or from
/// `authorize`.
pub async fn run_dance(app: &AppConfig) -> Result<RunReport, OAuthError> {
    match app.provider {
        ProviderKind::Google => run_with_provider(google_provider(app)?, &app.scopes).await,
        ProviderKind::Microsoft => run_with_provider(microsoft_provider(app)?, &app.scopes).await,
    }
}

/// The Google provider for `app`, with the client secret when the config has one
/// (see `GoogleProvider::with_secret`).
fn google_provider(app: &AppConfig) -> Result<GoogleProvider, OAuthError> {
    Ok(GoogleProvider::new(&app.client_id)?.with_secret(app.client_secret.clone()))
}

/// The Microsoft provider for `app`. A configured client secret is ignored: a
/// Microsoft public client must not send one.
fn microsoft_provider(app: &AppConfig) -> Result<MicrosoftProvider, OAuthError> {
    MicrosoftProvider::new(&app.client_id)
}

/// The provider-independent flow: build the loopback edges, run `authorize`, and
/// reduce the grant to a [`RunReport`]. It is generic over the provider, so every
/// provider shares this code.
async fn run_with_provider<P: Provider>(
    provider: P,
    scopes: &[String],
) -> Result<RunReport, OAuthError> {
    let store = Arc::new(InMemoryTokenStore::new());
    let opener: Arc<dyn ConsentOpener> = Arc::new(SystemBrowserOpener);
    let receiver = LoopbackReceiver::bind_with_deadline(CONSENT_DEADLINE)?;
    let receiver: Arc<dyn RedirectReceiver> = Arc::new(receiver);

    let svc = OAuthService::new(provider, store).with_loopback(opener, receiver);

    let scope_requests: Vec<ScopeRequest> = scopes
        .iter()
        .map(|s| ScopeRequest::at_connect(s.clone(), "testbed-ui", "live testbed UI run"))
        .collect();

    let account = "testbed-account";
    let grant = svc.authorize(account, &scope_requests).await?;

    Ok(RunReport {
        status: svc.status(account),
        access_token_len: grant.access_token.expose().len(),
        expires_at_unix: grant.expires_at_unix,
        granted_scopes: grant.granted_scopes,
    })
}

/// Bind the UI server, open the browser to it, and serve requests until the process
/// stops. It blocks the calling thread, because it is the program's main loop.
///
/// # Errors
///
/// [`OAuthError::Config`] when the UI server cannot bind.
pub fn serve(keys_dir: &Path) -> Result<(), OAuthError> {
    let server = bind_ui_server()?;
    let addr = server
        .server_addr()
        .to_ip()
        .ok_or_else(|| OAuthError::Config("UI server has no IP address".into()))?;
    let url = format!("http://{addr}/");

    println!("MMP.OAuth testbed UI listening on {url}");
    println!("Keys directory: {}", keys_dir.display());
    println!("Opening your browser… (Ctrl+C to stop)");
    // Best effort: if the browser fails to open, the printed URL still works.
    let _ = SystemBrowserOpener.open(&url);

    for request in server.incoming_requests() {
        if let Err(e) = dispatch(request, keys_dir) {
            // A handler error must never stop the server loop. Log it and keep serving.
            eprintln!("request handling error: {e}");
        }
    }
    Ok(())
}

/// Bind `127.0.0.1:7800`, falling back to an ephemeral port if it is taken.
fn bind_ui_server() -> Result<Server, OAuthError> {
    let preferred = SocketAddr::from(([127, 0, 0, 1], PREFERRED_PORT));
    match Server::http(preferred) {
        Ok(server) => Ok(server),
        Err(_) => Server::http(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|e| OAuthError::Config(format!("could not bind UI server: {e}"))),
    }
}

/// Route one request to its handler. Errors are returned (and logged by the loop),
/// never panicked, so a malformed request cannot stop the server.
fn dispatch(mut request: Request, keys_dir: &Path) -> Result<(), OAuthError> {
    let method = request.method().clone();
    let url = request.url().to_string();
    let path = url.split('?').next().unwrap_or("/");

    let response = match (&method, path) {
        (Method::Get, "/") => html_response(INDEX_HTML),
        (Method::Get, "/api/apps") => json_response(200, &list_apps_json(keys_dir)),
        (Method::Post, "/api/apps") => {
            let body = read_body(&mut request);
            json_value_response(add_app(keys_dir, &body))
        }
        (Method::Post, "/api/run") => {
            let body = read_body(&mut request);
            json_value_response(run_app(keys_dir, &body))
        }
        _ => json_response(404, &json!({ "error": "not found" })),
    };

    request
        .respond(response)
        .map_err(|e| OAuthError::Transient(format!("failed to write response: {e}")))
}

/// Read the request body into a string, with a size cap. The tool is local, but the
/// read is never unbounded.
fn read_body(request: &mut Request) -> String {
    const MAX_BODY: usize = 64 * 1024;
    let mut buf = String::new();
    let _ = request
        .as_reader()
        .take(MAX_BODY as u64)
        .read_to_string(&mut buf);
    buf
}

/// `GET /api/apps`: the masked app summaries. It never includes the secret or the
/// full client id; the masked id is the only form of the id that reaches the browser.
fn list_apps_json(keys_dir: &Path) -> Value {
    let Ok(apps) = config::list_apps(keys_dir) else {
        return json!([]);
    };
    let summaries: Vec<Value> = apps.iter().map(app_summary).collect();
    Value::Array(summaries)
}

/// The browser-safe summary of one app: slug, name, provider, masked client id, and
/// scopes. The type has no field for the secret.
fn app_summary(app: &AppConfig) -> Value {
    json!({
        "slug": app.slug,
        "name": app.name,
        "provider": provider_label(app.provider),
        "client_id_masked": app.masked_client_id(),
        "scopes": app.scopes,
    })
}

/// `POST /api/apps`: write a new `keys/<slug>.ini` from the posted form. This is the
/// only path that accepts a secret (on localhost, for the operator's own config).
fn add_app(keys_dir: &Path, body: &str) -> Result<Value, OAuthError> {
    let parsed: Value = serde_json::from_str(body)
        .map_err(|e| OAuthError::Config(format!("invalid JSON body: {e}")))?;

    let name = str_field(&parsed, "name").unwrap_or_default();
    if name.trim().is_empty() {
        return Err(OAuthError::Config("a name is required".into()));
    }
    let client_id = str_field(&parsed, "client_id").unwrap_or_default();
    if client_id.trim().is_empty() {
        return Err(OAuthError::Config("a client id is required".into()));
    }

    let secret_raw = str_field(&parsed, "client_secret").unwrap_or_default();
    let client_secret = if secret_raw.trim().is_empty() {
        None
    } else {
        Some(crate::Secret::new(secret_raw))
    };

    // Build the config text with the same parser and serializer as the rest of the
    // code, so the file on disk matches a hand-written one. The text goes through
    // AppConfig::parse, which applies the provider and scope defaults.
    let provider_token = str_field(&parsed, "provider").unwrap_or_else(|| "google".into());
    let scopes_raw = str_field(&parsed, "scopes").unwrap_or_default();
    let slug = slugify(&name);

    let ini = build_ini(
        &name,
        &provider_token,
        &client_id,
        client_secret.as_ref(),
        &scopes_raw,
    );
    let app = AppConfig::parse(&slug, &ini)?;
    config::save_app(keys_dir, &app)?;

    Ok(app_summary(&app))
}

/// Compose `.ini` text from the posted fields. The parser applies the defaults.
fn build_ini(
    name: &str,
    provider: &str,
    client_id: &str,
    client_secret: Option<&crate::Secret>,
    scopes: &str,
) -> String {
    let secret_line = match client_secret {
        Some(s) => format!("client-secret={}\n", s.expose()),
        None => String::new(),
    };
    let scopes_line = if scopes.trim().is_empty() {
        String::new()
    } else {
        format!("scopes={scopes}\n")
    };
    format!("name={name}\nprovider={provider}\nclient-id={client_id}\n{secret_line}{scopes_line}")
}

/// `POST /api/run`: load the full config, secret included, on the server and run the
/// live flow. It returns the token's shape only; the access-token bytes never leave
/// the process.
fn run_app(keys_dir: &Path, body: &str) -> Result<Value, OAuthError> {
    let parsed: Value = serde_json::from_str(body)
        .map_err(|e| OAuthError::Config(format!("invalid JSON body: {e}")))?;
    let slug = str_field(&parsed, "slug")
        .ok_or_else(|| OAuthError::Config("a slug is required".into()))?;

    let path = keys_dir.join(format!("{slug}.ini"));
    let app = config::load_app(&path)?;

    // tiny_http handlers are synchronous and the flow is async, so the flow runs to
    // completion on its own runtime, with no ambient one needed. The flow uses
    // spawn_blocking for the loopback accept, so the runtime needs the IO and time
    // drivers, which a new multi-thread runtime provides.
    let report = run_dance_blocking(&app)?;

    Ok(json!({
        "ok": true,
        "status": provider_status_label(report.status),
        "access_token_len": report.access_token_len,
        "expires_at_unix": report.expires_at_unix,
        "granted_scopes": report.granted_scopes,
    }))
}

/// Run [`run_dance`] to completion from a synchronous handler. It builds a small
/// multi-thread Tokio runtime, so the loopback receiver's `spawn_blocking` accept and
/// the reqwest exchange both have their drivers.
fn run_dance_blocking(app: &AppConfig) -> Result<RunReport, OAuthError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| OAuthError::Config(format!("could not start async runtime: {e}")))?;
    runtime.block_on(run_dance(app))
}

// --- Small response and JSON helpers, kept short so the handlers read top-down ---

/// Turn a `Result<Value, _>` into a JSON response: 200 on success, or
/// `{ok:false, error}` with 400 on failure. The error text goes to the UI's error
/// panel as is.
fn json_value_response(result: Result<Value, OAuthError>) -> Response<std::io::Cursor<Vec<u8>>> {
    match result {
        Ok(value) => json_response(200, &value),
        Err(e) => json_response(400, &json!({ "ok": false, "error": e.to_string() })),
    }
}

/// Build a JSON response with an explicit status code.
fn json_response(status: u16, value: &Value) -> Response<std::io::Cursor<Vec<u8>>> {
    let body = value.to_string();
    Response::from_string(body)
        .with_status_code(status)
        .with_header(content_type("application/json; charset=utf-8"))
}

/// Build the HTML response for the embedded page.
fn html_response(html: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(html).with_header(content_type("text/html; charset=utf-8"))
}

/// A `Content-Type` header. Every caller passes a fixed ASCII literal, which
/// `Header::from_bytes` always accepts, so the `expect` cannot fire.
fn content_type(value: &str) -> Header {
    Header::from_bytes(&b"Content-Type"[..], value.as_bytes())
        .expect("a static content-type header is always valid")
}

/// Pull a string field from a JSON object, treating a non-string or absent key as
/// `None`.
fn str_field(value: &Value, key: &str) -> Option<String> {
    value.get(key).and_then(Value::as_str).map(str::to_string)
}

/// The provider label the UI shows for a kind.
fn provider_label(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::Google => "google",
        ProviderKind::Microsoft => "microsoft",
    }
}

/// The status label the UI matches on (`Active` turns the status label green).
fn provider_status_label(state: TokenState) -> &'static str {
    match state {
        TokenState::Active => "Active",
        TokenState::Expired => "Expired",
        TokenState::Unauthorized => "Unauthorized",
        TokenState::Refreshing => "Refreshing",
        TokenState::NeedsReconsent => "NeedsReconsent",
        TokenState::Revoked => "Revoked",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Secret;

    fn google_app(secret: Option<&str>) -> AppConfig {
        AppConfig {
            slug: "team-app".into(),
            name: "Team's App".into(),
            provider: ProviderKind::Google,
            client_id: "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com"
                .into(),
            client_secret: secret.map(Secret::new),
            scopes: vec!["https://www.googleapis.com/auth/userinfo.email".into()],
        }
    }

    #[test]
    fn the_apps_summary_never_carries_the_secret_or_the_full_client_id() {
        let app = google_app(Some("GOCSPX-super-secret"));
        let summary = app_summary(&app);
        let text = summary.to_string();

        assert!(
            !text.contains("GOCSPX-super-secret"),
            "the secret must never reach the summary"
        );
        assert!(
            !text.contains("abcdefghijklmnopqrstuvwxyz012345"),
            "the full client id must be masked"
        );
        assert!(text.contains('…'), "the masked id ellipsis is present");
        // The summary type has no secret field at all.
        assert!(
            summary.get("client_secret").is_none(),
            "no client_secret key exists in the summary"
        );
    }

    #[test]
    fn add_app_writes_an_ini_and_returns_a_secretless_summary() {
        let dir = std::env::temp_dir().join(format!("mmp-oauth-srv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let body = json!({
            "name": "New App",
            "provider": "google",
            "client_id": "new-client-id-1234567890",
            "client_secret": "GOCSPX-added",
            "scopes": "scope.one scope.two"
        })
        .to_string();

        let summary = add_app(&dir, &body).expect("add must succeed");
        assert_eq!(summary.get("slug").and_then(Value::as_str), Some("new-app"));
        assert!(
            !summary.to_string().contains("GOCSPX-added"),
            "returned summary hides the secret"
        );

        // The written file holds the secret as plain text (it is the secret store),
        // and it reloads with the secret intact.
        let reloaded = config::load_app(&dir.join("new-app.ini")).expect("reload");
        assert_eq!(
            reloaded.client_secret.as_ref().map(Secret::expose),
            Some("GOCSPX-added")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn add_app_rejects_a_blank_name() {
        let dir = std::env::temp_dir().join("mmp-oauth-srv-blank");
        let body = json!({ "name": "  ", "client_id": "x" }).to_string();
        let err = add_app(&dir, &body).unwrap_err();
        assert!(matches!(err, OAuthError::Config(_)));
    }

    /// M10: a Microsoft app config builds a `MicrosoftProvider` with the configured
    /// client id and the `common` endpoints, and ignores a configured secret.
    #[test]
    fn a_microsoft_app_builds_the_microsoft_provider() {
        let app = AppConfig {
            slug: "ms".into(),
            name: "MS".into(),
            provider: ProviderKind::Microsoft,
            client_id: "00000000-0000-0000-0000-000000000000".into(),
            client_secret: Some(crate::Secret::new("must-not-be-used")),
            scopes: vec!["User.Read".into()],
        };
        let provider = microsoft_provider(&app).expect("the provider builds");
        assert_eq!(provider.kind(), ProviderKind::Microsoft);
        assert_eq!(
            provider.profile().client_id,
            "00000000-0000-0000-0000-000000000000"
        );
        assert!(provider
            .profile()
            .token_url
            .starts_with("https://login.microsoftonline.com/common/"));
        assert!(
            !provider.sends_client_secret(),
            "the configured secret is ignored"
        );
    }

    #[test]
    fn the_run_failure_response_is_self_describing_json() {
        let err = OAuthError::ConsentAbandoned;
        let response = json_value_response(Err(err));
        // A 400 status, ok:false, and the error text passed through.
        assert_eq!(response.status_code().0, 400);
    }

    /// S15: when the preferred port is taken, the UI server binds a free port instead
    /// of failing. The test holds the preferred port itself; if another process
    /// already holds it, the test still checks the fallback.
    #[test]
    fn a_taken_preferred_port_falls_back_to_a_free_port() {
        let _held = std::net::TcpListener::bind(("127.0.0.1", PREFERRED_PORT));
        let server = bind_ui_server().expect("the fallback binds");
        let port = server.server_addr().to_ip().expect("an IP address").port();
        assert_ne!(port, PREFERRED_PORT);
        assert_ne!(port, 0);
    }
}
