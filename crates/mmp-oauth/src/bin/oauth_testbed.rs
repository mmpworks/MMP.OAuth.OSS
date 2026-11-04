//! `oauth_testbed`: a runnable harness for the real desktop OAuth flow.
//!
//! It runs a live flow against a real provider. It opens the system browser to the
//! consent page, runs the real `127.0.0.1` loopback listener, captures the redirect,
//! exchanges the code, and prints the token's shape, never its bytes (the redacting
//! `Secret` type enforces that).
//!
//! It contains no credential. Supply a client id with `--client-id` or
//! `MMP_OAUTH_CLIENT_ID`. With none, it prints how to register an app and exits
//! with code 0.
//!
//! Run it live, once an app is registered:
//!
//! ```text
//! cargo run -p mmp-oauth --all-features --bin oauth_testbed -- \
//!   --provider microsoft --client-id <APPLICATION_CLIENT_ID>
//! cargo run -p mmp-oauth --all-features --bin oauth_testbed -- \
//!   --provider google --client-id <CLIENT_ID> --client-secret <CLIENT_SECRET>
//! ```
//!
//! Environment equivalents: `MMP_OAUTH_PROVIDER`, `MMP_OAUTH_CLIENT_ID`,
//! `MMP_OAUTH_CLIENT_SECRET`, `MMP_OAUTH_SCOPES` (space- or comma-separated). Pass
//! the secret when testing Google; `GoogleProvider::with_secret` explains why.

use std::path::PathBuf;

use mmp_oauth::provider::ProviderKind;
use mmp_oauth::testbed::config::{self, AppConfig};
use mmp_oauth::testbed::server;
use mmp_oauth::Secret;

/// The exit code when no client id is supplied: print how to register one, exit 0.
const EXIT_NEEDS_REGISTRATION: i32 = 0;

/// The `serve` web UI and the `--client-id` scripting CLI share the live flow
/// (`server::run_dance`). `serve` builds a runtime per request, and the CLI path
/// builds its own. `main` therefore avoids `#[tokio::main]`, because a `block_on`
/// inside that runtime panics.
fn main() {
    let mut args = std::env::args().skip(1).peekable();

    // `serve` is a subcommand, detected as the first positional argument. Every
    // other form is the scripting CLI.
    if args.peek().map(String::as_str) == Some("serve") {
        let _ = args.next(); // consume "serve"
        run_serve();
        return;
    }

    let app = match app_from_args_and_env(args) {
        Ok(Some(app)) => app,
        Ok(None) => {
            print_registration_help();
            std::process::exit(EXIT_NEEDS_REGISTRATION);
        }
        Err(msg) => {
            eprintln!("error: {msg}\n");
            print_usage();
            std::process::exit(2);
        }
    };

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("could not start async runtime: {e}");
            std::process::exit(1);
        }
    };
    println!("Starting the live OAuth flow with {:?}.", app.provider);
    println!("  scopes : {}", app.scopes.join(", "));
    println!("Opening your system browser. Approve the consent page.\n");
    match runtime.block_on(server::run_dance(&app)) {
        Ok(report) => {
            println!("Consent succeeded. Token shape (no secret bytes are printed):");
            println!(
                "  access_token   : <redacted len={}>",
                report.access_token_len
            );
            println!("  expires_at_unix: {}", report.expires_at_unix);
            println!("  granted_scopes : {:?}", report.granted_scopes);
            println!("  status         : {:?}", report.status);
        }
        Err(e) => {
            eprintln!("\nlive OAuth flow failed: {e}");
            std::process::exit(1);
        }
    }
}

/// Launch the local web UI. Resolve the keys directory and hand control to the
/// blocking server loop.
fn run_serve() {
    let keys_dir = keys_dir();
    if let Err(e) = server::serve(&keys_dir) {
        eprintln!("testbed UI failed: {e}");
        std::process::exit(1);
    }
}

/// The directory that holds the `.ini` app configs. `MMP_OAUTH_KEYS_DIR` overrides
/// it. The default is `./keys` relative to the working directory, which is the
/// repo's gitignored `keys/`.
fn keys_dir() -> PathBuf {
    std::env::var_os("MMP_OAUTH_KEYS_DIR").map_or_else(|| PathBuf::from("keys"), PathBuf::from)
}

/// Parse `--flag value` pairs, with environment variables as the fallback, into an
/// app config. `Ok(None)` means no client id was given. An unknown flag or provider
/// is an error, so a typo fails at once instead of running the wrong flow.
fn app_from_args_and_env(args: impl Iterator<Item = String>) -> Result<Option<AppConfig>, String> {
    let mut provider_raw = std::env::var("MMP_OAUTH_PROVIDER").ok();
    let mut client_id = std::env::var("MMP_OAUTH_CLIENT_ID").ok();
    let mut client_secret = std::env::var("MMP_OAUTH_CLIENT_SECRET").ok();
    let mut scopes_raw = std::env::var("MMP_OAUTH_SCOPES").ok();

    let mut args = args.peekable();
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--provider" => provider_raw = Some(take_value(&flag, args.next())?),
            "--client-id" => client_id = Some(take_value(&flag, args.next())?),
            "--client-secret" => client_secret = Some(take_value(&flag, args.next())?),
            "--scopes" => scopes_raw = Some(take_value(&flag, args.next())?),
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag `{other}`")),
        }
    }

    let provider = match non_empty(provider_raw) {
        None => ProviderKind::Google,
        Some(name) => config::provider_from_name(&name)
            .ok_or_else(|| format!("unknown provider `{name}` (use google or microsoft)"))?,
    };
    let Some(client_id) = non_empty(client_id) else {
        return Ok(None);
    };
    Ok(Some(AppConfig {
        slug: "cli".into(),
        name: "cli".into(),
        provider,
        client_id,
        client_secret: non_empty(client_secret).map(Secret::new),
        scopes: config::parse_scope_list(non_empty(scopes_raw).as_deref(), provider),
    }))
}

/// Read the value after a flag, or report that it is missing.
fn take_value(flag: &str, next: Option<String>) -> Result<String, String> {
    next.ok_or_else(|| format!("`{flag}` requires a value"))
}

/// Treat an empty string as an absent value, so `MMP_OAUTH_CLIENT_ID=` means "not
/// set", not "set to empty".
fn non_empty(v: Option<String>) -> Option<String> {
    v.filter(|s| !s.trim().is_empty())
}

fn print_usage() {
    eprintln!(
        "oauth_testbed: live desktop OAuth flow harness\n\n\
         USAGE:\n  \
           oauth_testbed serve                start the local web UI (multi-app picker)\n  \
           oauth_testbed [FLAGS]              one-shot CLI flow\n\n\
         FLAGS (environment fallback in parentheses):\n  \
           --provider       google or microsoft; default google (MMP_OAUTH_PROVIDER)\n  \
           --client-id      the app's client id (MMP_OAUTH_CLIENT_ID)\n  \
           --client-secret  Google Desktop app only (MMP_OAUTH_CLIENT_SECRET)\n  \
           --scopes         comma or space separated; default {} for google, {} for microsoft (MMP_OAUTH_SCOPES)\n  \
           --help, -h       this help\n\n\
         With no --client-id, prints how to register an app and exits 0.",
        config::default_scope(ProviderKind::Google),
        config::default_scope(ProviderKind::Microsoft),
    );
}

/// Printed when no client id is supplied. No credential is in the code; this is the
/// one-time registration a live smoke test needs. The README holds the full steps.
fn print_registration_help() {
    println!(
        "No OAuth client id supplied, so there is no app to run a live flow against.\n\n\
         The testbed holds no credential. Register an app once, then pass its id:\n\n\
         Microsoft: see \"Set up a Microsoft app\" in the README. Copy the\n\
           Application (client) ID, then run:\n  \
             cargo run -p mmp-oauth --all-features --bin oauth_testbed -- \\\n    \
               --provider microsoft --client-id <APPLICATION_CLIENT_ID>\n\n\
         Google: see \"Set up a Google app\" in the README. Copy the Client ID and\n\
           Client secret of a \"Desktop app\" client, then run:\n  \
             cargo run -p mmp-oauth --all-features --bin oauth_testbed -- \\\n    \
               --provider google --client-id <CLIENT_ID> --client-secret <CLIENT_SECRET>\n\n\
         Or set MMP_OAUTH_PROVIDER, MMP_OAUTH_CLIENT_ID and MMP_OAUTH_CLIENT_SECRET in the\n\
         environment and run the same command without the flags."
    );
}
