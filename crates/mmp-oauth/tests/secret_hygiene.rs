//! Scenario S17: no credential reaches a `Debug` string.
//!
//! Each public type that holds a credential is built with a sentinel in every
//! credential field, then formatted with `{:?}` and `{:#?}`. The sentinel must not
//! appear. A credential here is an access token, a refresh token, a PKCE verifier,
//! a client secret, or an authorization code (RFC 6749 section 10.5 treats a leaked
//! code as a credential, even with PKCE).

use mmp_oauth::flow::{AuthSession, PendingExchange, RedirectOutcome};
use mmp_oauth::{AccessGrant, RefreshedGrant, Secret, StoredTokens, TokenPair};

/// A value no type name or field name contains.
const SENTINEL: &str = "SENTINEL-7f3a";

fn secret() -> Secret {
    Secret::new(format!("pre-{SENTINEL}-post"))
}

fn grant() -> AccessGrant {
    AccessGrant {
        access_token: secret(),
        expires_at_unix: 1,
        granted_scopes: vec!["scope".into()],
    }
}

fn assert_redacted(name: &str, value: &dyn std::fmt::Debug) {
    for shown in [format!("{value:?}"), format!("{value:#?}")] {
        assert!(
            !shown.contains(SENTINEL),
            "{name} leaked a credential into Debug: {shown}"
        );
    }
}

#[test]
fn token_types_redact_every_credential() {
    assert_redacted("Secret", &secret());
    assert_redacted("AccessGrant", &grant());
    assert_redacted(
        "TokenPair",
        &TokenPair {
            grant: grant(),
            refresh_token: secret(),
        },
    );
    assert_redacted(
        "RefreshedGrant",
        &RefreshedGrant {
            grant: grant(),
            refresh_token: Some(secret()),
        },
    );
    assert_redacted(
        "StoredTokens",
        &StoredTokens {
            refresh_token: secret(),
            access_token: Some(secret()),
            access_expires_at_unix: Some(1),
            granted_scopes: vec![],
            refresh_scopes: None,
        },
    );
}

#[test]
fn flow_types_redact_the_verifier_and_the_authorization_code() {
    let code = format!("code-{SENTINEL}");
    assert_redacted(
        "AuthSession",
        &AuthSession::new(
            "https://example.com/auth",
            "http://127.0.0.1:1/callback",
            "state",
            secret(),
            vec![],
        ),
    );
    assert_redacted(
        "PendingExchange",
        &PendingExchange {
            code: code.clone(),
            pkce_verifier: secret(),
            requested_scopes: vec![],
            redirect_uri: "http://127.0.0.1:1/callback".into(),
        },
    );
    assert_redacted(
        "RedirectOutcome",
        &RedirectOutcome {
            code,
            state: "state".into(),
        },
    );
}

/// Scenario S18: the crate emits no log events, so no log line can carry a token.
/// This guard fails when a logging crate becomes a direct dependency. The change
/// that adds one must then add a test that runs a full flow under a capturing
/// subscriber and checks that no credential reaches the log.
#[test]
fn the_crate_links_no_logging_facade() {
    let manifest =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let section = manifest
        .split("[dependencies]")
        .nth(1)
        .expect("a [dependencies] table");
    let dependencies = section.split("\n[").next().unwrap();
    for line in dependencies.lines() {
        let name = line.split(['=', '.', ' ']).next().unwrap_or("").trim();
        assert!(
            !["log", "tracing", "slog", "env_logger"].contains(&name),
            "logging dependency `{name}` found"
        );
    }
}
