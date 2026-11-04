//! Fuzz target F2: token-endpoint response bodies.
//!
//! The token endpoint is a network peer, so its body is untrusted. The harness
//! feeds arbitrary bytes to the same parse-and-map path `GoogleProvider` runs once
//! `oauth2` accepts the HTTP response: a success body becomes a grant, an error body
//! becomes a classified `OAuthError`.
//!
//! Oracle:
//! 1. No input panics.
//! 2. A grant's scope entries are never empty strings, and its expiry is never
//!    before the moment of the call.
//! 3. An error never carries text from the body: a sentinel in the
//!    `error_description`, the `error_uri`, or an extension `error` code never
//!    appears in its Display or Debug.
//!
//! Under `cargo test` bolero runs random inputs. Under libFuzzer:
//! `cargo bolero test -p mmp-oauth --all-features --toolchain nightly -T 1800s token_bodies_never_panic_or_echo`.

use mmp_oauth::__fuzz::{error_body, error_body_microsoft, token_body};

const SENTINEL: &str = "SENTINELk2v";

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap()
}

fn check_token(body: &[u8]) {
    let before = now();
    if let Some(grant) = token_body(body, vec!["requested".into()]) {
        assert!(
            grant.granted_scopes.iter().all(|s| !s.is_empty()),
            "an empty scope entry"
        );
        assert!(grant.expires_at_unix >= before, "an expiry before the call");
    }
}

/// Checks the body against both classifiers: Google's default and Microsoft's,
/// which adds the re-consent extension codes.
fn check_error(body: &[u8]) {
    for err in [error_body(body), error_body_microsoft(body)]
        .into_iter()
        .flatten()
    {
        let shown = format!("{err} {err:?}");
        assert!(
            !shown.contains(SENTINEL),
            "body text reached the error: {shown}"
        );
    }
}

#[test]
fn token_bodies_never_panic_or_echo() {
    bolero::check!().for_each(|bytes: &[u8]| {
        check_token(bytes);
        check_error(bytes);
        // The same input placed in each attacker-controlled slot of an error body.
        let text = String::from_utf8_lossy(bytes).replace(['"', '\\'], "");
        for template in [
            r#"{"error":"S#"}"#,
            r#"{"error":"invalid_grant","error_description":"S#"}"#,
            r#"{"error":"invalid_client","error_uri":"S#"}"#,
        ] {
            let body = template.replace("S#", &format!("{SENTINEL}{text}"));
            check_error(body.as_bytes());
        }
    });
}

/// Shapes the random run may not reach.
#[test]
fn hand_picked_bodies_never_panic_or_echo() {
    let cases = [
        r#"{"access_token":"a","token_type":"Bearer","expires_in":18446744073709551615}"#
            .to_string(),
        r#"{"access_token":"a","token_type":"Bearer","scope":"   "}"#.to_string(),
        r#"{"access_token":"a","token_type":"Bearer","scope":" x  y "}"#.to_string(),
        r#"{"access_token":"a","token_type":"bearer"}"#.to_string(),
        format!(r#"{{"error":"{SENTINEL}"}}"#),
        format!(r#"{{"error":"invalid_scope","error_description":"{SENTINEL}"}}"#),
        "[]".to_string(),
        "null".to_string(),
    ];
    for body in &cases {
        check_token(body.as_bytes());
        check_error(body.as_bytes());
    }
}
