//! Fuzz target F3: the loopback redirect request target.
//!
//! Any local process can send a request to the loopback port, so the request target
//! is untrusted input. The harness feeds arbitrary bytes, read as UTF-8 with lossy
//! replacement, to the same split-and-parse path the receiver runs on each request.
//!
//! Oracle:
//! 1. No input panics. Each call returns `Ok` or a typed error.
//! 2. An `error=` value is attacker text. When the input carries the sentinel, the
//!    error's Display and Debug never contain it.
//!
//! Under `cargo test` bolero runs random inputs. Under libFuzzer:
//! `cargo bolero test -p mmp-oauth --all-features --toolchain nightly -T 1800s redirect_target_never_panics_or_echoes`.

use mmp_oauth::__fuzz::redirect_target;

/// A value no fixed error string contains. If it appears in an error, it came from
/// the input.
const SENTINEL: &str = "SENTINELq7x";

fn assert_no_echo(url: &str) {
    if let Err(err) = redirect_target(url) {
        let shown = format!("{err} {err:?}");
        assert!(
            !shown.contains(SENTINEL),
            "input text reached the error: {shown}"
        );
    }
}

#[test]
fn redirect_target_never_panics_or_echoes() {
    bolero::check!().for_each(|bytes: &[u8]| {
        let url = String::from_utf8_lossy(bytes);
        let _ = redirect_target(&url);
        // The same input with the sentinel placed in each attacker-reachable slot.
        assert_no_echo(&format!("/callback?error={SENTINEL}{url}"));
        assert_no_echo(&format!("/callback?{url}&error={SENTINEL}"));
        assert_no_echo(&format!("/callback?error_description={SENTINEL}&{url}"));
    });
}

/// Fixed shapes the random run may not reach: duplicated keys, no query, a huge
/// query, and percent-encoding errors.
#[test]
fn hand_picked_targets_never_panic_or_echo() {
    let long = "a".repeat(65_536);
    let cases = [
        String::new(),
        "/callback".into(),
        "/callback?".into(),
        "/callback?code=a&code=b&state=s".into(),
        "/callback?code=a&state=s&state=t".into(),
        "/callback?code=%ZZ&state=%".into(),
        format!("/callback?code={long}&state=s"),
        format!("/callback?error={SENTINEL}"),
        format!("/callback?error=access_denied&error_description={SENTINEL}"),
    ];
    for url in &cases {
        let _ = redirect_target(url);
        assert_no_echo(url);
    }
}
