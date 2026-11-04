//! Fuzz target F5: secret masking.
//!
//! Oracle, for any string:
//! 1. `Secret`'s Debug is `Secret(<redacted len=N>)` with N the byte length, and
//!    nothing else, so no part of the value can appear.
//! 2. The testbed's masked client id shows no more than 12 leading and 8 trailing
//!    characters, and shows none of a 20-character-or-shorter id.
//!
//! Under `cargo test` bolero runs random inputs. Under libFuzzer:
//! `cargo bolero test -p mmp-oauth --all-features --toolchain nightly -T 1800s masking_never_shows_the_value`.

#![cfg(feature = "testbed")]

use mmp_oauth::provider::ProviderKind;
use mmp_oauth::testbed::config::AppConfig;
use mmp_oauth::Secret;

fn check(value: &str) {
    let secret = Secret::new(value);
    assert_eq!(
        format!("{secret:?}"),
        format!("Secret(<redacted len={}>)", value.len())
    );
    assert_eq!(
        format!("{secret:#?}"),
        format!("Secret(<redacted len={}>)", value.len())
    );

    let app = AppConfig {
        slug: "app".into(),
        name: "app".into(),
        provider: ProviderKind::Google,
        client_id: value.into(),
        client_secret: Some(Secret::new(value)),
        scopes: vec![],
    };
    let masked = app.masked_client_id();
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 20 {
        assert!(
            masked.chars().all(|c| c == '•'),
            "a short id must be fully masked: {masked:?}"
        );
        assert_eq!(masked.chars().count(), chars.len());
    } else {
        let head: String = chars[..12].iter().collect();
        let tail: String = chars[chars.len() - 8..].iter().collect();
        assert!(
            masked.starts_with(&head) && masked.ends_with(&tail),
            "unexpected mask shape: {masked:?}"
        );
        assert_eq!(
            masked,
            format!("{head}…{tail}"),
            "the middle must be replaced by one ellipsis"
        );
    }
    assert!(
        format!("{app:?}").contains("client_secret: Some(Secret(<redacted"),
        "the secret field must print redacted"
    );
}

#[test]
fn masking_never_shows_the_value() {
    bolero::check!().for_each(|bytes: &[u8]| check(&String::from_utf8_lossy(bytes)));
}

#[test]
fn hand_picked_values_are_masked() {
    for value in [
        "",
        "a",
        "12345678901234567890",
        "123456789012345678901",
        "ünïcödé-ünïcödé-ünïcödé",
    ] {
        check(value);
    }
}
