//! Fuzz target F1: the testbed's `.ini` app-config parser.
//!
//! A config file is hand-edited, so its text is untrusted. The harness feeds
//! arbitrary bytes, read as UTF-8 with lossy replacement, to `AppConfig::parse`.
//!
//! Oracle:
//! 1. No input panics. Each call returns `Ok` or a `Config` error.
//! 2. Round trip: for every `Ok`, `to_ini` then `parse` gives the same config, and
//!    a second `to_ini` gives the same text.
//! 3. The masked client id shows at most 12 leading and 8 trailing characters,
//!    and none of an id of 20 characters or fewer.
//!
//! Under `cargo test` bolero runs random inputs. Under libFuzzer:
//! `cargo bolero test -p mmp-oauth --all-features --toolchain nightly -T 1800s ini_parse_round_trips_and_never_panics`.

#![cfg(feature = "testbed")]

use mmp_oauth::testbed::config::AppConfig;

fn same(a: &AppConfig, b: &AppConfig) -> bool {
    a.slug == b.slug
        && a.name == b.name
        && a.provider == b.provider
        && a.client_id == b.client_id
        && a.client_secret.as_ref().map(mmp_oauth::Secret::expose)
            == b.client_secret.as_ref().map(mmp_oauth::Secret::expose)
        && a.scopes == b.scopes
}

fn check(text: &str) {
    let Ok(config) = AppConfig::parse("app", text) else {
        return;
    };
    let ini = config.to_ini();
    let again = AppConfig::parse("app", &ini).expect("to_ini output must parse");
    assert!(
        same(&config, &again),
        "round trip changed the config for input {text:?}\nini: {ini:?}"
    );
    assert_eq!(
        again.to_ini(),
        ini,
        "to_ini is not stable for input {text:?}"
    );

    // The mask's shape, not a substring test: an id made of `•` characters equals
    // its own mask, and that reveals nothing.
    let chars: Vec<char> = config.client_id.chars().collect();
    let expected = if chars.len() <= 20 {
        "•".repeat(chars.len())
    } else {
        let head: String = chars[..12].iter().collect();
        let tail: String = chars[chars.len() - 8..].iter().collect();
        format!("{head}…{tail}")
    };
    assert_eq!(
        config.masked_client_id(),
        expected,
        "the mask shows more than 12 leading and 8 trailing characters"
    );
}

#[test]
fn ini_parse_round_trips_and_never_panics() {
    bolero::check!().for_each(|bytes: &[u8]| check(&String::from_utf8_lossy(bytes)));
}

/// Shapes the random run may not reach.
#[test]
fn hand_picked_configs_round_trip() {
    let cases = [
        "client-id=abc",
        "client-id=abc\nclient-secret=a#b ; comment\nscopes=a, b,,c",
        "name=  spaced  \nprovider=MICROSOFT\nclient-id=id\nunknown=x",
        "client-id==leading-equals\n",
        "client-id=x\nclient-id=y\n",
        "[section]\nclient-id=x",
        "client-id=123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com",
        // Found by libFuzzer (crash-170e63a1): an id made of the mask's own `•`
        // character. The mask equals the id, which the old "mask never contains the
        // id" oracle took for a leak.
        "\u{e}\n`\nclient-id=\u{2022}",
    ];
    for text in cases {
        check(text);
    }
}
