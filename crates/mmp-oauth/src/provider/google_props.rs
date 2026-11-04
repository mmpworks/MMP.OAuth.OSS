//! Property tests for `GoogleProvider`'s token-response handling, over the real
//! reqwest + oauth2 wiring against a wiremock token endpoint.
//!
//! Rules tested here:
//! 1. `scope` is split on spaces, and empty entries are dropped. A `scope` that
//!    gives no entries (absent, `""`, or only spaces) counts as omitted: a code
//!    exchange then records the requested scopes, and a refresh reports an empty
//!    list (the service then applies the refresh token's consent scope).
//! 2. A code exchange whose `refresh_token` is absent or empty is a Config error.
//! 3. A refresh passes the response's `refresh_token` through as given. The
//!    service decides what to save.
//! 4. Arbitrary response bytes, arbitrary JSON objects, and well-formed responses
//!    with arbitrary field values never panic. Each call returns `Ok` or a typed error.
//! 5. No text from the response reaches an error. A sentinel placed anywhere in a
//!    response (field values, nested values, keys, the Content-Type header) never
//!    appears in the error's Display or Debug output.

use proptest::collection::{btree_map, vec};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use serde_json::{json, Map, Value};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::google::GoogleProvider;
use crate::error::OAuthError;
use crate::flow::PendingExchange;
use crate::provider::{Provider, ProviderKind, ProviderProfile};
use crate::token::{RefreshedGrant, TokenPair};
use crate::Secret;

const CASES: u32 = 1_000;

/// One runtime, one mock token endpoint, one provider, reused across every case.
struct Harness {
    rt: tokio::runtime::Runtime,
    server: MockServer,
    provider: GoogleProvider,
}

impl Harness {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let server = rt.block_on(MockServer::start());
        let base = server.uri();
        let profile = ProviderProfile {
            kind: ProviderKind::Google,
            auth_url: format!("{base}/authorize"),
            token_url: format!("{base}/token"),
            revocation_url: Some(format!("{base}/revoke")),
            client_id: "test-client-id".into(),
            loopback_host: "127.0.0.1".into(),
            requires_pkce: true,
        };
        let provider = GoogleProvider::from_profile(profile).unwrap();
        Self {
            rt,
            server,
            provider,
        }
    }

    /// Make the mock server answer every POST (the token and revocation endpoints
    /// alike) with `status` and `body`.
    fn respond(&self, status: u16, body: Vec<u8>) {
        self.respond_typed(status, body, "application/json");
    }

    /// As `respond`, with a chosen Content-Type header.
    fn respond_typed(&self, status: u16, body: Vec<u8>, content_type: &str) {
        self.rt.block_on(async {
            self.server.reset().await;
            Mock::given(method("POST"))
                .respond_with(ResponseTemplate::new(status).set_body_raw(body, content_type))
                .mount(&self.server)
                .await;
        });
    }

    fn refresh(&self) -> Result<RefreshedGrant, OAuthError> {
        self.rt
            .block_on(self.provider.refresh(&Secret::new("1//presented")))
    }

    fn revoke(&self) -> Result<(), OAuthError> {
        self.rt
            .block_on(self.provider.revoke(&Secret::new("1//presented")))
    }

    fn exchange(&self, requested: Vec<String>) -> Result<TokenPair, OAuthError> {
        let pending = PendingExchange {
            code: "auth-code".into(),
            pkce_verifier: Secret::new("a-test-pkce-verifier-of-sufficient-length-000"),
            requested_scopes: requested,
            redirect_uri: "http://127.0.0.1:51219/callback".into(),
        };
        self.rt.block_on(self.provider.exchange_code(pending))
    }
}

fn runner() -> TestRunner {
    TestRunner::new(Config {
        cases: CASES,
        ..Config::default()
    })
}

/// The model for rule 1: the entries a `scope` string grants.
fn scope_entries(scope: Option<&str>) -> Vec<String> {
    scope
        .map(|s| {
            s.split(' ')
                .filter(|e| !e.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// `scope` values: absent, empty, only spaces, space-delimited lists with runs of
/// spaces, and arbitrary Unicode.
fn scope_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some(String::new())),
        "[ ]{1,5}".prop_map(Some),
        "[ ]{0,2}[a-z.:/]{1,20}([ ]{1,3}[a-z.:/]{1,20}){0,4}[ ]{0,2}".prop_map(Some),
        any::<String>().prop_map(Some),
    ]
}

/// `refresh_token` values: absent, empty, arbitrary Unicode, or very long.
fn refresh_token_strategy() -> impl Strategy<Value = Option<String>> {
    prop_oneof![
        Just(None),
        Just(Some(String::new())),
        any::<String>().prop_map(Some),
        "[A-Za-z0-9._/-]{1000,8192}".prop_map(Some),
    ]
}

/// A well-formed token response with the optional fields set as given.
fn token_body(refresh_token: Option<&str>, scope: Option<&str>) -> Vec<u8> {
    let mut body = json!({ "access_token": "ya29.at", "token_type": "Bearer", "expires_in": 3599 });
    if let Some(rt) = refresh_token {
        body["refresh_token"] = json!(rt);
    }
    if let Some(s) = scope {
        body["scope"] = json!(s);
    }
    serde_json::to_vec(&body).unwrap()
}

/// Arbitrary JSON values, nested up to three levels.
fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<f64>()
            .prop_filter("JSON has no NaN or infinity", |f| f.is_finite())
            .prop_map(Value::from),
        any::<String>().prop_map(Value::from),
    ];
    leaf.prop_recursive(3, 32, 6, |inner| {
        prop_oneof![
            vec(inner.clone(), 0..6).prop_map(Value::Array),
            btree_map(any::<String>(), inner, 0..6)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// Arbitrary JSON objects whose keys are mostly the token-response field names.
fn json_object() -> impl Strategy<Value = Value> {
    let key = prop_oneof![
        3 => prop_oneof![
            Just("access_token"), Just("token_type"), Just("expires_in"), Just("refresh_token"),
            Just("scope"), Just("error"), Just("error_description"), Just("error_uri"),
        ].prop_map(String::from),
        1 => any::<String>(),
    ];
    btree_map(key, json_value(), 0..8)
        .prop_map(|m| Value::Object(m.into_iter().collect::<Map<_, _>>()))
}

/// Well-formed responses whose optional fields carry arbitrary values: right-typed
/// extremes (any u64 `expires_in`) and wrong types alike.
fn near_valid_object() -> impl Strategy<Value = Value> {
    // Uniform u64 almost never lands near the i64 boundary, so the edges are listed.
    let expires_edge = prop_oneof![
        Just(0u64),
        Just(i64::MAX as u64),
        Just(i64::MAX as u64 - 1),
        Just(i64::MAX as u64 + 1),
        Just(u64::MAX),
        (i64::MAX as u64 - 4_000_000_000)..=(i64::MAX as u64),
    ];
    let expires = prop_oneof![
        any::<u64>().prop_map(Value::from),
        expires_edge.prop_map(Value::from),
        json_value(),
    ];
    let field = prop_oneof![any::<String>().prop_map(Value::from), json_value()];
    (
        proptest::option::of(expires),
        proptest::option::of(field.clone()),
        proptest::option::of(field),
    )
        .prop_map(|(expires_in, refresh_token, scope)| {
            let mut body = json!({ "access_token": "ya29.at", "token_type": "Bearer" });
            for (name, value) in [
                ("expires_in", expires_in),
                ("refresh_token", refresh_token),
                ("scope", scope),
            ] {
                if let Some(v) = value {
                    body[name] = v;
                }
            }
            body
        })
}

fn status_strategy() -> impl Strategy<Value = u16> {
    prop_oneof![Just(200u16), Just(400), Just(401), Just(500)]
}

/// Rule 1 and 3, on the wire: a refresh reports the scope entries the response
/// granted (empty when `scope` is omitted, empty, or only spaces), and passes the
/// response's `refresh_token` through unchanged.
#[test]
fn refresh_reports_the_granted_scope_entries_and_the_raw_refresh_token() {
    let h = Harness::new();
    runner()
        .run(
            &(scope_strategy(), refresh_token_strategy()),
            |(scope, refresh_token)| {
                h.respond(200, token_body(refresh_token.as_deref(), scope.as_deref()));
                let refreshed = h
                    .refresh()
                    .map_err(|e| TestCaseError::fail(format!("refresh failed: {e:?}")))?;
                prop_assert_eq!(
                    refreshed.grant.granted_scopes,
                    scope_entries(scope.as_deref())
                );
                prop_assert_eq!(
                    refreshed.refresh_token.map(|t| t.expose().to_string()),
                    refresh_token
                );
                Ok(())
            },
        )
        .unwrap();
}

/// Rules 1 and 2: a code exchange records the response's scope entries when there
/// are any, else the requested scopes. An absent or empty refresh token is a
/// Config error.
#[test]
fn exchange_records_granted_scopes_else_requested_and_requires_a_refresh_token() {
    let h = Harness::new();
    let requested = vec("[a-z.:/]{1,20}", 1..4);
    runner()
        .run(
            &(scope_strategy(), refresh_token_strategy(), requested),
            |(scope, refresh_token, requested)| {
                h.respond(200, token_body(refresh_token.as_deref(), scope.as_deref()));
                let result = h.exchange(requested.clone());
                match refresh_token.as_deref() {
                    None | Some("") => prop_assert!(
                        matches!(result, Err(OAuthError::Config(_))),
                        "got {result:?}"
                    ),
                    Some(rt) => {
                        let pair = result
                            .map_err(|e| TestCaseError::fail(format!("exchange failed: {e:?}")))?;
                        let granted = scope_entries(scope.as_deref());
                        let expected = if granted.is_empty() {
                            requested
                        } else {
                            granted
                        };
                        prop_assert_eq!(pair.grant.granted_scopes, expected);
                        prop_assert_eq!(pair.refresh_token.expose(), rt);
                    }
                }
                Ok(())
            },
        )
        .unwrap();
}

/// Rule 4: arbitrary response bytes never panic either call.
#[test]
fn arbitrary_response_bytes_never_panic() {
    let h = Harness::new();
    runner()
        .run(
            &(status_strategy(), vec(any::<u8>(), 0..2048)),
            |(status, body)| {
                h.respond(status, body);
                let _ = h.refresh();
                let _ = h.exchange(vec!["scope-a".into()]);
                Ok(())
            },
        )
        .unwrap();
}

/// Rule 4: arbitrary JSON objects never panic either call.
#[test]
fn arbitrary_json_objects_never_panic() {
    let h = Harness::new();
    runner()
        .run(&(status_strategy(), json_object()), |(status, body)| {
            h.respond(status, serde_json::to_vec(&body).unwrap());
            let _ = h.refresh();
            let _ = h.exchange(vec!["scope-a".into()]);
            Ok(())
        })
        .unwrap();
}

/// Rule 4: well-formed responses with arbitrary field values never panic.
#[test]
fn near_valid_responses_with_arbitrary_field_values_never_panic() {
    let h = Harness::new();
    runner()
        .run(&near_valid_object(), |body| {
            h.respond(200, serde_json::to_vec(&body).unwrap());
            let _ = h.refresh();
            let _ = h.exchange(vec!["scope-a".into()]);
            Ok(())
        })
        .unwrap();
}

// --- Rule 5: no response text reaches an error -------------------------------------

/// A value no fixed error string contains. If it shows up in an error, it came from
/// the response.
const SENTINEL: &str = "SENTINEL-c0ffee-7f3a";

/// Assert that neither the Display nor the Debug form of `err` carries the sentinel.
fn assert_no_sentinel(err: &OAuthError, case: &str) -> Result<(), TestCaseError> {
    let shown = format!("{err}");
    let debugged = format!("{err:?}");
    prop_assert!(
        !shown.contains(SENTINEL),
        "{case}: Display leaks response text: {shown}"
    );
    prop_assert!(
        !debugged.contains(SENTINEL),
        "{case}: Debug leaks response text: {debugged}"
    );
    Ok(())
}

/// Run both calls against the current response and check every error they return.
fn check_both_calls(h: &Harness, case: &str) -> Result<(), TestCaseError> {
    if let Err(e) = h.refresh() {
        assert_no_sentinel(&e, &format!("refresh, {case}"))?;
    }
    if let Err(e) = h.exchange(vec!["scope-a".into()]) {
        assert_no_sentinel(&e, &format!("exchange, {case}"))?;
    }
    if let Err(e) = h.revoke() {
        assert_no_sentinel(&e, &format!("revoke, {case}"))?;
    }
    Ok(())
}

/// Each response-driven error arm, with the sentinel where that arm reads text.
#[test]
fn no_error_path_echoes_response_text() {
    let s = SENTINEL;
    let cases: Vec<(&str, u16, String, String)> = vec![
        ("invalid_grant description", 400,
            json!({ "error": "invalid_grant", "error_description": format!("Rejected refresh token {s}") }).to_string(),
            "application/json".into()),
        ("invalid_request description", 400,
            json!({ "error": "invalid_request", "error_description": s }).to_string(), "application/json".into()),
        ("error_uri", 400,
            json!({ "error": "invalid_client", "error_uri": format!("https://x/{s}") }).to_string(), "application/json".into()),
        ("extension error code", 400, json!({ "error": s }).to_string(), "application/json".into()),
        ("extension code containing invalid_grant", 400,
            json!({ "error": format!("invalid_grant_{s}") }).to_string(), "application/json".into()),
        ("wrong-typed error field", 400, json!({ "error": [s] }).to_string(), "application/json".into()),
        ("wrong-typed expires_in", 200,
            json!({ "access_token": "at", "token_type": "Bearer", "expires_in": s }).to_string(), "application/json".into()),
        ("wrong-typed access_token", 200,
            json!({ "access_token": { "k": s }, "token_type": "Bearer" }).to_string(), "application/json".into()),
        ("wrong-typed scope", 200,
            json!({ "access_token": "at", "token_type": "Bearer", "scope": [s] }).to_string(), "application/json".into()),
        ("non-JSON body", 400, format!("<html>{s}</html>"), "application/json".into()),
        ("Content-Type header", 200,
            json!({ "access_token": "at", "token_type": "Bearer" }).to_string(), format!("text/plain; x={s}")),
    ];
    let h = Harness::new();
    for (case, status, body, content_type) in cases {
        h.respond_typed(status, body.into_bytes(), &content_type);
        check_both_calls(&h, case).unwrap();
    }
}

/// A value that carries the sentinel: inside a longer string, nested in an object or
/// an array, or as an object key.
fn sentinel_value() -> impl Strategy<Value = Value> {
    let text = (any::<String>(), any::<String>()).prop_map(|(a, b)| format!("{a}{SENTINEL}{b}"));
    prop_oneof![
        text.clone().prop_map(Value::from),
        text.clone().prop_map(|t| json!([t])),
        text.clone().prop_map(|t| json!({ "nested": t })),
        text.prop_map(|t| json!({ t: 1 })),
    ]
}

/// A token-shaped or error-shaped response with the sentinel in one field.
fn sentinel_response() -> impl Strategy<Value = (u16, Value)> {
    let field = prop_oneof![
        Just("access_token"),
        Just("token_type"),
        Just("expires_in"),
        Just("refresh_token"),
        Just("scope"),
        Just("error"),
        Just("error_description"),
        Just("error_uri"),
    ];
    let base = prop_oneof![
        Just(json!({ "access_token": "ya29.at", "token_type": "Bearer", "expires_in": 3599 })),
        Just(json!({ "error": "invalid_grant" })),
        Just(json!({ "error": "invalid_request", "error_description": "d" })),
        Just(json!({})),
    ];
    (status_strategy(), base, field, sentinel_value()).prop_map(
        |(status, mut body, field, value)| {
            body[field] = value;
            (status, body)
        },
    )
}

/// Rule 5: a sentinel placed in any response field, at any HTTP status, never
/// appears in the Display or Debug of an error from either call.
#[test]
fn a_sentinel_in_any_response_field_never_reaches_an_error() {
    let h = Harness::new();
    runner()
        .run(&sentinel_response(), |(status, body)| {
            h.respond(status, serde_json::to_vec(&body).unwrap());
            check_both_calls(&h, &format!("status {status}"))
        })
        .unwrap();
}

/// Rule 5: the sentinel in the Content-Type header never reaches an error.
#[test]
fn a_sentinel_in_the_content_type_never_reaches_an_error() {
    let h = Harness::new();
    let content_type =
        ("[a-z]{1,8}/[a-z]{1,8}", "[a-z]{0,8}").prop_map(|(t, p)| format!("{t}; {p}={SENTINEL}"));
    runner()
        .run(
            &(status_strategy(), content_type),
            |(status, content_type)| {
                let body = json!({ "access_token": "ya29.at", "token_type": "Bearer" }).to_string();
                h.respond_typed(status, body.into_bytes(), &content_type);
                check_both_calls(&h, &content_type)
            },
        )
        .unwrap();
}

// --- Expiry arithmetic ---------------------------------------------------------------

fn wall_clock_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The model: absolute expiry for `expires_in` at wall-clock second `now`.
fn expected_expiry(now: i64, expires_in: Option<u64>) -> i64 {
    match expires_in {
        Some(secs) => now.saturating_add(i64::try_from(secs).unwrap_or(i64::MAX)),
        None => now,
    }
}

/// `expires_in` values weighted toward the numeric boundaries.
fn expires_in_strategy() -> impl Strategy<Value = Option<u64>> {
    prop_oneof![
        Just(None),
        any::<u64>().prop_map(Some),
        prop_oneof![
            Just(0u64),
            Just(1),
            Just(3599),
            Just(i64::MAX as u64 - 1),
            Just(i64::MAX as u64),
            Just(i64::MAX as u64 + 1),
            Just(u64::MAX),
            (i64::MAX as u64 - 4_000_000_000)..=(i64::MAX as u64),
        ]
        .prop_map(Some),
    ]
}

/// A well-formed response parses, and the grant's expiry is `now + expires_in`
/// saturated at `i64::MAX`, or `now` (due at once) when `expires_in` is absent.
/// Checked on refresh and on code exchange.
#[test]
fn expiry_is_now_plus_expires_in_saturated_or_now_when_absent() {
    let h = Harness::new();
    runner()
        .run(&expires_in_strategy(), |expires_in| {
            let mut body = json!({ "access_token": "ya29.at", "token_type": "Bearer", "refresh_token": "1//rt" });
            if let Some(secs) = expires_in {
                body["expires_in"] = json!(secs);
            }
            h.respond(200, serde_json::to_vec(&body).unwrap());

            let before = wall_clock_unix();
            let refreshed = h.refresh().map_err(|e| TestCaseError::fail(format!("refresh failed: {e:?}")))?;
            let pair = h.exchange(vec!["scope-a".into()]).map_err(|e| TestCaseError::fail(format!("exchange failed: {e:?}")))?;
            let after = wall_clock_unix();

            let (low, high) = (expected_expiry(before, expires_in), expected_expiry(after, expires_in));
            for (call, exp) in [("refresh", refreshed.grant.expires_at_unix), ("exchange", pair.grant.expires_at_unix)] {
                prop_assert!((low..=high).contains(&exp), "{call}: expires_at {exp} outside [{low}, {high}] for {expires_in:?}");
            }
            Ok(())
        })
        .unwrap();
}
