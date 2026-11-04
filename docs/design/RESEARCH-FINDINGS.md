# MMP.OAuth: Rust OAuth ecosystem research (reuse or build)

**Date:** 2026-06-23. The versions and facts below were checked against crates.io, docs.rs, GitHub, Google and Microsoft Learn on that date.

## Result

Wrap `oauth2` 5.0 as the one RFC-complete base client for both providers. Build the four things it leaves to the caller: provider profiles, token persistence, automatic refresh, and the desktop loopback flow. Do not use `yup-oauth2` (Google-shaped, and its disk token cache competes with the host's store). Do not use `openidconnect` (identity proof is not needed to call an API). Offer `keyring` 4.x behind a feature flag. Test the token endpoint with `wiremock`, and unit-test the flow with a hand-built fake.

## Crate by crate

### `oauth2` 5.0.0: wrap it

1. Released 2025-01-21, MSRV 1.65 on the 5.0 line. An RFC 6749 client with first-class PKCE (RFC 7636), refresh (`exchange_refresh_token`), revocation (RFC 7009), and the device grant (RFC 8628). [docs.rs/crate/oauth2/latest]
2. Typestate builder: the `EndpointSet`, `EndpointNotSet` and `EndpointMaybeSet` markers turn "called `authorize_url` before setting the auth URI" into a compile error. The auth and token URIs are set explicitly (`set_auth_uri`, `set_token_uri`), so one code path serves Google and Microsoft with two endpoint profiles. [UPGRADE.md, github.com/ramosbugs/oauth2-rs]
3. It brings no HTTP client. The `AsyncHttpClient` trait injects one, and the `reqwest` feature makes `reqwest::Client` implement it. The docs recommend `redirect::Policy::none()` as an SSRF guard. [docs.rs/oauth2/latest]
4. It does not do token persistence, automatic refresh, provider presets, or loopback handling. That gap is the layer `mmp-oauth` provides.

### `yup-oauth2` 12.1.2: skip

1. Maintained. It ships an installed-app loopback flow, `persist_tokens_to_disk`, and a `TokenStorage` trait.
2. Reason to skip: it is Google-shaped, with no first-class non-Google auth and token URIs. Using it would mean one auth model for Google and another for Microsoft behind one facade. Its disk token cache would also run beside the host's encrypted store as a second, plain-JSON copy.

### `openidconnect` 4.0.1: reference only

Built on `oauth2` 5.0. It adds ID-token (JWT) verification and OIDC discovery. This crate authorizes API calls and does not prove federated identity, so the ID-token surface is unused code and extra attack surface. A future single-sign-on feature can use it as a separate consumer.

### `keyring` 4.1.2: wrap, behind a feature flag that is off by default

1. It is 4.x, not 3.x. Version 4 moved the core into `keyring-core`, renamed features, renamed `delete_password` to `delete_credential`, and requires a registered default store.
2. On Windows it uses Credential Manager, on macOS the Keychain, and on Linux the Secret Service.
3. `mmp-oauth` offers it as the `keyring-store` feature. A host with its own encrypted store turns it off and implements `TokenStore`.

### `reqwest` 0.12 and mocking: `wiremock` 0.6.5

`wiremock` is async-native (tokio), uses a random port per server, and `Mock::given(method("POST")).and(path("/token"))` maps directly onto a token-endpoint assertion. It is a better fit than `mockito` 1.7 (sync-first) and `httpmock` 0.8 (heavier).

### MSAL for Rust: does not exist

Microsoft's MSAL list covers .NET, Android, Java, JavaScript, Node, Python and Go (preview), not Rust. Microsoft Graph OAuth in Rust is the generic `oauth2` crate against the v2 endpoints. A public native app sends no client secret and should use PKCE. [learn.microsoft.com, MSAL overview]

## How existing desktop tools do OAuth

1. **GYB (Got Your Back):** loopback flow. Each user creates their own Google Cloud project and supplies their own client id and secret. Tokens live in a per-account file.
2. **lieer:** loopback flow. Ships a shared client id that a user can override.
3. **rustmailer:** a server-side broker, which is a different architecture from a desktop public client.
4. **The common shape:** loopback on `127.0.0.1` with an ephemeral port, PKCE, the system browser, and a local token store. The one design choice that differs is a per-user client id (GYB) or a shipped shared id with an override (lieer).

## Google desktop OAuth, current guidance

Loopback is the recommended desktop mechanism. Use `127.0.0.1` instead of `localhost`, because `localhost` can trip local firewalls. The out-of-band (OOB) flow is removed. PKCE is strongly recommended. An ephemeral-port loopback is the documented pattern: the Desktop client type does not pre-register the local redirect, and Google matches the loopback IP and ignores the port. The device-code flow is for hardware with no browser. [developers.google.com/identity/protocols/oauth2/native-app, oob-migration]

## Reuse or build

| Thing | Version | Verdict | Reason |
|---|---|---|---|
| `oauth2` | 5.0.0 | Wrap | RFC-complete. Typestate turns endpoint mistakes into compile errors. One client, two profiles. |
| `yup-oauth2` | 12.1.2 | Skip | Google-shaped. Its disk cache duplicates the host's store. |
| `openidconnect` | 4.0.1 | Reference | Identity proof is not needed to call an API. |
| `keyring` | 4.1.2 | Wrap, feature-gated, off | Cross-platform OS keystore for hosts without their own store. |
| `reqwest` | 0.12 | Wrap | Default async transport injected into `oauth2`, with redirects off. |
| `wiremock` | 0.6.5 | Wrap (tests) | Async token-endpoint mock. |
| MSAL for Rust | none | Build on `oauth2` | No official Rust MSAL. v2 endpoints, public client, PKCE. |
