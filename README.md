# MMP.OAuth

A small OAuth 2.0 client for Rust desktop applications. It turns a user's consent into an access token that refreshes itself, through four methods.

It is built on the [`oauth2`](https://crates.io/crates/oauth2) crate (5.0) and adds the four things `oauth2` leaves to the caller: provider profiles, token storage, automatic refresh, and the desktop loopback flow (RFC 8252). The provider, the token store, the clock, the browser and the loopback listener are injected traits, so the whole flow runs in tests with a mock provider and no network.

MIT licensed. Copyright 2026 MMPWorks LLC.


## Status

Version 0.1.0. It is not on crates.io yet; depend on it from git.

| Part | State |
|---|---|
| Google provider | Implemented and tested |
| Microsoft provider | Preview. Tested against a mock server only. Full support, with a live Microsoft Entra ID check, comes in a later version |
| Keyring token store | Implemented and tested against an in-memory keystore; see [Known limits](#known-limits) |
| Mock provider, in-memory store | For tests and examples |

## Quick start

```toml
[dependencies]
mmp-oauth = { git = "https://github.com/mmpworks/MMP.OAuth.OSS", features = ["reqwest-transport", "loopback-flow", "keyring-store"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

The quick-start example runs all four methods with a mock provider, so it needs no account:

```text
$ cargo run -p mmp-oauth --example quickstart_mock
1. consent URL : https://mock/authorize?redirect_uri=http://127.0.0.1:50000/callback&state=mock-state
2. authorize   : granted ["https://www.googleapis.com/auth/userinfo.email"], token Secret(<redacted len=22>)
3. access_token: Secret(<redacted len=22>), expires at 1800003600
4. status      : Active
5. revoke      : status is now Unauthorized
```

With Microsoft and the OS keystore, the wiring is:

```rust
let provider = MicrosoftProvider::new(client_id)?;          // the Application (client) ID
let store = Arc::new(KeyringTokenStore::new("my-app"));     // Windows Credential Manager, Keychain, Secret Service
let service = OAuthService::new(provider, store)
    .with_loopback(Arc::new(SystemBrowserOpener), Arc::new(LoopbackReceiver::bind()?));

let grant = service.authorize("user@example.com", &[ScopeRequest::at_connect("User.Read", "profile", "show the user's name")]).await?;
let token = service.access_token("user@example.com").await?;   // before each API call
```

With Google, use `GoogleProvider::new(client_id)?.with_secret(Some(Secret::new(client_secret)))`. See `crates/mmp-oauth/examples/google_loopback.rs`.

## The four methods

```rust
authorize(account, scopes) -> AccessGrant   // run consent, save the refresh token
access_token(account)      -> AccessGrant   // the current token, refreshed when due
revoke(account)            -> ()            // revoke at the provider, clear local tokens
status(account)            -> TokenState    // for a UI, with no I/O
```

A resource adapter calls `access_token` before each API request. Concurrent calls for one account cause one refresh. After a refresh token dies, `status` returns `NeedsReconsent` and the app calls `authorize` again.

## Set up a Microsoft app

**Preview.** No live sign-in against Microsoft Entra ID has run yet for this version, so these steps are untested. See [Known limits](#known-limits).

The steps follow Microsoft's guide "Register an application in Microsoft Entra ID" on learn.microsoft.com. That guide lists an Azure account with at least the Application Developer role as the prerequisite.

1. Sign in to the Microsoft Entra admin center: <https://entra.microsoft.com>.
2. Go to **Entra ID > App registrations** and select **New registration**.
3. **Name:** your app's name. Users see it on the consent page.
4. **Supported account types:** select **Any Entra ID Tenant + Personal Microsoft accounts**. That matches the `common` endpoint this crate uses by default. For one organization only, pick the single-tenant option and call `MicrosoftProvider::with_tenant("<tenant id>")`.
5. Leave **Redirect URI** empty for now and select **Register**.
6. On the app's **Overview** page, copy the **Application (client) ID**. That is the only value the code needs.
7. Add the redirect URI:
   1. Under **Manage**, select **Authentication**, then **Add Redirect URI** (or **Add a platform**).
   2. Select **Mobile and desktop applications**.
   3. Under **Custom redirect URIs**, enter `http://127.0.0.1/callback` and select **Configure**. The app listens on a different port each time; Microsoft ignores the port when it matches a loopback redirect (see [Known limits](#known-limits), item 3), so one entry is enough.
   4. If the portal refuses an `http` address on `127.0.0.1`, add it in **Manage > Manifest** instead: Microsoft's redirect URI guide says an `http` loopback address on `127.0.0.1` must be added through the application manifest. Or register `http://localhost/callback` and call `LoopbackReceiver::with_localhost_redirect()` in your app.
8. **Do not add a client secret.** A desktop app is a public client, and Microsoft's documentation says public clients must not use secrets when they redeem an authorization code. This crate never sends one for Microsoft. Leave **Certificates & secrets** empty.
9. **API permissions:** new registrations get Microsoft Graph **User.Read** (delegated). Add any other delegated Graph permission your app needs (for example `Mail.Read`). You do not need to add `offline_access`; the crate requests it, and Microsoft returns a refresh token only when it is requested.
10. Run the consent check with the testbed, which opens your browser:

    ```text
    cargo run -p mmp-oauth --all-features --bin oauth_testbed -- --provider microsoft --client-id <APPLICATION_CLIENT_ID>
    ```

    Success prints `Consent succeeded` and `status : Active`. Your own app passes the same id to `MicrosoftProvider::new`, usually from a config file or the `MMP_OAUTH_CLIENT_ID` environment variable. A client id is not a secret, but keep it in configuration, not in code.

## Set up a Google app

The steps follow Google's guide "OAuth 2.0 for Desktop Apps" on developers.google.com.

1. In the Google Cloud console, create or pick a project.
2. Go to the **Clients** page: <https://console.developers.google.com/auth/clients>. If the console asks you to configure the consent screen first, enter an app name and a support email.
3. Select **Create client**, choose the **Desktop app** application type, enter a name, and select **Create**.
4. Copy the **Client ID** and the **Client secret**. Google's Desktop app type sends the secret in the token exchange. Google states that desktop apps "cannot keep secrets confidential", so the secret is not a protection; this crate uses PKCE as well.
5. While the app is in testing, add your Google account as a test user on the console's **Audience** page (under Google Auth Platform).
6. Run the consent check:

    ```text
    cargo run -p mmp-oauth --all-features --bin oauth_testbed -- --provider google --client-id <CLIENT_ID> --client-secret <CLIENT_SECRET>
    ```

The default scope, `https://www.googleapis.com/auth/userinfo.email`, needs no Google app verification. Sensitive and restricted scopes (a mailbox scope is restricted) need Google's verification before your app ships to the public.

## Providers

1. **Google:** PKCE S256, a `127.0.0.1` loopback redirect, RFC 7009 revoke, and the Desktop app client secret.
2. **Microsoft (preview):** the v2.0 `common` endpoint (or a tenant you choose), PKCE S256, no client secret, `offline_access` added automatically, and refresh-token rotation. `interaction_required`, `consent_required` and `login_required` count as "sign in again".
3. **Your own:** implement the `Provider` trait and a `ProviderProfile`. The service and the host do not change.

The library is resource-agnostic. It ends at the access token, and a new resource (Drive, Calendar, Graph files) is a new scope string.

## Feature flags

| Feature | Adds |
|---|---|
| (default) | Traits, token state machine, mock provider, in-memory store. No network, no runtime. |
| `reqwest-transport` | `GoogleProvider`, `MicrosoftProvider`, `ReqwestTransport` |
| `loopback-flow` | `LoopbackReceiver` and `SystemBrowserOpener` |
| `keyring-store` | `KeyringTokenStore` over the OS keystore |
| `testbed` | The `testbed` module and the `oauth_testbed` binary (a developer tool) |

## Bring your own parts

| Trait | Default | Replace it to |
|---|---|---|
| `TokenStore` | none (pass one) | use your own encrypted store |
| `Clock` | `SystemClock` | control time in tests (`ManualClock`) |
| `ResilienceGuard` | `Passthrough` | add retry, backoff, circuit breaking |
| `ConsentOpener`, `RedirectReceiver` | system browser, loopback listener | run the flow in tests |

## Security

1. `Secret` prints only its length in `Debug`, has no `Display`, has no serde support, and zeroes its memory on drop. Authorization codes are redacted in `Debug` too.
2. The CSRF `state` check is a type-state: code cannot exchange an authorization code without passing it.
3. PKCE S256 on every authorization. The verifier is never saved.
4. Provider error text never reaches an error message.
5. The keyring store keeps each record in the OS keystore and zeroes its buffers.

See [SECURITY.md](SECURITY.md) for the full list and for how to report a vulnerability.

## Known limits

1. **Microsoft has no revocation endpoint for a desktop app.** `revoke` clears the local tokens only. The refresh token stays valid at Microsoft until it expires or the user removes the app's access in their Microsoft account settings (or the organization's admin does).
2. **`NeedsReconsent` is kept in memory.** After a restart, `status` reports `Expired` until the next refresh fails again.
3. **The Microsoft loopback port rule.** Microsoft documents that it ignores the port for `localhost` redirects and recommends `127.0.0.1`. If a tenant matches the port for `127.0.0.1`, use `LoopbackReceiver::with_localhost_redirect()`.
4. **Windows Credential Manager holds 2,560 bytes per entry.** When a record is larger, the keyring store saves it without the cached access token, which costs one refresh.
5. **Callers waiting on one refresh each try it after a 429.** The default policy does not wait for `retry_after`. When a refresh fails, the next waiting caller refreshes once more, one at a time. Supply a `ResilienceGuard` to apply a wait.
6. **A `Retry-After` HTTP date gives no wait value.** A 429 is `Throttled`. Its `retry_after` holds the header's seconds, capped at 24 hours, and is `None` when the header holds a date.
7. **Microsoft support is a preview.** The provider passes its tests against a mock server. No live sign-in against Microsoft Entra ID has run. Full support comes in a later version.
8. **The keyring store has no live test result yet.** Its tests use an in-memory keystore. The live test against the operating system's keystore is written and has not been run for this version.

## Testing and fuzzing

```text
cargo test --workspace --all-features
```

`.github/workflows/ci.yml` runs the format, clippy, test and doc checks on Windows and Linux.

The suite has unit and integration tests, proptest properties, compile-fail tests, and six bolero fuzz harnesses. A harness runs on random input under `cargo test`, and under libFuzzer on Linux (or WSL) with a nightly toolchain:

```text
cargo bolero test -p mmp-oauth --all-features --toolchain nightly -T 1800s ini_parse_round_trips_and_never_panics
```

The command for each harness is in the header of its file under `crates/*/tests/fuzz_*.rs`.

Last libFuzzer run: 2026-11-04, 30 minutes per target, all six in parallel, on Linux (WSL Ubuntu) with nightly 1.101 and AddressSanitizer. Each target finished with 0 crashes:

| Target | What it feeds | Runs |
|---|---|---|
| F1 `ini_parse_round_trips_and_never_panics` | `.ini` app-config text | 25,473,806 |
| F2 `token_bodies_never_panic_or_echo` | Token and error response bodies, parsed and classified (no HTTP round trip) | 24,995,368 |
| F3 `redirect_target_never_panics_or_echoes` | Loopback redirect request targets | 39,559,185 |
| F4 `quota_ops_match_the_model` | `mmp-quota` operation sequences | 55,208,509 |
| F5 `masking_never_shows_the_value` | Secret and client-id masking | 29,374,684 |
| F6 `stored_expiry_never_panics_and_matches_the_model` | Stored token expiry and clock values | 34,023,567 |

Earlier short runs found two failures, and both now have regression tests. In `mmp-quota`, `retry_after` returned a zero wait for a batch that did not fit when a spend's exit time passed `u64::MAX` milliseconds. The F1 check itself was wrong for a client id made of the mask's own `•` character.

## Examples

| Example | Shows | Needs credentials |
|---|---|---|
| `quickstart_mock` | The four methods end to end | No |
| `auto_refresh` | A token refreshing once, with an observer | No |
| `custom_token_store` | A `TokenStore` over a JSON file | No |
| `google_loopback` | The real Google desktop flow | A Google Desktop app client |
| `quota_budget` (mmp-quota) | Pacing batches against a per-minute quota | No |

The testbed (`oauth_testbed`, feature `testbed`) runs the real flow for Google or Microsoft from the command line or a local web page (`oauth_testbed serve`).

## Companion crates

1. **`mmp-secret`:** the redacting, zeroizing `Secret` string. It depends only on `zeroize`.
2. **`mmp-quota`:** a sliding-window request-budget calculator. It answers "how many requests fit now" and "how long until this batch fits".

## Rust version and versioning

The minimum supported Rust version is 1.94. The crates are at 0.x: a breaking change raises the minor version, and a fix raises the patch version.

## Design docs

| Doc | What it covers |
|---|---|
| `docs/design/ARCHITECTURE.md` | The design, the diagram, the pattern map, the designs considered |
| `docs/design/CAPABILITY-INTERFACE.md` | The stable surface a host depends on |
| `docs/design/RESEARCH-FINDINGS.md` | The Rust OAuth crate survey (reuse or build) |

## License

MIT. See [LICENSE](LICENSE).
