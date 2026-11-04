# Security policy

## Reporting a vulnerability

Report a vulnerability through [GitHub private vulnerability reporting](https://github.com/mmpworks/MMP.OAuth.OSS/security/advisories/new). Do not open a public issue for it.

Include the affected version, the steps to reproduce, and the impact you see.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## What the library protects

1. **Secrets stay out of logs.** `Secret` prints only its length in `Debug`, has no `Display`, and has no serde support. Compile-fail tests keep it that way. An authorization code is redacted in `Debug` too.
2. **Secrets are zeroed on drop.** `Secret` is `ZeroizeOnDrop`, and the keyring store zeroes the buffers that hold a saved record. This is defense in depth, not an end-to-end guarantee: a `String` can reallocate before it is wrapped, code that reads a secret with `expose` can copy it, and the OS keystore keeps its own copies.
3. **CSRF protection is a type-state.** `exchange_code` needs a `PendingExchange`, and the only way to get one is `AuthSession::validate_redirect`, which rejects a mismatched `state` (RFC 6749 section 10.12).
4. **PKCE S256 on every authorization** (RFC 7636). The verifier lives in memory only and is never saved.
5. **No client secret for Microsoft.** A desktop app is a public client, and `MicrosoftProvider` never sends a secret. Google's "Desktop app" client type requires one in the token exchange; Google does not treat it as confidential, and PKCE still applies.
6. **Loopback on `127.0.0.1` only** (RFC 8252). The listener serves one request on a port the OS picks, with a deadline.
7. **A redirect is checked strictly.** A repeated `code`, `state` or `error` parameter is rejected (RFC 6749 section 3.1).
8. **Provider text never reaches an error.** Error codes pass through an allowlist. An `error_description`, an extension code, or a body field never appears in an `OAuthError` message.
9. **A wrong client id is not retried.** The RFC 6749 client errors (`invalid_client`, `invalid_request`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`) are configuration errors, not retryable ones.
10. **No redirects on token requests.** The HTTP client sets `redirect::Policy::none()`, an SSRF guard, and uses rustls.
11. **No unsafe code.** Each crate sets `#![forbid(unsafe_code)]`.
12. **No server.** The library is a public client for native apps. It has no code path that sends a token to a backend.

## What the host application owns

1. The access token after `access_token` returns it.
2. The choice of `TokenStore`. It must encrypt the refresh token at rest and delete it on `revoke`. `KeyringTokenStore` does this through the OS keystore; `InMemoryTokenStore` is for tests only.
3. The scopes it requests. Ask for the narrowest scope that works.
4. The client id, kept in configuration. For Google's Desktop app client type, also the client secret.

## How the properties are tested

```text
cargo test --workspace --all-features
```

The suite includes property tests, compile-fail tests, and bolero fuzz harnesses. Each harness runs on random input under the command above, and under libFuzzer with `cargo bolero test` (see the header of each file in `crates/*/tests/fuzz_*.rs`).
