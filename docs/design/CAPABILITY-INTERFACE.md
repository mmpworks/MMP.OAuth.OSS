# MMP.OAuth capability interface

This is the contract a host application depends on. It is small on purpose, so it changes rarely while the provider code behind it changes freely.

## The four verbs

```rust
#[async_trait]
pub trait OAuthCapability: Send + Sync {
    /// Run consent for `scopes`, persist the refresh token, and return the first grant.
    async fn authorize(&self, account: &str, scopes: &[ScopeRequest]) -> Result<AccessGrant, OAuthError>;

    /// The current access token, refreshed first if it has expired. Call it before every API request.
    async fn access_token(&self, account: &str) -> Result<AccessGrant, OAuthError>;

    /// Revoke at the provider (best effort) and clear the stored tokens.
    async fn revoke(&self, account: &str) -> Result<(), OAuthError>;

    /// The lifecycle state, for a UI. No network I/O.
    fn status(&self, account: &str) -> TokenState;
}
```

A resource adapter in the host calls `access_token` before each request and gets a live bearer token. The refresh happens inside the call when it is due.

## Resource-agnostic

OAuth authorizes an application to access a user's data at a provider. Nothing in this surface is specific to one resource. The host requests the scopes its feature needs as `ScopeRequest` values, and the `Provider` mints a token for whatever those scopes select. A new resource (Drive, Calendar, Microsoft Graph files) is a new scope string, with no change to the library. Resource base URLs and API calls belong to the host.

## Value types that cross the boundary

```rust
pub struct AccessGrant {
    pub access_token: Secret,        // redacting Debug, zeroized on drop
    pub expires_at_unix: i64,        // absolute expiry, seconds since the Unix epoch
    pub granted_scopes: Vec<String>, // the scopes the provider granted
}

pub enum TokenState {
    Unauthorized, Active, Expired, Refreshing, NeedsReconsent, Revoked,
}

pub struct ScopeRequest {
    pub scope: String,         // any provider scope, for example ".../drive.readonly"
    pub capability: String,    // the feature that needs the scope
    pub justification: String, // why this is the narrowest scope that works
    pub incremental: bool,     // request the scope only when the feature is first used
}
```

`capability` and `justification` exist because Google's OAuth verification asks an app to justify each sensitive or restricted scope. Keeping the reason next to the request keeps that record in the code.

## Injected edges

The host builds an `OAuthService<P>` from a provider and a `TokenStore`, then adds the runtime edges with `with_*`:

```rust
let svc = OAuthService::new(GoogleProvider::new(client_id)?, store)
    .with_clock(clock)                  // a deterministic clock in tests
    .with_resilience(guard)             // the host's retry and circuit-breaker policy
    .with_refresh_observer(on_refresh); // optional notification on a silent refresh
```

1. `TokenStore` (Repository): the `keyring-store` feature gives a cross-platform OS keystore implementation. A host can supply its own. Tests use `InMemoryTokenStore`.
2. `Clock`: `SystemClock` in production, `ManualClock` in tests.
3. `ResilienceGuard`: the host's policy. The default is `Passthrough`.
4. `RefreshObserver`: optional. It runs after a silent refresh.

## Storage contract

```rust
pub trait TokenStore: Send + Sync {
    fn load(&self, key: &AccountKey) -> Result<Option<StoredTokens>, OAuthError>;
    fn save(&self, key: &AccountKey, t: &StoredTokens) -> Result<(), OAuthError>;
    fn delete(&self, key: &AccountKey) -> Result<(), OAuthError>;
}
// AccountKey = (provider, account); storage_ref() = "oauth:<provider>:<account>"
```

A `TokenStore` implementation must:

1. Encrypt the refresh token at rest (an OS keystore or equivalent, never plain text).
2. Delete the record on revoke, so no refresh token stays after a disconnect.
3. Never log a token. The `Secret` type covers the `Debug` half of this rule.

## Compatibility rules

1. **New provider:** a new `Provider` implementation and a new `ProviderKind` variant. `OAuthCapability` does not change. A host that matches on `ProviderKind` gets a compile error until it handles the new variant, which is intended.
2. **New resource:** new `ScopeRequest` scope strings only.
3. **New storage backend:** a new `TokenStore` implementation. No surface change.
4. **New flow (device code):** an additive `Provider` method with a default "unsupported" body. The four verbs do not change.
5. **`OAuthError` is `#[non_exhaustive]`:** new variants do not break hosts.

## What a host must not do

1. Persist or send the access token or refresh token anywhere other than through the `TokenStore`.
2. Send a token to a server it controls. That turns the desktop public-client design into a server-side design, with the security and provider-verification obligations that come with one.
