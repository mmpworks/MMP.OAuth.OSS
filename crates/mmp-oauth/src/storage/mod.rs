//! Token persistence behind a swappable backend (the Repository pattern).
//!
//! [`TokenStore`] holds the long-lived refresh token, and optionally a cached
//! access token, at rest. The service depends on this trait, never on a concrete
//! keystore:
//!   - A host with its own encrypted store (for example one vault for every
//!     credential the app holds) implements `TokenStore` over it, keyed by
//!     [`AccountKey::storage_ref`].
//!   - A host without one enables the `keyring-store` feature for a cross-platform
//!     OS keystore (Credential Manager, Keychain, Secret Service).
//!   - Tests use [`InMemoryTokenStore`], with no I/O and no OS keystore.
//!
//! The host owns the mapping from its own account records to an [`AccountKey`].
//! This trait takes the key and needs no database.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::error::OAuthError;
use crate::provider::ProviderKind;
use crate::Secret;

#[cfg(feature = "keyring-store")]
mod keyring_store;
#[cfg(feature = "keyring-store")]
pub use keyring_store::KeyringTokenStore;

/// Identifies one account's tokens as a `(provider, account)` pair, so one
/// identity at two providers never collides. The key has no resource field: under
/// incremental authorization one grant can span several resources. It renders as
/// `oauth:google:user@example.com`.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AccountKey {
    /// The provider these tokens authenticate against.
    pub provider: ProviderKind,
    /// The account identity as connected, usually the user's email address or UPN.
    pub account: String,
}

impl AccountKey {
    /// Build a key.
    pub fn new(provider: ProviderKind, account: impl Into<String>) -> Self {
        Self {
            provider,
            account: account.into(),
        }
    }

    /// The namespaced storage reference, `oauth:<provider>:<account>`. It is stable
    /// across releases, so a backend can key on it.
    #[must_use]
    pub fn storage_ref(&self) -> String {
        format!("oauth:{}:{}", self.provider.as_str(), self.account)
    }
}

/// What the service saves for an account. The refresh token is the long-lived
/// credential. The access token is an optional cache: a refresh can replace it,
/// so losing it costs one refresh. Both are [`Secret`] values (redacted, zeroized).
#[derive(Clone, Debug)]
pub struct StoredTokens {
    /// The long-lived refresh token. The one value that must be saved.
    pub refresh_token: Secret,
    /// The cached access token, so a launch with a still-valid token needs no
    /// refresh.
    pub access_token: Option<Secret>,
    /// The cached access token's expiry, in Unix seconds, if present.
    pub access_expires_at_unix: Option<i64>,
    /// The scopes the cached access token holds (the newest token's scope).
    pub granted_scopes: Vec<String>,
    /// The scopes the refresh token was granted at consent. RFC 6749 section 6
    /// keeps them fixed for the life of the grant, rotation included, and a refresh
    /// response that omits `scope` grants this set (section 5.1). `None` marks a
    /// record written before this field existed. A store that does not save it
    /// returns `None`, and the service then falls back to `granted_scopes`.
    pub refresh_scopes: Option<Vec<String>>,
}

/// The swappable token-persistence backend. It is synchronous: a keystore read is
/// a fast local call, and a sync trait works as `dyn TokenStore` with no async
/// runtime dependency.
///
/// An implementation must encrypt the refresh token at rest, delete the record on
/// `delete`, and never log a token.
pub trait TokenStore: Send + Sync {
    /// Load the stored tokens for an account, or `Ok(None)` if it never connected.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Storage`] when the backend cannot be read.
    fn load(&self, key: &AccountKey) -> Result<Option<StoredTokens>, OAuthError>;
    /// Save (insert or replace) the tokens for an account.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Storage`] when the backend cannot be written.
    fn save(&self, key: &AccountKey, tokens: &StoredTokens) -> Result<(), OAuthError>;
    /// Remove the tokens for an account, on revoke or disconnect.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Storage`] when the backend cannot be written.
    fn delete(&self, key: &AccountKey) -> Result<(), OAuthError>;
}

/// An in-memory token store for tests and examples. No I/O, no OS keystore.
#[derive(Default)]
pub struct InMemoryTokenStore {
    inner: Mutex<HashMap<String, StoredTokens>>,
}

impl InMemoryTokenStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The records, locked. A poisoned lock (another thread panicked while it held
    /// the lock) is a [`OAuthError::Storage`] error, as a failed keystore would be.
    fn records(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, StoredTokens>>, OAuthError> {
        self.inner
            .lock()
            .map_err(|_| OAuthError::Storage("the in-memory token store lock is poisoned".into()))
    }
}

impl TokenStore for InMemoryTokenStore {
    fn load(&self, key: &AccountKey) -> Result<Option<StoredTokens>, OAuthError> {
        Ok(self.records()?.get(&key.storage_ref()).cloned())
    }

    fn save(&self, key: &AccountKey, tokens: &StoredTokens) -> Result<(), OAuthError> {
        self.records()?.insert(key.storage_ref(), tokens.clone());
        Ok(())
    }

    fn delete(&self, key: &AccountKey) -> Result<(), OAuthError> {
        self.records()?.remove(&key.storage_ref());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> StoredTokens {
        StoredTokens {
            refresh_token: Secret::new("rt"),
            access_token: Some(Secret::new("at")),
            access_expires_at_unix: Some(3600),
            granted_scopes: vec!["https://www.googleapis.com/auth/drive.readonly".into()],
            refresh_scopes: Some(vec!["https://www.googleapis.com/auth/drive.readonly".into()]),
        }
    }

    #[test]
    fn account_key_renders_a_namespaced_ref() {
        let k = AccountKey::new(ProviderKind::Google, "user@x.com");
        assert_eq!(k.storage_ref(), "oauth:google:user@x.com");
    }

    #[test]
    fn same_identity_at_different_providers_does_not_collide() {
        let store = InMemoryTokenStore::new();
        let g = AccountKey::new(ProviderKind::Google, "a@x.com");
        let o = AccountKey::new(ProviderKind::Microsoft, "a@x.com");
        store.save(&g, &sample()).unwrap();
        assert!(store.load(&g).unwrap().is_some());
        assert!(
            store.load(&o).unwrap().is_none(),
            "same identity, different provider must not collide"
        );
    }

    #[test]
    fn save_load_delete_roundtrip() {
        let store = InMemoryTokenStore::new();
        let k = AccountKey::new(ProviderKind::Google, "a@x.com");
        assert!(store.load(&k).unwrap().is_none());
        store.save(&k, &sample()).unwrap();
        assert_eq!(
            store.load(&k).unwrap().unwrap().refresh_token.expose(),
            "rt"
        );
        store.delete(&k).unwrap();
        assert!(store.load(&k).unwrap().is_none());
    }

    /// A poisoned lock is a `Storage` error on each call, never a panic.
    #[test]
    fn a_poisoned_store_returns_storage_errors() {
        let store = std::sync::Arc::new(InMemoryTokenStore::new());
        let held = std::sync::Arc::clone(&store);
        let _ = std::thread::spawn(move || {
            let _guard = held.inner.lock().unwrap();
            panic!("poison the lock");
        })
        .join();
        let key = AccountKey::new(ProviderKind::Google, "a@x.com");
        assert!(matches!(store.load(&key), Err(OAuthError::Storage(_))));
        assert!(matches!(
            store.save(&key, &sample()),
            Err(OAuthError::Storage(_))
        ));
        assert!(matches!(store.delete(&key), Err(OAuthError::Storage(_))));
    }
}
