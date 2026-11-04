//! A [`TokenStore`] over the OS keystore, through the `keyring` 4.x crate: Windows
//! Credential Manager, macOS Keychain, or the Linux Secret Service. It sits behind
//! the `keyring-store` feature, off by default, so a host with its own encrypted
//! store does not compile it.
//!
//! ## Record format
//!
//! Each account is one keystore entry. The entry's service is the namespace given
//! to [`KeyringTokenStore::new`] (for example the application name), and its user is
//! [`AccountKey::storage_ref`] (`oauth:<provider>:<account>`). The entry's secret is
//! a JSON object with the fields of [`StoredTokens`], as UTF-8 bytes.
//!
//! `Secret` has no serde support, so this module is the one place that copies the
//! token text out with [`Secret::expose`]. The serialized bytes live in a
//! `zeroize::Zeroizing` buffer, sized up front so it does not reallocate, and are
//! zeroed on drop. Copies inside `keyring` and the OS keystore are outside this
//! crate's control.
//!
//! ## Size limit
//!
//! Windows Credential Manager holds at most 2,560 bytes per entry. A Microsoft
//! access token and refresh token together can pass that. When the full record is
//! too long, the store saves it without the cached access token, which is only a
//! cache: the next `access_token` call refreshes. When even that is too long, `save`
//! returns [`OAuthError::Storage`].

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::error::OAuthError;
use crate::storage::{AccountKey, StoredTokens, TokenStore};
use crate::Secret;

/// A cross-platform OS-keystore token store (Windows Credential Manager, macOS
/// Keychain, Linux Secret Service), through the `keyring` 4.x crate.
pub struct KeyringTokenStore {
    service: String,
    /// The credential store to use. `None` means the platform's default store,
    /// which `keyring` chooses and installs on first use.
    store: Option<Arc<keyring_core::CredentialStore>>,
}

/// The JSON shape of one saved record. It borrows from [`StoredTokens`] when it
/// saves, so it makes no copy of a token before serialization.
#[derive(Serialize)]
struct RecordOut<'a> {
    refresh_token: &'a str,
    access_token: Option<&'a str>,
    access_expires_at_unix: Option<i64>,
    granted_scopes: &'a [String],
    refresh_scopes: Option<&'a [String]>,
}

/// The JSON shape of one loaded record. Each token string moves into a `Secret`
/// with no further copy. A record that fails to decode drops its partial strings
/// unzeroed; serde has no zeroizing string type here.
#[derive(Deserialize)]
struct RecordIn {
    refresh_token: String,
    access_token: Option<String>,
    access_expires_at_unix: Option<i64>,
    #[serde(default)]
    granted_scopes: Vec<String>,
    refresh_scopes: Option<Vec<String>>,
}

impl KeyringTokenStore {
    /// Build a store in the platform's default keystore, with `service` as the
    /// entry namespace (for example the application name).
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            store: None,
        }
    }

    /// Build a store over a specific `keyring-core` credential store. Tests pass
    /// `keyring_core::mock::Store`; a host can pass any store it chose.
    pub fn with_credential_store(
        service: impl Into<String>,
        store: Arc<keyring_core::CredentialStore>,
    ) -> Self {
        Self {
            service: service.into(),
            store: Some(store),
        }
    }

    fn entry(&self, key: &AccountKey) -> Result<keyring_core::Entry, OAuthError> {
        let user = key.storage_ref();
        let entry = match &self.store {
            Some(store) => store.build(&self.service, &user, None),
            None => keyring::Entry::new(&self.service, &user).map(|e| e.inner),
        };
        entry.map_err(storage_error)
    }
}

/// Serialize `tokens`, with or without the cached access token, into a `Secret`.
fn encode(
    tokens: &StoredTokens,
    with_access_token: bool,
) -> Result<zeroize::Zeroizing<Vec<u8>>, OAuthError> {
    let access_token = tokens
        .access_token
        .as_ref()
        .filter(|_| with_access_token)
        .map(Secret::expose);
    let record = RecordOut {
        refresh_token: tokens.refresh_token.expose(),
        access_token,
        access_expires_at_unix: tokens.access_expires_at_unix.filter(|_| with_access_token),
        granted_scopes: &tokens.granted_scopes,
        refresh_scopes: tokens.refresh_scopes.as_deref(),
    };
    // Size the buffer up front, so it does not reallocate and leave a freed copy of
    // the tokens unzeroed. The 1 KiB margin covers the field names, the scopes and
    // JSON escapes for a typical record; a larger record still encodes correctly.
    let scopes: usize = tokens
        .granted_scopes
        .iter()
        .chain(tokens.refresh_scopes.iter().flatten())
        .map(String::len)
        .sum();
    let capacity = record.refresh_token.len() + access_token.map_or(0, str::len) + scopes + 1024;
    let mut buffer = zeroize::Zeroizing::new(Vec::with_capacity(capacity));
    serde_json::to_writer(&mut *buffer, &record)
        .map_err(|_| OAuthError::Storage("could not encode the token record".into()))?;
    Ok(buffer)
}

fn decode(bytes: &[u8]) -> Result<StoredTokens, OAuthError> {
    // The error names no byte of the entry: a corrupt record may still hold a token.
    let record: RecordIn = serde_json::from_slice(bytes).map_err(|_| {
        OAuthError::Storage("the keystore entry is not a valid token record".into())
    })?;
    Ok(StoredTokens {
        refresh_token: Secret::new(record.refresh_token),
        access_token: record.access_token.map(Secret::new),
        access_expires_at_unix: record.access_expires_at_unix,
        granted_scopes: record.granted_scopes,
        refresh_scopes: record.refresh_scopes,
    })
}

/// Map a keystore error to [`OAuthError::Storage`]. The keystore's own message names
/// the failure (a locked store, a missing service); it carries no token bytes.
#[allow(clippy::needless_pass_by_value)] // `map_err` hands the error over by value.
fn storage_error(e: keyring_core::Error) -> OAuthError {
    OAuthError::Storage(format!("keystore: {e}"))
}

impl TokenStore for KeyringTokenStore {
    fn load(&self, key: &AccountKey) -> Result<Option<StoredTokens>, OAuthError> {
        match self.entry(key)?.get_secret() {
            Ok(bytes) => {
                // The returned buffer holds the tokens, so it is zeroed on drop.
                let bytes = zeroize::Zeroizing::new(bytes);
                decode(&bytes).map(Some)
            }
            Err(keyring_core::Error::NoEntry) => Ok(None),
            Err(e) => Err(storage_error(e)),
        }
    }

    fn save(&self, key: &AccountKey, tokens: &StoredTokens) -> Result<(), OAuthError> {
        let entry = self.entry(key)?;
        let full = encode(tokens, true)?;
        match entry.set_secret(&full) {
            Err(keyring_core::Error::TooLong(..)) => {
                // Drop the cached access token and try once more (see "Size limit").
                let lean = encode(tokens, false)?;
                entry.set_secret(&lean).map_err(|e| match e {
                    keyring_core::Error::TooLong(..) => OAuthError::Storage(
                        "the refresh token is too long for this keystore entry".into(),
                    ),
                    other => storage_error(other),
                })
            }
            other => other.map_err(storage_error),
        }
    }

    fn delete(&self, key: &AccountKey) -> Result<(), OAuthError> {
        match self.entry(key)?.delete_credential() {
            Ok(()) | Err(keyring_core::Error::NoEntry) => Ok(()),
            Err(e) => Err(storage_error(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    //! Tests K1 to K8 from the open-source readiness plan run against
    //! `keyring_core::mock::Store`, an in-memory keystore, so they touch no real
    //! keystore. The live test at the end uses the platform store and is ignored by
    //! default.

    use super::*;
    use crate::provider::{MockProvider, ProviderKind};
    use crate::{OAuthCapability, OAuthService, TokenState};

    const SERVICE: &str = "mmp-oauth-test";

    fn mock_store() -> KeyringTokenStore {
        let store: Arc<keyring_core::CredentialStore> = keyring_core::mock::Store::new().unwrap();
        KeyringTokenStore::with_credential_store(SERVICE, store)
    }

    fn key(provider: ProviderKind, account: &str) -> AccountKey {
        AccountKey::new(provider, account)
    }

    fn tokens(refresh: &str, access: &str) -> StoredTokens {
        StoredTokens {
            refresh_token: Secret::new(refresh),
            access_token: Some(Secret::new(access)),
            access_expires_at_unix: Some(1_800_000_000),
            granted_scopes: vec!["User.Read".into(), "offline_access".into()],
            refresh_scopes: Some(vec!["User.Read".into()]),
        }
    }

    fn same(a: &StoredTokens, b: &StoredTokens) -> bool {
        a.refresh_token.expose() == b.refresh_token.expose()
            && a.access_token.as_ref().map(Secret::expose)
                == b.access_token.as_ref().map(Secret::expose)
            && a.access_expires_at_unix == b.access_expires_at_unix
            && a.granted_scopes == b.granted_scopes
            && a.refresh_scopes == b.refresh_scopes
    }

    /// Make the next call on `k`'s mock entry fail with `error`.
    fn arm(store: &KeyringTokenStore, k: &AccountKey, error: keyring_core::Error) {
        let entry = store.entry(k).unwrap();
        let mock: &keyring_core::mock::Cred = entry.as_any().downcast_ref().unwrap();
        mock.set_error(error);
    }

    /// K1: save then load returns every field.
    #[test]
    fn k1_save_then_load_round_trips_every_field() {
        let store = mock_store();
        let k = key(ProviderKind::Microsoft, "a@x.com");
        let saved = tokens("refresh-1", "access-1");
        store.save(&k, &saved).unwrap();
        assert!(same(&store.load(&k).unwrap().expect("a record"), &saved));
    }

    /// K2: a missing entry loads as `Ok(None)`.
    #[test]
    fn k2_a_missing_entry_is_none() {
        assert!(mock_store()
            .load(&key(ProviderKind::Google, "nobody"))
            .unwrap()
            .is_none());
    }

    /// K3: deleting a missing entry succeeds, and delete removes a saved one.
    #[test]
    fn k3_delete_is_idempotent() {
        let store = mock_store();
        let k = key(ProviderKind::Google, "a@x.com");
        store.delete(&k).expect("deleting nothing is fine");
        store.save(&k, &tokens("r", "a")).unwrap();
        store.delete(&k).unwrap();
        assert!(store.load(&k).unwrap().is_none());
    }

    /// K4: two accounts and two providers never collide.
    #[test]
    fn k4_accounts_and_providers_do_not_collide() {
        let store = mock_store();
        let keys = [
            key(ProviderKind::Google, "a@x.com"),
            key(ProviderKind::Microsoft, "a@x.com"),
            key(ProviderKind::Google, "b@x.com"),
        ];
        for (i, k) in keys.iter().enumerate() {
            store
                .save(k, &tokens(&format!("refresh-{i}"), "a"))
                .unwrap();
        }
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(
                store.load(k).unwrap().unwrap().refresh_token.expose(),
                format!("refresh-{i}")
            );
        }
    }

    /// K5: a corrupt entry is a Storage error, and the error holds no entry bytes.
    #[test]
    fn k5_a_corrupt_entry_is_a_storage_error_without_its_bytes() {
        let store = mock_store();
        let k = key(ProviderKind::Google, "a@x.com");
        store
            .entry(&k)
            .unwrap()
            .set_secret(br#"{"refresh_token": "SENTINEL-k5""#)
            .unwrap();
        let err = store.load(&k).unwrap_err();
        assert!(matches!(err, OAuthError::Storage(_)), "{err:?}");
        assert!(!format!("{err} {err:?}").contains("SENTINEL"), "{err:?}");
    }

    /// K6: when the full record is too long for the keystore, the store saves it
    /// without the cached access token (only a cache), and a load returns the rest.
    #[test]
    fn k6_an_oversized_record_is_saved_without_the_access_token() {
        let store = mock_store();
        let k = key(ProviderKind::Microsoft, "a@x.com");
        arm(
            &store,
            &k,
            keyring_core::Error::TooLong("secret".into(), 2560),
        );
        store
            .save(&k, &tokens("refresh-1", "a-long-access-token"))
            .expect("the lean record fits");
        let loaded = store.load(&k).unwrap().unwrap();
        assert_eq!(loaded.refresh_token.expose(), "refresh-1");
        assert!(loaded.access_token.is_none() && loaded.access_expires_at_unix.is_none());
        assert_eq!(loaded.refresh_scopes, Some(vec!["User.Read".to_string()]));
    }

    /// K7: a keystore failure (a locked store) is a Storage error on every call.
    #[test]
    fn k7_a_backend_failure_is_a_storage_error() {
        let store = mock_store();
        let k = key(ProviderKind::Google, "a@x.com");
        store.save(&k, &tokens("r", "a")).unwrap();
        for call in ["load", "save", "delete"] {
            arm(
                &store,
                &k,
                keyring_core::Error::NoStorageAccess(Box::new(std::io::Error::other("locked"))),
            );
            let result = match call {
                "load" => store.load(&k).map(|_| ()),
                "save" => store.save(&k, &tokens("r", "a")),
                _ => store.delete(&k),
            };
            assert!(
                matches!(result, Err(OAuthError::Storage(_))),
                "{call}: {result:?}"
            );
        }
    }

    /// K8: the service runs authorize, `access_token` and revoke over this store.
    #[tokio::test]
    async fn k8_the_service_runs_over_the_keyring_store() {
        use crate::flow::{ConsentOpener, ManualClock, RedirectOutcome, RedirectReceiver};
        struct NoBrowser;
        impl ConsentOpener for NoBrowser {
            fn open(&self, _url: &str) -> Result<(), OAuthError> {
                Ok(())
            }
        }
        struct Redirect;
        #[async_trait::async_trait]
        impl RedirectReceiver for Redirect {
            fn redirect_uri(&self) -> String {
                "http://127.0.0.1:50000/callback".into()
            }
            async fn wait_for_redirect(&self) -> Result<RedirectOutcome, OAuthError> {
                Ok(RedirectOutcome {
                    code: "code".into(),
                    state: "mock-state".into(),
                })
            }
        }

        let provider = MockProvider::new(3600);
        provider.set_issued_at(1_000);
        let service = OAuthService::new(provider, Arc::new(mock_store()))
            .with_clock(Arc::new(ManualClock::new(1_000)))
            .with_loopback(Arc::new(NoBrowser), Arc::new(Redirect));
        let scope = crate::ScopeRequest::at_connect("User.Read", "identify", "profile");

        service.authorize("a@x.com", &[scope]).await.unwrap();
        assert_eq!(service.status("a@x.com"), TokenState::Active);
        assert_eq!(
            service
                .access_token("a@x.com")
                .await
                .unwrap()
                .access_token
                .expose(),
            "mock-access-1000"
        );
        service.revoke("a@x.com").await.unwrap();
        assert_eq!(service.status("a@x.com"), TokenState::Unauthorized);
    }

    /// The live run: save, load and delete one record in the real platform keystore
    /// (Windows Credential Manager on Windows). Ignored by default, because it writes
    /// to the user's keystore. Run it by hand with:
    /// `cargo test -p mmp-oauth --features keyring-store --lib live_platform -- --ignored --nocapture`.
    #[test]
    #[ignore = "writes to the real OS keystore; run by hand"]
    fn live_platform_keystore_round_trip() {
        let store = KeyringTokenStore::new("mmp-oauth-live-test");
        let k = key(ProviderKind::Microsoft, "live-test@example.com");
        let saved = tokens("live-refresh-token", "live-access-token");
        store
            .save(&k, &saved)
            .expect("save to the platform keystore");
        let loaded = store.load(&k).expect("load").expect("the record exists");
        assert!(
            same(&loaded, &saved),
            "the platform keystore returned a different record"
        );
        store.delete(&k).expect("delete");
        assert!(store.load(&k).expect("load after delete").is_none());
        println!("live keystore round trip: save, load, compare, delete, load-none all passed");
    }
}
