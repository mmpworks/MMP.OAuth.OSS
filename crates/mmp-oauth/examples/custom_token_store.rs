//! A custom `TokenStore`: tokens saved as a JSON file.
//!
//! The example shows the storage seam. `StoredTokens` holds `Secret` values, and
//! `Secret` has no serde support on purpose, so a store copies each secret out with
//! `Secret::expose` at this one storage site. The JSON file here is plain text, for
//! the example only. A real store must encrypt the refresh token at rest (an OS
//! keystore, DPAPI, or an encrypted vault).
//!
//! Run it with `cargo run -p mmp-oauth --example custom_token_store`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Mutex;

use mmp_oauth::{AccountKey, OAuthError, ProviderKind, Secret, StoredTokens, TokenStore};
use serde_json::{json, Value};

/// A store that keeps every account in one JSON file, keyed by
/// `AccountKey::storage_ref()`.
struct JsonFileStore {
    path: PathBuf,
    // One lock around read-modify-write, so two saves cannot interleave.
    lock: Mutex<()>,
}

impl JsonFileStore {
    fn read_all(&self) -> Result<BTreeMap<String, Value>, OAuthError> {
        match std::fs::read_to_string(&self.path) {
            Ok(text) => serde_json::from_str(&text)
                .map_err(|_| OAuthError::Storage("token file is not valid JSON".into())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
            Err(e) => Err(OAuthError::Storage(format!("cannot read token file: {e}"))),
        }
    }

    fn write_all(&self, all: &BTreeMap<String, Value>) -> Result<(), OAuthError> {
        let text =
            serde_json::to_string_pretty(all).map_err(|e| OAuthError::Storage(e.to_string()))?;
        std::fs::write(&self.path, text)
            .map_err(|e| OAuthError::Storage(format!("cannot write token file: {e}")))
    }
}

/// The one place a secret leaves its `Secret` wrapper: the storage boundary.
fn to_json(tokens: &StoredTokens) -> Value {
    json!({
        "refresh_token": tokens.refresh_token.expose(),
        "access_token": tokens.access_token.as_ref().map(Secret::expose),
        "access_expires_at_unix": tokens.access_expires_at_unix,
        "granted_scopes": tokens.granted_scopes,
        "refresh_scopes": tokens.refresh_scopes,
    })
}

fn from_json(value: &Value) -> Option<StoredTokens> {
    let strings = |v: &Value| -> Option<Vec<String>> {
        v.as_array().map(|a| {
            a.iter()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        })
    };
    Some(StoredTokens {
        refresh_token: Secret::new(value["refresh_token"].as_str()?),
        access_token: value["access_token"].as_str().map(Secret::new),
        access_expires_at_unix: value["access_expires_at_unix"].as_i64(),
        granted_scopes: strings(&value["granted_scopes"]).unwrap_or_default(),
        refresh_scopes: strings(&value["refresh_scopes"]),
    })
}

impl TokenStore for JsonFileStore {
    fn load(&self, key: &AccountKey) -> Result<Option<StoredTokens>, OAuthError> {
        let _guard = self.lock.lock().unwrap();
        match self.read_all()?.get(&key.storage_ref()) {
            None => Ok(None),
            Some(value) => from_json(value)
                .map(Some)
                .ok_or_else(|| OAuthError::Storage("token record is malformed".into())),
        }
    }

    fn save(&self, key: &AccountKey, tokens: &StoredTokens) -> Result<(), OAuthError> {
        let _guard = self.lock.lock().unwrap();
        let mut all = self.read_all()?;
        all.insert(key.storage_ref(), to_json(tokens));
        self.write_all(&all)
    }

    fn delete(&self, key: &AccountKey) -> Result<(), OAuthError> {
        let _guard = self.lock.lock().unwrap();
        let mut all = self.read_all()?;
        all.remove(&key.storage_ref());
        self.write_all(&all)
    }
}

fn main() -> Result<(), OAuthError> {
    let path = std::env::temp_dir().join("mmp-oauth-example-tokens.json");
    let store = JsonFileStore {
        path: path.clone(),
        lock: Mutex::new(()),
    };
    let key = AccountKey::new(ProviderKind::Google, "user@example.com");

    let tokens = StoredTokens {
        refresh_token: Secret::new("example-refresh-token"),
        access_token: Some(Secret::new("example-access-token")),
        access_expires_at_unix: Some(1_800_003_600),
        granted_scopes: vec!["https://www.googleapis.com/auth/userinfo.email".into()],
        refresh_scopes: Some(vec!["https://www.googleapis.com/auth/userinfo.email".into()]),
    };
    store.save(&key, &tokens)?;
    println!("1. saved under {} in {}", key.storage_ref(), path.display());

    let loaded = store.load(&key)?.expect("the record was just saved");
    println!("2. loaded      : {:?}", loaded.refresh_token);
    assert_eq!(loaded.refresh_token.expose(), "example-refresh-token");

    store.delete(&key)?;
    println!(
        "3. deleted     : load now returns {:?}",
        store.load(&key)?.map(|_| "a record")
    );
    std::fs::remove_file(&path).ok();
    Ok(())
}
