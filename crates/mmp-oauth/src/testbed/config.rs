//! Testbed app configs: the `keys/*.ini` files the web UI picks from.
//!
//! Each `.ini` is one OAuth app to test: a label, a provider, the client id, an
//! optional client secret, and the scopes. The format is a small `key=value`
//! dialect (one pair per line, trimmed, blank lines and `;` or `#` comments
//! skipped). It is not a full INI crate: the schema has five keys, and a short
//! parser keeps the dependency list, and the code to review, small.
//!
//! The module needs no feature flag. It is string and filesystem work only, so its
//! tests run in the default `cargo test`. The server that reads these configs sits
//! behind the production feature flags.
//!
//! ## Minimal files
//!
//! A file with only `client-id` and `client-secret` loads.
//! [`AppConfig::parse`] gives every other field a default: `name` falls back to
//! the file stem, `provider` to Google, and `scopes` to the email scope.
//!
//! ## Extension
//!
//! `provider` is a lowercase string mapped to [`ProviderKind`], and the parser
//! ignores unknown keys instead of failing. A new provider or a new field can be
//! added without breaking an existing file.

use std::fs;
use std::path::{Path, PathBuf};

use crate::error::OAuthError;
use crate::provider::ProviderKind;
use crate::Secret;

/// The default Google scope when a config omits `scopes`: the email scope. See the
/// `GoogleProvider` docs for why it needs no Google app verification.
const DEFAULT_GOOGLE_SCOPE: &str = "https://www.googleapis.com/auth/userinfo.email";

/// The default Microsoft scope when a config omits `scopes`: Graph `User.Read`
/// (sign in and read the user's profile). Microsoft adds it to every new app
/// registration, and `MicrosoftProvider` adds `offline_access` itself.
const DEFAULT_MICROSOFT_SCOPE: &str = "User.Read";

/// The scope a smoke test requests for `provider` when the config or the CLI names
/// none. The testbed config and the testbed CLI both use it.
#[must_use]
pub fn default_scope(provider: ProviderKind) -> &'static str {
    match provider {
        ProviderKind::Google => DEFAULT_GOOGLE_SCOPE,
        ProviderKind::Microsoft => DEFAULT_MICROSOFT_SCOPE,
    }
}

/// How many leading client-id characters the masked form keeps before the ellipsis.
const MASK_PREFIX_LEN: usize = 12;
/// How many trailing client-id characters the masked form keeps after the ellipsis.
const MASK_SUFFIX_LEN: usize = 8;

/// One testbed OAuth app, parsed from a `keys/<slug>.ini`.
///
/// The `client_secret` is a [`Secret`]. Its `Debug` is redacted, and it has no
/// serde implementation, so it cannot reach a log or an API response by accident.
/// It reaches the wire only through the [`Secret::expose`] call in the token
/// exchange.
///
/// The derived `Debug` is safe: the only sensitive field is `client_secret`, whose
/// own `Debug` redacts its bytes.
#[derive(Debug)]
pub struct AppConfig {
    /// The slug: the file stem (`my-app` for `my-app.ini`). A stable id.
    pub slug: String,
    /// The label shown in the picker. Defaults to the slug when the file omits `name`.
    pub name: String,
    /// The provider whose endpoints the run uses.
    pub provider: ProviderKind,
    /// The OAuth client id. A desktop client id is not secret, but the UI shows only
    /// a masked form.
    pub client_id: String,
    /// The optional client secret. See `GoogleProvider::with_secret` for when
    /// Google needs one. `None` when the file has none.
    pub client_secret: Option<Secret>,
    /// The requested scopes. Defaults to the email scope when the file omits them.
    pub scopes: Vec<String>,
}

impl AppConfig {
    /// Parse an app config from raw `.ini` text and its slug (the file stem).
    ///
    /// Unknown keys are ignored and every later field has a default, so an older
    /// two-key file (`client-id` and `client-secret`) parses.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when `client-id` is missing or empty. Without it there
    /// is no app to test.
    pub fn parse(slug: &str, text: &str) -> Result<Self, OAuthError> {
        let mut name = None;
        let mut provider_raw = None;
        let mut client_id = None;
        let mut client_secret = None;
        let mut scopes_raw = None;

        for (key, value) in parse_pairs(text) {
            match key.as_str() {
                "name" => name = non_empty(&value),
                "provider" => provider_raw = non_empty(&value),
                "client-id" => client_id = non_empty(&value),
                "client-secret" => client_secret = non_empty(&value),
                "scopes" => scopes_raw = non_empty(&value),
                _ => {} // Ignore unknown keys, so a file with a newer field still loads.
            }
        }

        let client_id = client_id.ok_or_else(|| {
            OAuthError::Config(format!("config `{slug}` is missing a non-empty client-id"))
        })?;
        let provider = parse_provider(provider_raw.as_deref());

        Ok(Self {
            slug: slug.to_string(),
            name: name.unwrap_or_else(|| slug.to_string()),
            provider,
            client_id,
            client_secret: client_secret.map(Secret::new),
            scopes: parse_scope_list(scopes_raw.as_deref(), provider),
        })
    }

    /// Serialize back to `.ini` text. The secret is written as plain text, because
    /// the file is the secret store (local and gitignored). This is the one place the
    /// plain text is meant to reach the disk.
    #[must_use]
    pub fn to_ini(&self) -> String {
        let secret_line = match &self.client_secret {
            Some(s) => format!("client-secret={}\n", s.expose()),
            None => String::new(),
        };
        format!(
            "name={}\n\
             provider={}\n\
             client-id={}\n\
             {}\
             scopes={}\n",
            self.name,
            provider_token(self.provider),
            self.client_id,
            secret_line,
            self.scopes.join(","),
        )
    }

    /// The client id with its middle masked, for the browser. A GET never sends the
    /// full id to the UI; only this form.
    ///
    /// An id shorter than the prefix and suffix together is fully masked, so a short
    /// id never reaches the page.
    #[must_use]
    pub fn masked_client_id(&self) -> String {
        mask_client_id(&self.client_id)
    }
}

/// Mask a client id: keep the first [`MASK_PREFIX_LEN`] and the last
/// [`MASK_SUFFIX_LEN`] characters and replace the middle with an ellipsis. An id too
/// short to split is fully masked (all `•`), never echoed.
fn mask_client_id(id: &str) -> String {
    let chars: Vec<char> = id.chars().collect();
    if chars.len() <= MASK_PREFIX_LEN + MASK_SUFFIX_LEN {
        return "•".repeat(chars.len());
    }
    let prefix: String = chars[..MASK_PREFIX_LEN].iter().collect();
    let suffix: String = chars[chars.len() - MASK_SUFFIX_LEN..].iter().collect();
    format!("{prefix}…{suffix}")
}

/// List every app under `keys_dir`, sorted by slug. A missing directory gives an
/// empty list (no apps yet), not an error. A file that fails to parse is skipped,
/// so one broken config does not hide the others from the picker.
///
/// # Errors
///
/// [`OAuthError::Config`] when the directory exists but cannot be read.
pub fn list_apps(keys_dir: &Path) -> Result<Vec<AppConfig>, OAuthError> {
    let entries = match fs::read_dir(keys_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(OAuthError::Config(format!("could not read keys dir: {e}"))),
    };

    let mut apps: Vec<AppConfig> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "ini"))
        .filter_map(|p| load_app(&p).ok())
        .collect();

    apps.sort_by(|a, b| a.slug.cmp(&b.slug));
    Ok(apps)
}

/// Load one app config from a `.ini` path. The slug is the file stem.
///
/// # Errors
///
/// [`OAuthError::Config`] when the file cannot be read or has no `client-id`.
pub fn load_app(path: &Path) -> Result<AppConfig, OAuthError> {
    let slug = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or_else(|| OAuthError::Config("config path has no file stem".into()))?;
    let text = fs::read_to_string(path)
        .map_err(|e| OAuthError::Config(format!("could not read config `{slug}`: {e}")))?;
    AppConfig::parse(slug, &text)
}

/// Write `app` to `keys_dir/<slug>.ini`, where the slug comes from the name, and
/// return the path written. Creates `keys_dir` if it does not exist.
///
/// # Errors
///
/// [`OAuthError::Config`] when the directory or the file cannot be written.
pub fn save_app(keys_dir: &Path, app: &AppConfig) -> Result<PathBuf, OAuthError> {
    fs::create_dir_all(keys_dir)
        .map_err(|e| OAuthError::Config(format!("could not create keys dir: {e}")))?;
    let path = keys_dir.join(format!("{}.ini", app.slug));
    fs::write(&path, app.to_ini())
        .map_err(|e| OAuthError::Config(format!("could not write config `{}`: {e}", app.slug)))?;
    Ok(path)
}

/// Turn a name into a filesystem-safe slug: lowercase, each run of non-alphanumeric
/// characters becomes one `-`, and leading and trailing `-` are trimmed.
/// `"Team's App"` becomes `"team-s-app"`. An empty result becomes `"app"`, so the
/// code never writes a file named `.ini`.
#[must_use]
pub fn slugify(name: &str) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut last_was_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            slug.push('-');
            last_was_dash = true;
        }
    }
    let trimmed = slug.trim_matches('-');
    if trimmed.is_empty() {
        "app".to_string()
    } else {
        trimmed.to_string()
    }
}

/// Iterate the `key=value` pairs in `.ini` text. Blank lines and `;` or `#` comment
/// lines are skipped. The key is lowercased and trimmed, and the value is trimmed. A
/// line with no `=` is skipped, not an error, because the file is hand-edited.
///
/// A trailing inline `; comment` is stripped from the value, so annotated lines in
/// the example file (`provider=google ; default`) parse to the bare value.
fn parse_pairs(text: &str) -> impl Iterator<Item = (String, String)> + '_ {
    text.lines().filter_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            return None;
        }
        let (key, value) = line.split_once('=')?;
        let value = strip_inline_comment(value);
        Some((key.trim().to_ascii_lowercase(), value.trim().to_string()))
    })
}

/// Strip a trailing `; ...` or `# ...` inline comment from a value. Only a marker
/// after whitespace counts as a comment. A `#` or `;` with no space before it is part
/// of the value, so a secret that contains one stays whole.
fn strip_inline_comment(value: &str) -> &str {
    let mut prev_ws = false;
    for (idx, ch) in value.char_indices() {
        if (ch == ';' || ch == '#') && prev_ws {
            return &value[..idx];
        }
        prev_ws = ch.is_whitespace();
    }
    value
}

/// Map a provider name (`google`, `microsoft`) to a [`ProviderKind`]. An unknown
/// value maps to Google instead of failing, so a typo in a hand-edited file still
/// loads.
fn parse_provider(raw: Option<&str>) -> ProviderKind {
    raw.and_then(provider_from_name)
        .unwrap_or(ProviderKind::Google)
}

/// The [`ProviderKind`] for a provider name (`google`, `microsoft`, any case), or
/// `None` for an unknown name. The CLI uses it to reject a typo in `--provider`.
#[must_use]
pub fn provider_from_name(raw: &str) -> Option<ProviderKind> {
    match raw.to_ascii_lowercase().as_str() {
        "google" => Some(ProviderKind::Google),
        "microsoft" => Some(ProviderKind::Microsoft),
        _ => None,
    }
}

/// The `.ini` name for a [`ProviderKind`], the inverse of [`parse_provider`].
fn provider_token(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::Google => "google",
        ProviderKind::Microsoft => "microsoft",
    }
}

/// Split a `scopes` value on commas or whitespace. An absent or empty value gives
/// [`default_scope`] for `provider`. The testbed config and the testbed CLI both
/// call it.
pub fn parse_scope_list(raw: Option<&str>, provider: ProviderKind) -> Vec<String> {
    let scopes: Vec<String> = raw
        .unwrap_or_default()
        .split([',', ' ', '\t'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if scopes.is_empty() {
        vec![default_scope(provider).to_string()]
    } else {
        scopes
    }
}

/// Treat a blank or whitespace-only string as absent.
fn non_empty(v: &str) -> Option<String> {
    let v = v.trim();
    if v.is_empty() {
        None
    } else {
        Some(v.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_full_extended_schema() {
        let ini = "name=Team's App\n\
                   provider=google\n\
                   client-id=abc123.apps.googleusercontent.com\n\
                   client-secret=GOCSPX-topsecret\n\
                   scopes=https://www.googleapis.com/auth/userinfo.email, https://mail.google.com/\n";
        let cfg = AppConfig::parse("team-app", ini).expect("full schema must parse");

        assert_eq!(cfg.name, "Team's App");
        assert_eq!(cfg.provider, ProviderKind::Google);
        assert_eq!(cfg.client_id, "abc123.apps.googleusercontent.com");
        assert_eq!(
            cfg.client_secret.as_ref().map(Secret::expose),
            Some("GOCSPX-topsecret")
        );
        assert_eq!(cfg.scopes.len(), 2, "comma-separated scopes split");
    }

    #[test]
    fn legacy_two_key_file_loads_with_defaults() {
        // The oldest config shape: only client-id and client-secret. Every later
        // field must have a default, so an existing file keeps working.
        let ini = "client-id=123456789012-abcde.apps.googleusercontent.com\n\
                   client-secret=GOCSPX-legacy\n";
        let cfg = AppConfig::parse("team-app", ini).expect("a 2-key file must parse");

        assert_eq!(cfg.name, "team-app", "name defaults to the slug");
        assert_eq!(
            cfg.provider,
            ProviderKind::Google,
            "provider defaults to google"
        );
        assert_eq!(
            cfg.scopes,
            vec![DEFAULT_GOOGLE_SCOPE],
            "scopes default to the email scope"
        );
        assert!(
            cfg.client_secret.is_some(),
            "the legacy secret is preserved"
        );
    }

    #[test]
    fn a_secretless_public_client_parses_with_no_secret() {
        let ini = "name=Public App\nclient-id=public-client-id\n";
        let cfg = AppConfig::parse("public", ini).unwrap();
        assert!(cfg.client_secret.is_none(), "a public client has no secret");
    }

    #[test]
    fn a_missing_client_id_is_a_clear_config_error() {
        let err = AppConfig::parse("broken", "name=No Id\n").unwrap_err();
        match err {
            OAuthError::Config(msg) => {
                assert!(msg.contains("client-id"), "error must name client-id");
            }
            other => panic!("expected a Config error, got {other:?}"),
        }
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let ini = "; this is a comment\n\
                   # so is this\n\
                   \n\
                   client-id=with-comments\n\
                   provider=google ; inline comment stripped\n";
        let cfg = AppConfig::parse("c", ini).unwrap();
        assert_eq!(cfg.client_id, "with-comments");
        assert_eq!(cfg.provider, ProviderKind::Google);
    }

    #[test]
    fn microsoft_provider_round_trips_through_the_token() {
        let ini = "client-id=ms-id\nprovider=microsoft\n";
        let cfg = AppConfig::parse("ms", ini).unwrap();
        assert_eq!(cfg.provider, ProviderKind::Microsoft);
        assert!(cfg.to_ini().contains("provider=microsoft"));
    }

    #[test]
    fn an_unknown_provider_degrades_to_google() {
        let cfg = AppConfig::parse("x", "client-id=id\nprovider=dropbox\n").unwrap();
        assert_eq!(
            cfg.provider,
            ProviderKind::Google,
            "unknown provider must not error"
        );
    }

    #[test]
    fn ini_round_trips_through_parse_and_serialize() {
        let original = "name=Round Trip\n\
                        provider=google\n\
                        client-id=rt-client-id\n\
                        client-secret=rt-secret\n\
                        scopes=scope.a,scope.b\n";
        let parsed = AppConfig::parse("round-trip", original).unwrap();
        let reserialized = parsed.to_ini();
        let reparsed = AppConfig::parse("round-trip", &reserialized).unwrap();

        assert_eq!(reparsed.name, "Round Trip");
        assert_eq!(reparsed.client_id, "rt-client-id");
        assert_eq!(reparsed.scopes, vec!["scope.a", "scope.b"]);
        assert_eq!(
            reparsed.client_secret.as_ref().map(Secret::expose),
            Some("rt-secret")
        );
    }

    #[test]
    fn slugify_turns_a_name_into_a_filesystem_safe_stem() {
        assert_eq!(slugify("Team's App"), "team-s-app");
        assert_eq!(slugify("My  App  2"), "my-app-2");
        assert_eq!(slugify("  Trim Me  "), "trim-me");
        assert_eq!(slugify("Café — Notes"), "caf-notes");
        assert_eq!(
            slugify("!!!"),
            "app",
            "an all-symbol name falls back to 'app'"
        );
    }

    #[test]
    fn masking_keeps_only_the_ends_of_a_real_client_id() {
        let id = "123456789012-abcdefghijklmnopqrstuvwxyz012345.apps.googleusercontent.com";
        let masked = mask_client_id(id);
        assert!(masked.starts_with("123456789012"), "first 12 chars kept");
        assert!(masked.ends_with("tent.com"), "last 8 chars kept");
        assert!(masked.contains('…'), "the middle is elided");
        assert!(
            !masked.contains("abcdefghijklmnopqrstuvwxyz012345"),
            "the unique middle never appears"
        );
    }

    #[test]
    fn masking_a_short_id_hides_it_entirely() {
        // Too short to split, so fully masked: no bytes reach the UI.
        let masked = mask_client_id("short-id");
        assert!(
            masked.chars().all(|c| c == '•'),
            "a short id is fully masked: {masked}"
        );
        assert_eq!(masked.chars().count(), "short-id".chars().count());
    }

    #[test]
    fn a_secret_containing_a_hash_is_not_truncated_as_a_comment() {
        // A `#` with no leading whitespace is part of the value, not a comment.
        let cfg = AppConfig::parse("h", "client-id=id\nclient-secret=GOCSPX-a#b#c\n").unwrap();
        assert_eq!(
            cfg.client_secret.as_ref().map(Secret::expose),
            Some("GOCSPX-a#b#c")
        );
    }

    #[test]
    fn round_trip_through_the_filesystem() {
        let dir = std::env::temp_dir().join(format!("mmp-oauth-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let app = AppConfig {
            slug: slugify("Test Save"),
            name: "Test Save".into(),
            provider: ProviderKind::Google,
            client_id: "saved-client-id".into(),
            client_secret: Some(Secret::new("saved-secret")),
            scopes: vec![DEFAULT_GOOGLE_SCOPE.into()],
        };
        let path = save_app(&dir, &app).expect("save must succeed");
        assert!(path.ends_with("test-save.ini"), "slug becomes the filename");

        let loaded = load_app(&path).expect("load must succeed");
        assert_eq!(loaded.name, "Test Save");
        assert_eq!(loaded.client_id, "saved-client-id");

        let listed = list_apps(&dir).expect("list must succeed");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].slug, "test-save");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn listing_a_missing_dir_is_empty_not_an_error() {
        let missing = std::env::temp_dir().join("mmp-oauth-definitely-not-here-xyz");
        let apps = list_apps(&missing).expect("a missing keys dir is just no apps");
        assert!(apps.is_empty());
    }
}
