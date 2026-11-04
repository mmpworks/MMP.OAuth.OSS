//! [`ProviderProfile`] is a provider's configuration as data (endpoints, client
//! id, quirks). [`ScopeRequest`] is a scope with the reason it was requested, so a
//! reviewer can see what was asked for and why.

use crate::provider::ProviderKind;

/// A scope request with its reason. Each scope records the feature that needs it
/// and why it is the narrowest scope that works. Google's OAuth verification asks
/// an app to justify every sensitive and restricted scope, and incremental
/// authorization asks for a scope only when its feature is first used. These
/// fields keep both facts next to the request in code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScopeRequest {
    /// The provider scope string. This crate never interprets it, so it can be any
    /// scope for any resource (for example `.../auth/gmail.readonly`,
    /// `.../auth/drive.readonly`, or Graph `Files.Read`).
    pub scope: String,
    /// The feature that needs the scope (for example `read-mailbox`, `read-drive`).
    pub capability: String,
    /// A plain-language reason this is the narrowest scope that works.
    pub justification: String,
    /// True when the scope is requested when its feature is first used, instead of
    /// at connect time.
    pub incremental: bool,
}

impl ScopeRequest {
    /// A scope requested at connect time (`incremental` is false).
    pub fn at_connect(
        scope: impl Into<String>,
        capability: impl Into<String>,
        justification: impl Into<String>,
    ) -> Self {
        Self {
            scope: scope.into(),
            capability: capability.into(),
            justification: justification.into(),
            incremental: false,
        }
    }
}

/// A provider's static configuration. The endpoint and quirk differences between
/// Google and Microsoft are data here, so one client code path serves both.
#[derive(Clone, Debug)]
pub struct ProviderProfile {
    /// Which provider this profile describes.
    pub kind: ProviderKind,
    /// The authorization endpoint.
    pub auth_url: String,
    /// The token endpoint.
    pub token_url: String,
    /// The revocation endpoint (RFC 7009), if the provider exposes one.
    pub revocation_url: Option<String>,
    /// The OAuth client id. A desktop app is a public client (RFC 8252 section
    /// 8.5), so the profile holds no secret. Google's "Desktop app" client type is
    /// the one exception; see `GoogleProvider::with_secret`.
    pub client_id: String,
    /// The loopback redirect host. Google requires the literal `127.0.0.1`, not
    /// `localhost`. The rule is data here, not a branch in code.
    pub loopback_host: String,
    /// Whether PKCE S256 is required. True for Google and Microsoft desktop clients.
    pub requires_pkce: bool,
}

impl ProviderProfile {
    /// The Google profile. It serves any Google resource (Gmail, Drive, Calendar);
    /// the host's scopes pick the resource.
    ///
    /// The loopback host is `127.0.0.1`, per Google's desktop-app guidance. The
    /// `client_id` comes from the application's configuration. One client id ships
    /// with the application, so users sign in with no setup of their own.
    pub fn google(client_id: impl Into<String>) -> Self {
        Self {
            kind: ProviderKind::Google,
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_url: "https://oauth2.googleapis.com/token".into(),
            revocation_url: Some("https://oauth2.googleapis.com/revoke".into()),
            client_id: client_id.into(),
            loopback_host: "127.0.0.1".into(),
            requires_pkce: true,
        }
    }

    /// The Microsoft Graph profile. It uses the v2 `common` endpoints, which accept
    /// personal and work or school accounts, and serves any Graph resource the
    /// host's scopes select (mail, files, calendar). It is a public native client
    /// with PKCE and no secret. The `client_id` comes from the application's
    /// configuration.
    pub fn microsoft(client_id: impl Into<String>) -> Self {
        Self {
            kind: ProviderKind::Microsoft,
            auth_url: "https://login.microsoftonline.com/common/oauth2/v2.0/authorize".into(),
            token_url: "https://login.microsoftonline.com/common/oauth2/v2.0/token".into(),
            revocation_url: None,
            client_id: client_id.into(),
            loopback_host: "127.0.0.1".into(),
            requires_pkce: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn google_profile_uses_127_not_localhost() {
        let p = ProviderProfile::google("cid");
        assert_eq!(
            p.loopback_host, "127.0.0.1",
            "Google rejects localhost; must be the IP literal"
        );
        assert!(p.requires_pkce);
    }

    #[test]
    fn scope_request_carries_provenance() {
        let s = ScopeRequest::at_connect(
            "https://www.googleapis.com/auth/gmail.readonly",
            "read-mailbox",
            "narrowest scope that lets the classifier read message bodies",
        );
        assert_eq!(s.capability, "read-mailbox");
        assert!(!s.incremental);
    }

    #[test]
    fn scope_request_is_resource_agnostic() {
        // A non-mail resource (Drive) passes through the same type with no change.
        // The library is not tied to one resource.
        let drive = ScopeRequest::at_connect(
            "https://www.googleapis.com/auth/drive.readonly",
            "read-drive",
            "read the documents the user picks",
        );
        assert_eq!(drive.capability, "read-drive");
        assert!(drive.scope.ends_with("drive.readonly"));
        assert!(!drive.incremental);
    }
}
