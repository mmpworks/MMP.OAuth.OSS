//! `MicrosoftProvider`: the Microsoft identity platform (v2.0) adapter.
//!
//! It issues tokens for any Microsoft Graph resource the host's scopes select
//! (mail, files, calendar). All scopes are delegated permissions: the app acts as
//! the signed-in user. Application permissions, which would act across a whole
//! organization, are out of scope.
//!
//! ## Microsoft's rules, and where they come from
//!
//! Each rule below is from Microsoft's documentation of the v2.0 authorization code
//! flow, the redirect URI rules, and the scope reference on learn.microsoft.com.
//!
//! 1. **Endpoints.** `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`
//!    and `.../token`. `{tenant}` is `common` (work, school and personal accounts),
//!    `organizations`, `consumers`, or one tenant id. The default here is `common`;
//!    [`MicrosoftProvider::with_tenant`] picks another.
//! 2. **No client secret.** A desktop app is a public client, and Microsoft states
//!    that public clients "must not use secrets or certificates when redeeming an
//!    authorization code". This adapter never sends one.
//! 3. **PKCE S256** on every authorization, which Microsoft recommends for all
//!    application types.
//! 4. **`offline_access`.** Microsoft returns a refresh token only when the request
//!    includes the `offline_access` scope. This adapter adds it when the host's
//!    scopes leave it out.
//! 5. **Rotation.** "Refresh tokens replace themselves with a fresh token upon every
//!    use." The service saves each new refresh token (see [`crate::RefreshedGrant`]).
//! 6. **Loopback redirect.** Microsoft ignores the port when it matches a
//!    `localhost` redirect URI (citing RFC 8252 sections 7.3 and 8.3), and asks apps
//!    to prefer the `127.0.0.1` literal over `localhost`. The app registers
//!    `http://127.0.0.1/callback` once, through the application manifest, because the
//!    portal's text box refuses an `http` loopback URI. The README's "Set up a
//!    Microsoft app" section shows the steps, and the fallback to `localhost`
//!    (`LoopbackReceiver::with_localhost_redirect`) if a tenant matches
//!    the port for `127.0.0.1`.
//! 7. **No revocation endpoint.** The v2.0 protocol documents no endpoint for a
//!    client to revoke a refresh token, so [`Provider::revoke`] clears nothing at
//!    Microsoft: the service deletes the local tokens, and the refresh token stays
//!    valid at Microsoft until it expires or the user removes the app's access.
//! 8. **Re-consent codes.** Besides `invalid_grant`, the token endpoint can answer
//!    `interaction_required` ("the request requires user interaction"),
//!    `consent_required` or `login_required`. All four mean the user must sign in
//!    again, so they map to [`OAuthError::InvalidGrant`].

use async_trait::async_trait;
use oauth2::basic::BasicErrorResponseType;

use super::oauth2_core::{classify_token_error, Core};
use crate::error::OAuthError;
use crate::flow::{AuthSession, PendingExchange};
use crate::provider::{Provider, ProviderKind, ProviderProfile, ScopeRequest};
use crate::token::{RefreshedGrant, TokenPair};
use crate::Secret;

/// The scope that makes Microsoft issue a refresh token.
const OFFLINE_ACCESS: &str = "offline_access";

/// Microsoft extension error codes that mean "sign in again". Each is a fixed
/// string, so it can travel in an error as an allowlisted label.
const RECONSENT_CODES: [&str; 3] = ["interaction_required", "consent_required", "login_required"];

/// The Microsoft Graph OAuth provider. The host's scopes pick the resource (mail,
/// files, calendar), always as delegated permissions.
pub struct MicrosoftProvider {
    core: Core,
}

impl MicrosoftProvider {
    /// Build the provider with the application (client) id from the app's Microsoft
    /// Entra ID registration, read from configuration. It uses the `common` tenant.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the TLS backend cannot start.
    pub fn new(client_id: impl Into<String>) -> Result<Self, OAuthError> {
        Ok(Self {
            core: Core::new(
                ProviderProfile::microsoft(client_id),
                classify_microsoft_error,
            )?,
        })
    }

    /// Use another `{tenant}` in the endpoint URLs: `organizations` (work and school
    /// accounts only), `consumers` (personal accounts only), or one tenant id (an app
    /// registered for a single tenant).
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when `tenant` is empty or holds a character other than
    /// an ASCII letter, a digit, `-` or `.`, or when it does not start with a letter or
    /// a digit. The value goes into a URL path, so the check keeps it to one path
    /// segment (`.` and `..` would collapse the path).
    pub fn with_tenant(mut self, tenant: &str) -> Result<Self, OAuthError> {
        let valid = tenant.starts_with(|c: char| c.is_ascii_alphanumeric())
            && tenant
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.');
        if !valid {
            return Err(OAuthError::Config(
                "tenant must be one URL path segment (letters, digits, '-', '.')".into(),
            ));
        }
        let profile = &mut self.core.profile;
        profile.auth_url =
            format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize");
        profile.token_url = format!("https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token");
        Ok(self)
    }

    /// Build from an explicit profile. The wiremock tests use it to point the
    /// endpoints at a local mock server.
    #[cfg(test)]
    pub(crate) fn from_profile(profile: ProviderProfile) -> Result<Self, OAuthError> {
        Ok(Self {
            core: Core::new(profile, classify_microsoft_error)?,
        })
    }

    /// Whether this provider would send a client secret. Always false; tests check it.
    #[cfg(test)]
    pub(crate) fn sends_client_secret(&self) -> bool {
        self.core.client_secret.is_some()
    }
}

/// The host's scopes, with `offline_access` added when they leave it out (rule 4 in
/// the module docs). The order of the host's scopes is kept.
fn with_offline_access(scopes: &[ScopeRequest]) -> Vec<String> {
    let mut requested: Vec<String> = scopes.iter().map(|s| s.scope.clone()).collect();
    // Microsoft scope names are case-insensitive, so `Offline_Access` counts.
    if !requested
        .iter()
        .any(|s| s.eq_ignore_ascii_case(OFFLINE_ACCESS))
    {
        requested.push(OFFLINE_ACCESS.to_string());
    }
    requested
}

/// The Microsoft classification of a token-endpoint error: the default rules, plus
/// the three re-consent extension codes (rule 8 in the module docs).
pub(crate) fn classify_microsoft_error(code: &BasicErrorResponseType) -> OAuthError {
    if let BasicErrorResponseType::Extension(raw) = code {
        if let Some(label) = RECONSENT_CODES
            .iter()
            .copied()
            .find(|known| *known == raw.as_str())
        {
            return OAuthError::InvalidGrant {
                reason: label.to_string(),
            };
        }
    }
    classify_token_error(code)
}

#[async_trait]
impl Provider for MicrosoftProvider {
    fn kind(&self) -> ProviderKind {
        ProviderKind::Microsoft
    }

    fn profile(&self) -> &ProviderProfile {
        &self.core.profile
    }

    fn begin_authorization(&self, scopes: &[ScopeRequest], redirect_uri: &str) -> AuthSession {
        self.core
            .begin(with_offline_access(scopes), redirect_uri, &[])
    }

    async fn exchange_code(&self, pending: PendingExchange) -> Result<TokenPair, OAuthError> {
        self.core
            .exchange(
                pending,
                "Microsoft returned no refresh token (the request needs the offline_access scope)",
            )
            .await
    }

    async fn refresh(&self, refresh_token: &Secret) -> Result<RefreshedGrant, OAuthError> {
        self.core.refresh(refresh_token).await
    }

    /// Microsoft documents no revocation endpoint for a client (rule 7 in the module
    /// docs). This returns `Ok` with no network call; the service then deletes the
    /// local tokens.
    async fn revoke(&self, _refresh_token: &Secret) -> Result<(), OAuthError> {
        Ok(())
    }
}
