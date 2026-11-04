//! The production [`HttpTransport`] over `reqwest` (feature `reqwest-transport`).
//!
//! One `reqwest::Client` with `redirect::Policy::none()`. The `oauth2` docs name
//! this as an SSRF guard: a token or revocation request must never follow a
//! redirect to a host an attacker chose. The provider adapters send their form
//! bodies through this one edge.

use async_trait::async_trait;

use crate::error::OAuthError;
use crate::flow::transport::{HttpResponse, HttpTransport};

/// A reqwest-backed HTTP edge for the token and revocation endpoints.
pub struct ReqwestTransport {
    client: reqwest::Client,
}

impl ReqwestTransport {
    /// Build the transport with redirects turned off.
    ///
    /// # Errors
    ///
    /// [`OAuthError::Config`] when the TLS backend cannot start.
    pub fn new() -> Result<Self, OAuthError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| OAuthError::Config(format!("could not build HTTP client: {e}")))?;
        Ok(Self { client })
    }
}

#[async_trait]
impl HttpTransport for ReqwestTransport {
    async fn post_form(
        &self,
        url: &str,
        form: &[(&str, &str)],
    ) -> Result<HttpResponse, OAuthError> {
        let response = self
            .client
            .post(url)
            .form(form)
            .send()
            .await
            .map_err(classify_reqwest_error)?;

        let status = response.status().as_u16();
        let body = response
            .bytes()
            .await
            .map_err(|e| OAuthError::Transient(format!("reading token response body failed: {e}")))?
            .to_vec();

        Ok(HttpResponse { status, body })
    }
}

/// Map a reqwest send failure to [`OAuthError::Transient`]. A connection reset or a
/// timeout is worth a retry. The cause stays in the error.
#[allow(clippy::needless_pass_by_value)] // `map_err` hands the error over by value.
fn classify_reqwest_error(e: reqwest::Error) -> OAuthError {
    if e.is_timeout() || e.is_connect() {
        OAuthError::Transient(format!("transport failure: {e}"))
    } else {
        OAuthError::Transient(format!("request failed: {e}"))
    }
}
