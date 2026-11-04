//! The retry hook: a trait the host implements to retry failed token calls, or to
//! stop calling a provider that keeps failing (a circuit breaker).
//!
//! The guard wraps the semantic operation (`refresh`, or a host's own call to
//! `exchange_code`), not the raw HTTP request. The error classifier has meaning
//! only at that level: `invalid_grant` is permanent (stop, ask for consent), and a
//! 429 or 5xx is retryable (retry with backoff; a 429 can name the wait in
//! [`OAuthError::Throttled`]). A guard around raw bytes cannot
//! tell them apart and would spend retries resending a dead refresh token.
//!
//! The crate ships no retry logic. It defines a trait that the host implements
//! with its own policy. The default, [`Passthrough`], runs the operation once, so
//! the crate works with no policy wired.

use async_trait::async_trait;

use crate::error::OAuthError;

/// Wraps an async token operation in the host's resilience policy. An
/// implementation decides retry or give-up with [`OAuthError::is_retryable`].
#[async_trait]
pub trait ResilienceGuard: Send + Sync {
    /// Run `op` under the host's retry, backoff and circuit-breaking policy, and
    /// return its final result. Each call of `op` makes one new attempt.
    async fn guard<'a>(
        &'a self,
        op: ResilientOp<'a>,
    ) -> Result<crate::token::RefreshedGrant, OAuthError>;
}

/// A token operation the guard can retry. Each call starts one new attempt.
pub type ResilientOp<'a> = &'a (dyn Fn() -> ResilientAttempt<'a> + Send + Sync + 'a);

/// One attempt of a [`ResilientOp`].
pub type ResilientAttempt<'a> = std::pin::Pin<
    Box<
        dyn std::future::Future<Output = Result<crate::token::RefreshedGrant, OAuthError>>
            + Send
            + 'a,
    >,
>;

/// The default policy: run the operation once. The crate works before a host wires
/// a policy, and tests use it.
#[derive(Default)]
pub struct Passthrough;

#[async_trait]
impl ResilienceGuard for Passthrough {
    async fn guard<'a>(
        &'a self,
        op: ResilientOp<'a>,
    ) -> Result<crate::token::RefreshedGrant, OAuthError> {
        op().await
    }
}
