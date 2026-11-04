//! # mmp-secret
//!
//! [`Secret`] is a secret string whose `Debug` never prints its bytes and whose
//! heap memory is zeroed on drop. The crate depends only on `zeroize`, so any
//! crate that holds a credential (an OAuth refresh token, an app password) can use
//! this one type instead of writing its own.
//!
//! ## The limit of zeroize
//!
//! A token stays in memory for its whole lifetime, so [`Secret`] is
//! `ZeroizeOnDrop`: its bytes are overwritten when it drops. Zeroizing on drop is
//! defense in depth. It cannot clear a copy the program already made: a `String`
//! that reallocates before it is wrapped frees its old buffer unzeroed, and
//! [`Secret::expose`] lets a caller copy the value.
//!
//! ## No serde, on purpose
//!
//! `Secret` implements neither `Serialize` nor `Deserialize`. A serde
//! implementation would let any serde-aware logger or tracer write the plain text,
//! which defeats the redacting `Debug`. Code that must save a secret calls
//! [`Secret::expose`] at its one storage site. Do not add serde for convenience.
//!
//! ## Example
//!
//! ```
//! use mmp_secret::Secret;
//!
//! let token = Secret::new("ya29.example-access-token");
//! assert_eq!(format!("{token:?}"), "Secret(<redacted len=25>)");
//! assert_eq!(token.expose(), "ya29.example-access-token");
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A secret string that does not appear in logs or panic messages.
///
/// `Debug` prints only the length. There is no `Display`, so `{}` does not compile.
///
/// `Clone` copies the secret to a new heap `String`. Each copy zeroizes itself on
/// drop.
// Keep `Clone` a real copy, not a borrow: each instance must zeroize itself.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    /// Wrap a secret value.
    pub fn new(value: impl Into<String>) -> Self {
        Secret(value.into())
    }

    /// The plain text, for the code that needs it: an HTTP `Authorization: Bearer`
    /// header, a token-endpoint request body, or the one save call in a storage
    /// backend.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret(<redacted len={}>)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_leaks_the_bytes() {
        let s = Secret::new("ya29.super-secret-access-token");
        let shown = format!("{s:?}");
        assert!(!shown.contains("ya29"), "secret leaked into Debug");
        assert!(shown.contains("len=30"));
    }

    #[test]
    fn expose_returns_the_value_for_the_one_caller_that_needs_it() {
        let s = Secret::new("refresh-token-xyz");
        assert_eq!(s.expose(), "refresh-token-xyz");
    }

    #[test]
    fn clone_is_an_independent_zeroizing_instance() {
        // Each clone is its own heap String; both redact, and both zeroize on drop.
        let a = Secret::new("dup");
        let b = a.clone();
        assert_eq!(a.expose(), b.expose());
        assert!(
            format!("{b:?}").contains("len=3"),
            "clone keeps the redacting Debug"
        );
    }
}
