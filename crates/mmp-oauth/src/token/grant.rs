//! The token value types the service and the providers return: [`AccessGrant`],
//! [`TokenPair`], and [`RefreshedGrant`].

use crate::Secret;

/// A live access grant: the bearer token, its expiry, and the granted scopes.
///
/// It is an immutable value. A refresh produces a new grant and never changes an
/// existing one, so a grant a caller holds stays consistent.
#[derive(Clone, Debug)]
pub struct AccessGrant {
    /// The bearer token for the `Authorization` header. `Debug` redacts it.
    pub access_token: Secret,
    /// The expiry, in seconds since the Unix epoch. The refresh check compares it
    /// with the injected clock, never with `SystemTime::now()`, so tests control
    /// expiry.
    pub expires_at_unix: i64,
    /// The scopes the provider granted. A provider can grant fewer scopes than were
    /// requested, so this is the record of what access is live.
    pub granted_scopes: Vec<String>,
}

impl AccessGrant {
    /// True when `now_unix` is at or past `expires_at_unix - skew_secs`. The skew
    /// makes the caller refresh before the provider's deadline, not on it.
    #[must_use]
    pub fn is_expired_at(&self, now_unix: i64, skew_secs: i64) -> bool {
        is_due(now_unix, self.expires_at_unix, skew_secs)
    }
}

/// True when a token that expires at `expires_at_unix` is due for refresh at
/// `now_unix`, that is, at or past `expires_at_unix - skew_secs`. This is the one
/// statement of the expiry rule; [`AccessGrant::is_expired_at`] and the service's
/// token cache both call it.
///
/// The subtraction saturates. The expiry can come from a token store, which a host
/// supplies, so it can hold any `i64`, and so can the skew. With plain subtraction,
/// an expiry near `i64::MIN` panics in a debug build and wraps to a far-future time
/// in a release build, which would serve an expired token as valid. Saturating
/// keeps an ancient expiry ancient.
pub(crate) fn is_due(now_unix: i64, expires_at_unix: i64, skew_secs: i64) -> bool {
    now_unix >= expires_at_unix.saturating_sub(skew_secs)
}

/// The result of a code exchange: the live grant and the long-lived refresh token
/// to save. Only `exchange_code` returns it. A refresh returns a
/// [`RefreshedGrant`] instead, because a refresh response may or may not carry a
/// new refresh token. Two return types keep the "what to save" choice explicit
/// at each call site, instead of an `Option` inside one shared type.
#[derive(Clone, Debug)]
pub struct TokenPair {
    /// The live access grant: bearer token, expiry, and granted scopes.
    pub grant: AccessGrant,
    /// The refresh token to save. It is the one long-lived credential.
    pub refresh_token: Secret,
}

/// The result of a refresh: the new live grant, and the refresh token the response
/// carried, if any. A provider that rotates refresh tokens issues a new one on each
/// refresh and invalidates the one it received, so the service saves
/// `refresh_token` when it is `Some`. When it is `None` (Google does not rotate) or
/// an empty string, the service keeps the stored refresh token.
#[derive(Clone, Debug)]
pub struct RefreshedGrant {
    /// The live access grant: bearer token, expiry, and granted scopes.
    pub grant: AccessGrant,
    /// The refresh token from the token response, when the response carried one.
    pub refresh_token: Option<Secret>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(expires_at: i64) -> AccessGrant {
        AccessGrant {
            access_token: Secret::new("at"),
            expires_at_unix: expires_at,
            granted_scopes: vec!["gmail.readonly".into()],
        }
    }

    #[test]
    fn fresh_token_is_not_expired() {
        assert!(!grant(1000).is_expired_at(500, 60));
    }

    #[test]
    fn token_is_expired_within_the_skew_window() {
        // expiry at 1000, skew 60 → treat as expired from 940 onward.
        assert!(grant(1000).is_expired_at(940, 60));
        assert!(!grant(1000).is_expired_at(939, 60));
    }

    /// S9 class: the subtraction must saturate. An expiry at `i64::MIN`, or a skew at
    /// `i64::MIN`, must give an answer instead of overflowing.
    #[test]
    fn extreme_expiry_or_skew_does_not_overflow() {
        assert!(
            grant(i64::MIN).is_expired_at(0, 60),
            "an expiry at i64::MIN is expired"
        );
        assert!(
            !grant(1000).is_expired_at(0, i64::MIN),
            "a skew at i64::MIN never expires a token early"
        );
    }

    /// `is_due` against wide `i128` arithmetic over the extremes of all three
    /// inputs. The two agree everywhere except one safe-direction point: when the
    /// wide bound is above `i64::MAX`, saturation puts it at `i64::MAX`, so
    /// `now == i64::MAX` reads as due. Saturation never reads a due token as valid.
    #[test]
    fn is_due_matches_exact_arithmetic_except_in_the_safe_direction() {
        let edges = [
            i64::MIN,
            i64::MIN + 1,
            -60,
            -1,
            0,
            1,
            60,
            i64::MAX - 1,
            i64::MAX,
        ];
        for &now in &edges {
            for &exp in &edges {
                for &skew in &edges {
                    let bound = i128::from(exp) - i128::from(skew);
                    let wide = i128::from(now) >= bound;
                    let got = is_due(now, exp, skew);
                    let safe_point = !wide && now == i64::MAX && bound > i128::from(i64::MAX);
                    assert!(
                        got == wide || safe_point,
                        "now={now} exp={exp} skew={skew}: got {got}, wide {wide}"
                    );
                }
            }
        }
    }
}
