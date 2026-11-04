//! [`Clock`]: injectable time, so expiry and refresh checks are deterministic
//! in tests. A host that already has a clock abstraction can wrap it in this
//! trait; the crate defines its own so it needs no extra dependency.

/// A source of the current time in Unix seconds. The refresh check reads this
/// trait, never `SystemTime::now()` directly.
pub trait Clock: Send + Sync {
    /// The current time, in seconds since the Unix epoch.
    fn now_unix(&self) -> i64;
}

/// The production clock, backed by the system wall clock.
#[derive(Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> i64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

/// A test clock. It returns a fixed time that `advance` moves forward, so "the
/// token expired" is one call instead of a `sleep`.
pub struct ManualClock {
    now: std::sync::atomic::AtomicI64,
}

impl ManualClock {
    /// Start the clock at `start_unix`.
    #[must_use]
    pub fn new(start_unix: i64) -> Self {
        Self {
            now: std::sync::atomic::AtomicI64::new(start_unix),
        }
    }

    /// Move the clock forward by `secs`.
    pub fn advance(&self, secs: i64) {
        self.now
            .fetch_add(secs, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_unix(&self) -> i64 {
        self.now.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_clock_advances_deterministically() {
        let c = ManualClock::new(1000);
        assert_eq!(c.now_unix(), 1000);
        c.advance(3601);
        assert_eq!(c.now_unix(), 4601);
    }
}
