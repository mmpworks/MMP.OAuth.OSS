//! `mmp-quota`: a sliding-window request-budget calculator.
//!
//! It does one job. Given a request `limit` per `window`, it tracks how many
//! requests were spent in the trailing `window` and answers the caller's question:
//! how many more requests may I make now? ([`QuotaBudget::available`]).
//!
//! A token-bucket limiter (a bucket that refills at a fixed rate) paces requests
//! per second. It cannot see the total spent over a rolling window. Back-to-back
//! bursts, or back-to-back program runs, can then add up past a provider's
//! per-window quota. This calculator models the budget itself. For example, Gmail
//! allows a fixed number of queries per minute per user; `available(now)` returns
//! how many are left in the current minute, and the number grows as old requests
//! leave the window.
//!
//! ## Design
//!
//! - Pure arithmetic over `(state, now_ms)`, with no dependencies. The caller
//!   supplies the time in milliseconds and owns any sleeping, fetching, or
//!   blocking, so any rate-limited client can use it.
//! - Every method is a pure function of `(state, now_ms)`. There is no hidden clock,
//!   so tests use synthetic times instead of sleeps.
//! - All arithmetic saturates, and the crate has `#![forbid(unsafe_code)]`.
//! ```
//! use std::time::Duration;
//! use mmp_quota::QuotaBudget;
//!
//! // 15,000 queries per rolling minute.
//! let mut budget = QuotaBudget::new(15_000, Duration::from_secs(60));
//! let t0 = 1_000_000; // any millisecond time value the caller supplies
//!
//! assert_eq!(budget.available(t0), 15_000);     // a new budget: all of it is free
//! budget.record(t0, 4_322);                     // spend 4,322 requests now
//! assert_eq!(budget.available(t0), 10_678);     // 10,678 are left
//! assert!(budget.allows(t0, 10_000));           // a 10k batch fits
//! assert!(!budget.allows(t0, 11_000));          // an 11k batch does not
//!
//! // One minute and one millisecond later, that spend has left the window.
//! assert_eq!(budget.available(t0 + 60_001), 15_000);
//! ```
#![forbid(unsafe_code)]

use std::collections::VecDeque;
use std::time::Duration;

/// A sliding-window request-budget calculator. All of the sliding-count arithmetic
/// lives in this type. See the [crate docs](crate) for the design.
#[derive(Debug, Clone)]
pub struct QuotaBudget {
    /// The maximum number of requests allowed in any trailing interval of `window`.
    limit: u32,
    /// The width of the rolling window, in milliseconds.
    window_ms: u64,
    /// Each recorded spend, oldest at the front. Spends leave the front as the window
    /// moves forward. `spent` is kept as a running sum, so
    /// [`available`](Self::available) is O(1) after the front is pruned.
    events: VecDeque<Spend>,
    /// The running count of requests still inside the window (the sum of `events`).
    /// It is a `u64` although each count is a `u32`. The sum of several counts can pass
    /// `u32::MAX`, and a `u32` sum that saturated on add would then subtract the true
    /// count on prune and under-count, which would grant more than the quota.
    spent: u64,
}

/// One recorded spend: `count` requests made at `at_ms`.
#[derive(Debug, Clone)]
struct Spend {
    at_ms: u64,
    count: u32,
}

impl QuotaBudget {
    /// Build a budget of `limit` requests per `window`. A zero limit or a zero window
    /// is allowed: with a zero limit nothing is ever available, and with a zero window
    /// every spend leaves at once. The arithmetic stays defined in both cases.
    #[must_use]
    pub fn new(limit: u32, window: Duration) -> Self {
        // A window longer than u64::MAX milliseconds saturates. A truncating cast
        // would wrap it to a short window, and spends would leave it early.
        Self {
            limit,
            window_ms: u64::try_from(window.as_millis()).unwrap_or(u64::MAX),
            events: VecDeque::new(),
            spent: 0,
        }
    }

    /// Record that `n` requests were made at `now_ms`. The window moves to `now_ms`
    /// first, so a record after a long idle period drops old spends before it adds the
    /// new one.
    pub fn record(&mut self, now_ms: u64, n: u32) {
        self.prune(now_ms);
        if n == 0 {
            return;
        }
        // Keep `events` in time order, oldest first: `prune` stops at the first spend
        // still in the window, and `retry_after` walks from the oldest. A record with
        // an earlier time than the last one (a clock step back, or merged sources)
        // goes into its place instead of the back. The usual in-order record lands at
        // the back, so the search costs O(log n) and the insert O(1).
        let position = self.events.partition_point(|s| s.at_ms <= now_ms);
        self.events.insert(
            position,
            Spend {
                at_ms: now_ms,
                count: n,
            },
        );
        self.spent = self.spent.saturating_add(u64::from(n));
    }

    /// How many requests were spent in the window that ends at `now_ms`.
    /// The result saturates at `u32::MAX`.
    pub fn spent(&mut self, now_ms: u64) -> u32 {
        self.prune(now_ms);
        self.spent_u32()
    }

    /// The running sum as a `u32`, saturated. `spent`, `available` and `allows` read
    /// it, so a sum past `u32::MAX` reads as "over the limit".
    fn spent_u32(&self) -> u32 {
        u32::try_from(self.spent).unwrap_or(u32::MAX)
    }

    /// How many more requests may be made now without passing the limit. This is the
    /// main query. Returns `limit - spent`, with a floor of zero.
    pub fn available(&mut self, now_ms: u64) -> u32 {
        self.limit.saturating_sub(self.spent(now_ms))
    }

    /// Whether a batch of `n` requests fits in the budget that is available now.
    pub fn allows(&mut self, now_ms: u64, n: u32) -> bool {
        self.available(now_ms) >= n
    }

    /// How long to wait until `n` requests fit. `Duration::ZERO` when they fit now. The
    /// wait lasts until enough of the oldest spends in the window leave it to cover the
    /// shortfall.
    ///
    /// For `n` up to `limit`, the batch fits once the returned wait has passed, if the
    /// caller records nothing in between. The wait also covers an overshoot, when
    /// earlier `record` calls went past the limit. When the batch cannot fit before
    /// the time value reaches `u64::MAX` milliseconds, the wait is `Duration::MAX`.
    /// Adding that to an `Instant` panics, so a caller that sleeps on the result caps
    /// it or uses `Instant::checked_add`.
    ///
    /// When `n` is greater than `limit`, no window can ever hold the batch. The method
    /// then returns the full `window` (the most that waiting can free), and the caller
    /// must split the batch. That full window is a lower bound, not a promise.
    pub fn retry_after(&mut self, now_ms: u64, n: u32) -> Duration {
        self.prune(now_ms);
        // The requests that must leave the window before `n` more fit. It is
        // `spent + n - limit`, in u64 so an overspent window (`record` never refuses)
        // counts its overshoot too.
        if n == 0 {
            return Duration::ZERO; // an empty batch always fits.
        }
        let shortfall = self
            .spent
            .saturating_add(u64::from(n))
            .saturating_sub(u64::from(self.limit));
        if shortfall == 0 {
            return Duration::ZERO; // it already fits.
        }
        // Walk from the oldest spend to the newest and add up the requests each one
        // frees when it leaves. The spend that covers the shortfall frees the last slot
        // needed. `prune` frees a spend only once `now - window > at` (the strict `<`),
        // so the spend leaves at `at_ms + window_ms + 1`, and that time minus `now_ms`
        // is the wait. Waiting only to `at_ms + window_ms` would let the caller send
        // while the spend still counts.
        let mut freed = 0u64;
        for ev in &self.events {
            freed = freed.saturating_add(u64::from(ev.count));
            if freed >= shortfall {
                // When `at + window + 1` passes `u64::MAX`, the spend never leaves the
                // window in representable time. Say so with `Duration::MAX`; a
                // saturated `ready_at` would give a wait that is too short, or zero.
                let Some(ready_at) = ev
                    .at_ms
                    .checked_add(self.window_ms)
                    .and_then(|t| t.checked_add(1))
                else {
                    return Duration::MAX;
                };
                return Duration::from_millis(ready_at - now_ms);
            }
        }
        // Even when every spend in the window leaves, the shortfall stays (n > limit).
        // The caller can only wait a full window and then split the batch.
        Duration::from_millis(self.window_ms)
    }

    /// The configured request limit per window.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
    }

    /// The spends still in the window, as `(at_ms, count)` pairs, oldest first, after
    /// pruning to `now_ms`. The caller saves them (for example as JSON in a data
    /// directory), so the rolling budget survives a restart. Back-to-back program runs
    /// then share one window instead of each starting empty and adding up past the
    /// quota. Pass the saved pairs back to [`from_snapshot`](Self::from_snapshot).
    ///
    /// Clock rule for saved snapshots: across processes, `now_ms` and every `record`
    /// time must come from a wall-clock source (milliseconds since the Unix epoch),
    /// not a monotonic clock. A monotonic clock restarts in each process, so a saved
    /// monotonic time means nothing in the next run. The calculator does not check
    /// this; the caller that saves snapshots must follow it.
    pub fn snapshot(&mut self, now_ms: u64) -> Vec<(u64, u32)> {
        self.prune(now_ms);
        self.events.iter().map(|e| (e.at_ms, e.count)).collect()
    }

    /// Rebuild a budget from a [`snapshot`](Self::snapshot), and drop any spend that
    /// has already left the window at `now_ms`. A new process resumes the rolling
    /// window where the previous one stopped. Input order does not matter: the spends
    /// are sorted and pruned on the way in.
    pub fn from_snapshot(
        limit: u32,
        window: Duration,
        now_ms: u64,
        spends: impl IntoIterator<Item = (u64, u32)>,
    ) -> Self {
        let mut b = Self::new(limit, window);
        for (at_ms, count) in spends {
            if count > 0 {
                b.events.push_back(Spend { at_ms, count });
                b.spent = b.spent.saturating_add(u64::from(count));
            }
        }
        b.events.make_contiguous().sort_by_key(|s| s.at_ms);
        b.prune(now_ms);
        b
    }

    /// Drop spends that have fully left the trailing window: those older than
    /// `now_ms - window_ms`, that is, once a complete `window` has passed since the
    /// spend. The comparison is a strict `<` on purpose. A request counts against the
    /// budget for the whole window: a spend at `t` still counts at `t + window` and is
    /// freed only after it. So the budget never under-counts and never lets the caller
    /// pass the quota at the boundary. Each removal lowers the running `spent`.
    /// Amortized O(1): each spend is pruned once.
    fn prune(&mut self, now_ms: u64) {
        let cutoff = now_ms.saturating_sub(self.window_ms);
        while let Some(front) = self.events.front() {
            if front.at_ms < cutoff {
                self.spent = self.spent.saturating_sub(u64::from(front.count));
                self.events.pop_front();
            } else {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);
    const T0: u64 = 1_000_000; // an arbitrary base time in milliseconds

    #[test]
    fn a_fresh_budget_offers_the_whole_limit() {
        let mut b = QuotaBudget::new(15_000, MIN);
        assert_eq!(b.available(T0), 15_000);
        assert_eq!(b.spent(T0), 0);
    }

    #[test]
    fn recording_spends_reduces_the_available_size() {
        let mut b = QuotaBudget::new(15_000, MIN);
        b.record(T0, 4_322);
        assert_eq!(b.spent(T0), 4_322);
        assert_eq!(b.available(T0), 10_678);
    }

    #[test]
    fn available_floors_at_zero_when_over_spent() {
        let mut b = QuotaBudget::new(100, MIN);
        b.record(T0, 80);
        b.record(T0, 80); // 160 spent against a 100 limit.
        assert_eq!(b.available(T0), 0);
        assert!(!b.allows(T0, 1));
    }

    #[test]
    fn allows_answers_whether_a_batch_fits() {
        let mut b = QuotaBudget::new(15_000, MIN);
        b.record(T0, 4_322);
        assert!(b.allows(T0, 10_678)); // the whole remainder fits
        assert!(!b.allows(T0, 10_679)); // one over does not.
    }

    #[test]
    fn a_spend_ages_out_after_a_full_window() {
        let mut b = QuotaBudget::new(15_000, MIN);
        b.record(T0, 5_000);
        assert_eq!(b.available(T0), 10_000);
        // Still inside the window one millisecond before the edge.
        assert_eq!(b.available(T0 + 60_000), 10_000);
        // One millisecond past the window: the spend has left, and the full budget is back.
        assert_eq!(b.available(T0 + 60_001), 15_000);
    }

    #[test]
    fn only_the_aged_out_portion_is_forgotten() {
        let mut b = QuotaBudget::new(15_000, MIN);
        b.record(T0, 6_000); // at T0
        b.record(T0 + 30_000, 4_000); // 30s later
        assert_eq!(b.spent(T0 + 30_000), 10_000);
        // At T0+60_001 the first spend has left the window and the second has not.
        assert_eq!(b.spent(T0 + 60_001), 4_000);
        assert_eq!(b.available(T0 + 60_001), 11_000);
    }

    #[test]
    fn retry_after_is_zero_when_the_batch_already_fits() {
        let mut b = QuotaBudget::new(15_000, MIN);
        b.record(T0, 5_000);
        assert_eq!(b.retry_after(T0, 10_000), Duration::ZERO);
    }

    #[test]
    fn retry_after_waits_until_enough_old_spend_ages_out() {
        let mut b = QuotaBudget::new(10_000, MIN);
        b.record(T0, 8_000); // spent 8k of 10k at T0.
                             // Want 5k now with only 2k free: a shortfall of 3k. The 8k spend still counts
                             // at T0+window and leaves one millisecond later, at T0+60_001. Asked at
                             // T0+10_000, the wait is 50_001 ms.
        assert_eq!(
            b.retry_after(T0 + 10_000, 5_000),
            Duration::from_millis(50_001)
        );
    }

    /// A caller that waits `retry_after` and then sends must fit. `prune` frees a
    /// spend only after `at + window` (the strict `<`), so the wait must reach one
    /// millisecond past `at + window`. A wait to `at + window` itself let the caller
    /// send while the old spend still counted, and pass the quota.
    #[test]
    fn waiting_retry_after_always_makes_the_batch_fit() {
        let mut b = QuotaBudget::new(15_000, MIN);
        b.record(0, 4_000);
        b.record(1_000, 4_000);
        b.record(2_000, 4_000);
        let now = 3_000;
        let wait = u64::try_from(b.retry_after(now, 4_000).as_millis()).unwrap();
        // Ask the earlier time first: `allows` prunes, and pruning cannot be undone.
        assert!(
            !b.allows(now + wait - 1, 4_000),
            "the wait must be the shortest that fits"
        );
        assert!(
            b.allows(now + wait, 4_000),
            "after waiting {wait} ms the batch must fit"
        );
    }

    /// `record` does not refuse a spend, so a caller can go over the limit. The wait
    /// must then cover the overshoot too: after it, the window must hold the batch.
    /// The old shortfall `n - (limit - spent)` floored `limit - spent` at zero and
    /// so ignored the overshoot.
    #[test]
    fn retry_after_covers_an_overspent_window() {
        let mut b = QuotaBudget::new(100, MIN);
        b.record(0, 100);
        b.record(1_000, 100); // 200 spent against a limit of 100
        let now = 2_000;
        let wait = u64::try_from(b.retry_after(now, 1).as_millis()).unwrap();
        assert!(
            b.allows(now + wait, 1),
            "after waiting {wait} ms one request must fit"
        );
    }

    /// Found by libFuzzer (F4, crash-1991aeb1): when the time a spend leaves the
    /// window is past `u64::MAX` milliseconds, `ready_at` saturates and the wait came
    /// out as zero although the batch did not fit. The wait must then be
    /// `Duration::MAX` ("not within representable time"), never zero.
    #[test]
    fn a_wait_past_the_end_of_u64_time_is_duration_max_not_zero() {
        let mut b = QuotaBudget::new(16_777_216, Duration::from_millis(72_057_594_037_927_936));
        b.record(18_446_744_071_109_083_136, 16_777_216);
        let now = u64::MAX;
        assert!(!b.allows(now, 1));
        assert_eq!(b.retry_after(now, 1), Duration::MAX);
    }

    /// A batch of zero always fits, so its wait is zero, even in an overspent window.
    #[test]
    fn retry_after_for_zero_requests_is_zero_even_when_overspent() {
        let mut b = QuotaBudget::new(10, MIN);
        b.record(0, 50);
        assert!(b.allows(1, 0));
        assert_eq!(b.retry_after(1, 0), Duration::ZERO);
    }

    /// A record with an earlier time than the last one must still leave the window
    /// at its own time. Spends are kept in time order, so `prune` and `retry_after`
    /// can walk from the oldest.
    #[test]
    fn a_spend_recorded_out_of_order_still_ages_out_on_time() {
        let mut b = QuotaBudget::new(10, Duration::from_millis(100));
        b.record(100, 5);
        b.record(50, 5);
        assert_eq!(
            b.available(151),
            5,
            "the spend at 50 has left the window at 151"
        );
    }

    #[test]
    fn retry_after_for_a_batch_bigger_than_the_limit_returns_a_full_window() {
        let mut b = QuotaBudget::new(10_000, MIN);
        b.record(T0, 1_000);
        // 11k never fits in a 10k window. The best wait is a full window, then a split.
        assert_eq!(b.retry_after(T0, 11_000), MIN);
    }

    #[test]
    fn snapshot_round_trips_the_in_window_spends() {
        let mut b = QuotaBudget::new(15_000, MIN);
        b.record(T0, 5_000);
        b.record(T0 + 20_000, 3_000);
        let snap = b.snapshot(T0 + 20_000);
        assert_eq!(snap, vec![(T0, 5_000), (T0 + 20_000, 3_000)]);

        // A new process restores the budget and continues the same window.
        let mut resumed = QuotaBudget::from_snapshot(15_000, MIN, T0 + 20_000, snap);
        assert_eq!(resumed.spent(T0 + 20_000), 8_000);
        assert_eq!(resumed.available(T0 + 20_000), 7_000);
    }

    #[test]
    fn from_snapshot_drops_spends_already_aged_out() {
        // The first spend is older than a full window at the resume time, so it is dropped.
        let resumed = {
            let mut r = QuotaBudget::from_snapshot(
                15_000,
                MIN,
                T0 + 70_000,
                vec![(T0, 5_000), (T0 + 30_000, 3_000)],
            );
            r.spent(T0 + 70_000)
        };
        assert_eq!(resumed, 3_000); // only the in-window 3k survives.
    }

    #[test]
    fn snapshot_then_restore_prevents_a_back_to_back_run_from_stacking_past_the_limit() {
        // Run 1 spends most of the budget, then saves.
        let mut run1 = QuotaBudget::new(15_000, MIN);
        run1.record(T0, 12_000);
        let snap = run1.snapshot(T0);

        // Run 2 starts 10 seconds later from the snapshot. It must see the spent budget.
        let mut run2 = QuotaBudget::from_snapshot(15_000, MIN, T0 + 10_000, snap);
        assert_eq!(run2.available(T0 + 10_000), 3_000); // 3,000, not 15,000: the saved spend still counts
        assert!(!run2.allows(T0 + 10_000, 5_000)); // a 5k batch correctly does not fit.
    }

    #[test]
    fn idle_then_record_forgets_the_aged_out_history() {
        let mut b = QuotaBudget::new(15_000, MIN);
        b.record(T0, 12_000);
        // Record again two minutes later: the old spend must be pruned first.
        b.record(T0 + 120_000, 1_000);
        assert_eq!(b.spent(T0 + 120_000), 1_000);
        assert_eq!(b.available(T0 + 120_000), 14_000);
    }

    /// S20: a window too long for `u64` milliseconds must saturate, not truncate. A
    /// truncated window could be short, and a spend would then leave the window early.
    #[test]
    fn a_window_past_u64_millis_saturates_and_never_forgets_a_spend() {
        // (u64::MAX / 1000 + 1) seconds is more milliseconds than u64 holds. A
        // truncating cast wraps it to a 384 ms window.
        let mut b = QuotaBudget::new(10, Duration::from_secs(u64::MAX / 1000 + 1));
        b.record(0, 5);
        assert_eq!(
            b.available(1_000),
            5,
            "the spend is still inside the window one second later"
        );

        let mut m = QuotaBudget::new(10, Duration::MAX);
        m.record(0, 5);
        assert_eq!(
            m.available(u64::MAX),
            5,
            "Duration::MAX holds the spend for any u64 time"
        );
    }

    /// Spends whose counts add up past `u32::MAX` must not under-count. The running
    /// sum used to saturate on add but subtract the true count on prune, so after the
    /// big spend left, the later spend no longer counted and the budget over-granted.
    #[test]
    fn counts_past_u32_max_do_not_under_count_after_a_prune() {
        let mut b =
            QuotaBudget::from_snapshot(100, MIN, T0 + 60_001, [(T0, u32::MAX), (T0 + 50_000, 10)]);
        assert_eq!(b.spent(T0 + 60_001), 10, "the later spend still counts");
        assert_eq!(b.available(T0 + 60_001), 90);

        let mut r = QuotaBudget::new(100, MIN);
        r.record(T0, u32::MAX);
        r.record(T0 + 50_000, 10);
        assert_eq!(r.available(T0 + 60_001), 90, "the same through record()");
    }
}
