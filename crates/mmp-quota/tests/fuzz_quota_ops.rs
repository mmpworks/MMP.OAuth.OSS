//! Fuzz target F4: `QuotaBudget` arithmetic over arbitrary operation sequences.
//!
//! The harness builds a budget with an arbitrary limit and window, then runs a
//! sequence of operations. The clock never moves back (each step moves it by an
//! arbitrary amount, saturating at `u64::MAX`), but a record can carry an earlier
//! time than the clock. A plain model keeps every record and
//! recomputes the spent count from scratch at each step.
//!
//! Oracle:
//! 1. No sequence panics or overflows.
//! 2. `spent` equals the model: the sum of counts recorded at or after
//!    `now - window`, saturated at `u32::MAX`.
//! 3. `available` is `limit - spent` with a floor of zero, and `allows(n)` is
//!    `available >= n`.
//! 4. For a batch no larger than the limit, `retry_after(n)` is zero if and only if
//!    `allows(n)`, and after waiting it the batch fits.
//! 5. A snapshot restored at the same time gives the same `available`.
//!
//! Under `cargo test` bolero runs random inputs. Under libFuzzer:
//! `cargo bolero test -p mmp-quota --toolchain nightly -T 1800s quota_ops_match_the_model`.

use std::time::Duration;

use bolero::TypeGenerator;
use mmp_quota::QuotaBudget;

#[derive(Debug, TypeGenerator)]
enum Op {
    Record {
        step_ms: u32,
        n: u32,
    },
    /// A record stamped earlier than the clock (a step back, or a merged source).
    RecordEarlier {
        back_ms: u32,
        n: u32,
    },
    Query {
        step_ms: u32,
        n: u32,
    },
    Snapshot {
        step_ms: u32,
    },
}

#[derive(Debug, TypeGenerator)]
struct Case {
    limit: u32,
    window_ms: u64,
    start_ms: u64,
    ops: Vec<Op>,
}

/// Every record kept, so the spent count can be recomputed with no pruning state.
struct Model {
    records: Vec<(u64, u32)>,
    window_ms: u64,
}

impl Model {
    fn spent(&self, now: u64) -> u32 {
        let cutoff = now.saturating_sub(self.window_ms);
        let total: u64 = self
            .records
            .iter()
            .filter(|(at, _)| *at >= cutoff)
            .map(|(_, n)| u64::from(*n))
            .sum();
        u32::try_from(total).unwrap_or(u32::MAX)
    }
}

fn check_query(budget: &mut QuotaBudget, model: &Model, limit: u32, now: u64, n: u32) {
    let spent = model.spent(now);
    assert_eq!(budget.spent(now), spent, "spent at {now}");
    let available = budget.available(now);
    assert_eq!(available, limit.saturating_sub(spent), "available at {now}");
    let allows = budget.allows(now, n);
    assert_eq!(allows, available >= n, "allows({n}) at {now}");
    let wait = budget.retry_after(now, n);
    // For a batch larger than the limit, retry_after returns the full window (which
    // can be zero), so the zero-iff-fits rule holds only up to the limit.
    if n <= limit {
        assert_eq!(wait.is_zero(), allows, "retry_after({n}) at {now}");
    }

    // A caller that waits `retry_after` and then sends must fit, whenever the batch
    // can fit at all. A copy is probed, because `allows` prunes the budget.
    if n <= limit {
        let wait_ms = u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        let later = now.saturating_add(wait_ms);
        if later < u64::MAX {
            assert!(
                budget.clone().allows(later, n),
                "after waiting {wait_ms} ms from {now}, {n} must fit"
            );
        }
    }
}

fn run(case: &Case) {
    let window = Duration::from_millis(case.window_ms);
    let mut budget = QuotaBudget::new(case.limit, window);
    let mut model = Model {
        records: Vec::new(),
        window_ms: case.window_ms,
    };
    let mut now = case.start_ms;
    for op in case.ops.iter().take(64) {
        match *op {
            Op::Record { step_ms, n } => {
                now = now.saturating_add(u64::from(step_ms));
                budget.record(now, n);
                if n > 0 {
                    model.records.push((now, n));
                }
            }
            Op::RecordEarlier { back_ms, n } => {
                let at = now.saturating_sub(u64::from(back_ms));
                budget.record(at, n);
                if n > 0 {
                    model.records.push((at, n));
                }
            }
            Op::Query { step_ms, n } => {
                now = now.saturating_add(u64::from(step_ms));
                check_query(&mut budget, &model, case.limit, now, n);
            }
            Op::Snapshot { step_ms } => {
                now = now.saturating_add(u64::from(step_ms));
                let saved = budget.snapshot(now);
                let mut restored = QuotaBudget::from_snapshot(case.limit, window, now, saved);
                assert_eq!(
                    restored.available(now),
                    budget.available(now),
                    "snapshot round trip at {now}"
                );
            }
        }
    }
}

#[test]
fn quota_ops_match_the_model() {
    bolero::check!().with_type::<Case>().for_each(run);
}
