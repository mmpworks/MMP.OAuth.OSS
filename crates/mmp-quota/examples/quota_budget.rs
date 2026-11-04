//! Pace a batch of API calls against a per-minute quota with `QuotaBudget`.
//!
//! The example uses a quota of 15,000 requests per rolling minute. It sends batches
//! of 4,000 requests on a simulated clock: a batch goes when it fits, and
//! otherwise the loop waits for `retry_after`. No network, no sleeping: the clock
//! is a number the example moves.
//!
//! Run it with `cargo run -p mmp-quota --example quota_budget`.

use std::time::Duration;

use mmp_quota::QuotaBudget;

fn main() {
    let mut budget = QuotaBudget::new(15_000, Duration::from_secs(60));
    let batch = 4_000;
    let mut now_ms: u64 = 0;

    for number in 1..=6 {
        let wait = budget.retry_after(now_ms, batch);
        if !wait.is_zero() {
            println!(
                "batch {number}: {} left, wait {} ms",
                budget.available(now_ms),
                wait.as_millis()
            );
            now_ms += u64::try_from(wait.as_millis()).unwrap_or(u64::MAX);
        }
        budget.record(now_ms, batch);
        println!(
            "batch {number}: sent at {now_ms} ms, {} left in this window",
            budget.available(now_ms)
        );
        now_ms += 1_000; // the batch itself takes one second
    }
}
