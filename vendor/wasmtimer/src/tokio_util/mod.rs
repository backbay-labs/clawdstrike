use std::time::Duration;

mod wheel;

pub mod delay_queue;

#[doc(inline)]
pub use delay_queue::DelayQueue;

// ===== Internal utils =====

enum Round {
    Up,
    Down,
}

#[inline]
fn ms(duration: Duration, round: Round) -> u64 {
    const NANOS_PER_MILLI: u32 = 1_000_000;
    const MILLIS_PER_SEC: u64 = 1_000;

    // Round up.
    let millis = match round {
        Round::Up => duration.subsec_nanos().div_ceil(NANOS_PER_MILLI),
        Round::Down => duration.subsec_millis(),
    };

    duration
        .as_secs()
        .saturating_mul(MILLIS_PER_SEC)
        .saturating_add(u64::from(millis))
}
