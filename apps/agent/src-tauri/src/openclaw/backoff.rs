//! Reconnect backoff and connection-stability helpers.

use std::time::Duration;

pub(super) fn was_connected_long_enough(
    connected_at_ms: Option<u64>,
    stable_reset: Duration,
    now_ms_value: u64,
) -> bool {
    connected_at_ms.is_some_and(|connected_at| {
        now_ms_value.saturating_sub(connected_at) >= stable_reset.as_millis() as u64
    })
}

pub(super) fn next_reconnect_attempt(current_attempt: u32, was_stable: bool) -> u32 {
    if was_stable {
        1
    } else {
        current_attempt.saturating_add(1)
    }
}

/// Compute the next reconnect sleep duration, applying exponential growth plus
/// ±20% jitter to prevent thundering-herd reconnect storms.
pub(super) fn compute_reconnect_sleep_ms(reconnect_attempt: u32) -> u64 {
    let base_backoff_ms = (400.0_f64 * 1.6_f64.powi(reconnect_attempt as i32)).round() as u64;
    let base_backoff_ms = base_backoff_ms.clamp(250, 12_000);
    let jitter_range = (base_backoff_ms as f64 * 0.2) as u64;
    let jitter = if jitter_range > 0 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        std::time::SystemTime::now().hash(&mut hasher);
        reconnect_attempt.hash(&mut hasher);
        (hasher.finish() % (jitter_range * 2 + 1)) as i64 - jitter_range as i64
    } else {
        0
    };
    (base_backoff_ms as i64 + jitter).max(100) as u64
}
