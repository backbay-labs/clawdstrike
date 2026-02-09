use std::time::Duration;

use crate::async_guards::types::{AsyncGuardError, RetryConfig};

pub async fn retry<F, Fut, T>(cfg: &RetryConfig, mut f: F) -> Result<T, AsyncGuardError>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T, AsyncGuardError>>,
{
    let mut attempt: u32 = 0;
    loop {
        match f(attempt).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt >= cfg.max_retries {
                    return Err(e);
                }

                let backoff = backoff_for_attempt(cfg, attempt);
                tokio::time::sleep(backoff).await;
                attempt = attempt.saturating_add(1);
            }
        }
    }
}

fn backoff_for_attempt(cfg: &RetryConfig, attempt: u32) -> Duration {
    let base = cfg.initial_backoff.as_secs_f64();
    let mult = cfg.multiplier.max(1.0);
    let scaled = base * mult.powi(attempt as i32);

    let capped = scaled.min(cfg.max_backoff.as_secs_f64());

    // Deterministic small jitter to avoid stampedes without adding extra deps.
    let jitter_ms = (attempt.wrapping_mul(17) % 97) as u64;
    Duration::from_secs_f64(capped).saturating_add(Duration::from_millis(jitter_ms))
}
