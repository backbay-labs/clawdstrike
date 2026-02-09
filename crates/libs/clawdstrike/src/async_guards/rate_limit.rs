use std::time::{Duration, Instant};

use tokio::sync::Mutex;

#[derive(Debug)]
struct TokenBucketState {
    tokens: f64,
    last_refill: Instant,
}

/// A simple token-bucket limiter supporting fractional rates (e.g. 4/60 req/s).
#[derive(Debug)]
pub struct TokenBucket {
    rate_per_sec: f64,
    capacity: f64,
    state: Mutex<TokenBucketState>,
}

impl TokenBucket {
    pub fn new(rate_per_sec: f64, burst: u32) -> Self {
        let capacity = burst.max(1) as f64;
        Self {
            rate_per_sec: rate_per_sec.max(0.0),
            capacity,
            state: Mutex::new(TokenBucketState {
                tokens: capacity,
                last_refill: Instant::now(),
            }),
        }
    }

    pub async fn acquire(&self) {
        // Rate limiting is best-effort; if misconfigured, allow through.
        if self.rate_per_sec <= 0.0 {
            return;
        }

        loop {
            let wait = {
                let mut st = self.state.lock().await;
                self.refill_locked(&mut st);

                if st.tokens >= 1.0 {
                    st.tokens -= 1.0;
                    None
                } else {
                    let needed = 1.0 - st.tokens;
                    let secs = needed / self.rate_per_sec;
                    Some(Duration::from_secs_f64(secs.max(0.0)))
                }
            };

            match wait {
                None => return,
                Some(d) => tokio::time::sleep(d).await,
            }
        }
    }

    fn refill_locked(&self, st: &mut TokenBucketState) {
        let now = Instant::now();
        let elapsed = now.duration_since(st.last_refill).as_secs_f64();
        st.last_refill = now;

        let added = elapsed * self.rate_per_sec;
        st.tokens = (st.tokens + added).min(self.capacity);
    }
}
