use std::num::NonZeroU32;
use std::sync::Arc;

use governor::{
    clock::{Clock, DefaultClock},
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};

use crate::siem::exporter::RateLimitConfig;

type DirectRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

#[derive(Clone)]
pub struct ExportRateLimiter {
    limiter: Option<Arc<DirectRateLimiter>>,
}

impl ExportRateLimiter {
    pub fn new(config: Option<&RateLimitConfig>) -> Self {
        let Some(config) = config else {
            return Self { limiter: None };
        };

        let default_rps = NonZeroU32::new(1).unwrap_or(NonZeroU32::MIN);
        let default_burst = NonZeroU32::new(1).unwrap_or(NonZeroU32::MIN);

        let rps = NonZeroU32::new(config.requests_per_second).unwrap_or(default_rps);
        let burst = NonZeroU32::new(config.burst_size).unwrap_or(default_burst);
        let quota = Quota::per_second(rps).allow_burst(burst);

        Self {
            limiter: Some(Arc::new(RateLimiter::direct(quota))),
        }
    }

    pub async fn acquire(&self) {
        let Some(limiter) = &self.limiter else {
            return;
        };

        loop {
            match limiter.check() {
                Ok(_) => return,
                Err(not_until) => {
                    let wait = not_until.wait_time_from(DefaultClock::default().now());
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
}
