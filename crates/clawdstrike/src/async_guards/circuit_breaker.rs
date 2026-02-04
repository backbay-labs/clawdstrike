use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::async_guards::types::CircuitBreakerConfig;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BreakerState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Debug)]
struct Inner {
    state: BreakerState,
    failures: u32,
    successes: u32,
    opened_at: Option<Instant>,
}

#[derive(Debug)]
pub struct CircuitBreaker {
    cfg: CircuitBreakerConfig,
    inner: Mutex<Inner>,
}

impl CircuitBreaker {
    pub fn new(cfg: CircuitBreakerConfig) -> Self {
        Self {
            cfg,
            inner: Mutex::new(Inner {
                state: BreakerState::Closed,
                failures: 0,
                successes: 0,
                opened_at: None,
            }),
        }
    }

    pub async fn before_request(&self) -> Result<(), Duration> {
        let mut inner = self.inner.lock().await;

        match inner.state {
            BreakerState::Closed => Ok(()),
            BreakerState::HalfOpen => Ok(()),
            BreakerState::Open => {
                let Some(opened_at) = inner.opened_at else {
                    inner.opened_at = Some(Instant::now());
                    return Err(self.cfg.reset_timeout);
                };

                let elapsed = Instant::now().duration_since(opened_at);
                if elapsed >= self.cfg.reset_timeout {
                    // Allow a trial request.
                    inner.state = BreakerState::HalfOpen;
                    inner.successes = 0;
                    inner.failures = 0;
                    Ok(())
                } else {
                    Err(self.cfg.reset_timeout.saturating_sub(elapsed))
                }
            }
        }
    }

    pub async fn record_success(&self) {
        let mut inner = self.inner.lock().await;

        match inner.state {
            BreakerState::Closed => {
                inner.failures = 0;
            }
            BreakerState::HalfOpen => {
                inner.successes = inner.successes.saturating_add(1);
                if inner.successes >= self.cfg.success_threshold {
                    inner.state = BreakerState::Closed;
                    inner.failures = 0;
                    inner.successes = 0;
                    inner.opened_at = None;
                }
            }
            BreakerState::Open => {}
        }
    }

    pub async fn record_failure(&self) {
        let mut inner = self.inner.lock().await;

        match inner.state {
            BreakerState::Closed => {
                inner.failures = inner.failures.saturating_add(1);
                if inner.failures >= self.cfg.failure_threshold {
                    inner.state = BreakerState::Open;
                    inner.opened_at = Some(Instant::now());
                    inner.successes = 0;
                }
            }
            BreakerState::HalfOpen => {
                inner.state = BreakerState::Open;
                inner.opened_at = Some(Instant::now());
                inner.failures = 0;
                inner.successes = 0;
            }
            BreakerState::Open => {}
        }
    }
}
