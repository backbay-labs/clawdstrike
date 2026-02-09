use futures::future::poll_fn;
use pin_utils::unsafe_pinned;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use futures::prelude::*;

use crate::std::Instant;
use crate::tokio::Sleep;

/// A stream representing notifications at fixed interval
///
/// Intervals are created through the `Interval::new` or
/// `Interval::new_at` methods indicating when a first notification
/// should be triggered and when it will be repeated.
///
/// Note that intervals are not intended for high resolution timers, but rather
/// they will likely fire some granularity after the exact instant that they're
/// otherwise indicated to fire at.
#[derive(Debug)]
pub struct Interval {
    sleep: Sleep,
    interval: Duration,
    missed_tick_behavior: MissedTickBehavior,
}

impl Interval {
    unsafe_pinned!(sleep: Sleep);

    /// Creates a new interval which will fire at `dur` time into the future,
    /// and will repeat every `dur` interval after. The first tick completes immediately.
    ///
    /// The returned object will be bound to the default timer for this thread.
    /// The default timer will be spun up in a helper thread on first use.
    pub(crate) fn new(dur: Duration) -> Interval {
        Interval::new_at(Instant::now(), dur)
    }

    /// Creates a new interval which will fire at the time specified by `at`,
    /// and then will repeat every `dur` interval after
    ///
    /// The returned object will be bound to the default timer for this thread.
    /// The default timer will be spun up in a helper thread on first use.
    pub(crate) fn new_at(at: Instant, dur: Duration) -> Interval {
        Interval {
            sleep: Sleep::new_at(at),
            interval: dur,
            missed_tick_behavior: MissedTickBehavior::default(),
        }
    }

    pub async fn tick(&mut self) -> Instant {
        let instant = poll_fn(|cx| self.poll_tick(cx));
        instant.await
    }

    pub fn poll_tick(&mut self, cx: &mut Context<'_>) -> Poll<Instant> {
        if Pin::new(&mut *self).sleep().poll(cx).is_pending() {
            return Poll::Pending;
        }

        let timeout = self.sleep.deadline();
        let now = Instant::now();

        let next = if now > timeout + Duration::from_millis(5) {
            self.missed_tick_behavior
                .next_timeout(timeout, now, self.interval)
        } else {
            timeout + self.interval
        };

        Pin::new(&mut self.sleep).reset(next);
        Poll::Ready(timeout)
    }

    pub fn reset(&mut self) {
        Pin::new(&mut self.sleep).reset(Instant::now() + self.interval);
    }

    /// Returns the [`MissedTickBehavior`] strategy currently being used.
    pub fn missed_tick_behavior(&self) -> MissedTickBehavior {
        self.missed_tick_behavior
    }

    /// Sets the [`MissedTickBehavior`] strategy that should be used.
    pub fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
        self.missed_tick_behavior = behavior;
    }

    /// Returns the period of the interval.
    pub fn period(&self) -> Duration {
        self.interval
    }
}

#[derive(Debug, PartialEq, Clone, Copy, Eq, Default)]
pub enum MissedTickBehavior {
    #[default]
    Burst,
    Delay,
    Skip,
}

impl MissedTickBehavior {
    /// If a tick is missed, this method is called to determine when the next tick should happen.
    fn next_timeout(&self, timeout: Instant, now: Instant, period: Duration) -> Instant {
        match self {
            Self::Burst => timeout + period,
            Self::Delay => now + period,
            Self::Skip => {
                now + period
                    - Duration::from_nanos(
                        ((now - timeout).as_nanos() % period.as_nanos())
                            .try_into()
                            // This operation is practically guaranteed not to
                            // fail, as in order for it to fail, `period` would
                            // have to be longer than `now - timeout`, and both
                            // would have to be longer than 584 years.
                            //
                            // If it did fail, there's not a good way to pass
                            // the error along to the user, so we just panic.
                            .expect(
                                "too much time has elapsed since the interval was supposed to tick",
                            ),
                    )
            }
        }
    }
}

pub fn interval(period: Duration) -> Interval {
    Interval::new(period)
}

pub fn interval_at(start: Instant, period: Duration) -> Interval {
    Interval::new_at(start, period)
}
