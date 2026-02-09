use futures::task::AtomicWaker;
use futures::Future;

use crate::std::Instant;
use crate::timer::arc_list::Node;
use crate::timer::{ScheduledTimer, TimerHandle};
use std::fmt;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

pub struct Sleep {
    state: Option<Arc<Node<ScheduledTimer>>>,
    deadline: Instant,
}

impl Sleep {
    /// Creates a new future which will fire at `dur` time into the future.
    ///
    /// The returned object will be bound to the default timer for this thread.
    /// The default timer will be spun up in a helper thread on first use.
    #[inline]
    pub(crate) fn new(dur: Duration) -> Sleep {
        Sleep::new_at(Instant::now() + dur)
    }

    /// Creates a new future which will fire at the time specified by `at`.
    ///
    /// The returned object will be bound to the default timer for this thread.
    /// The default timer will be spun up in a helper thread on first use.
    #[inline]
    pub(crate) fn new_at(at: Instant) -> Sleep {
        Sleep::new_handle(at, Default::default())
    }

    /// Creates a new future which will fire at the time specified by `at`.
    ///
    /// The returned instance of `Delay` will be bound to the timer specified by
    /// the `handle` argument.
    pub(crate) fn new_handle(at: Instant, handle: TimerHandle) -> Sleep {
        let inner = match handle.inner.upgrade() {
            Some(i) => i,
            None => {
                return Sleep {
                    state: None,
                    deadline: at,
                }
            }
        };
        let state = Arc::new(Node::new(ScheduledTimer {
            at: Mutex::new(Some(at)),
            state: AtomicUsize::new(0),
            waker: AtomicWaker::new(),
            inner: handle.inner,
            slot: Mutex::new(None),
        }));

        // If we fail to actually push our node then we've become an inert
        // timer, meaning that we'll want to immediately return an error from
        // `poll`.
        if inner.list.push(&state).is_err() {
            return Sleep {
                state: None,
                deadline: at,
            };
        }

        inner.waker.wake();
        Sleep {
            state: Some(state),
            deadline: at,
        }
    }

    /// Returns the instant at which the future will complete.
    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Returns `true` if `Sleep` has elapsed
    ///
    /// A `Sleep` instance is elapsed when the requested duration has elapsed
    pub fn is_elapsed(&self) -> bool {
        match self.state {
            Some(ref state) => state.state.load(Ordering::SeqCst) & 1 != 0,
            None => false,
        }
    }

    /// Resets this timeout to an new timeout which will fire at the time
    /// specified by `dur`.
    ///
    /// This method is usable even of this instance of `Delay` has "already
    /// fired". That is, if this future has resovled, calling this method means
    /// that the future will still re-resolve at the specified instant.
    ///
    /// If `at` is in the past then this future will immediately be resolved
    /// (when `poll` is called).
    ///
    /// Note that if any task is currently blocked on this future then that task
    /// will be dropped. It is required to call `poll` again after this method
    /// has been called to ensure tha ta task is blocked on this future.
    // Actually we do not want to self to be a `Pin` but we gauranteed the
    // API should be similiar to tokio API. So we have to accept a `Pin` to
    // this method
    #[inline]
    pub fn reset(self: Pin<&mut Self>, deadline: Instant) {
        let inner = self.get_mut();
        inner.deadline = deadline;
        if inner._reset(deadline).is_err() {
            inner.state = None
        }
    }

    fn _reset(&mut self, at: Instant) -> Result<(), ()> {
        let state = match self.state {
            Some(ref state) => state,
            None => return Err(()),
        };
        if let Some(timeouts) = state.inner.upgrade() {
            let mut bits = state.state.load(Ordering::SeqCst);
            loop {
                // If we've been invalidated, cancel this reset
                if bits & 0b10 != 0 {
                    return Err(());
                }
                let new = bits.wrapping_add(0b100) & !0b11;
                match state
                    .state
                    .compare_exchange(bits, new, Ordering::SeqCst, Ordering::SeqCst)
                {
                    Ok(_) => break,
                    Err(s) => bits = s,
                }
            }
            *state.at.lock().unwrap() = Some(at);
            // If we fail to push our node then we've become an inert timer, so
            // we'll want to clear our `state` field accordingly
            timeouts.list.push(state)?;
            timeouts.waker.wake();
        }

        Ok(())
    }
}

pub fn sleep(duration: Duration) -> Sleep {
    Sleep::new(duration)
}

pub fn sleep_until(instant: Instant) -> Sleep {
    Sleep::new_at(instant)
}

impl Future for Sleep {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let state = match self.state {
            Some(ref state) => state,
            None => panic!("timer has gone away"),
        };

        if state.state.load(Ordering::SeqCst) & 1 != 0 {
            return Poll::Ready(());
        }

        state.waker.register(cx.waker());

        // Now that we've registered, do the full check of our own internal
        // state. If we've fired the first bit is set, and if we've been
        // invalidated the second bit is set.
        match state.state.load(Ordering::SeqCst) {
            n if n & 0b01 != 0 => Poll::Ready(()),
            n if n & 0b10 != 0 => panic!("Timer has gone away"),
            _ => Poll::Pending,
        }
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        let state = match self.state {
            Some(ref s) => s,
            None => return,
        };
        if let Some(timeouts) = state.inner.upgrade() {
            *state.at.lock().unwrap() = None;
            if timeouts.list.push(state).is_ok() {
                timeouts.waker.wake();
            }
        }
    }
}

impl fmt::Debug for Sleep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.debug_struct("Delay")
            .field("deadline", &self.deadline)
            .finish()
    }
}
