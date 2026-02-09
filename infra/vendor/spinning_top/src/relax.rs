//! Relax strategies.
//!
//! Relax strategies are used when the thread cannot acquire a spinlock.

/// A relax strategy.
///
/// `Relax` types are used to relax the current thread during contention.
pub trait Relax: Default {
    /// Relaxes the current thread.
    fn relax(&mut self);
}

/// Rapid spinning.
///
/// This emits [`core::hint::spin_loop`].
#[derive(Default, Debug)]
pub struct Spin;

impl Relax for Spin {
    #[inline]
    fn relax(&mut self) {
        core::hint::spin_loop();
    }
}

/// Exponential backoff.
///
/// This performs exponential backoff to avoid unnecessarily stressing the cache.
//Adapted from <https://github.com/crossbeam-rs/crossbeam/blob/crossbeam-utils-0.8.16/crossbeam-utils/src/backoff.rs>.
#[derive(Default, Debug)]
pub struct Backoff {
    step: u8,
}

impl Backoff {
    const YIELD_LIMIT: u8 = 10;
}

impl Relax for Backoff {
    #[inline]
    fn relax(&mut self) {
        for _ in 0..1_u16 << self.step {
            core::hint::spin_loop();
        }

        if self.step <= Self::YIELD_LIMIT {
            self.step += 1;
        }
    }
}
