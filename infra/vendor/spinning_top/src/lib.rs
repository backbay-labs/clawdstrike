//! Provides simple spinlocks based on the abstractions provided by the [`lock_api`] crate.
//!
//! [`lock_api`]: https://docs.rs/lock_api/
//!
//! # Examples
//!
//! Use [`Spinlock`] for mutual exclusion:
//!
//! ```
//! use spinning_top::Spinlock;
//!
//! fn main() {
//!     let data = String::from("Hello");
//!     // Wrap some data in a spinlock
//!     let spinlock = Spinlock::new(data);
//!
//!     // Lock the spinlock to get a mutex guard for the data
//!     let mut locked_data = spinlock.lock();
//!     // The guard implements the `Deref` trait, so we can use it like a `&String`
//!     assert_eq!(locked_data.as_str(), "Hello");
//!     // It also implements `DerefMut` so mutation is possible too. This is safe
//!     // because the spinlock ensures mutual exclusion
//!     locked_data.make_ascii_uppercase();
//!     assert_eq!(locked_data.as_str(), "HELLO");
//!
//!     // the guard automatically frees the lock at the end of the scope
//! }
//! ```
//!
//! Use [`RwSpinlock`] if you need a readers-writer lock:
//!
//! ```
//! use spinning_top::RwSpinlock;
//!
//! let lock = RwSpinlock::new(5);
//!
//! // many reader locks can be held at once
//! {
//!     let r1 = lock.read();
//!     let r2 = lock.read();
//!     assert_eq!(*r1, 5);
//!     assert_eq!(*r2, 5);
//! } // read locks are dropped at this point
//!
//! // only one write lock may be held, however
//! {
//!     let mut w = lock.write();
//!     *w += 1;
//!     assert_eq!(*w, 6);
//! } // write lock is dropped here
//! ```

#![cfg_attr(not(test), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

/// The spinlock implemenation is based on the abstractions provided by the `lock_api` crate.
pub use lock_api;

pub use rw_spinlock::{BackoffRwSpinlock, RawRwSpinlock, RwSpinlock};
pub use spinlock::{BackoffSpinlock, RawSpinlock, Spinlock};

/// Type aliases for guards.
pub mod guard {
    #[cfg(feature = "arc_lock")]
    pub use super::rw_spinlock::{
        ArcBackoffRwSpinlockReadGuard, ArcBackoffRwSpinlockUpgradableReadGuard,
        ArcBackoffRwSpinlockWriteGuard, ArcRwSpinlockReadGuard, ArcRwSpinlockUpgradableReadGuard,
        ArcRwSpinlockWriteGuard,
    };
    pub use super::rw_spinlock::{
        BackoffRwSpinlockReadGuard, BackoffRwSpinlockUpgradableReadGuard,
        BackoffRwSpinlockWriteGuard, RwSpinlockReadGuard, RwSpinlockUpgradableReadGuard,
        RwSpinlockWriteGuard,
    };
    #[cfg(feature = "arc_lock")]
    pub use super::spinlock::{ArcBackoffSpinlockGuard, ArcSpinlockGuard};
    pub use super::spinlock::{
        BackoffSpinlockGuard, MappedBackoffSpinlockGuard, MappedSpinlockGuard, SpinlockGuard,
    };
}

pub mod relax;
mod rw_spinlock;
mod spinlock;
