use core::marker::PhantomData;
use core::sync::atomic::{AtomicUsize, Ordering};

use lock_api::{
    GuardSend, RawRwLock, RawRwLockDowngrade, RawRwLockRecursive, RawRwLockUpgrade,
    RawRwLockUpgradeDowngrade,
};

use crate::relax::{Backoff, Relax, Spin};

/// A simple, spinning, read-preferring readers-writer lock.
// Adapted from `spin::rwlock::RwLock`, but
// - with separation of `UPGRADABLE` and `EXCLUSIVE`,
// - with optional exponential backoff,
// - with `impl RawRwLockRecursive`.
// <https://github.com/mvdnes/spin-rs/blob/d064a66b450c6c90e49a7e73fbea161e39f7a724/src/rwlock.rs>
#[derive(Debug)]
pub struct RawRwSpinlock<R: Relax = Spin> {
    lock: AtomicUsize,
    relax: PhantomData<R>,
}

/// Normal shared lock counter
const SHARED: usize = 1 << 2;
/// Special upgradable shared lock flag
const UPGRADABLE: usize = 1 << 1;
/// Exclusive lock flag
const EXCLUSIVE: usize = 1;

impl<R: Relax> RawRwSpinlock<R> {
    #[inline]
    fn is_locked_shared(&self) -> bool {
        self.lock.load(Ordering::Relaxed) & !(EXCLUSIVE | UPGRADABLE) != 0
    }

    #[inline]
    fn is_locked_upgradable(&self) -> bool {
        self.lock.load(Ordering::Relaxed) & UPGRADABLE == UPGRADABLE
    }

    /// Acquire a shared lock, returning the new lock value.
    #[inline]
    fn acquire_shared(&self) -> usize {
        let value = self.lock.fetch_add(SHARED, Ordering::Acquire);

        // An arbitrary cap that allows us to catch overflows long before they happen
        if value > usize::MAX / 2 {
            self.lock.fetch_sub(SHARED, Ordering::Relaxed);
            panic!("Too many shared locks, cannot safely proceed");
        }

        value
    }
}

unsafe impl<R: Relax> RawRwLock for RawRwSpinlock<R> {
    #[allow(clippy::declare_interior_mutable_const)]
    const INIT: Self = Self {
        lock: AtomicUsize::new(0),
        relax: PhantomData,
    };

    type GuardMarker = GuardSend;

    #[inline]
    fn lock_shared(&self) {
        let mut relax = R::default();

        while !self.try_lock_shared() {
            relax.relax();
        }
    }

    #[inline]
    fn try_lock_shared(&self) -> bool {
        let value = self.acquire_shared();

        let acquired = value & EXCLUSIVE != EXCLUSIVE;

        if !acquired {
            unsafe {
                self.unlock_shared();
            }
        }

        acquired
    }

    #[inline]
    unsafe fn unlock_shared(&self) {
        debug_assert!(self.is_locked_shared());

        self.lock.fetch_sub(SHARED, Ordering::Release);
    }

    #[inline]
    fn lock_exclusive(&self) {
        let mut relax = R::default();

        while !self.try_lock_exclusive() {
            relax.relax();
        }
    }

    #[inline]
    fn try_lock_exclusive(&self) -> bool {
        self.lock
            .compare_exchange(0, EXCLUSIVE, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }

    #[inline]
    unsafe fn unlock_exclusive(&self) {
        debug_assert!(self.is_locked_exclusive());

        self.lock.fetch_and(!EXCLUSIVE, Ordering::Release);
    }

    #[inline]
    fn is_locked(&self) -> bool {
        self.lock.load(Ordering::Relaxed) != 0
    }

    #[inline]
    fn is_locked_exclusive(&self) -> bool {
        self.lock.load(Ordering::Relaxed) & EXCLUSIVE == EXCLUSIVE
    }
}

unsafe impl<R: Relax> RawRwLockRecursive for RawRwSpinlock<R> {
    #[inline]
    fn lock_shared_recursive(&self) {
        self.lock_shared();
    }

    #[inline]
    fn try_lock_shared_recursive(&self) -> bool {
        self.try_lock_shared()
    }
}

unsafe impl<R: Relax> RawRwLockDowngrade for RawRwSpinlock<R> {
    #[inline]
    unsafe fn downgrade(&self) {
        // Reserve the shared guard for ourselves
        self.acquire_shared();

        unsafe {
            self.unlock_exclusive();
        }
    }
}

unsafe impl<R: Relax> RawRwLockUpgrade for RawRwSpinlock<R> {
    #[inline]
    fn lock_upgradable(&self) {
        let mut relax = R::default();

        while !self.try_lock_upgradable() {
            relax.relax();
        }
    }

    #[inline]
    fn try_lock_upgradable(&self) -> bool {
        let value = self.lock.fetch_or(UPGRADABLE, Ordering::Acquire);

        let acquired = value & (UPGRADABLE | EXCLUSIVE) == 0;

        if !acquired && value & UPGRADABLE == 0 {
            unsafe {
                self.unlock_upgradable();
            }
        }

        acquired
    }

    #[inline]
    unsafe fn unlock_upgradable(&self) {
        debug_assert!(self.is_locked_upgradable());

        self.lock.fetch_and(!UPGRADABLE, Ordering::Release);
    }

    #[inline]
    unsafe fn upgrade(&self) {
        let mut relax = R::default();

        while !self.try_upgrade() {
            relax.relax();
        }
    }

    #[inline]
    unsafe fn try_upgrade(&self) -> bool {
        self.lock
            .compare_exchange(UPGRADABLE, EXCLUSIVE, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
    }
}

unsafe impl<R: Relax> RawRwLockUpgradeDowngrade for RawRwSpinlock<R> {
    #[inline]
    unsafe fn downgrade_upgradable(&self) {
        self.acquire_shared();

        unsafe {
            self.unlock_upgradable();
        }
    }

    #[inline]
    unsafe fn downgrade_to_upgradable(&self) {
        debug_assert!(self.is_locked_exclusive());

        self.lock
            .fetch_xor(UPGRADABLE | EXCLUSIVE, Ordering::Release);
    }
}

/// A [`lock_api::RwLock`] based on [`RawRwSpinlock`].
pub type RwSpinlock<T> = lock_api::RwLock<RawRwSpinlock<Spin>, T>;

/// A [`lock_api::RwLockReadGuard`] based on [`RawRwSpinlock`].
pub type RwSpinlockReadGuard<'a, T> = lock_api::RwLockReadGuard<'a, RawRwSpinlock<Spin>, T>;

/// A [`lock_api::RwLockUpgradableReadGuard`] based on [`RawRwSpinlock`].
pub type RwSpinlockUpgradableReadGuard<'a, T> =
    lock_api::RwLockUpgradableReadGuard<'a, RawRwSpinlock<Spin>, T>;

/// A [`lock_api::RwLockWriteGuard`] based on [`RawRwSpinlock`].
pub type RwSpinlockWriteGuard<'a, T> = lock_api::RwLockWriteGuard<'a, RawRwSpinlock<Spin>, T>;

/// A [`lock_api::ArcRwLockReadGuard`] based on [`RawRwSpinlock`].
#[cfg(feature = "arc_lock")]
pub type ArcRwSpinlockReadGuard<T> = lock_api::ArcRwLockReadGuard<RawRwSpinlock<Spin>, T>;

/// A [`lock_api::ArcRwLockUpgradableReadGuard`] based on [`RawRwSpinlock`].
#[cfg(feature = "arc_lock")]
pub type ArcRwSpinlockUpgradableReadGuard<T> =
    lock_api::ArcRwLockUpgradableReadGuard<RawRwSpinlock<Spin>, T>;

/// A [`lock_api::ArcRwLockWriteGuard`] based on [`RawRwSpinlock`].
#[cfg(feature = "arc_lock")]
pub type ArcRwSpinlockWriteGuard<T> = lock_api::ArcRwLockWriteGuard<RawRwSpinlock<Spin>, T>;

/// A [`lock_api::RwLock`] based on [`RawRwSpinlock`]`<`[`Backoff`]`>`.
pub type BackoffRwSpinlock<T> = lock_api::RwLock<RawRwSpinlock<Backoff>, T>;

/// A [`lock_api::RwLockReadGuard`] based on [`RawRwSpinlock`]`<`[`Backoff`]`>`.
pub type BackoffRwSpinlockReadGuard<'a, T> =
    lock_api::RwLockReadGuard<'a, RawRwSpinlock<Backoff>, T>;

/// A [`lock_api::RwLockUpgradableReadGuard`] based on [`RawRwSpinlock`]`<`[`Backoff`]`>`.
pub type BackoffRwSpinlockUpgradableReadGuard<'a, T> =
    lock_api::RwLockUpgradableReadGuard<'a, RawRwSpinlock<Backoff>, T>;

/// A [`lock_api::RwLockWriteGuard`] based on [`RawRwSpinlock`]`<`[`Backoff`]`>`.
pub type BackoffRwSpinlockWriteGuard<'a, T> =
    lock_api::RwLockWriteGuard<'a, RawRwSpinlock<Backoff>, T>;

/// A [`lock_api::ArcRwLockReadGuard`] based on [`RawRwSpinlock`]`<`[`Backoff`]`>`.
#[cfg(feature = "arc_lock")]
pub type ArcBackoffRwSpinlockReadGuard<T> = lock_api::ArcRwLockReadGuard<RawRwSpinlock<Backoff>, T>;

/// A [`lock_api::ArcRwLockUpgradableReadGuard`] based on [`RawRwSpinlock`]`<`[`Backoff`]`>`.
#[cfg(feature = "arc_lock")]
pub type ArcBackoffRwSpinlockUpgradableReadGuard<T> =
    lock_api::ArcRwLockUpgradableReadGuard<RawRwSpinlock<Backoff>, T>;

/// A [`lock_api::ArcRwLockWriteGuard`] based on [`RawRwSpinlock`]`<`[`Backoff`]`>`.
#[cfg(feature = "arc_lock")]
pub type ArcBackoffRwSpinlockWriteGuard<T> =
    lock_api::ArcRwLockWriteGuard<RawRwSpinlock<Backoff>, T>;

// Adapted from `spin::rwlock`.
#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::channel;
    use std::sync::Arc;
    use std::{mem, thread};

    use lock_api::{RwLockUpgradableReadGuard, RwLockWriteGuard};

    use super::*;

    #[test]
    fn test_unlock_shared() {
        let m: RawRwSpinlock = RawRwSpinlock::INIT;
        m.lock_shared();
        m.lock_shared();
        m.lock_shared();
        assert!(!m.try_lock_exclusive());
        unsafe {
            m.unlock_shared();
            m.unlock_shared();
        }
        assert!(!m.try_lock_exclusive());
        unsafe {
            m.unlock_shared();
        }
        assert!(m.try_lock_exclusive());
    }

    #[test]
    fn test_unlock_exclusive() {
        let m: RawRwSpinlock = RawRwSpinlock::INIT;
        m.lock_exclusive();
        assert!(!m.try_lock_shared());
        unsafe {
            m.unlock_exclusive();
        }
        assert!(m.try_lock_shared());
    }

    #[test]
    fn smoke() {
        let l = RwSpinlock::new(());
        drop(l.read());
        drop(l.write());
        drop((l.read(), l.read()));
        drop(l.write());
    }

    #[test]
    fn frob() {
        use rand::Rng;

        static R: RwSpinlock<usize> = RwSpinlock::new(0);
        const N: usize = 10;
        const M: usize = 1000;

        let (tx, rx) = channel::<()>();
        for _ in 0..N {
            let tx = tx.clone();
            thread::spawn(move || {
                let mut rng = rand::thread_rng();
                for _ in 0..M {
                    if rng.gen_bool(1.0 / N as f64) {
                        drop(R.write());
                    } else {
                        drop(R.read());
                    }
                }
                drop(tx);
            });
        }
        drop(tx);
        let _ = rx.recv();
    }

    #[test]
    fn test_rw_arc() {
        let arc = Arc::new(RwSpinlock::new(0));
        let arc2 = arc.clone();
        let (tx, rx) = channel();

        thread::spawn(move || {
            let mut lock = arc2.write();
            for _ in 0..10 {
                let tmp = *lock;
                *lock = -1;
                thread::yield_now();
                *lock = tmp + 1;
            }
            tx.send(()).unwrap();
        });

        // Readers try to catch the writer in the act
        let mut children = Vec::new();
        for _ in 0..5 {
            let arc3 = arc.clone();
            children.push(thread::spawn(move || {
                let lock = arc3.read();
                assert!(*lock >= 0);
            }));
        }

        // Wait for children to pass their asserts
        for r in children {
            assert!(r.join().is_ok());
        }

        // Wait for writer to finish
        rx.recv().unwrap();
        let lock = arc.read();
        assert_eq!(*lock, 10);
    }

    #[test]
    fn test_rw_access_in_unwind() {
        let arc = Arc::new(RwSpinlock::new(1));
        let arc2 = arc.clone();
        let _ = thread::spawn(move || -> () {
            struct Unwinder {
                i: Arc<RwSpinlock<isize>>,
            }
            impl Drop for Unwinder {
                fn drop(&mut self) {
                    let mut lock = self.i.write();
                    *lock += 1;
                }
            }
            let _u = Unwinder { i: arc2 };
            panic!();
        })
        .join();
        let lock = arc.read();
        assert_eq!(*lock, 2);
    }

    #[test]
    fn test_rwlock_unsized() {
        let rw: &RwSpinlock<[i32]> = &RwSpinlock::new([1, 2, 3]);
        {
            let b = &mut *rw.write();
            b[0] = 4;
            b[2] = 5;
        }
        let comp: &[i32] = &[4, 2, 5];
        assert_eq!(&*rw.read(), comp);
    }

    #[test]
    fn test_rwlock_try_write() {
        let lock = RwSpinlock::new(0isize);
        let read_guard = lock.read();

        let write_result = lock.try_write();
        match write_result {
            None => (),
            Some(_) => assert!(
                false,
                "try_write should not succeed while read_guard is in scope"
            ),
        }

        drop(read_guard);
    }

    #[test]
    fn test_rw_try_read() {
        let m = RwSpinlock::new(0);
        mem::forget(m.write());
        assert!(m.try_read().is_none());
    }

    #[test]
    fn test_into_inner() {
        let m = RwSpinlock::new(Box::new(10));
        assert_eq!(m.into_inner(), Box::new(10));
    }

    #[test]
    fn test_into_inner_drop() {
        struct Foo(Arc<AtomicUsize>);
        impl Drop for Foo {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let num_drops = Arc::new(AtomicUsize::new(0));
        let m = RwSpinlock::new(Foo(num_drops.clone()));
        assert_eq!(num_drops.load(Ordering::SeqCst), 0);
        {
            let _inner = m.into_inner();
            assert_eq!(num_drops.load(Ordering::SeqCst), 0);
        }
        assert_eq!(num_drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn test_upgrade_downgrade() {
        let m = RwSpinlock::new(());
        {
            let _r = m.read();
            let upg = m.try_upgradable_read().unwrap();
            assert!(m.try_read().is_some());
            assert!(m.try_write().is_none());
            assert!(RwLockUpgradableReadGuard::try_upgrade(upg).is_err());
        }
        {
            let w = m.write();
            assert!(m.try_upgradable_read().is_none());
            let _r = RwLockWriteGuard::downgrade(w);
            assert!(m.try_upgradable_read().is_some());
            assert!(m.try_read().is_some());
            assert!(m.try_write().is_none());
        }
        {
            let _u = m.upgradable_read();
            assert!(m.try_upgradable_read().is_none());
        }

        assert!(RwLockUpgradableReadGuard::try_upgrade(m.try_upgradable_read().unwrap()).is_ok());
    }
}
