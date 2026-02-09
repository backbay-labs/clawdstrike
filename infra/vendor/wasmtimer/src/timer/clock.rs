use crate::std::Instant;
use std::sync::atomic::{AtomicPtr, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use std::time::Duration;

static CLOCK: AtomicPtr<Inner> = AtomicPtr::new(EMPTY_CLOCK);
const EMPTY_CLOCK: *mut Inner = std::ptr::null_mut();

pub(crate) fn clock() -> Clock {
    let mut clock = CLOCK.load(std::sync::atomic::Ordering::SeqCst);

    if clock == EMPTY_CLOCK {
        let clock_new = Clock::new(false);
        CLOCK
            .compare_exchange(EMPTY_CLOCK, clock_new.into_raw(), SeqCst, SeqCst)
            .unwrap();
        clock = CLOCK.load(SeqCst);
    }

    assert!(clock != EMPTY_CLOCK);
    unsafe {
        let clock = Clock::from_raw(clock);
        let ret = clock.clone();
        let _ = clock.into_raw();
        ret
    }
}

pub(crate) fn now() -> Instant {
    clock().now()
}

#[derive(Debug)]
struct Inner {
    base: Mutex<Instant>,
    unfrozen: Mutex<Option<Instant>>,
}

#[derive(Debug, Clone)]
pub struct Clock {
    inner: Arc<Inner>,
}

impl Clock {
    fn into_raw(self) -> *mut Inner {
        Arc::into_raw(self.inner) as *mut Inner
    }

    unsafe fn from_raw(raw: *mut Inner) -> Clock {
        let inner = Arc::from_raw(raw);
        Clock { inner }
    }

    pub(crate) fn new(start_paused: bool) -> Clock {
        let now = Instant::now_js();

        let clock = Clock {
            inner: Arc::new(Inner {
                base: Mutex::new(now),
                unfrozen: Mutex::new(Some(now)),
            }),
        };

        if start_paused {
            clock.pause();
        }

        clock
    }

    pub(crate) fn resume(&self) {
        if self.inner.unfrozen.lock().unwrap().is_some() {
            panic!("time is not frozen");
        }

        let mut unforzen = self.inner.unfrozen.lock().unwrap();
        (*unforzen) = Some(Instant::now_js());
    }

    pub(crate) fn paused(&self) -> bool {
        self.inner.unfrozen.lock().unwrap().is_none()
    }

    #[track_caller]
    pub(crate) fn pause(&self) {
        let unfrozen = self
            .inner
            .unfrozen
            .lock()
            .unwrap()
            .expect("time is already frozen");
        let elapsed = Instant::now_js() - unfrozen;
        let mut base = self.inner.base.lock().unwrap();
        (*base) += elapsed;
        let mut unfrozen = self.inner.unfrozen.lock().unwrap();
        (*unfrozen) = None;
    }

    #[track_caller]
    pub(crate) fn advance(&self, duration: Duration) {
        if self.inner.unfrozen.lock().unwrap().is_some() {
            panic!("time is not frozen");
        }

        let mut base = self.inner.base.lock().unwrap();

        (*base) += duration;
    }

    pub(crate) fn now(&self) -> Instant {
        let mut ret = *self.inner.base.lock().unwrap();

        let unfrozen = self.inner.unfrozen.lock().unwrap();

        if let Some(unfrozen) = *unfrozen {
            ret += Instant::now_js() - unfrozen;
        }

        ret
    }
}
