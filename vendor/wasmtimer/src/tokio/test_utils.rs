use crate::timer::TimerHandle;
use std::time::Duration;

use crate::timer::clock::clock;

pub fn pause() {
    let clock = clock();
    clock.pause();
    let handle = TimerHandle::default();
    if let Some(inner) = handle.inner.upgrade() {
        inner.waker.wake();
    }
}

pub fn resume() {
    let clock = clock();
    clock.resume();
    let handle = TimerHandle::default();
    if let Some(inner) = handle.inner.upgrade() {
        inner.waker.wake();
    }
}

pub async fn advance(duration: Duration) {
    let clock = clock();
    clock.advance(duration);
    let handle = TimerHandle::default();
    if let Some(inner) = handle.inner.upgrade() {
        inner.waker.wake();
    }
}
