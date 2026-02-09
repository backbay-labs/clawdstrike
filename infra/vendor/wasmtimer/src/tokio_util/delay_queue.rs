//! A queue of delayed elements.
//!
//! See [`DelayQueue`] for more details.
//!
//! [`DelayQueue`]: struct@DelayQueue

use super::wheel::{self, Wheel};

use crate::std::Instant;
use crate::tokio::{sleep_until, Sleep};
use futures::ready;
use std::time::Duration;

use core::ops::{Index, IndexMut};
use slab::Slab;
use std::cmp;
use std::collections::HashMap;
use std::convert::From;
use std::fmt;
use std::fmt::Debug;
use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::task::{self, Poll, Waker};

#[derive(Debug)]
pub struct DelayQueue<T> {
    slab: SlabStorage<T>,
    wheel: Wheel<Stack<T>>,
    expired: Stack<T>,
    delay: Option<Pin<Box<Sleep>>>,
    wheel_now: u64,
    start: Instant,
    waker: Option<Waker>,
}

#[derive(Default)]
struct SlabStorage<T> {
    inner: Slab<Data<T>>,
    key_map: HashMap<Key, KeyInternal>,
    next_key_index: usize,
    compact_called: bool,
}

impl<T> SlabStorage<T> {
    pub(crate) fn with_capacity(capacity: usize) -> SlabStorage<T> {
        SlabStorage {
            inner: Slab::with_capacity(capacity),
            key_map: HashMap::new(),
            next_key_index: 0,
            compact_called: false,
        }
    }

    pub(crate) fn insert(&mut self, val: Data<T>) -> Key {
        let mut key = KeyInternal::new(self.inner.insert(val));
        let key_contained = self.key_map.contains_key(&key.into());

        if key_contained {
            let key_to_give_out = self.create_new_key();
            assert!(!self.key_map.contains_key(&key_to_give_out.into()));
            self.key_map.insert(key_to_give_out.into(), key);
            key = key_to_give_out;
        } else if self.compact_called {
            self.key_map.insert(key.into(), key);
        }

        key.into()
    }

    pub(crate) fn remove(&mut self, key: &Key) -> Data<T> {
        let remapped_key = if self.compact_called {
            match self.key_map.remove(key) {
                Some(key_internal) => key_internal,
                None => panic!("invalid key"),
            }
        } else {
            (*key).into()
        };

        self.inner.remove(remapped_key.index)
    }

    pub(crate) fn shrink_to_fit(&mut self) {
        self.inner.shrink_to_fit();
        self.key_map.shrink_to_fit();
    }

    pub(crate) fn compact(&mut self) {
        if !self.compact_called {
            for (key, _) in self.inner.iter() {
                self.key_map.insert(Key::new(key), KeyInternal::new(key));
            }
        }

        let mut remapping = HashMap::new();
        self.inner.compact(|_, from, to| {
            remapping.insert(from, to);
            true
        });

        for internal_key in self.key_map.values_mut() {
            if let Some(new_internal_key) = remapping.get(&internal_key.index) {
                *internal_key = KeyInternal::new(*new_internal_key);
            }
        }

        if self.key_map.capacity() > 2 * self.key_map.len() {
            self.key_map.shrink_to_fit();
        }

        self.compact_called = true;
    }

    fn remap_key(&self, key: &Key) -> Option<KeyInternal> {
        let key_map = &self.key_map;
        if self.compact_called {
            key_map.get(key).copied()
        } else {
            Some((*key).into())
        }
    }

    fn create_new_key(&mut self) -> KeyInternal {
        while self.key_map.contains_key(&Key::new(self.next_key_index)) {
            self.next_key_index = self.next_key_index.wrapping_add(1);
        }

        KeyInternal::new(self.next_key_index)
    }

    pub(crate) fn len(&self) -> usize {
        self.inner.len()
    }

    pub(crate) fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    pub(crate) fn clear(&mut self) {
        self.inner.clear();
        self.key_map.clear();
        self.compact_called = false;
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);

        if self.compact_called {
            self.key_map.reserve(additional);
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub(crate) fn contains(&self, key: &Key) -> bool {
        let remapped_key = self.remap_key(key);

        match remapped_key {
            Some(internal_key) => self.inner.contains(internal_key.index),
            None => false,
        }
    }
}

impl<T> fmt::Debug for SlabStorage<T>
where
    T: fmt::Debug,
{
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        if fmt.alternate() {
            fmt.debug_map().entries(self.inner.iter()).finish()
        } else {
            fmt.debug_struct("Slab")
                .field("len", &self.len())
                .field("cap", &self.capacity())
                .finish()
        }
    }
}

impl<T> Index<Key> for SlabStorage<T> {
    type Output = Data<T>;

    fn index(&self, key: Key) -> &Self::Output {
        let remapped_key = self.remap_key(&key);

        match remapped_key {
            Some(internal_key) => &self.inner[internal_key.index],
            None => panic!("Invalid index {}", key.index),
        }
    }
}

impl<T> IndexMut<Key> for SlabStorage<T> {
    fn index_mut(&mut self, key: Key) -> &mut Data<T> {
        let remapped_key = self.remap_key(&key);

        match remapped_key {
            Some(internal_key) => &mut self.inner[internal_key.index],
            None => panic!("Invalid index {}", key.index),
        }
    }
}

#[derive(Debug)]
pub struct Expired<T> {
    data: T,
    deadline: Instant,
    key: Key,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    index: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct KeyInternal {
    index: usize,
}

#[derive(Debug)]
struct Stack<T> {
    head: Option<Key>,
    _p: PhantomData<fn() -> T>,
}

#[derive(Debug)]
struct Data<T> {
    inner: T,
    when: u64,
    expired: bool,
    next: Option<Key>,
    prev: Option<Key>,
}

const MAX_ENTRIES: usize = (1 << 30) - 1;

impl<T> DelayQueue<T> {
    pub fn new() -> DelayQueue<T> {
        DelayQueue::with_capacity(0)
    }

    pub fn with_capacity(capacity: usize) -> DelayQueue<T> {
        DelayQueue {
            wheel: Wheel::new(),
            slab: SlabStorage::with_capacity(capacity),
            expired: Stack::default(),
            delay: None,
            wheel_now: 0,
            start: Instant::now(),
            waker: None,
        }
    }

    #[track_caller]
    pub fn insert_at(&mut self, value: T, when: Instant) -> Key {
        assert!(self.slab.len() < MAX_ENTRIES, "max entries exceeded");

        // Normalize the deadline. Values cannot be set to expire in the past.
        let when = self.normalize_deadline(when);

        // Insert the value in the store
        let key = self.slab.insert(Data {
            inner: value,
            when,
            expired: false,
            next: None,
            prev: None,
        });

        self.insert_idx(when, key);

        // Set a new delay if the current's deadline is later than the one of the new item
        let should_set_delay = if let Some(ref delay) = self.delay {
            let current_exp = self.normalize_deadline(delay.deadline());
            current_exp > when
        } else {
            true
        };

        if should_set_delay {
            if let Some(waker) = self.waker.take() {
                waker.wake();
            }

            let delay_time = self.start + Duration::from_millis(when);
            if let Some(ref mut delay) = &mut self.delay {
                delay.as_mut().reset(delay_time);
            } else {
                self.delay = Some(Box::pin(sleep_until(delay_time)));
            }
        }

        key
    }

    pub fn poll_expired(&mut self, cx: &mut task::Context<'_>) -> Poll<Option<Expired<T>>> {
        if !self
            .waker
            .as_ref()
            .map(|w| w.will_wake(cx.waker()))
            .unwrap_or(false)
        {
            self.waker = Some(cx.waker().clone());
        }

        let item = ready!(self.poll_idx(cx));
        Poll::Ready(item.map(|key| {
            let data = self.slab.remove(&key);
            debug_assert!(data.next.is_none());
            debug_assert!(data.prev.is_none());

            Expired {
                key,
                data: data.inner,
                deadline: self.start + Duration::from_millis(data.when),
            }
        }))
    }

    #[track_caller]
    pub fn insert(&mut self, value: T, timeout: Duration) -> Key {
        self.insert_at(value, Instant::now() + timeout)
    }

    #[track_caller]
    fn insert_idx(&mut self, when: u64, key: Key) {
        use self::wheel::{InsertError, Stack};

        // Register the deadline with the timer wheel
        match self.wheel.insert(when, key, &mut self.slab) {
            Ok(_) => {}
            Err((_, InsertError::Elapsed)) => {
                self.slab[key].expired = true;
                // The delay is already expired, store it in the expired queue
                self.expired.push(key, &mut self.slab);
            }
            Err((_, err)) => panic!("invalid deadline; err={err:?}"),
        }
    }

    #[track_caller]
    fn remove_key(&mut self, key: &Key) {
        use super::wheel::Stack;

        // Special case the `expired` queue
        if self.slab[*key].expired {
            self.expired.remove(key, &mut self.slab);
        } else {
            self.wheel.remove(key, &mut self.slab);
        }
    }

    #[track_caller]
    pub fn remove(&mut self, key: &Key) -> Expired<T> {
        let prev_deadline = self.next_deadline();

        self.remove_key(key);
        let data = self.slab.remove(key);

        let next_deadline = self.next_deadline();
        if prev_deadline != next_deadline {
            match (next_deadline, &mut self.delay) {
                (None, _) => self.delay = None,
                (Some(deadline), Some(delay)) => delay.as_mut().reset(deadline),
                (Some(deadline), None) => self.delay = Some(Box::pin(sleep_until(deadline))),
            }
        }

        Expired {
            key: Key::new(key.index),
            data: data.inner,
            deadline: self.start + Duration::from_millis(data.when),
        }
    }

    pub fn try_remove(&mut self, key: &Key) -> Option<Expired<T>> {
        if self.slab.contains(key) {
            Some(self.remove(key))
        } else {
            None
        }
    }

    #[track_caller]
    pub fn reset_at(&mut self, key: &Key, when: Instant) {
        self.remove_key(key);

        // Normalize the deadline. Values cannot be set to expire in the past.
        let when = self.normalize_deadline(when);

        self.slab[*key].when = when;
        self.slab[*key].expired = false;

        self.insert_idx(when, *key);

        let next_deadline = self.next_deadline();
        if let (Some(ref mut delay), Some(deadline)) = (&mut self.delay, next_deadline) {
            // This should awaken us if necessary (ie, if already expired)
            delay.as_mut().reset(deadline);
        }
    }

    pub fn shrink_to_fit(&mut self) {
        self.slab.shrink_to_fit();
    }

    pub fn compact(&mut self) {
        self.slab.compact();
    }

    fn next_deadline(&mut self) -> Option<Instant> {
        self.wheel
            .poll_at()
            .map(|poll_at| self.start + Duration::from_millis(poll_at))
    }

    #[track_caller]
    pub fn reset(&mut self, key: &Key, timeout: Duration) {
        self.reset_at(key, Instant::now() + timeout);
    }

    pub fn clear(&mut self) {
        self.slab.clear();
        self.expired = Stack::default();
        self.wheel = Wheel::new();
        self.delay = None;
    }

    pub fn capacity(&self) -> usize {
        self.slab.capacity()
    }

    pub fn len(&self) -> usize {
        self.slab.len()
    }

    #[track_caller]
    pub fn reserve(&mut self, additional: usize) {
        assert!(
            self.slab.capacity() + additional <= MAX_ENTRIES,
            "max queue capacity exceeded"
        );
        self.slab.reserve(additional);
    }

    pub fn is_empty(&self) -> bool {
        self.slab.is_empty()
    }

    fn poll_idx(&mut self, cx: &mut task::Context<'_>) -> Poll<Option<Key>> {
        use self::wheel::Stack;

        let expired = self.expired.pop(&mut self.slab);

        if expired.is_some() {
            return Poll::Ready(expired);
        }

        loop {
            if let Some(ref mut delay) = self.delay {
                if !delay.is_elapsed() {
                    ready!(Pin::new(&mut *delay).poll(cx));
                }

                let now = super::ms(delay.deadline() - self.start, super::Round::Down);

                #[cfg(feature = "tokio-test-util")]
                {
                    // +1 here is a tricky way to avoid infinite loop
                    // in tokio the auto advance feature will always advances time to next time
                    // event and prevent the infinite loop. But this crate doesn't support auto
                    // advancing and it will lead this loop to run till infinity.
                    self.wheel_now = now + 1;
                }
                #[cfg(not(feature = "tokio-test-util"))]
                {
                    self.wheel_now = now;
                }
            }

            // We poll the wheel to get the next value out before finding the next deadline.
            let wheel_idx = self.wheel.poll(self.wheel_now, &mut self.slab);

            self.delay = self.next_deadline().map(|when| Box::pin(sleep_until(when)));

            if let Some(idx) = wheel_idx {
                return Poll::Ready(Some(idx));
            }

            if self.delay.is_none() {
                return Poll::Ready(None);
            }
        }
    }

    fn normalize_deadline(&self, when: Instant) -> u64 {
        let when = if when < self.start {
            0
        } else {
            super::ms(when - self.start, super::Round::Up)
        };

        cmp::max(when, self.wheel.elapsed())
    }
}

// We never put `T` in a `Pin`...
impl<T> Unpin for DelayQueue<T> {}

impl<T> Default for DelayQueue<T> {
    fn default() -> DelayQueue<T> {
        DelayQueue::new()
    }
}

impl<T> futures::Stream for DelayQueue<T> {
    // DelayQueue seems much more specific, where a user may care that it
    // has reached capacity, so return those errors instead of panicking.
    type Item = Expired<T>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<Option<Self::Item>> {
        DelayQueue::poll_expired(self.get_mut(), cx)
    }
}

impl<T> wheel::Stack for Stack<T> {
    type Owned = Key;
    type Borrowed = Key;
    type Store = SlabStorage<T>;

    fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    fn push(&mut self, item: Self::Owned, store: &mut Self::Store) {
        // Ensure the entry is not already in a stack.
        debug_assert!(store[item].next.is_none());
        debug_assert!(store[item].prev.is_none());

        // Remove the old head entry
        let old = self.head.take();

        if let Some(idx) = old {
            store[idx].prev = Some(item);
        }

        store[item].next = old;
        self.head = Some(item);
    }

    fn pop(&mut self, store: &mut Self::Store) -> Option<Self::Owned> {
        if let Some(key) = self.head {
            self.head = store[key].next;

            if let Some(idx) = self.head {
                store[idx].prev = None;
            }

            store[key].next = None;
            debug_assert!(store[key].prev.is_none());

            Some(key)
        } else {
            None
        }
    }

    #[track_caller]
    fn remove(&mut self, item: &Self::Borrowed, store: &mut Self::Store) {
        let key = *item;
        assert!(store.contains(item));

        // Ensure that the entry is in fact contained by the stack
        debug_assert!({
            // This walks the full linked list even if an entry is found.
            let mut next = self.head;
            let mut contains = false;

            while let Some(idx) = next {
                let data = &store[idx];

                if idx == *item {
                    debug_assert!(!contains);
                    contains = true;
                }

                next = data.next;
            }

            contains
        });

        if let Some(next) = store[key].next {
            store[next].prev = store[key].prev;
        }

        if let Some(prev) = store[key].prev {
            store[prev].next = store[key].next;
        } else {
            self.head = store[key].next;
        }

        store[key].next = None;
        store[key].prev = None;
    }

    fn when(item: &Self::Borrowed, store: &Self::Store) -> u64 {
        store[*item].when
    }
}

impl<T> Default for Stack<T> {
    fn default() -> Stack<T> {
        Stack {
            head: None,
            _p: PhantomData,
        }
    }
}

impl Key {
    pub(crate) fn new(index: usize) -> Key {
        Key { index }
    }
}

impl KeyInternal {
    pub(crate) fn new(index: usize) -> KeyInternal {
        KeyInternal { index }
    }
}

impl From<Key> for KeyInternal {
    fn from(item: Key) -> Self {
        KeyInternal::new(item.index)
    }
}

impl From<KeyInternal> for Key {
    fn from(item: KeyInternal) -> Self {
        Key::new(item.index)
    }
}

impl<T> Expired<T> {
    pub fn get_ref(&self) -> &T {
        &self.data
    }

    pub fn get_mut(&mut self) -> &mut T {
        &mut self.data
    }

    pub fn into_inner(self) -> T {
        self.data
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    pub fn key(&self) -> Key {
        self.key
    }
}
