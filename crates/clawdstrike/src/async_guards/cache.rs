use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use dashmap::DashMap;

use crate::guards::GuardResult;

struct CacheEntry {
    bytes: Vec<u8>,
    expires_at: Instant,
    size: usize,
}

/// A small in-memory TTL cache with best-effort LRU eviction.
///
/// This is intentionally simple: it is a safety/performance primitive, not a general-purpose cache.
pub struct TtlCache {
    map: DashMap<String, CacheEntry>,
    order: Mutex<VecDeque<String>>,
    max_bytes: usize,
    total_bytes: AtomicUsize,
}

impl TtlCache {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            map: DashMap::new(),
            order: Mutex::new(VecDeque::new()),
            max_bytes,
            total_bytes: AtomicUsize::new(0),
        }
    }

    pub fn get_guard_result(&self, key: &str) -> Option<GuardResult> {
        let now = Instant::now();

        let entry = self.map.get(key)?;
        if entry.expires_at <= now {
            drop(entry);
            self.remove(key);
            return None;
        }

        // Best-effort LRU: move key to back.
        self.touch(key);

        serde_json::from_slice::<GuardResult>(&entry.bytes).ok()
    }

    pub fn set_guard_result(&self, key: String, value: &GuardResult, ttl: Duration) {
        let bytes = match serde_json::to_vec(value) {
            Ok(v) => v,
            Err(_) => return,
        };

        let size = bytes.len();
        if size > self.max_bytes {
            // Single entry too large; do not cache.
            return;
        }

        let expires_at = Instant::now() + ttl;

        // Remove existing entry to keep accounting sane.
        self.remove(&key);

        self.map.insert(
            key.clone(),
            CacheEntry {
                bytes,
                expires_at,
                size,
            },
        );

        self.total_bytes.fetch_add(size, Ordering::Relaxed);
        self.push_key(key);
        self.evict_if_needed();
    }

    fn remove(&self, key: &str) {
        if let Some((_, entry)) = self.map.remove(key) {
            self.total_bytes.fetch_sub(entry.size, Ordering::Relaxed);
        }

        let mut order = self.order_lock();
        if let Some(pos) = order.iter().position(|k| k == key) {
            order.remove(pos);
        }
    }

    fn push_key(&self, key: String) {
        let mut order = self.order_lock();
        order.push_back(key);
    }

    fn touch(&self, key: &str) {
        let mut order = self.order_lock();
        if let Some(pos) = order.iter().position(|k| k == key) {
            let k = order.remove(pos).unwrap_or_default();
            order.push_back(k);
        }
    }

    fn evict_if_needed(&self) {
        while self.total_bytes.load(Ordering::Relaxed) > self.max_bytes {
            let oldest = {
                let mut order = self.order_lock();
                order.pop_front()
            };

            let Some(key) = oldest else {
                break;
            };

            if let Some((_, entry)) = self.map.remove(&key) {
                self.total_bytes.fetch_sub(entry.size, Ordering::Relaxed);
            }
        }
    }

    fn order_lock(&self) -> std::sync::MutexGuard<'_, VecDeque<String>> {
        match self.order.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}
