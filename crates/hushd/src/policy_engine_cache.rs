//! Cache of compiled policy engines keyed by policy hash.

use std::sync::Arc;
use std::time::{Duration, Instant};

use clawdstrike::HushEngine;
use dashmap::DashMap;

use crate::config::PolicyScopingCacheConfig;

#[derive(Clone)]
pub struct PolicyEngineCache {
    enabled: bool,
    ttl: Duration,
    max_entries: usize,
    inner: Arc<DashMap<String, CachedEngine>>,
}

#[derive(Clone)]
struct CachedEngine {
    inserted_at: Instant,
    engine: Arc<HushEngine>,
}

impl PolicyEngineCache {
    pub fn new(enabled: bool, ttl: Duration, max_entries: usize) -> Self {
        Self {
            enabled,
            ttl,
            max_entries,
            inner: Arc::new(DashMap::new()),
        }
    }

    pub fn from_config(cfg: &PolicyScopingCacheConfig) -> Self {
        Self::new(
            cfg.enabled && cfg.max_entries > 0,
            Duration::from_secs(cfg.ttl_seconds.max(1)),
            cfg.max_entries,
        )
    }

    pub fn clear(&self) {
        self.inner.clear();
    }

    pub fn get_or_insert_with(&self, key: &str, build: impl FnOnce() -> Arc<HushEngine>) -> Arc<HushEngine> {
        if !self.enabled {
            return build();
        }

        if let Some(entry) = self.inner.get(key) {
            if entry.inserted_at.elapsed() <= self.ttl {
                return entry.engine.clone();
            }
        }

        // Evict aggressively to avoid unbounded growth.
        if self.max_entries > 0 && self.inner.len() >= self.max_entries {
            self.inner.clear();
        }

        let engine = build();
        self.inner.insert(
            key.to_string(),
            CachedEngine {
                inserted_at: Instant::now(),
                engine: engine.clone(),
            },
        );
        engine
    }
}

