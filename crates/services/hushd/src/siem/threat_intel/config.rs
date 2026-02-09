use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ThreatIntelConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub servers: Vec<TaxiiServerConfig>,
    #[serde(default)]
    pub feed: FeedConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub actions: ThreatIntelActions,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaxiiServerConfig {
    pub url: String,
    pub api_root: String,
    pub collection_id: String,
    #[serde(default)]
    pub auth: Option<TaxiiAuthConfig>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaxiiAuthConfig {
    #[serde(rename = "type")]
    pub auth_type: String, // basic | api_key | certificate
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub cert_path: Option<PathBuf>,
    #[serde(default)]
    pub key_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedConfig {
    #[serde(default = "default_interval_minutes")]
    pub interval_minutes: u64,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    #[serde(default)]
    pub include_types: Vec<String>,
    #[serde(default)]
    pub min_confidence: Option<u8>,
    #[serde(default)]
    pub added_after: Option<String>,
    #[serde(default = "default_cache_ttl_hours")]
    pub cache_ttl_hours: u64,
}

fn default_interval_minutes() -> u64 {
    15
}

fn default_page_size() -> u32 {
    1000
}

fn default_cache_ttl_hours() -> u64 {
    24
}

impl Default for FeedConfig {
    fn default() -> Self {
        Self {
            interval_minutes: default_interval_minutes(),
            page_size: default_page_size(),
            include_types: Vec::new(),
            min_confidence: None,
            added_after: None,
            cache_ttl_hours: default_cache_ttl_hours(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default)]
    pub persistent: bool,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_max_size")]
    pub max_size: usize,
}

fn default_max_size() -> usize {
    500_000
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            persistent: false,
            path: None,
            max_size: default_max_size(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatIntelActions {
    #[serde(default = "default_block_egress")]
    pub block_egress: bool,
    #[serde(default)]
    pub block_paths: bool,
    #[serde(default = "default_enrich_events")]
    pub enrich_events: bool,
}

fn default_block_egress() -> bool {
    true
}

fn default_enrich_events() -> bool {
    true
}

impl Default for ThreatIntelActions {
    fn default() -> Self {
        Self {
            block_egress: default_block_egress(),
            block_paths: false,
            enrich_events: default_enrich_events(),
        }
    }
}
