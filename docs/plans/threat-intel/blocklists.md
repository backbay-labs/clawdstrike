# Auto-Updating Blocklist Architecture

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0.0-draft |
| Status | Proposal |
| Component | BlocklistManager, BlocklistGuard |
| Last Updated | 2026-02-02 |

---

## 1. Problem Statement

### 1.1 Current State

The existing `EgressAllowlistGuard` uses static domain/IP lists defined in policy configuration. This approach has significant limitations:

1. **Stale Data**: Malicious infrastructure evolves rapidly; static lists become outdated
2. **Manual Maintenance**: Security teams must manually update policies
3. **No Threat Context**: Lists don't include information about *why* something is blocked
4. **Limited Sources**: Only internal knowledge, no community threat intel

### 1.2 Requirements

- Automatically update blocklists from trusted threat intelligence feeds
- Support multiple data types: domains, IPs, CIDRs, URLs, file hashes
- Provide fast lookup (sub-millisecond for most queries)
- Include threat context (malware family, confidence, first seen)
- Support both cloud-hosted and air-gapped deployments
- Enable organizations to contribute to shared blocklists

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        BlocklistManager                                  │
│  (Central coordination for blocklist updates and queries)               │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
          ┌─────────────────────────┼─────────────────────────────────────┐
          │                         │                                     │
          v                         v                                     v
┌─────────────────────┐  ┌─────────────────────┐  ┌─────────────────────┐
│   Feed Fetcher      │  │   Local Cache       │  │   Query Engine      │
│                     │  │                     │  │                     │
│ - HTTP/S polling    │  │ - SQLite/RocksDB    │  │ - Bloom filter      │
│ - Streaming feeds   │  │ - Encrypted storage │  │ - Trie lookup       │
│ - Signature verify  │  │ - Versioned updates │  │ - CIDR matching     │
└──────────┬──────────┘  └──────────┬──────────┘  └──────────┬──────────┘
           │                        │                        │
           └────────────────────────┼────────────────────────┘
                                    │
                                    v
┌─────────────────────────────────────────────────────────────────────────┐
│                         BlocklistGuard                                   │
│  - Integrates with Guard system                                         │
│  - Checks network egress, file hashes, URLs                            │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    v
┌─────────────────────────────────────────────────────────────────────────┐
│                         Data Sources                                     │
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ Clawdstrike │  │   abuse.ch  │  │   MISP      │  │   Custom    │   │
│  │  Default    │  │   Feeds     │  │   Feeds     │  │   Feeds     │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Supported Blocklist Types

### 3.1 Indicator Types

| Type | Description | Example | Lookup Method |
|------|-------------|---------|---------------|
| Domain | Malicious domains | `malware.example.com` | Trie with wildcard |
| IP | Malicious IP addresses | `192.168.1.100` | Radix tree |
| CIDR | IP ranges | `10.0.0.0/8` | CIDR tree |
| URL | Malicious URLs | `https://evil.com/payload` | Hash table |
| FileHash | Malware hashes (MD5/SHA1/SHA256) | `a1b2c3...` | Bloom filter + hash table |
| ASN | Malicious AS numbers | `AS12345` | Hash set |

### 3.2 Feed Formats

```yaml
# Supported feed formats
formats:
  - stix2.1           # STIX 2.1 bundles
  - misp              # MISP event format
  - csv               # Simple CSV (domain, IP lists)
  - json              # Generic JSON with schema
  - text              # Plain text, one indicator per line
  - clawdstrike       # Native Clawdstrike format
```

---

## 4. API Design

### 4.1 Rust Interface

```rust
//! Blocklist Management for Clawdstrike
//!
//! Auto-updating threat intelligence blocklists with fast lookup.
//!
//! External crate dependencies:
//! - `bloom`: Bloom filter implementation (or `bloomfilter` crate)
//! - `sled`: Embedded database for persistent cache
//! - `reqwest`: HTTP client for feed fetching
//! - `ipnetwork`: IP/CIDR parsing and matching
//! - `csv`: CSV feed parsing
//! - `humantime-serde`: Duration serialization

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// Indicator type
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndicatorType {
    Domain,
    Ip,
    Cidr,
    Url,
    FileHashMd5,
    FileHashSha1,
    FileHashSha256,
    Asn,
}

/// Threat category for context
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    Malware,
    Phishing,
    CommandAndControl,
    Botnet,
    Spam,
    Cryptominer,
    Ransomware,
    Exploit,
    Tor,
    Vpn,
    Proxy,
    Scanner,
    Unknown,
}

/// Confidence level for indicators
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Confirmed,
}

/// A threat indicator with metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatIndicator {
    /// The indicator value
    pub value: String,
    /// Type of indicator
    pub indicator_type: IndicatorType,
    /// Threat category
    pub category: ThreatCategory,
    /// Confidence level
    pub confidence: Confidence,
    /// Source feed ID
    pub source: String,
    /// When first seen
    pub first_seen: DateTime<Utc>,
    /// When last seen
    pub last_seen: DateTime<Utc>,
    /// Optional malware family
    pub malware_family: Option<String>,
    /// Optional description
    pub description: Option<String>,
    /// Related indicators
    pub related: Vec<String>,
    /// Custom tags
    pub tags: Vec<String>,
}

/// Result of a blocklist lookup
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlocklistMatch {
    /// Whether the indicator was found
    pub matched: bool,
    /// Matching indicator (if found)
    pub indicator: Option<ThreatIndicator>,
    /// Additional matches (e.g., domain matched via wildcard)
    pub related_matches: Vec<ThreatIndicator>,
    /// Lookup latency
    pub lookup_ms: f64,
}

impl BlocklistMatch {
    pub fn no_match(lookup_ms: f64) -> Self {
        Self {
            matched: false,
            indicator: None,
            related_matches: vec![],
            lookup_ms,
        }
    }

    pub fn found(indicator: ThreatIndicator, lookup_ms: f64) -> Self {
        Self {
            matched: true,
            indicator: Some(indicator),
            related_matches: vec![],
            lookup_ms,
        }
    }
}

/// Feed source configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FeedSource {
    /// HTTP/HTTPS URL
    Http {
        url: String,
        #[serde(default)]
        headers: HashMap<String, String>,
        #[serde(default)]
        auth: Option<FeedAuth>,
    },
    /// Local file path
    File {
        path: String,
    },
    /// Built-in Clawdstrike feed
    Builtin {
        name: String,
    },
    /// MISP instance
    Misp {
        url: String,
        api_key_env: String,
        #[serde(default)]
        event_filters: MispFilters,
    },
}

/// Authentication for feeds
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FeedAuth {
    ApiKey {
        header: String,
        key_env: String,
    },
    Basic {
        username_env: String,
        password_env: String,
    },
    Bearer {
        token_env: String,
    },
}

/// MISP event filters
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MispFilters {
    pub tags: Vec<String>,
    pub threat_level: Option<u8>,
    pub published: Option<bool>,
}

/// Feed configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedConfig {
    /// Unique feed ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Feed source
    pub source: FeedSource,
    /// Feed format
    pub format: FeedFormat,
    /// Update interval
    #[serde(with = "humantime_serde")]
    pub update_interval: Duration,
    /// Whether feed is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Default confidence for indicators from this feed
    #[serde(default)]
    pub default_confidence: Confidence,
    /// Indicator types to import
    #[serde(default)]
    pub indicator_types: Vec<IndicatorType>,
    /// Custom tags to apply
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_true() -> bool { true }

/// Feed format specification
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FeedFormat {
    /// STIX 2.1 bundle
    Stix21,
    /// MISP JSON
    Misp,
    /// CSV with configurable columns
    Csv {
        delimiter: char,
        columns: CsvColumns,
        skip_header: bool,
    },
    /// Plain text, one indicator per line
    Text {
        indicator_type: IndicatorType,
        comment_prefix: Option<String>,
    },
    /// JSON with JSONPath expressions
    Json {
        indicators_path: String,
        value_path: String,
        type_path: Option<String>,
    },
    /// Native Clawdstrike format
    Clawdstrike,
}

/// CSV column mapping
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CsvColumns {
    pub value: usize,
    pub indicator_type: Option<usize>,
    pub category: Option<usize>,
    pub first_seen: Option<usize>,
    pub description: Option<usize>,
}

/// Blocklist manager configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlocklistConfig {
    /// Whether blocklist checking is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Feed configurations
    #[serde(default)]
    pub feeds: Vec<FeedConfig>,

    /// Path to local cache database
    #[serde(default = "default_cache_path")]
    pub cache_path: String,

    /// Maximum cache size in MB
    #[serde(default = "default_cache_size")]
    pub max_cache_mb: u32,

    /// Whether to use Bloom filter for fast negative lookups
    #[serde(default = "default_true")]
    pub use_bloom_filter: bool,

    /// Bloom filter false positive rate
    #[serde(default = "default_fp_rate")]
    pub bloom_fp_rate: f64,

    /// Minimum confidence to block
    #[serde(default)]
    pub min_confidence: Confidence,

    /// Categories to block (empty = all)
    #[serde(default)]
    pub block_categories: Vec<ThreatCategory>,

    /// Custom local blocklist entries
    #[serde(default)]
    pub local_entries: Vec<ThreatIndicator>,

    /// Local allowlist (overrides blocklist)
    #[serde(default)]
    pub allowlist: Vec<String>,
}

fn default_cache_path() -> String { ".clawdstrike/blocklist.db".to_string() }
fn default_cache_size() -> u32 { 256 }
fn default_fp_rate() -> f64 { 0.01 }

impl Default for BlocklistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            feeds: vec![
                FeedConfig {
                    id: "clawdstrike-malware-domains".to_string(),
                    name: "Clawdstrike Malware Domains".to_string(),
                    source: FeedSource::Builtin {
                        name: "malware-domains".to_string(),
                    },
                    format: FeedFormat::Clawdstrike,
                    update_interval: Duration::from_secs(6 * 3600),
                    enabled: true,
                    default_confidence: Confidence::High,
                    indicator_types: vec![IndicatorType::Domain],
                    tags: vec![],
                },
                FeedConfig {
                    id: "clawdstrike-malware-ips".to_string(),
                    name: "Clawdstrike Malware IPs".to_string(),
                    source: FeedSource::Builtin {
                        name: "malware-ips".to_string(),
                    },
                    format: FeedFormat::Clawdstrike,
                    update_interval: Duration::from_secs(6 * 3600),
                    enabled: true,
                    default_confidence: Confidence::High,
                    indicator_types: vec![IndicatorType::Ip, IndicatorType::Cidr],
                    tags: vec![],
                },
            ],
            cache_path: default_cache_path(),
            max_cache_mb: default_cache_size(),
            use_bloom_filter: true,
            bloom_fp_rate: default_fp_rate(),
            min_confidence: Confidence::Low,
            block_categories: vec![],
            local_entries: vec![],
            allowlist: vec![],
        }
    }
}

/// Feed update result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FeedUpdateResult {
    pub feed_id: String,
    pub success: bool,
    pub indicators_added: u64,
    pub indicators_removed: u64,
    pub error: Option<String>,
    pub duration_ms: u64,
}

/// Blocklist statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlocklistStats {
    pub total_indicators: u64,
    pub indicators_by_type: HashMap<String, u64>,
    pub indicators_by_source: HashMap<String, u64>,
    pub last_update: Option<DateTime<Utc>>,
    pub bloom_filter_size_bytes: u64,
    pub cache_size_bytes: u64,
}

/// Blocklist manager trait
#[async_trait]
pub trait BlocklistManager: Send + Sync {
    /// Check if a domain is blocklisted
    async fn check_domain(&self, domain: &str) -> BlocklistMatch;

    /// Check if an IP is blocklisted
    async fn check_ip(&self, ip: IpAddr) -> BlocklistMatch;

    /// Check if a URL is blocklisted
    async fn check_url(&self, url: &str) -> BlocklistMatch;

    /// Check if a file hash is blocklisted
    async fn check_hash(&self, hash: &str) -> BlocklistMatch;

    /// Update all feeds
    async fn update_feeds(&self) -> Vec<FeedUpdateResult>;

    /// Update a specific feed
    async fn update_feed(&self, feed_id: &str) -> FeedUpdateResult;

    /// Get blocklist statistics
    async fn stats(&self) -> BlocklistStats;

    /// Add a local indicator
    async fn add_local(&self, indicator: ThreatIndicator) -> Result<(), BlocklistError>;

    /// Remove a local indicator
    async fn remove_local(&self, value: &str) -> Result<bool, BlocklistError>;

    /// Check if value is in allowlist
    fn is_allowlisted(&self, value: &str) -> bool;
}

/// Blocklist errors
#[derive(Debug, thiserror::Error)]
pub enum BlocklistError {
    #[error("Feed fetch failed: {0}")]
    FetchError(String),
    #[error("Feed parse failed: {0}")]
    ParseError(String),
    #[error("Cache error: {0}")]
    CacheError(String),
    #[error("Invalid indicator: {0}")]
    InvalidIndicator(String),
}

// Note: `bloom::BloomFilter` is a placeholder for your chosen bloom filter implementation.
// Recommended crates: `bloomfilter`, `probabilistic-collections`, or `bloom`

/// Default blocklist manager implementation
pub struct DefaultBlocklistManager {
    config: BlocklistConfig,
    /// Bloom filter for fast negative lookups
    /// Using bloom::BloomFilter as placeholder - substitute with actual crate
    bloom_filter: Arc<RwLock<bloom::BloomFilter>>,
    /// Domain trie for wildcard matching
    domain_trie: Arc<RwLock<DomainTrie>>,
    /// IP/CIDR tree
    ip_tree: Arc<RwLock<IpTree>>,
    /// Hash table for exact matches
    hash_table: Arc<RwLock<HashMap<String, ThreatIndicator>>>,
    /// Local cache database
    cache: Arc<RwLock<sled::Db>>,
    /// Feed update state
    feed_state: Arc<RwLock<HashMap<String, FeedState>>>,
    /// Allowlist set
    allowlist: Arc<std::collections::HashSet<String>>,
}

/// Internal state for a feed
struct FeedState {
    last_update: Option<DateTime<Utc>>,
    last_etag: Option<String>,
    indicator_count: u64,
}

/// Trie for domain lookups with wildcard support
pub struct DomainTrie {
    // Implementation uses reversed domain labels for efficient suffix matching
    // e.g., "malware.example.com" -> ["com", "example", "malware"]
    root: TrieNode,
}

struct TrieNode {
    children: HashMap<String, TrieNode>,
    indicator: Option<ThreatIndicator>,
    is_wildcard: bool,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self {
            root: TrieNode {
                children: HashMap::new(),
                indicator: None,
                is_wildcard: false,
            },
        }
    }

    /// Insert a domain (supports wildcards like *.example.com)
    pub fn insert(&mut self, domain: &str, indicator: ThreatIndicator) {
        let labels: Vec<&str> = domain.split('.').rev().collect();
        let mut node = &mut self.root;

        for label in labels {
            if label == "*" {
                node.is_wildcard = true;
                break;
            }
            node = node.children.entry(label.to_lowercase()).or_insert_with(|| TrieNode {
                children: HashMap::new(),
                indicator: None,
                is_wildcard: false,
            });
        }
        node.indicator = Some(indicator);
    }

    /// Lookup a domain (checks wildcards)
    pub fn lookup(&self, domain: &str) -> Option<&ThreatIndicator> {
        let labels: Vec<&str> = domain.split('.').rev().collect();
        let mut node = &self.root;
        let mut last_match: Option<&ThreatIndicator> = None;

        for label in labels {
            // Check wildcard match
            if node.is_wildcard {
                last_match = node.indicator.as_ref();
            }

            // Try exact match
            if let Some(child) = node.children.get(&label.to_lowercase()) {
                node = child;
                if node.indicator.is_some() {
                    last_match = node.indicator.as_ref();
                }
            } else {
                break;
            }
        }

        last_match
    }
}

/// IP/CIDR tree for network lookups
pub struct IpTree {
    // Uses a radix tree for efficient CIDR matching
    /// IPv4 CIDR entries
    v4_entries: Vec<(ipnetwork::Ipv4Network, ThreatIndicator)>,
    /// IPv6 CIDR entries
    v6_entries: Vec<(ipnetwork::Ipv6Network, ThreatIndicator)>,
    /// Direct IP -> indicator mapping for exact matches
    exact_ips: HashMap<String, ThreatIndicator>,
}

impl IpTree {
    pub fn new() -> Self {
        Self {
            v4_entries: Vec::new(),
            v6_entries: Vec::new(),
            exact_ips: HashMap::new(),
        }
    }

    /// Insert an IP or CIDR range
    pub fn insert(&mut self, cidr_or_ip: &str, indicator: ThreatIndicator) {
        // Try parsing as CIDR first
        if let Ok(v4net) = cidr_or_ip.parse::<ipnetwork::Ipv4Network>() {
            self.v4_entries.push((v4net, indicator));
        } else if let Ok(v6net) = cidr_or_ip.parse::<ipnetwork::Ipv6Network>() {
            self.v6_entries.push((v6net, indicator));
        } else {
            // Store as exact IP
            self.exact_ips.insert(cidr_or_ip.to_string(), indicator);
        }
    }

    /// Lookup an IP address
    pub fn lookup(&self, ip: std::net::IpAddr) -> Option<&ThreatIndicator> {
        // Check exact match first
        if let Some(indicator) = self.exact_ips.get(&ip.to_string()) {
            return Some(indicator);
        }

        // Check CIDR ranges
        match ip {
            std::net::IpAddr::V4(v4) => {
                for (network, indicator) in &self.v4_entries {
                    if network.contains(v4) {
                        return Some(indicator);
                    }
                }
            }
            std::net::IpAddr::V6(v6) => {
                for (network, indicator) in &self.v6_entries {
                    if network.contains(v6) {
                        return Some(indicator);
                    }
                }
            }
        }

        None
    }
}

impl DefaultBlocklistManager {
    pub async fn new(config: BlocklistConfig) -> Result<Self, BlocklistError> {
        let cache = sled::open(&config.cache_path)
            .map_err(|e| BlocklistError::CacheError(e.to_string()))?;

        let bloom_filter = bloom::BloomFilter::with_rate(
            config.bloom_fp_rate,
            1_000_000, // Expected items
        );

        let allowlist: std::collections::HashSet<String> = config
            .allowlist
            .iter()
            .map(|s| s.to_lowercase())
            .collect();

        let manager = Self {
            config,
            bloom_filter: Arc::new(RwLock::new(bloom_filter)),
            domain_trie: Arc::new(RwLock::new(DomainTrie::new())),
            ip_tree: Arc::new(RwLock::new(IpTree::new())),
            hash_table: Arc::new(RwLock::new(HashMap::new())),
            cache: Arc::new(RwLock::new(cache)),
            feed_state: Arc::new(RwLock::new(HashMap::new())),
            allowlist: Arc::new(allowlist),
        };

        // Load from cache
        manager.load_from_cache().await?;

        Ok(manager)
    }

    async fn load_from_cache(&self) -> Result<(), BlocklistError> {
        // Load cached indicators into memory structures
        let cache = self.cache.read().await;
        let mut bloom = self.bloom_filter.write().await;
        let mut domain_trie = self.domain_trie.write().await;
        let mut hash_table = self.hash_table.write().await;

        for result in cache.iter() {
            let (key, value) = result.map_err(|e| BlocklistError::CacheError(e.to_string()))?;
            let indicator: ThreatIndicator = serde_json::from_slice(&value)
                .map_err(|e| BlocklistError::ParseError(e.to_string()))?;

            // Add to bloom filter
            bloom.insert(&indicator.value);

            // Add to appropriate data structure
            match indicator.indicator_type {
                IndicatorType::Domain => {
                    domain_trie.insert(&indicator.value, indicator);
                }
                IndicatorType::FileHashMd5
                | IndicatorType::FileHashSha1
                | IndicatorType::FileHashSha256 => {
                    hash_table.insert(indicator.value.to_lowercase(), indicator);
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn fetch_feed(&self, feed: &FeedConfig) -> Result<Vec<ThreatIndicator>, BlocklistError> {
        match &feed.source {
            FeedSource::Http { url, headers, auth } => {
                self.fetch_http_feed(url, headers, auth.as_ref(), &feed.format).await
            }
            FeedSource::File { path } => {
                self.fetch_file_feed(path, &feed.format).await
            }
            FeedSource::Builtin { name } => {
                self.fetch_builtin_feed(name).await
            }
            FeedSource::Misp { url, api_key_env, event_filters } => {
                self.fetch_misp_feed(url, api_key_env, event_filters).await
            }
        }
    }

    async fn fetch_http_feed(
        &self,
        url: &str,
        headers: &HashMap<String, String>,
        auth: Option<&FeedAuth>,
        format: &FeedFormat,
    ) -> Result<Vec<ThreatIndicator>, BlocklistError> {
        let client = reqwest::Client::new();
        let mut request = client.get(url);

        // Add headers
        for (key, value) in headers {
            request = request.header(key, value);
        }

        // Add authentication
        if let Some(auth) = auth {
            request = match auth {
                FeedAuth::ApiKey { header, key_env } => {
                    let key = std::env::var(key_env)
                        .map_err(|_| BlocklistError::FetchError(format!("Missing env var: {}", key_env)))?;
                    request.header(header, key)
                }
                FeedAuth::Bearer { token_env } => {
                    let token = std::env::var(token_env)
                        .map_err(|_| BlocklistError::FetchError(format!("Missing env var: {}", token_env)))?;
                    request.bearer_auth(token)
                }
                FeedAuth::Basic { username_env, password_env } => {
                    let username = std::env::var(username_env)
                        .map_err(|_| BlocklistError::FetchError(format!("Missing env var: {}", username_env)))?;
                    let password = std::env::var(password_env)
                        .map_err(|_| BlocklistError::FetchError(format!("Missing env var: {}", password_env)))?;
                    request.basic_auth(username, Some(password))
                }
            };
        }

        let response = request
            .send()
            .await
            .map_err(|e| BlocklistError::FetchError(e.to_string()))?;

        let content = response
            .text()
            .await
            .map_err(|e| BlocklistError::FetchError(e.to_string()))?;

        self.parse_feed(&content, format)
    }

    fn parse_feed(&self, content: &str, format: &FeedFormat) -> Result<Vec<ThreatIndicator>, BlocklistError> {
        match format {
            FeedFormat::Text { indicator_type, comment_prefix } => {
                let mut indicators = Vec::new();
                for line in content.lines() {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    if let Some(prefix) = comment_prefix {
                        if line.starts_with(prefix) {
                            continue;
                        }
                    }
                    indicators.push(ThreatIndicator {
                        value: line.to_string(),
                        indicator_type: indicator_type.clone(),
                        category: ThreatCategory::Unknown,
                        confidence: Confidence::Medium,
                        source: "feed".to_string(),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        malware_family: None,
                        description: None,
                        related: vec![],
                        tags: vec![],
                    });
                }
                Ok(indicators)
            }
            FeedFormat::Csv { delimiter, columns, skip_header } => {
                let mut indicators = Vec::new();
                let mut reader = csv::ReaderBuilder::new()
                    .delimiter(*delimiter as u8)
                    .has_headers(*skip_header)
                    .from_reader(content.as_bytes());

                for result in reader.records() {
                    let record = result.map_err(|e| BlocklistError::ParseError(e.to_string()))?;
                    if let Some(value) = record.get(columns.value) {
                        indicators.push(ThreatIndicator {
                            value: value.to_string(),
                            indicator_type: IndicatorType::Domain, // Default
                            category: ThreatCategory::Unknown,
                            confidence: Confidence::Medium,
                            source: "feed".to_string(),
                            first_seen: Utc::now(),
                            last_seen: Utc::now(),
                            malware_family: None,
                            description: columns.description.and_then(|i| record.get(i)).map(String::from),
                            related: vec![],
                            tags: vec![],
                        });
                    }
                }
                Ok(indicators)
            }
            _ => Ok(vec![]),
        }
    }

    async fn fetch_file_feed(&self, path: &str, format: &FeedFormat) -> Result<Vec<ThreatIndicator>, BlocklistError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| BlocklistError::FetchError(e.to_string()))?;
        self.parse_feed(&content, format)
    }

    async fn fetch_builtin_feed(&self, name: &str) -> Result<Vec<ThreatIndicator>, BlocklistError> {
        // Built-in feeds are compiled into the binary or fetched from Clawdstrike servers
        match name {
            "malware-domains" => {
                let content = include_str!("../data/malware-domains.txt");
                self.parse_feed(content, &FeedFormat::Text {
                    indicator_type: IndicatorType::Domain,
                    comment_prefix: Some("#".to_string()),
                })
            }
            "malware-ips" => {
                let content = include_str!("../data/malware-ips.txt");
                self.parse_feed(content, &FeedFormat::Text {
                    indicator_type: IndicatorType::Ip,
                    comment_prefix: Some("#".to_string()),
                })
            }
            _ => Err(BlocklistError::FetchError(format!("Unknown builtin feed: {}", name))),
        }
    }

    async fn fetch_misp_feed(
        &self,
        url: &str,
        api_key_env: &str,
        filters: &MispFilters,
    ) -> Result<Vec<ThreatIndicator>, BlocklistError> {
        // MISP API integration
        let api_key = std::env::var(api_key_env)
            .map_err(|_| BlocklistError::FetchError(format!("Missing MISP API key env: {}", api_key_env)))?;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/attributes/restSearch", url))
            .header("Authorization", api_key)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({
                "returnFormat": "json",
                "type": ["domain", "ip-dst", "ip-src", "url", "md5", "sha1", "sha256"],
                "tags": filters.tags,
                "published": filters.published,
            }))
            .send()
            .await
            .map_err(|e| BlocklistError::FetchError(e.to_string()))?;

        // Parse MISP response and convert to ThreatIndicators
        let misp_response: serde_json::Value = response
            .json()
            .await
            .map_err(|e| BlocklistError::ParseError(e.to_string()))?;

        // Convert MISP attributes to ThreatIndicators
        let mut indicators = Vec::new();
        if let Some(attributes) = misp_response["response"]["Attribute"].as_array() {
            for attr in attributes {
                if let (Some(value), Some(attr_type)) = (attr["value"].as_str(), attr["type"].as_str()) {
                    let indicator_type = match attr_type {
                        "domain" => IndicatorType::Domain,
                        "ip-dst" | "ip-src" => IndicatorType::Ip,
                        "url" => IndicatorType::Url,
                        "md5" => IndicatorType::FileHashMd5,
                        "sha1" => IndicatorType::FileHashSha1,
                        "sha256" => IndicatorType::FileHashSha256,
                        _ => continue,
                    };

                    indicators.push(ThreatIndicator {
                        value: value.to_string(),
                        indicator_type,
                        category: ThreatCategory::Unknown,
                        confidence: Confidence::Medium,
                        source: "misp".to_string(),
                        first_seen: Utc::now(),
                        last_seen: Utc::now(),
                        malware_family: None,
                        description: attr["comment"].as_str().map(String::from),
                        related: vec![],
                        tags: vec![],
                    });
                }
            }
        }

        Ok(indicators)
    }
}

#[async_trait]
impl BlocklistManager for DefaultBlocklistManager {
    async fn check_domain(&self, domain: &str) -> BlocklistMatch {
        let start = std::time::Instant::now();
        let domain = domain.to_lowercase();

        // Check allowlist first
        if self.is_allowlisted(&domain) {
            return BlocklistMatch::no_match(start.elapsed().as_secs_f64() * 1000.0);
        }

        // Fast Bloom filter check
        if self.config.use_bloom_filter {
            let bloom = self.bloom_filter.read().await;
            if !bloom.contains(&domain) {
                return BlocklistMatch::no_match(start.elapsed().as_secs_f64() * 1000.0);
            }
        }

        // Full trie lookup
        let trie = self.domain_trie.read().await;
        if let Some(indicator) = trie.lookup(&domain) {
            // Check confidence threshold
            if indicator.confidence >= self.config.min_confidence {
                return BlocklistMatch::found(indicator.clone(), start.elapsed().as_secs_f64() * 1000.0);
            }
        }

        BlocklistMatch::no_match(start.elapsed().as_secs_f64() * 1000.0)
    }

    async fn check_ip(&self, ip: IpAddr) -> BlocklistMatch {
        let start = std::time::Instant::now();
        let ip_str = ip.to_string();

        if self.is_allowlisted(&ip_str) {
            return BlocklistMatch::no_match(start.elapsed().as_secs_f64() * 1000.0);
        }

        // IP tree lookup
        let ip_tree = self.ip_tree.read().await;
        if let Some(indicator) = ip_tree.lookup(ip) {
            return BlocklistMatch::found(indicator.clone(), start.elapsed().as_secs_f64() * 1000.0);
        }

        BlocklistMatch::no_match(start.elapsed().as_secs_f64() * 1000.0)
    }

    async fn check_url(&self, url: &str) -> BlocklistMatch {
        let start = std::time::Instant::now();

        // Extract domain from URL and check
        if let Ok(parsed) = url::Url::parse(url) {
            if let Some(host) = parsed.host_str() {
                let domain_match = self.check_domain(host).await;
                if domain_match.matched {
                    return domain_match;
                }
            }
        }

        // Check full URL hash
        let hash_table = self.hash_table.read().await;
        if let Some(indicator) = hash_table.get(&url.to_lowercase()) {
            return BlocklistMatch::found(indicator.clone(), start.elapsed().as_secs_f64() * 1000.0);
        }

        BlocklistMatch::no_match(start.elapsed().as_secs_f64() * 1000.0)
    }

    async fn check_hash(&self, hash: &str) -> BlocklistMatch {
        let start = std::time::Instant::now();
        let hash = hash.to_lowercase();

        // Bloom filter check
        if self.config.use_bloom_filter {
            let bloom = self.bloom_filter.read().await;
            if !bloom.contains(&hash) {
                return BlocklistMatch::no_match(start.elapsed().as_secs_f64() * 1000.0);
            }
        }

        // Hash table lookup
        let hash_table = self.hash_table.read().await;
        if let Some(indicator) = hash_table.get(&hash) {
            return BlocklistMatch::found(indicator.clone(), start.elapsed().as_secs_f64() * 1000.0);
        }

        BlocklistMatch::no_match(start.elapsed().as_secs_f64() * 1000.0)
    }

    async fn update_feeds(&self) -> Vec<FeedUpdateResult> {
        let mut results = Vec::new();

        for feed in &self.config.feeds {
            if feed.enabled {
                results.push(self.update_feed(&feed.id).await);
            }
        }

        results
    }

    async fn update_feed(&self, feed_id: &str) -> FeedUpdateResult {
        let start = std::time::Instant::now();

        let feed = match self.config.feeds.iter().find(|f| f.id == feed_id) {
            Some(f) => f,
            None => return FeedUpdateResult {
                feed_id: feed_id.to_string(),
                success: false,
                indicators_added: 0,
                indicators_removed: 0,
                error: Some("Feed not found".to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        };

        match self.fetch_feed(feed).await {
            Ok(indicators) => {
                let count = indicators.len() as u64;

                // Update data structures
                let mut bloom = self.bloom_filter.write().await;
                let mut domain_trie = self.domain_trie.write().await;
                let mut hash_table = self.hash_table.write().await;

                for indicator in indicators {
                    bloom.insert(&indicator.value);

                    match indicator.indicator_type {
                        IndicatorType::Domain => {
                            domain_trie.insert(&indicator.value, indicator);
                        }
                        IndicatorType::FileHashMd5
                        | IndicatorType::FileHashSha1
                        | IndicatorType::FileHashSha256 => {
                            hash_table.insert(indicator.value.to_lowercase(), indicator);
                        }
                        _ => {}
                    }
                }

                FeedUpdateResult {
                    feed_id: feed_id.to_string(),
                    success: true,
                    indicators_added: count,
                    indicators_removed: 0,
                    error: None,
                    duration_ms: start.elapsed().as_millis() as u64,
                }
            }
            Err(e) => FeedUpdateResult {
                feed_id: feed_id.to_string(),
                success: false,
                indicators_added: 0,
                indicators_removed: 0,
                error: Some(e.to_string()),
                duration_ms: start.elapsed().as_millis() as u64,
            },
        }
    }

    async fn stats(&self) -> BlocklistStats {
        let hash_table = self.hash_table.read().await;
        let domain_trie = self.domain_trie.read().await;

        BlocklistStats {
            total_indicators: hash_table.len() as u64,
            indicators_by_type: HashMap::new(), // TODO: track by type
            indicators_by_source: HashMap::new(), // TODO: track by source
            last_update: None,
            bloom_filter_size_bytes: 0, // TODO: calculate
            cache_size_bytes: 0, // TODO: calculate
        }
    }

    async fn add_local(&self, indicator: ThreatIndicator) -> Result<(), BlocklistError> {
        let mut bloom = self.bloom_filter.write().await;
        let mut domain_trie = self.domain_trie.write().await;
        let mut hash_table = self.hash_table.write().await;

        bloom.insert(&indicator.value);

        match indicator.indicator_type {
            IndicatorType::Domain => {
                domain_trie.insert(&indicator.value, indicator);
            }
            _ => {
                hash_table.insert(indicator.value.to_lowercase(), indicator);
            }
        }

        Ok(())
    }

    async fn remove_local(&self, value: &str) -> Result<bool, BlocklistError> {
        let mut hash_table = self.hash_table.write().await;
        Ok(hash_table.remove(&value.to_lowercase()).is_some())
    }

    fn is_allowlisted(&self, value: &str) -> bool {
        self.allowlist.contains(&value.to_lowercase())
    }
}
```

### 4.2 TypeScript Interface

```typescript
/**
 * @clawdstrike/openclaw - Blocklist Management
 */

/** Indicator types */
export type IndicatorType =
  | 'domain'
  | 'ip'
  | 'cidr'
  | 'url'
  | 'file_hash_md5'
  | 'file_hash_sha1'
  | 'file_hash_sha256'
  | 'asn';

/** Threat categories */
export type ThreatCategory =
  | 'malware'
  | 'phishing'
  | 'command_and_control'
  | 'botnet'
  | 'spam'
  | 'cryptominer'
  | 'ransomware'
  | 'exploit'
  | 'tor'
  | 'vpn'
  | 'proxy'
  | 'scanner'
  | 'unknown';

/** Confidence levels */
export type Confidence = 'low' | 'medium' | 'high' | 'confirmed';

/** Threat indicator */
export interface ThreatIndicator {
  value: string;
  indicatorType: IndicatorType;
  category: ThreatCategory;
  confidence: Confidence;
  source: string;
  firstSeen: string;
  lastSeen: string;
  malwareFamily?: string;
  description?: string;
  related: string[];
  tags: string[];
}

/** Blocklist match result */
export interface BlocklistMatch {
  matched: boolean;
  indicator?: ThreatIndicator;
  relatedMatches: ThreatIndicator[];
  lookupMs: number;
}

/** Blocklist configuration */
export interface BlocklistConfig {
  enabled?: boolean;
  feeds?: FeedConfig[];
  cachePath?: string;
  maxCacheMb?: number;
  useBloomFilter?: boolean;
  bloomFpRate?: number;
  minConfidence?: Confidence;
  blockCategories?: ThreatCategory[];
  localEntries?: ThreatIndicator[];
  allowlist?: string[];
}

/** Feed configuration */
export interface FeedConfig {
  id: string;
  name: string;
  source: FeedSource;
  format: FeedFormat;
  updateIntervalMs: number;
  enabled?: boolean;
  defaultConfidence?: Confidence;
  indicatorTypes?: IndicatorType[];
  tags?: string[];
}

/** Feed source types */
export type FeedSource =
  | { type: 'http'; url: string; headers?: Record<string, string> }
  | { type: 'file'; path: string }
  | { type: 'builtin'; name: string }
  | { type: 'misp'; url: string; apiKeyEnv: string };

/** Feed format types */
export type FeedFormat =
  | { type: 'stix21' }
  | { type: 'misp' }
  | { type: 'csv'; delimiter: string; columns: CsvColumns; skipHeader: boolean }
  | { type: 'text'; indicatorType: IndicatorType; commentPrefix?: string }
  | { type: 'json'; indicatorsPath: string; valuePath: string }
  | { type: 'clawdstrike' };

/** CSV column mapping */
export interface CsvColumns {
  value: number;
  indicatorType?: number;
  category?: number;
  firstSeen?: number;
  description?: number;
}

/** Blocklist manager interface */
export interface BlocklistManager {
  checkDomain(domain: string): Promise<BlocklistMatch>;
  checkIp(ip: string): Promise<BlocklistMatch>;
  checkUrl(url: string): Promise<BlocklistMatch>;
  checkHash(hash: string): Promise<BlocklistMatch>;
  updateFeeds(): Promise<FeedUpdateResult[]>;
  updateFeed(feedId: string): Promise<FeedUpdateResult>;
  stats(): Promise<BlocklistStats>;
  addLocal(indicator: ThreatIndicator): Promise<void>;
  removeLocal(value: string): Promise<boolean>;
  isAllowlisted(value: string): boolean;
}

/** Feed update result */
export interface FeedUpdateResult {
  feedId: string;
  success: boolean;
  indicatorsAdded: number;
  indicatorsRemoved: number;
  error?: string;
  durationMs: number;
}

/** Blocklist statistics */
export interface BlocklistStats {
  totalIndicators: number;
  indicatorsByType: Record<string, number>;
  indicatorsBySource: Record<string, number>;
  lastUpdate?: string;
  bloomFilterSizeBytes: number;
  cacheSizeBytes: number;
}
```

---

## 5. Performance Considerations

### 5.1 Data Structures

| Structure | Use Case | Complexity | Memory |
|-----------|----------|------------|--------|
| Bloom Filter | Fast negative lookup | O(k) | ~1.2 bytes/item |
| Domain Trie | Wildcard domain matching | O(m) | Variable |
| Radix Tree | CIDR matching | O(32) for IPv4 | Variable |
| Hash Table | Exact match (hashes, URLs) | O(1) | ~100 bytes/item |

### 5.2 Latency Targets

| Operation | Target | Strategy |
|-----------|--------|----------|
| Domain lookup | < 1ms | Bloom filter + trie |
| IP lookup | < 1ms | Radix tree |
| Hash lookup | < 0.5ms | Hash table |
| Feed update | < 30s | Async, background |

### 5.3 Memory Budget

```yaml
blocklist:
  memory_budget:
    bloom_filter_mb: 16    # ~13M indicators at 1% FP rate
    domain_trie_mb: 64     # ~500K domains
    ip_tree_mb: 32         # ~1M IP/CIDR entries
    hash_table_mb: 128     # ~1M file hashes
    total_mb: 240
```

---

## 6. Security Considerations

### 6.1 Feed Integrity

- All HTTP feeds must use HTTPS
- Support for cryptographic signatures on feed content
- Certificate pinning for critical feeds
- Feed content validation before import

### 6.2 Cache Security

```rust
// Encrypt sensitive indicators at rest
impl EncryptedCache {
    pub fn store(&self, key: &str, indicator: &ThreatIndicator) -> Result<()> {
        let serialized = serde_json::to_vec(indicator)?;
        let encrypted = self.cipher.encrypt(&serialized)?;
        self.db.insert(key, encrypted)?;
        Ok(())
    }
}
```

### 6.3 Rate Limiting

```rust
// Prevent feed polling abuse
struct FeedRateLimiter {
    min_interval: Duration,
    last_fetch: HashMap<String, Instant>,
}

impl FeedRateLimiter {
    fn can_fetch(&self, feed_id: &str) -> bool {
        self.last_fetch
            .get(feed_id)
            .map(|t| t.elapsed() >= self.min_interval)
            .unwrap_or(true)
    }
}
```

---

## 7. Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
- [ ] Indicator data model
- [ ] Bloom filter implementation
- [ ] Domain trie implementation
- [ ] Local cache (SQLite)

### Phase 2: Feed Support (Week 2-3)
- [ ] HTTP feed fetcher
- [ ] Text/CSV parsers
- [ ] Built-in feeds
- [ ] Feed scheduling

### Phase 3: Advanced Features (Week 3-4)
- [ ] MISP integration
- [ ] STIX 2.1 parser
- [ ] IP/CIDR tree
- [ ] Wildcard support

### Phase 4: Guard Integration (Week 4)
- [ ] BlocklistGuard implementation
- [ ] Policy configuration
- [ ] Testing and benchmarks

---

## 8. Related Documents

- [overview.md](./overview.md) - Threat Intelligence Overview
- [virustotal-integration.md](./virustotal-integration.md) - VirusTotal Integration
- [yara-integration.md](./yara-integration.md) - YARA Rule Integration
