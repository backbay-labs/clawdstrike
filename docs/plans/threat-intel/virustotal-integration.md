# VirusTotal and urlscan.io Integration Design

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0.0-draft |
| Status | Proposal |
| Component | VirusTotalGuard, UrlscanGuard |
| Last Updated | 2026-02-02 |

---

## 1. Problem Statement

### 1.1 The Gap

Local blocklists and YARA rules provide deterministic detection but have limitations:

1. **Coverage**: Cannot cover all malicious domains, IPs, and file hashes
2. **Freshness**: New threats emerge faster than local lists update
3. **Context**: Limited threat intelligence context (malware family, confidence)
4. **Reputation**: No aggregate community detection scores

### 1.2 External Intelligence Benefits

Services like VirusTotal and urlscan.io provide:

- **Multi-vendor Detection**: 70+ antivirus engines for files
- **URL Analysis**: Safe browsing, phishing, malware distribution
- **Real-time Intelligence**: Continuously updated threat data
- **Rich Context**: Detection names, malware families, behavior analysis
- **Community Data**: Crowdsourced threat intelligence

### 1.3 Goals

- Integrate VirusTotal for file hash and URL reputation
- Integrate urlscan.io for URL analysis and screenshots
- Support both synchronous and asynchronous checks
- Implement intelligent caching to minimize API calls
- Respect API rate limits and quotas

---

## 2. Architecture

### 2.1 System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    External Intelligence Hub                             │
│                                                                         │
│  ┌────────────────────────────┐    ┌────────────────────────────┐     │
│  │     VirusTotalClient       │    │     UrlscanClient          │     │
│  │                            │    │                            │     │
│  │  - File hash lookup        │    │  - URL submission          │     │
│  │  - URL scan                │    │  - Result polling          │     │
│  │  - Domain reports          │    │  - Screenshot retrieval    │     │
│  │  - IP reports              │    │  - Verdict extraction      │     │
│  └────────────────────────────┘    └────────────────────────────┘     │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      Rate Limiter                                 │  │
│  │  - Per-API quotas                                                │  │
│  │  - Request queuing                                               │  │
│  │  - Backoff strategies                                            │  │
│  └──────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │                      Response Cache                               │  │
│  │  - TTL-based expiration                                          │  │
│  │  - Hash/URL keyed                                                │  │
│  │  - Persistent storage option                                     │  │
│  └──────────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    v
┌─────────────────────────────────────────────────────────────────────────┐
│                         Guard Integration                                │
│                                                                         │
│  ┌────────────────────────────┐    ┌────────────────────────────┐     │
│  │     VirusTotalGuard        │    │     UrlscanGuard           │     │
│  │                            │    │                            │     │
│  │  - File write (hash)       │    │  - Network egress (URL)    │     │
│  │  - Network egress (URL)    │    │  - Link in content         │     │
│  │  - Domain reputation       │    │  - Async scan + poll       │     │
│  └────────────────────────────┘    └────────────────────────────┘     │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Request Flow

```
                        Guard Check Request
                               │
                               v
              ┌────────────────────────────────┐
              │        Cache Lookup            │
              │  - Check if result cached      │
              │  - Check if cache valid        │
              └───────────────┬────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
         Cache Hit                       Cache Miss
              │                               │
              v                               v
    ┌──────────────────┐        ┌──────────────────────┐
    │  Return Cached   │        │   Rate Limit Check   │
    │     Result       │        │  - Quota available?  │
    └──────────────────┘        │  - Queue if needed   │
                                └──────────┬───────────┘
                                           │
                              ┌────────────┴────────────┐
                              │                         │
                         Quota OK                  Quota Exceeded
                              │                         │
                              v                         v
                   ┌──────────────────┐     ┌──────────────────┐
                   │  API Request     │     │  Fallback        │
                   │  - VT or urlscan │     │  - Use stale     │
                   │  - With timeout  │     │  - Allow + warn  │
                   └────────┬─────────┘     │  - Block (strict)│
                            │               └──────────────────┘
                            v
                   ┌──────────────────┐
                   │  Process Result  │
                   │  - Parse response│
                   │  - Cache result  │
                   │  - Return        │
                   └──────────────────┘
```

---

## 3. API Design

### 3.1 Rust Interface

```rust
//! VirusTotal and urlscan.io Integration for Clawdstrike
//!
//! External threat intelligence lookups for files, URLs, and domains.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, Semaphore};

use crate::guards::{Guard, GuardAction, GuardContext, GuardResult, Severity};

// External crate dependencies:
// - reqwest: HTTP client
// - sha2: SHA256 hashing
// - base64: URL encoding for VirusTotal API

// ============================================================================
// VirusTotal Types
// ============================================================================

/// VirusTotal analysis statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtAnalysisStats {
    /// Number of vendors that detected as malicious
    pub malicious: u32,
    /// Number of vendors that flagged as suspicious
    pub suspicious: u32,
    /// Number of vendors that found nothing
    pub undetected: u32,
    /// Number of vendors that timed out
    pub timeout: u32,
    /// Number of vendors unable to process
    pub failure: u32,
    /// Unsupported file type
    pub type_unsupported: u32,
}

impl VtAnalysisStats {
    /// Total number of vendors that analyzed
    pub fn total_analyzed(&self) -> u32 {
        self.malicious + self.suspicious + self.undetected + self.timeout
    }

    /// Detection ratio as percentage
    pub fn detection_ratio(&self) -> f32 {
        let total = self.total_analyzed();
        if total == 0 {
            return 0.0;
        }
        (self.malicious as f32 / total as f32) * 100.0
    }

    /// Is considered malicious (threshold-based)
    pub fn is_malicious(&self, threshold: u32) -> bool {
        self.malicious >= threshold
    }
}

/// VirusTotal vendor result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtVendorResult {
    /// Vendor name
    pub vendor: String,
    /// Detection category
    pub category: VtCategory,
    /// Detection result/name
    pub result: Option<String>,
    /// Engine version
    pub engine_version: Option<String>,
    /// Definition update date
    pub update: Option<String>,
}

/// VirusTotal detection category
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VtCategory {
    Malicious,
    Suspicious,
    Undetected,
    Timeout,
    Failure,
    #[serde(rename = "type-unsupported")]
    TypeUnsupported,
}

/// VirusTotal file report
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtFileReport {
    /// Resource identifier (hash)
    pub resource: String,
    /// File SHA256
    pub sha256: String,
    /// File SHA1
    pub sha1: Option<String>,
    /// File MD5
    pub md5: Option<String>,
    /// File size in bytes
    pub size: Option<u64>,
    /// File type description
    pub type_description: Option<String>,
    /// Analysis statistics
    pub stats: VtAnalysisStats,
    /// Per-vendor results
    pub results: HashMap<String, VtVendorResult>,
    /// Popular threat label
    pub popular_threat_label: Option<String>,
    /// Suggested threat label
    pub suggested_threat_label: Option<String>,
    /// First submission date
    pub first_submission_date: Option<DateTime<Utc>>,
    /// Last analysis date
    pub last_analysis_date: Option<DateTime<Utc>>,
    /// Scan permalink
    pub permalink: Option<String>,
}

/// VirusTotal URL report
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtUrlReport {
    /// The URL analyzed
    pub url: String,
    /// Final URL after redirects
    pub final_url: Option<String>,
    /// Analysis statistics
    pub stats: VtAnalysisStats,
    /// Per-vendor results
    pub results: HashMap<String, VtVendorResult>,
    /// Categories assigned to URL
    pub categories: HashMap<String, String>,
    /// HTTP response code
    pub last_http_response_code: Option<u16>,
    /// Last analysis date
    pub last_analysis_date: Option<DateTime<Utc>>,
    /// Reputation score
    pub reputation: Option<i32>,
    /// Total votes
    pub total_votes: Option<VtVotes>,
}

/// VirusTotal community votes
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtVotes {
    pub harmless: u32,
    pub malicious: u32,
}

/// VirusTotal domain report
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtDomainReport {
    /// The domain analyzed
    pub domain: String,
    /// Registrar
    pub registrar: Option<String>,
    /// Creation date
    pub creation_date: Option<DateTime<Utc>>,
    /// Last DNS records
    pub last_dns_records: Vec<DnsRecord>,
    /// Analysis statistics
    pub stats: VtAnalysisStats,
    /// Categories
    pub categories: HashMap<String, String>,
    /// Reputation score
    pub reputation: Option<i32>,
    /// Whois data
    pub whois: Option<String>,
}

/// DNS record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: Option<u32>,
}

/// VirusTotal IP report
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtIpReport {
    /// The IP address
    pub ip: String,
    /// AS owner
    pub as_owner: Option<String>,
    /// ASN
    pub asn: Option<u32>,
    /// Country
    pub country: Option<String>,
    /// Analysis statistics
    pub stats: VtAnalysisStats,
    /// Reputation score
    pub reputation: Option<i32>,
    /// Tags
    pub tags: Vec<String>,
}

/// VirusTotal client configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VtConfig {
    /// API key (or env var name)
    #[serde(default)]
    pub api_key_env: String,

    /// Whether to enable VT lookups
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// API endpoint (for private cloud)
    #[serde(default = "default_vt_endpoint")]
    pub endpoint: String,

    /// Request timeout
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    /// Cache TTL for positive results (hours)
    #[serde(default = "default_positive_ttl")]
    pub cache_ttl_positive_hours: u32,

    /// Cache TTL for negative results (hours)
    #[serde(default = "default_negative_ttl")]
    pub cache_ttl_negative_hours: u32,

    /// Minimum detections to block
    #[serde(default = "default_min_detections")]
    pub min_detections_block: u32,

    /// Minimum detections to warn
    #[serde(default = "default_min_warn")]
    pub min_detections_warn: u32,

    /// Check file hashes
    #[serde(default = "default_true")]
    pub check_files: bool,

    /// Check URLs
    #[serde(default = "default_true")]
    pub check_urls: bool,

    /// Check domains
    #[serde(default = "default_true")]
    pub check_domains: bool,

    /// Check IPs
    #[serde(default = "default_true")]
    pub check_ips: bool,

    /// Rate limit (requests per minute)
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,

    /// Fail open if API unavailable
    #[serde(default = "default_true")]
    pub fail_open: bool,
}

fn default_true() -> bool { true }
fn default_vt_endpoint() -> String { "https://www.virustotal.com/api/v3".to_string() }
fn default_timeout() -> u64 { 10000 }
fn default_positive_ttl() -> u32 { 24 }
fn default_negative_ttl() -> u32 { 1 }
fn default_min_detections() -> u32 { 3 }
fn default_min_warn() -> u32 { 1 }
fn default_rate_limit() -> u32 { 4 } // Free tier: 4/min

impl Default for VtConfig {
    fn default() -> Self {
        Self {
            api_key_env: "VIRUSTOTAL_API_KEY".to_string(),
            enabled: true,
            endpoint: default_vt_endpoint(),
            timeout_ms: default_timeout(),
            cache_ttl_positive_hours: default_positive_ttl(),
            cache_ttl_negative_hours: default_negative_ttl(),
            min_detections_block: default_min_detections(),
            min_detections_warn: default_min_warn(),
            check_files: true,
            check_urls: true,
            check_domains: true,
            check_ips: true,
            rate_limit_per_minute: default_rate_limit(),
            fail_open: true,
        }
    }
}

/// VirusTotal client errors
#[derive(Debug, thiserror::Error)]
pub enum VtError {
    #[error("API key not configured")]
    NoApiKey,
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("Rate limited")]
    RateLimited,
    #[error("Resource not found")]
    NotFound,
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Timeout after {0}ms")]
    Timeout(u64),
}

/// VirusTotal client trait
#[async_trait]
pub trait VtClient: Send + Sync {
    /// Look up a file by hash (MD5, SHA1, or SHA256)
    async fn get_file_report(&self, hash: &str) -> Result<VtFileReport, VtError>;

    /// Scan a URL
    async fn get_url_report(&self, url: &str) -> Result<VtUrlReport, VtError>;

    /// Get domain report
    async fn get_domain_report(&self, domain: &str) -> Result<VtDomainReport, VtError>;

    /// Get IP report
    async fn get_ip_report(&self, ip: &str) -> Result<VtIpReport, VtError>;

    /// Submit a file for scanning (returns analysis ID)
    async fn submit_file(&self, content: &[u8], filename: &str) -> Result<String, VtError>;

    /// Submit a URL for scanning (returns analysis ID)
    async fn submit_url(&self, url: &str) -> Result<String, VtError>;
}

/// Rate limiter for API calls
pub struct RateLimiter {
    /// Semaphore for concurrent requests
    semaphore: Semaphore,
    /// Requests per window
    requests_per_window: u32,
    /// Window duration
    window: Duration,
    /// Request timestamps
    timestamps: RwLock<Vec<std::time::Instant>>,
}

impl RateLimiter {
    pub fn new(requests_per_minute: u32) -> Self {
        Self {
            semaphore: Semaphore::new(requests_per_minute as usize),
            requests_per_window: requests_per_minute,
            window: Duration::from_secs(60),
            timestamps: RwLock::new(Vec::new()),
        }
    }

    pub async fn acquire(&self) -> Result<(), VtError> {
        // Clean old timestamps
        let now = std::time::Instant::now();
        {
            let mut timestamps = self.timestamps.write().await;
            timestamps.retain(|t| now.duration_since(*t) < self.window);

            if timestamps.len() >= self.requests_per_window as usize {
                return Err(VtError::RateLimited);
            }

            timestamps.push(now);
        }

        Ok(())
    }
}

/// Cache entry for VT results
#[derive(Clone, Debug, Serialize, Deserialize)]
struct CacheEntry<T> {
    value: T,
    cached_at: DateTime<Utc>,
    ttl_hours: u32,
}

impl<T> CacheEntry<T> {
    fn is_valid(&self) -> bool {
        let age = Utc::now() - self.cached_at;
        age.num_hours() < self.ttl_hours as i64
    }
}

/// Default VirusTotal client implementation
pub struct DefaultVtClient {
    config: VtConfig,
    api_key: String,
    http_client: reqwest::Client,
    rate_limiter: RateLimiter,
    /// File hash cache
    file_cache: Arc<RwLock<HashMap<String, CacheEntry<VtFileReport>>>>,
    /// URL cache
    url_cache: Arc<RwLock<HashMap<String, CacheEntry<VtUrlReport>>>>,
    /// Domain cache
    domain_cache: Arc<RwLock<HashMap<String, CacheEntry<VtDomainReport>>>>,
    /// IP cache
    ip_cache: Arc<RwLock<HashMap<String, CacheEntry<VtIpReport>>>>,
}

impl DefaultVtClient {
    pub fn new(config: VtConfig) -> Result<Self, VtError> {
        let api_key = std::env::var(&config.api_key_env)
            .map_err(|_| VtError::NoApiKey)?;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| VtError::RequestFailed(e.to_string()))?;

        let rate_limiter = RateLimiter::new(config.rate_limit_per_minute);

        Ok(Self {
            config,
            api_key,
            http_client,
            rate_limiter,
            file_cache: Arc::new(RwLock::new(HashMap::new())),
            url_cache: Arc::new(RwLock::new(HashMap::new())),
            domain_cache: Arc::new(RwLock::new(HashMap::new())),
            ip_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn get_ttl(&self, is_malicious: bool) -> u32 {
        if is_malicious {
            self.config.cache_ttl_positive_hours
        } else {
            self.config.cache_ttl_negative_hours
        }
    }
}

#[async_trait]
impl VtClient for DefaultVtClient {
    async fn get_file_report(&self, hash: &str) -> Result<VtFileReport, VtError> {
        let hash = hash.to_lowercase();

        // Check cache
        {
            let cache = self.file_cache.read().await;
            if let Some(entry) = cache.get(&hash) {
                if entry.is_valid() {
                    return Ok(entry.value.clone());
                }
            }
        }

        // Rate limit
        self.rate_limiter.acquire().await?;

        // Make request
        let url = format!("{}/files/{}", self.config.endpoint, hash);
        let response = self.http_client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| VtError::RequestFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(VtError::NotFound);
        }

        if response.status() == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(VtError::RateLimited);
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| VtError::ParseError(e.to_string()))?;

        // Parse response into VtFileReport
        let report = Self::parse_file_report(&json, &hash)?;

        // Cache result
        {
            let mut cache = self.file_cache.write().await;
            let ttl = self.get_ttl(report.stats.malicious > 0);
            cache.insert(hash, CacheEntry {
                value: report.clone(),
                cached_at: Utc::now(),
                ttl_hours: ttl,
            });
        }

        Ok(report)
    }

    async fn get_url_report(&self, url: &str) -> Result<VtUrlReport, VtError> {
        // URL ID is base64 of URL without padding
        let url_id = base64::encode_config(url, base64::URL_SAFE_NO_PAD);

        // Check cache
        {
            let cache = self.url_cache.read().await;
            if let Some(entry) = cache.get(url) {
                if entry.is_valid() {
                    return Ok(entry.value.clone());
                }
            }
        }

        // Rate limit
        self.rate_limiter.acquire().await?;

        // Make request
        let api_url = format!("{}/urls/{}", self.config.endpoint, url_id);
        let response = self.http_client
            .get(&api_url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| VtError::RequestFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            // URL not in database, submit for scanning
            return Err(VtError::NotFound);
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| VtError::ParseError(e.to_string()))?;

        let report = Self::parse_url_report(&json, url)?;

        // Cache
        {
            let mut cache = self.url_cache.write().await;
            let ttl = self.get_ttl(report.stats.malicious > 0);
            cache.insert(url.to_string(), CacheEntry {
                value: report.clone(),
                cached_at: Utc::now(),
                ttl_hours: ttl,
            });
        }

        Ok(report)
    }

    async fn get_domain_report(&self, domain: &str) -> Result<VtDomainReport, VtError> {
        let domain = domain.to_lowercase();

        // Check cache
        {
            let cache = self.domain_cache.read().await;
            if let Some(entry) = cache.get(&domain) {
                if entry.is_valid() {
                    return Ok(entry.value.clone());
                }
            }
        }

        self.rate_limiter.acquire().await?;

        let url = format!("{}/domains/{}", self.config.endpoint, domain);
        let response = self.http_client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| VtError::RequestFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(VtError::NotFound);
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| VtError::ParseError(e.to_string()))?;

        let report = Self::parse_domain_report(&json, &domain)?;

        // Cache
        {
            let mut cache = self.domain_cache.write().await;
            let ttl = self.get_ttl(report.stats.malicious > 0);
            cache.insert(domain, CacheEntry {
                value: report.clone(),
                cached_at: Utc::now(),
                ttl_hours: ttl,
            });
        }

        Ok(report)
    }

    async fn get_ip_report(&self, ip: &str) -> Result<VtIpReport, VtError> {
        // Similar implementation to domain report
        self.rate_limiter.acquire().await?;

        let url = format!("{}/ip_addresses/{}", self.config.endpoint, ip);
        let response = self.http_client
            .get(&url)
            .header("x-apikey", &self.api_key)
            .send()
            .await
            .map_err(|e| VtError::RequestFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(VtError::NotFound);
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| VtError::ParseError(e.to_string()))?;

        Self::parse_ip_report(&json, ip)
    }

    async fn submit_file(&self, content: &[u8], filename: &str) -> Result<String, VtError> {
        self.rate_limiter.acquire().await?;

        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(content.to_vec())
                .file_name(filename.to_string()));

        let url = format!("{}/files", self.config.endpoint);
        let response = self.http_client
            .post(&url)
            .header("x-apikey", &self.api_key)
            .multipart(form)
            .send()
            .await
            .map_err(|e| VtError::RequestFailed(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| VtError::ParseError(e.to_string()))?;

        json["data"]["id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| VtError::ParseError("Missing analysis ID".to_string()))
    }

    async fn submit_url(&self, url: &str) -> Result<String, VtError> {
        self.rate_limiter.acquire().await?;

        let api_url = format!("{}/urls", self.config.endpoint);
        let response = self.http_client
            .post(&api_url)
            .header("x-apikey", &self.api_key)
            .form(&[("url", url)])
            .send()
            .await
            .map_err(|e| VtError::RequestFailed(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| VtError::ParseError(e.to_string()))?;

        json["data"]["id"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| VtError::ParseError("Missing analysis ID".to_string()))
    }
}

impl DefaultVtClient {
    fn parse_file_report(json: &serde_json::Value, hash: &str) -> Result<VtFileReport, VtError> {
        let data = &json["data"]["attributes"];

        let stats = VtAnalysisStats {
            malicious: data["last_analysis_stats"]["malicious"].as_u64().unwrap_or(0) as u32,
            suspicious: data["last_analysis_stats"]["suspicious"].as_u64().unwrap_or(0) as u32,
            undetected: data["last_analysis_stats"]["undetected"].as_u64().unwrap_or(0) as u32,
            timeout: data["last_analysis_stats"]["timeout"].as_u64().unwrap_or(0) as u32,
            failure: data["last_analysis_stats"]["failure"].as_u64().unwrap_or(0) as u32,
            type_unsupported: data["last_analysis_stats"]["type-unsupported"].as_u64().unwrap_or(0) as u32,
        };

        Ok(VtFileReport {
            resource: hash.to_string(),
            sha256: data["sha256"].as_str().unwrap_or(hash).to_string(),
            sha1: data["sha1"].as_str().map(String::from),
            md5: data["md5"].as_str().map(String::from),
            size: data["size"].as_u64(),
            type_description: data["type_description"].as_str().map(String::from),
            stats,
            results: HashMap::new(), // Would parse full results
            popular_threat_label: data["popular_threat_classification"]["popular_threat_name"]
                .as_str().map(String::from),
            suggested_threat_label: data["popular_threat_classification"]["suggested_threat_label"]
                .as_str().map(String::from),
            first_submission_date: None,
            last_analysis_date: None,
            permalink: None,
        })
    }

    fn parse_url_report(json: &serde_json::Value, url: &str) -> Result<VtUrlReport, VtError> {
        let data = &json["data"]["attributes"];

        let stats = VtAnalysisStats {
            malicious: data["last_analysis_stats"]["malicious"].as_u64().unwrap_or(0) as u32,
            suspicious: data["last_analysis_stats"]["suspicious"].as_u64().unwrap_or(0) as u32,
            undetected: data["last_analysis_stats"]["undetected"].as_u64().unwrap_or(0) as u32,
            timeout: data["last_analysis_stats"]["timeout"].as_u64().unwrap_or(0) as u32,
            failure: 0,
            type_unsupported: 0,
        };

        Ok(VtUrlReport {
            url: url.to_string(),
            final_url: data["last_final_url"].as_str().map(String::from),
            stats,
            results: HashMap::new(),
            categories: HashMap::new(),
            last_http_response_code: data["last_http_response_code"].as_u64().map(|c| c as u16),
            last_analysis_date: None,
            reputation: data["reputation"].as_i64().map(|r| r as i32),
            total_votes: None,
        })
    }

    fn parse_domain_report(json: &serde_json::Value, domain: &str) -> Result<VtDomainReport, VtError> {
        let data = &json["data"]["attributes"];

        let stats = VtAnalysisStats {
            malicious: data["last_analysis_stats"]["malicious"].as_u64().unwrap_or(0) as u32,
            suspicious: data["last_analysis_stats"]["suspicious"].as_u64().unwrap_or(0) as u32,
            undetected: data["last_analysis_stats"]["undetected"].as_u64().unwrap_or(0) as u32,
            timeout: data["last_analysis_stats"]["timeout"].as_u64().unwrap_or(0) as u32,
            failure: 0,
            type_unsupported: 0,
        };

        Ok(VtDomainReport {
            domain: domain.to_string(),
            registrar: data["registrar"].as_str().map(String::from),
            creation_date: None,
            last_dns_records: vec![],
            stats,
            categories: HashMap::new(),
            reputation: data["reputation"].as_i64().map(|r| r as i32),
            whois: data["whois"].as_str().map(String::from),
        })
    }

    fn parse_ip_report(json: &serde_json::Value, ip: &str) -> Result<VtIpReport, VtError> {
        let data = &json["data"]["attributes"];

        let stats = VtAnalysisStats {
            malicious: data["last_analysis_stats"]["malicious"].as_u64().unwrap_or(0) as u32,
            suspicious: data["last_analysis_stats"]["suspicious"].as_u64().unwrap_or(0) as u32,
            undetected: data["last_analysis_stats"]["undetected"].as_u64().unwrap_or(0) as u32,
            timeout: data["last_analysis_stats"]["timeout"].as_u64().unwrap_or(0) as u32,
            failure: 0,
            type_unsupported: 0,
        };

        Ok(VtIpReport {
            ip: ip.to_string(),
            as_owner: data["as_owner"].as_str().map(String::from),
            asn: data["asn"].as_u64().map(|n| n as u32),
            country: data["country"].as_str().map(String::from),
            stats,
            reputation: data["reputation"].as_i64().map(|r| r as i32),
            tags: vec![],
        })
    }
}

// ============================================================================
// VirusTotal Guard
// ============================================================================

/// VirusTotal guard configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VirusTotalGuardConfig {
    /// VirusTotal client config
    #[serde(flatten)]
    pub vt: VtConfig,

    /// Check file writes
    #[serde(default = "default_true")]
    pub check_file_writes: bool,

    /// Check network egress URLs
    #[serde(default = "default_true")]
    pub check_egress_urls: bool,

    /// Check network egress domains
    #[serde(default = "default_true")]
    pub check_egress_domains: bool,

    /// Async mode (submit and continue, check later)
    #[serde(default)]
    pub async_mode: bool,
}

impl Default for VirusTotalGuardConfig {
    fn default() -> Self {
        Self {
            vt: VtConfig::default(),
            check_file_writes: true,
            check_egress_urls: true,
            check_egress_domains: true,
            async_mode: false,
        }
    }
}

/// VirusTotal guard implementation
pub struct VirusTotalGuard {
    config: VirusTotalGuardConfig,
    client: Arc<dyn VtClient>,
}

impl VirusTotalGuard {
    pub fn new(config: VirusTotalGuardConfig) -> Result<Self, VtError> {
        let client = Arc::new(DefaultVtClient::new(config.vt.clone())?);
        Ok(Self { config, client })
    }

    /// Compute SHA256 hash of content
    fn compute_sha256(content: &[u8]) -> String {
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(content);
        format!("{:x}", hasher.finalize())
    }

    /// Extract URL from egress action
    fn extract_url(host: &str, port: u16) -> String {
        let scheme = if port == 443 { "https" } else { "http" };
        format!("{}://{}", scheme, host)
    }
}

#[async_trait]
impl Guard for VirusTotalGuard {
    fn name(&self) -> &str {
        "virustotal"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        match action {
            GuardAction::FileWrite(_, _) => self.config.check_file_writes,
            GuardAction::NetworkEgress(_, _) => {
                self.config.check_egress_urls || self.config.check_egress_domains
            }
            _ => false,
        }
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.config.vt.enabled {
            return GuardResult::allow(self.name());
        }

        match action {
            GuardAction::FileWrite(path, content) => {
                let hash = Self::compute_sha256(content);

                match self.client.get_file_report(&hash).await {
                    Ok(report) => {
                        if report.stats.is_malicious(self.config.vt.min_detections_block) {
                            return GuardResult::block(
                                self.name(),
                                Severity::Critical,
                                format!(
                                    "VirusTotal: {}/{} detections for {}. Threat: {}",
                                    report.stats.malicious,
                                    report.stats.total_analyzed(),
                                    path,
                                    report.popular_threat_label.unwrap_or_else(|| "Unknown".to_string())
                                ),
                            );
                        }

                        if report.stats.malicious >= self.config.vt.min_detections_warn {
                            return GuardResult::warn(
                                self.name(),
                                format!(
                                    "VirusTotal: {}/{} detections for {}",
                                    report.stats.malicious,
                                    report.stats.total_analyzed(),
                                    path
                                ),
                            );
                        }

                        GuardResult::allow(self.name())
                    }
                    Err(VtError::NotFound) => {
                        // Hash not in VT database - allow (unknown)
                        GuardResult::allow(self.name())
                    }
                    Err(VtError::RateLimited) => {
                        if self.config.vt.fail_open {
                            GuardResult::warn(self.name(), "VirusTotal rate limited")
                        } else {
                            GuardResult::block(
                                self.name(),
                                Severity::Warning,
                                "VirusTotal rate limited, blocking in strict mode",
                            )
                        }
                    }
                    Err(e) => {
                        if self.config.vt.fail_open {
                            GuardResult::warn(self.name(), format!("VirusTotal error: {}", e))
                        } else {
                            GuardResult::block(
                                self.name(),
                                Severity::Warning,
                                format!("VirusTotal error: {}", e),
                            )
                        }
                    }
                }
            }
            GuardAction::NetworkEgress(host, port) => {
                // Check domain first
                if self.config.check_egress_domains {
                    match self.client.get_domain_report(host).await {
                        Ok(report) => {
                            if report.stats.is_malicious(self.config.vt.min_detections_block) {
                                return GuardResult::block(
                                    self.name(),
                                    Severity::Critical,
                                    format!(
                                        "VirusTotal: Domain {} has {}/{} malicious detections",
                                        host,
                                        report.stats.malicious,
                                        report.stats.total_analyzed()
                                    ),
                                );
                            }

                            if report.stats.malicious >= self.config.vt.min_detections_warn {
                                return GuardResult::warn(
                                    self.name(),
                                    format!(
                                        "VirusTotal: Domain {} has {} detections",
                                        host,
                                        report.stats.malicious
                                    ),
                                );
                            }
                        }
                        Err(VtError::NotFound) => {
                            // Domain not in VT - that's fine
                        }
                        Err(VtError::RateLimited) if !self.config.vt.fail_open => {
                            return GuardResult::block(
                                self.name(),
                                Severity::Warning,
                                "VirusTotal rate limited",
                            );
                        }
                        Err(_) => {}
                    }
                }

                GuardResult::allow(self.name())
            }
            _ => GuardResult::allow(self.name()),
        }
    }
}

// ============================================================================
// urlscan.io Integration
// ============================================================================

/// urlscan.io scan result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlscanResult {
    /// Scan UUID
    pub uuid: String,
    /// Scan URL
    pub url: String,
    /// Final URL after redirects
    pub final_url: Option<String>,
    /// Overall verdict
    pub verdict: UrlscanVerdict,
    /// Threat categories
    pub categories: Vec<String>,
    /// Screenshot URL
    pub screenshot_url: Option<String>,
    /// DOM URL
    pub dom_url: Option<String>,
    /// Page statistics
    pub stats: UrlscanStats,
    /// Detected technologies
    pub technologies: Vec<String>,
    /// Geographic data
    pub geo: Option<UrlscanGeo>,
    /// Certificates
    pub certificates: Vec<UrlscanCert>,
    /// Is the URL malicious?
    pub malicious: bool,
    /// Scan timestamp
    pub scanned_at: DateTime<Utc>,
}

/// urlscan verdict
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlscanVerdict {
    /// Overall score (0-100, higher = more malicious)
    pub score: u32,
    /// Verdict categories
    pub categories: Vec<String>,
    /// Brands targeted (for phishing)
    pub brands: Vec<String>,
    /// Is malicious?
    pub malicious: bool,
    /// Has known malicious indicators
    pub has_verdict: bool,
}

/// urlscan statistics
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlscanStats {
    /// Number of requests
    pub requests: u32,
    /// Number of IPs contacted
    pub ips: u32,
    /// Number of domains contacted
    pub domains: u32,
    /// Data transferred (bytes)
    pub data_length: u64,
}

/// Geographic information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlscanGeo {
    pub country: Option<String>,
    pub city: Option<String>,
    pub ip: Option<String>,
}

/// Certificate information
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlscanCert {
    pub subject: String,
    pub issuer: String,
    pub valid_from: Option<DateTime<Utc>>,
    pub valid_to: Option<DateTime<Utc>>,
}

/// urlscan.io client configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UrlscanConfig {
    /// API key env var
    #[serde(default = "default_urlscan_key")]
    pub api_key_env: String,

    /// Whether enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// API endpoint
    #[serde(default = "default_urlscan_endpoint")]
    pub endpoint: String,

    /// Request timeout (ms)
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    /// Visibility for submissions
    #[serde(default = "default_visibility")]
    pub visibility: String,

    /// Score threshold to block
    #[serde(default = "default_score_threshold")]
    pub score_threshold_block: u32,

    /// Score threshold to warn
    #[serde(default = "default_score_warn")]
    pub score_threshold_warn: u32,

    /// Cache TTL (hours)
    #[serde(default = "default_positive_ttl")]
    pub cache_ttl_hours: u32,

    /// Rate limit (per minute)
    #[serde(default = "default_urlscan_rate")]
    pub rate_limit_per_minute: u32,

    /// Poll interval for async scans (ms)
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,

    /// Max poll attempts
    #[serde(default = "default_max_polls")]
    pub max_poll_attempts: u32,
}

fn default_urlscan_key() -> String { "URLSCAN_API_KEY".to_string() }
fn default_urlscan_endpoint() -> String { "https://urlscan.io/api/v1".to_string() }
fn default_visibility() -> String { "private".to_string() }
fn default_score_threshold() -> u32 { 50 }
fn default_score_warn() -> u32 { 25 }
fn default_urlscan_rate() -> u32 { 60 }
fn default_poll_interval() -> u64 { 5000 }
fn default_max_polls() -> u32 { 12 }

impl Default for UrlscanConfig {
    fn default() -> Self {
        Self {
            api_key_env: default_urlscan_key(),
            enabled: true,
            endpoint: default_urlscan_endpoint(),
            timeout_ms: default_timeout(),
            visibility: default_visibility(),
            score_threshold_block: default_score_threshold(),
            score_threshold_warn: default_score_warn(),
            cache_ttl_hours: default_positive_ttl(),
            rate_limit_per_minute: default_urlscan_rate(),
            poll_interval_ms: default_poll_interval(),
            max_poll_attempts: default_max_polls(),
        }
    }
}

/// urlscan.io client trait
#[async_trait]
pub trait UrlscanClient: Send + Sync {
    /// Submit a URL for scanning
    async fn submit(&self, url: &str) -> Result<String, UrlscanError>;

    /// Get scan result by UUID
    async fn get_result(&self, uuid: &str) -> Result<UrlscanResult, UrlscanError>;

    /// Search for existing scans of a URL
    async fn search(&self, url: &str) -> Result<Vec<UrlscanResult>, UrlscanError>;

    /// Submit and wait for result
    async fn scan_and_wait(&self, url: &str) -> Result<UrlscanResult, UrlscanError>;
}

/// urlscan.io errors
#[derive(Debug, thiserror::Error)]
pub enum UrlscanError {
    #[error("API key not configured")]
    NoApiKey,
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("Rate limited")]
    RateLimited,
    #[error("Scan not ready")]
    NotReady,
    #[error("Scan failed: {0}")]
    ScanFailed(String),
    #[error("Parse error: {0}")]
    ParseError(String),
    #[error("Timeout")]
    Timeout,
}

/// Default urlscan.io client implementation
pub struct DefaultUrlscanClient {
    config: UrlscanConfig,
    api_key: String,
    http_client: reqwest::Client,
    rate_limiter: RateLimiter,
    cache: Arc<RwLock<HashMap<String, CacheEntry<UrlscanResult>>>>,
}

impl DefaultUrlscanClient {
    pub fn new(config: UrlscanConfig) -> Result<Self, UrlscanError> {
        let api_key = std::env::var(&config.api_key_env)
            .map_err(|_| UrlscanError::NoApiKey)?;

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.timeout_ms))
            .build()
            .map_err(|e| UrlscanError::RequestFailed(e.to_string()))?;

        Ok(Self {
            config: config.clone(),
            api_key,
            http_client,
            rate_limiter: RateLimiter::new(config.rate_limit_per_minute),
            cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

#[async_trait]
impl UrlscanClient for DefaultUrlscanClient {
    async fn submit(&self, url: &str) -> Result<String, UrlscanError> {
        self.rate_limiter.acquire().await
            .map_err(|_| UrlscanError::RateLimited)?;

        let api_url = format!("{}/scan/", self.config.endpoint);
        let response = self.http_client
            .post(&api_url)
            .header("API-Key", &self.api_key)
            .json(&serde_json::json!({
                "url": url,
                "visibility": self.config.visibility
            }))
            .send()
            .await
            .map_err(|e| UrlscanError::RequestFailed(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| UrlscanError::ParseError(e.to_string()))?;

        json["uuid"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| UrlscanError::ParseError("Missing UUID".to_string()))
    }

    async fn get_result(&self, uuid: &str) -> Result<UrlscanResult, UrlscanError> {
        let api_url = format!("{}/result/{}/", self.config.endpoint, uuid);
        let response = self.http_client
            .get(&api_url)
            .send()
            .await
            .map_err(|e| UrlscanError::RequestFailed(e.to_string()))?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(UrlscanError::NotReady);
        }

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| UrlscanError::ParseError(e.to_string()))?;

        Self::parse_result(&json)
    }

    async fn search(&self, url: &str) -> Result<Vec<UrlscanResult>, UrlscanError> {
        let encoded_url = urlencoding::encode(url);
        let api_url = format!(
            "{}/search/?q=page.url:\"{}\"",
            self.config.endpoint,
            encoded_url
        );

        let response = self.http_client
            .get(&api_url)
            .send()
            .await
            .map_err(|e| UrlscanError::RequestFailed(e.to_string()))?;

        let json: serde_json::Value = response
            .json()
            .await
            .map_err(|e| UrlscanError::ParseError(e.to_string()))?;

        let results = json["results"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| Self::parse_search_result(v).ok())
                    .collect()
            })
            .unwrap_or_default();

        Ok(results)
    }

    async fn scan_and_wait(&self, url: &str) -> Result<UrlscanResult, UrlscanError> {
        let uuid = self.submit(url).await?;

        for _ in 0..self.config.max_poll_attempts {
            tokio::time::sleep(Duration::from_millis(self.config.poll_interval_ms)).await;

            match self.get_result(&uuid).await {
                Ok(result) => return Ok(result),
                Err(UrlscanError::NotReady) => continue,
                Err(e) => return Err(e),
            }
        }

        Err(UrlscanError::Timeout)
    }
}

impl DefaultUrlscanClient {
    fn parse_result(json: &serde_json::Value) -> Result<UrlscanResult, UrlscanError> {
        let verdicts = &json["verdicts"]["overall"];

        Ok(UrlscanResult {
            uuid: json["task"]["uuid"].as_str().unwrap_or("").to_string(),
            url: json["task"]["url"].as_str().unwrap_or("").to_string(),
            final_url: json["page"]["url"].as_str().map(String::from),
            verdict: UrlscanVerdict {
                score: verdicts["score"].as_u64().unwrap_or(0) as u32,
                categories: verdicts["categories"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                brands: verdicts["brands"]
                    .as_array()
                    .map(|arr| arr.iter().filter_map(|v| v["name"].as_str().map(String::from)).collect())
                    .unwrap_or_default(),
                malicious: verdicts["malicious"].as_bool().unwrap_or(false),
                has_verdict: verdicts["hasVerdicts"].as_bool().unwrap_or(false),
            },
            categories: vec![],
            screenshot_url: json["task"]["screenshotURL"].as_str().map(String::from),
            dom_url: json["task"]["domURL"].as_str().map(String::from),
            stats: UrlscanStats {
                requests: json["stats"]["requests"].as_u64().unwrap_or(0) as u32,
                ips: json["stats"]["ips"].as_u64().unwrap_or(0) as u32,
                domains: json["stats"]["domains"].as_u64().unwrap_or(0) as u32,
                data_length: json["stats"]["dataLength"].as_u64().unwrap_or(0),
            },
            technologies: vec![],
            geo: json["page"]["ip"].as_str().map(|ip| UrlscanGeo {
                country: json["page"]["country"].as_str().map(String::from),
                city: json["page"]["city"].as_str().map(String::from),
                ip: Some(ip.to_string()),
            }),
            certificates: vec![],
            malicious: verdicts["malicious"].as_bool().unwrap_or(false),
            scanned_at: Utc::now(),
        })
    }

    fn parse_search_result(json: &serde_json::Value) -> Result<UrlscanResult, UrlscanError> {
        Ok(UrlscanResult {
            uuid: json["_id"].as_str().unwrap_or("").to_string(),
            url: json["page"]["url"].as_str().unwrap_or("").to_string(),
            final_url: None,
            verdict: UrlscanVerdict {
                score: json["verdicts"]["overall"]["score"].as_u64().unwrap_or(0) as u32,
                categories: vec![],
                brands: vec![],
                malicious: json["verdicts"]["overall"]["malicious"].as_bool().unwrap_or(false),
                has_verdict: true,
            },
            categories: vec![],
            screenshot_url: json["screenshot"].as_str().map(String::from),
            dom_url: None,
            stats: UrlscanStats { requests: 0, ips: 0, domains: 0, data_length: 0 },
            technologies: vec![],
            geo: None,
            certificates: vec![],
            malicious: json["verdicts"]["overall"]["malicious"].as_bool().unwrap_or(false),
            scanned_at: Utc::now(),
        })
    }
}

/// urlscan.io guard
pub struct UrlscanGuard {
    config: UrlscanConfig,
    client: Arc<dyn UrlscanClient>,
}

impl UrlscanGuard {
    pub fn new(config: UrlscanConfig) -> Result<Self, UrlscanError> {
        let client = Arc::new(DefaultUrlscanClient::new(config.clone())?);
        Ok(Self { config, client })
    }
}

#[async_trait]
impl Guard for UrlscanGuard {
    fn name(&self) -> &str {
        "urlscan"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::NetworkEgress(_, _))
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.config.enabled {
            return GuardResult::allow(self.name());
        }

        let GuardAction::NetworkEgress(host, port) = action else {
            return GuardResult::allow(self.name());
        };

        let url = format!(
            "{}://{}",
            if *port == 443 { "https" } else { "http" },
            host
        );

        // Search for existing scan first
        match self.client.search(&url).await {
            Ok(results) if !results.is_empty() => {
                let latest = &results[0];

                if latest.verdict.score >= self.config.score_threshold_block {
                    return GuardResult::block(
                        self.name(),
                        Severity::Critical,
                        format!(
                            "urlscan.io: URL has malicious score {} (threshold: {}). Categories: {}",
                            latest.verdict.score,
                            self.config.score_threshold_block,
                            latest.verdict.categories.join(", ")
                        ),
                    );
                }

                if latest.verdict.score >= self.config.score_threshold_warn {
                    return GuardResult::warn(
                        self.name(),
                        format!(
                            "urlscan.io: URL has suspicious score {}",
                            latest.verdict.score
                        ),
                    );
                }
            }
            Err(UrlscanError::RateLimited) => {
                return GuardResult::warn(self.name(), "urlscan.io rate limited");
            }
            _ => {}
        }

        GuardResult::allow(self.name())
    }
}
```

### 3.2 TypeScript Interface

```typescript
/**
 * @clawdstrike/openclaw - VirusTotal and urlscan.io Integration
 */

/** VirusTotal analysis stats */
export interface VtAnalysisStats {
  malicious: number;
  suspicious: number;
  undetected: number;
  timeout: number;
}

/** VirusTotal configuration */
export interface VtConfig {
  apiKeyEnv?: string;
  enabled?: boolean;
  endpoint?: string;
  timeoutMs?: number;
  cacheTtlPositiveHours?: number;
  cacheTtlNegativeHours?: number;
  minDetectionsBlock?: number;
  minDetectionsWarn?: number;
  checkFiles?: boolean;
  checkUrls?: boolean;
  checkDomains?: boolean;
  rateLimitPerMinute?: number;
  failOpen?: boolean;
}

/** urlscan.io configuration */
export interface UrlscanConfig {
  apiKeyEnv?: string;
  enabled?: boolean;
  endpoint?: string;
  timeoutMs?: number;
  visibility?: 'public' | 'private' | 'unlisted';
  scoreThresholdBlock?: number;
  scoreThresholdWarn?: number;
  cacheTtlHours?: number;
  rateLimitPerMinute?: number;
}

/** Combined external intel guard config */
export interface ExternalIntelConfig {
  virustotal?: VtConfig;
  urlscan?: UrlscanConfig;
}
```

---

## 4. Policy Configuration

```yaml
version: "1.1.0"
guards:
  virustotal:
    enabled: true
    api_key_env: VIRUSTOTAL_API_KEY
    min_detections_block: 3
    min_detections_warn: 1
    check_files: true
    check_urls: true
    check_domains: true
    rate_limit_per_minute: 4
    fail_open: true
    cache_ttl_positive_hours: 24
    cache_ttl_negative_hours: 1

  urlscan:
    enabled: true
    api_key_env: URLSCAN_API_KEY
    visibility: private
    score_threshold_block: 50
    score_threshold_warn: 25
    rate_limit_per_minute: 60
```

---

## 5. Performance Considerations

### 5.1 Caching Strategy

| Cache Type | TTL (Positive) | TTL (Negative) | Rationale |
|------------|----------------|----------------|-----------|
| VT File Hash | 24 hours | 1 hour | Malicious files don't become safe |
| VT URL | 6 hours | 30 min | URLs can change quickly |
| VT Domain | 12 hours | 1 hour | Domain reputation more stable |
| urlscan | 6 hours | 30 min | Fresh scans preferred |

### 5.2 Rate Limiting

```yaml
rate_limits:
  virustotal:
    free_tier: 4/min, 500/day
    premium: configurable
  urlscan:
    free_tier: 60/min
    premium: higher
```

### 5.3 Latency Impact

| Operation | Typical Latency | Strategy |
|-----------|-----------------|----------|
| Cache hit | < 1ms | Always check cache first |
| VT API call | 200-500ms | Async where possible |
| urlscan search | 100-300ms | Use search before submit |
| urlscan submit + poll | 30-60s | Background task |

---

## 6. Security Considerations

### 6.1 API Key Protection

- Store keys in environment variables, never in config files
- Rotate keys regularly
- Use separate keys for different environments

### 6.2 Data Privacy

- urlscan visibility setting controls public exposure
- Consider hashing URLs before submission for privacy
- VT file submissions share file content - use hash lookups when possible

### 6.3 Fail-Safe Behavior

```rust
// Default: fail open (allow on API errors)
// Can be configured to fail closed for high-security environments
fail_open: true
```

---

## 7. Implementation Phases

### Phase 1: VirusTotal (Week 1-2)
- [ ] VT client implementation
- [ ] File hash lookups
- [ ] URL/domain lookups
- [ ] Caching layer

### Phase 2: urlscan.io (Week 2-3)
- [ ] urlscan client
- [ ] Submit + poll flow
- [ ] Search existing scans
- [ ] Guard integration

### Phase 3: Production Ready (Week 3-4)
- [ ] Rate limiting
- [ ] Error handling
- [ ] Metrics/observability
- [ ] Documentation

---

## 8. Related Documents

- [overview.md](./overview.md) - Threat Intelligence Overview
- [blocklists.md](./blocklists.md) - Blocklist Architecture
- [yara-integration.md](./yara-integration.md) - YARA Integration
