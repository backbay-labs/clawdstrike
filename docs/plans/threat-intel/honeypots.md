# Honeypot Paths and Domains Architecture

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0.0-draft |
| Status | Proposal |
| Component | HoneypotGuard |
| Last Updated | 2026-02-02 |

---

## 1. Problem Statement

### 1.1 Current Limitations

The existing `ForbiddenPathGuard` blocks access to sensitive paths but provides no insight into attack attempts. When an agent is compromised or behaving maliciously, it may probe for sensitive resources before finding actual targets. These reconnaissance attempts go undetected with current binary allow/deny guards.

### 1.2 Attack Patterns Not Detected

1. **Credential Harvesting Probes**: Attackers systematically check common credential locations
2. **Configuration Enumeration**: Scanning for config files that reveal infrastructure details
3. **Lateral Movement Attempts**: Probing for access to other systems/services
4. **Data Exfiltration Reconnaissance**: Identifying valuable data before extraction

### 1.3 Goals

- Detect malicious intent through access to decoy resources
- Distinguish accidental access from systematic reconnaissance
- Generate high-fidelity alerts with low false positive rates
- Provide forensic evidence for incident response

---

## 2. Solution Overview

### 2.1 Concept

Honeypot detection places "canary" resources that:
- Have no legitimate use in normal agent operations
- Appear attractive to attackers (credential files, admin endpoints)
- Generate immediate alerts when accessed
- Record detailed telemetry for forensics

### 2.2 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Agent Request                                 │
│  - File access: /var/lib/secrets/admin-creds.json                   │
│  - Network: internal-api.company.local                              │
└───────────────────────────────┬─────────────────────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────────┐
│                      HoneypotGuard                                   │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   Indicator Matcher                          │   │
│  │  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐   │   │
│  │  │  Path Trie    │  │ Domain Index  │  │   IP Set      │   │   │
│  │  │  (fast prefix │  │  (glob match) │  │  (CIDR match) │   │   │
│  │  │   matching)   │  │               │  │               │   │   │
│  │  └───────────────┘  └───────────────┘  └───────────────┘   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                │                                     │
│                                v                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   Alert Classifier                           │   │
│  │  - Single probe vs. systematic scan                          │   │
│  │  - Known attack pattern matching                             │   │
│  │  - Contextual risk scoring                                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                │                                     │
│                                v                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                   Alert Dispatcher                           │   │
│  │  - Immediate block + alert                                   │   │
│  │  - Session termination (optional)                            │   │
│  │  - Forensic data capture                                     │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
                                │
                                v
┌─────────────────────────────────────────────────────────────────────┐
│                      Alert Destinations                              │
│  - Audit log (always)                                               │
│  - SIEM/SOC webhook                                                  │
│  - PagerDuty/Slack integration                                      │
│  - Session quarantine                                                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. API Design

### 3.1 Rust Interface

```rust
//! Honeypot detection guard for Clawdstrike
//!
//! Detects access to canary resources that indicate reconnaissance or attack.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use async_trait::async_trait;
use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::guards::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Severity level for honeypot alerts
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HoneypotAlertSeverity {
    /// Informational - logged but may be accidental
    Info,
    /// Warning - suspicious but could be misconfiguration
    Warning,
    /// High - likely malicious intent
    High,
    /// Critical - definite attack indicator, immediate action required
    Critical,
}

/// Type of honeypot indicator
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HoneypotIndicator {
    /// Filesystem path honeypot
    Path {
        /// Glob pattern for the honeypot path
        pattern: String,
        /// Human-readable description
        description: String,
        /// Alert severity when triggered
        severity: HoneypotAlertSeverity,
        /// Tags for categorization
        #[serde(default)]
        tags: Vec<String>,
    },
    /// Domain/hostname honeypot
    Domain {
        /// Domain pattern (supports wildcards)
        pattern: String,
        /// Description
        description: String,
        /// Alert severity
        severity: HoneypotAlertSeverity,
        #[serde(default)]
        tags: Vec<String>,
    },
    /// IP address/CIDR honeypot
    IpRange {
        /// IP or CIDR notation
        cidr: String,
        /// Description
        description: String,
        /// Alert severity
        severity: HoneypotAlertSeverity,
        #[serde(default)]
        tags: Vec<String>,
    },
    /// URL pattern honeypot
    UrlPattern {
        /// Regex pattern for URL matching
        pattern: String,
        /// Description
        description: String,
        /// Alert severity
        severity: HoneypotAlertSeverity,
        #[serde(default)]
        tags: Vec<String>,
    },
}

/// Honeypot guard configuration
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HoneypotConfig {
    /// Whether the guard is enabled
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// Honeypot indicators (paths, domains, IPs)
    #[serde(default)]
    pub indicators: Vec<HoneypotIndicator>,

    /// Use built-in default honeypots
    #[serde(default = "default_true")]
    pub use_defaults: bool,

    /// Action on honeypot trigger
    #[serde(default)]
    pub on_trigger: HoneypotAction,

    /// Enable session tracking for pattern detection
    #[serde(default)]
    pub track_session: bool,

    /// Threshold for systematic scan detection (triggers in time window)
    #[serde(default = "default_scan_threshold")]
    pub scan_threshold: u32,

    /// Time window for scan detection (seconds)
    #[serde(default = "default_scan_window")]
    pub scan_window_secs: u32,

    /// Webhook URL for alerts (optional)
    #[serde(default)]
    pub alert_webhook: Option<String>,
}

fn default_enabled() -> bool { true }
fn default_true() -> bool { true }
fn default_scan_threshold() -> u32 { 3 }
fn default_scan_window() -> u32 { 60 }

/// Action to take when honeypot is triggered
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoneypotAction {
    /// Block the action and continue
    #[default]
    Block,
    /// Block and terminate the session
    Terminate,
    /// Allow but alert (deception mode)
    AllowAndAlert,
    /// Just log (passive monitoring)
    LogOnly,
}

/// Result of a honeypot check
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HoneypotHit {
    /// The indicator that was triggered
    pub indicator: HoneypotIndicator,
    /// The actual value that triggered it
    pub triggered_by: String,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Session context
    pub session_id: Option<String>,
    /// Whether this appears to be part of a scan
    pub part_of_scan: bool,
    /// Number of honeypot hits in current session
    pub session_hit_count: u32,
}

/// Session tracking state for scan detection
#[derive(Default)]
pub struct HoneypotSessionState {
    /// Recent honeypot hits for this session
    hits: Vec<(chrono::DateTime<chrono::Utc>, String)>,
}

/// Honeypot guard implementation
pub struct HoneypotGuard {
    config: HoneypotConfig,
    /// Compiled path patterns for fast matching
    path_patterns: Vec<(glob::Pattern, HoneypotIndicator)>,
    /// Compiled domain patterns
    domain_patterns: Vec<(globset::GlobMatcher, HoneypotIndicator)>,
    /// IP ranges for CIDR matching
    ip_ranges: Vec<(IpNetwork, HoneypotIndicator)>,
    /// URL regex patterns
    url_patterns: Vec<(regex::Regex, HoneypotIndicator)>,
    /// Session tracking state
    sessions: Arc<RwLock<std::collections::HashMap<String, HoneypotSessionState>>>,
}

impl HoneypotGuard {
    /// Create a new honeypot guard with configuration
    pub fn with_config(config: HoneypotConfig) -> Self {
        let mut guard = Self {
            config: config.clone(),
            path_patterns: Vec::new(),
            domain_patterns: Vec::new(),
            ip_ranges: Vec::new(),
            url_patterns: Vec::new(),
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
        };

        // Load default honeypots
        if config.use_defaults {
            guard.load_defaults();
        }

        // Compile user-defined indicators
        for indicator in &config.indicators {
            guard.add_indicator(indicator.clone());
        }

        guard
    }

    /// Load built-in default honeypot indicators
    fn load_defaults(&mut self) {
        let defaults = vec![
            // Credential file honeypots
            HoneypotIndicator::Path {
                pattern: "**/honeypot-credentials/**".to_string(),
                description: "Honeypot credential directory".to_string(),
                severity: HoneypotAlertSeverity::Critical,
                tags: vec!["credentials".to_string(), "default".to_string()],
            },
            HoneypotIndicator::Path {
                pattern: "**/.secret-admin-key".to_string(),
                description: "Fake admin key file".to_string(),
                severity: HoneypotAlertSeverity::Critical,
                tags: vec!["credentials".to_string(), "default".to_string()],
            },
            HoneypotIndicator::Path {
                pattern: "**/backup-passwords.txt".to_string(),
                description: "Decoy password backup".to_string(),
                severity: HoneypotAlertSeverity::High,
                tags: vec!["credentials".to_string(), "default".to_string()],
            },
            // AWS/Cloud credential honeypots
            HoneypotIndicator::Path {
                pattern: "**/.aws-backup/credentials".to_string(),
                description: "Fake AWS credentials backup".to_string(),
                severity: HoneypotAlertSeverity::Critical,
                tags: vec!["cloud".to_string(), "aws".to_string()],
            },
            HoneypotIndicator::Path {
                pattern: "**/gcp-service-account-backup.json".to_string(),
                description: "Fake GCP service account".to_string(),
                severity: HoneypotAlertSeverity::Critical,
                tags: vec!["cloud".to_string(), "gcp".to_string()],
            },
            // Internal service honeypots
            HoneypotIndicator::Domain {
                pattern: "internal-admin.*.local".to_string(),
                description: "Fake internal admin service".to_string(),
                severity: HoneypotAlertSeverity::High,
                tags: vec!["internal".to_string(), "admin".to_string()],
            },
            HoneypotIndicator::Domain {
                pattern: "vault-backup.*.internal".to_string(),
                description: "Fake Vault backup service".to_string(),
                severity: HoneypotAlertSeverity::Critical,
                tags: vec!["secrets".to_string(), "vault".to_string()],
            },
            // Database honeypots
            HoneypotIndicator::Domain {
                pattern: "db-replica-readonly.*.internal".to_string(),
                description: "Fake database replica".to_string(),
                severity: HoneypotAlertSeverity::High,
                tags: vec!["database".to_string()],
            },
        ];

        for indicator in defaults {
            self.add_indicator(indicator);
        }
    }

    /// Add a honeypot indicator
    fn add_indicator(&mut self, indicator: HoneypotIndicator) {
        match &indicator {
            HoneypotIndicator::Path { pattern, .. } => {
                if let Ok(compiled) = glob::Pattern::new(pattern) {
                    self.path_patterns.push((compiled, indicator));
                }
            }
            HoneypotIndicator::Domain { pattern, .. } => {
                if let Ok(compiled) = globset::GlobBuilder::new(pattern)
                    .case_insensitive(true)
                    .build()
                    .map(|g| g.compile_matcher())
                {
                    self.domain_patterns.push((compiled, indicator));
                }
            }
            HoneypotIndicator::IpRange { cidr, .. } => {
                if let Ok(network) = cidr.parse::<IpNetwork>() {
                    self.ip_ranges.push((network, indicator));
                }
            }
            HoneypotIndicator::UrlPattern { pattern, .. } => {
                if let Ok(compiled) = regex::Regex::new(pattern) {
                    self.url_patterns.push((compiled, indicator));
                }
            }
        }
    }

    /// Check if a path matches any honeypot
    pub fn check_path(&self, path: &str) -> Option<&HoneypotIndicator> {
        for (pattern, indicator) in &self.path_patterns {
            if pattern.matches(path) {
                return Some(indicator);
            }
        }
        None
    }

    /// Check if a domain matches any honeypot
    pub fn check_domain(&self, domain: &str) -> Option<&HoneypotIndicator> {
        for (matcher, indicator) in &self.domain_patterns {
            if matcher.is_match(domain) {
                return Some(indicator);
            }
        }
        None
    }

    /// Check if an IP matches any honeypot range
    pub fn check_ip(&self, ip: IpAddr) -> Option<&HoneypotIndicator> {
        for (network, indicator) in &self.ip_ranges {
            if network.contains(ip) {
                return Some(indicator);
            }
        }
        None
    }

    /// Check if a URL matches any honeypot pattern
    pub fn check_url(&self, url: &str) -> Option<&HoneypotIndicator> {
        for (regex, indicator) in &self.url_patterns {
            if regex.is_match(url) {
                return Some(indicator);
            }
        }
        None
    }

    /// Record a honeypot hit and check for scan patterns
    async fn record_hit(
        &self,
        session_id: &str,
        triggered_by: &str,
    ) -> (bool, u32) {
        if !self.config.track_session {
            return (false, 1);
        }

        let now = chrono::Utc::now();
        let window = chrono::Duration::seconds(self.config.scan_window_secs as i64);
        let threshold = self.config.scan_threshold;

        let mut sessions = self.sessions.write().await;
        let state = sessions.entry(session_id.to_string()).or_default();

        // Add this hit
        state.hits.push((now, triggered_by.to_string()));

        // Clean old hits outside window
        state.hits.retain(|(ts, _)| now - *ts < window);

        let hit_count = state.hits.len() as u32;
        let is_scan = hit_count >= threshold;

        (is_scan, hit_count)
    }

    /// Create alert for honeypot hit
    fn create_alert(
        &self,
        indicator: &HoneypotIndicator,
        triggered_by: &str,
        session_id: Option<&str>,
        is_scan: bool,
        hit_count: u32,
    ) -> HoneypotHit {
        HoneypotHit {
            indicator: indicator.clone(),
            triggered_by: triggered_by.to_string(),
            timestamp: chrono::Utc::now(),
            session_id: session_id.map(String::from),
            part_of_scan: is_scan,
            session_hit_count: hit_count,
        }
    }

    /// Send alert to webhook if configured
    async fn send_webhook_alert(&self, hit: &HoneypotHit) {
        if let Some(ref webhook_url) = self.config.alert_webhook {
            // Non-blocking webhook send
            let url = webhook_url.clone();
            let hit_json = serde_json::to_string(hit).unwrap_or_default();

            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let _ = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(hit_json)
                    .timeout(std::time::Duration::from_secs(5))
                    .send()
                    .await;
            });
        }
    }
}

impl Default for HoneypotGuard {
    fn default() -> Self {
        Self::with_config(HoneypotConfig::default())
    }
}

#[async_trait]
impl Guard for HoneypotGuard {
    fn name(&self) -> &str {
        "honeypot"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(
            action,
            GuardAction::FileAccess(_)
                | GuardAction::FileWrite(_, _)
                | GuardAction::NetworkEgress(_, _)
        )
    }

    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult {
        if !self.config.enabled {
            return GuardResult::allow(self.name());
        }

        // Extract the indicator to check based on action type
        let (indicator, triggered_by) = match action {
            GuardAction::FileAccess(path) | GuardAction::FileWrite(path, _) => {
                match self.check_path(path) {
                    Some(ind) => (ind, *path),
                    None => return GuardResult::allow(self.name()),
                }
            }
            GuardAction::NetworkEgress(host, _port) => {
                // Try domain match first
                if let Some(ind) = self.check_domain(host) {
                    (ind, *host)
                } else if let Ok(ip) = host.parse::<IpAddr>() {
                    match self.check_ip(ip) {
                        Some(ind) => (ind, *host),
                        None => return GuardResult::allow(self.name()),
                    }
                } else {
                    return GuardResult::allow(self.name());
                }
            }
            _ => return GuardResult::allow(self.name()),
        };

        // Record hit and check for scan pattern
        let session_id = context.session_id.as_deref().unwrap_or("unknown");
        let (is_scan, hit_count) = self.record_hit(session_id, triggered_by).await;

        // Create and dispatch alert
        let hit = self.create_alert(
            indicator,
            triggered_by,
            context.session_id.as_deref(),
            is_scan,
            hit_count,
        );

        // Send webhook alert
        self.send_webhook_alert(&hit).await;

        // Determine response based on configuration
        let severity = match indicator {
            HoneypotIndicator::Path { severity, .. }
            | HoneypotIndicator::Domain { severity, .. }
            | HoneypotIndicator::IpRange { severity, .. }
            | HoneypotIndicator::UrlPattern { severity, .. } => severity,
        };

        let guard_severity = match severity {
            HoneypotAlertSeverity::Info => Severity::Info,
            HoneypotAlertSeverity::Warning => Severity::Warning,
            HoneypotAlertSeverity::High => Severity::Error,
            HoneypotAlertSeverity::Critical => Severity::Critical,
        };

        let message = if is_scan {
            format!(
                "HONEYPOT SCAN DETECTED: {} (hit {} honeypots in {}s window)",
                triggered_by, hit_count, self.config.scan_window_secs
            )
        } else {
            format!("HONEYPOT TRIGGERED: {}", triggered_by)
        };

        match self.config.on_trigger {
            HoneypotAction::Block | HoneypotAction::Terminate => {
                GuardResult::block(self.name(), guard_severity, message)
            }
            HoneypotAction::AllowAndAlert | HoneypotAction::LogOnly => {
                GuardResult::warn(self.name(), message)
            }
        }
    }
}
```

### 3.2 TypeScript Interface

```typescript
/**
 * @clawdstrike/openclaw - Honeypot Guard
 *
 * Detects access to canary resources indicating reconnaissance or attack.
 */

import type { Guard, GuardResult, PolicyEvent, Policy } from '../types.js';

/** Severity level for honeypot alerts */
export type HoneypotAlertSeverity = 'info' | 'warning' | 'high' | 'critical';

/** Type of honeypot indicator */
export type HoneypotIndicator =
  | {
      type: 'path';
      pattern: string;
      description: string;
      severity: HoneypotAlertSeverity;
      tags?: string[];
    }
  | {
      type: 'domain';
      pattern: string;
      description: string;
      severity: HoneypotAlertSeverity;
      tags?: string[];
    }
  | {
      type: 'ip_range';
      cidr: string;
      description: string;
      severity: HoneypotAlertSeverity;
      tags?: string[];
    }
  | {
      type: 'url_pattern';
      pattern: string;
      description: string;
      severity: HoneypotAlertSeverity;
      tags?: string[];
    };

/** Action to take when honeypot is triggered */
export type HoneypotAction = 'block' | 'terminate' | 'allow_and_alert' | 'log_only';

/** Honeypot guard configuration */
export interface HoneypotConfig {
  /** Whether the guard is enabled */
  enabled?: boolean;
  /** Custom honeypot indicators */
  indicators?: HoneypotIndicator[];
  /** Use built-in default honeypots */
  useDefaults?: boolean;
  /** Action on honeypot trigger */
  onTrigger?: HoneypotAction;
  /** Enable session tracking for scan detection */
  trackSession?: boolean;
  /** Threshold for systematic scan detection */
  scanThreshold?: number;
  /** Time window for scan detection (seconds) */
  scanWindowSecs?: number;
  /** Webhook URL for alerts */
  alertWebhook?: string;
}

/** Result of a honeypot check */
export interface HoneypotHit {
  indicator: HoneypotIndicator;
  triggeredBy: string;
  timestamp: string;
  sessionId?: string;
  partOfScan: boolean;
  sessionHitCount: number;
}

/** Session state for scan detection */
interface SessionState {
  hits: Array<{ timestamp: Date; value: string }>;
}

/**
 * HoneypotGuard - Detects access to canary resources
 */
export class HoneypotGuard implements Guard {
  private config: Required<HoneypotConfig>;
  private pathPatterns: Array<{ regex: RegExp; indicator: HoneypotIndicator }> = [];
  private domainPatterns: Array<{ regex: RegExp; indicator: HoneypotIndicator }> = [];
  private sessions: Map<string, SessionState> = new Map();

  constructor(config: HoneypotConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      indicators: config.indicators ?? [],
      useDefaults: config.useDefaults ?? true,
      onTrigger: config.onTrigger ?? 'block',
      trackSession: config.trackSession ?? true,
      scanThreshold: config.scanThreshold ?? 3,
      scanWindowSecs: config.scanWindowSecs ?? 60,
      alertWebhook: config.alertWebhook ?? '',
    };

    this.initializePatterns();
  }

  name(): string {
    return 'honeypot';
  }

  handles(): Array<import('../types.js').EventType> {
    return ['file_read', 'file_write', 'network_egress'];
  }

  isEnabled(): boolean {
    return this.config.enabled;
  }

  async check(event: PolicyEvent, _policy: Policy): Promise<GuardResult> {
    if (!this.config.enabled) {
      return { status: 'allow', guard: this.name() };
    }

    const indicator = this.findMatchingIndicator(event);
    if (!indicator) {
      return { status: 'allow', guard: this.name() };
    }

    const triggeredBy = this.extractValue(event);
    const sessionId = event.sessionId ?? 'unknown';
    const { isScanning, hitCount } = this.recordHit(sessionId, triggeredBy);

    // Send webhook alert if configured
    if (this.config.alertWebhook) {
      this.sendWebhookAlert({
        indicator,
        triggeredBy,
        timestamp: new Date().toISOString(),
        sessionId,
        partOfScan: isScanning,
        sessionHitCount: hitCount,
      });
    }

    const message = isScanning
      ? `HONEYPOT SCAN DETECTED: ${triggeredBy} (${hitCount} hits in ${this.config.scanWindowSecs}s)`
      : `HONEYPOT TRIGGERED: ${triggeredBy}`;

    const severity = this.mapSeverity(indicator.severity);

    if (this.config.onTrigger === 'block' || this.config.onTrigger === 'terminate') {
      return { status: 'deny', reason: message, severity, guard: this.name() };
    }

    return { status: 'warn', reason: message, guard: this.name() };
  }

  checkSync(event: PolicyEvent, policy: Policy): GuardResult {
    // Sync version without session tracking or webhooks
    if (!this.config.enabled) {
      return { status: 'allow', guard: this.name() };
    }

    const indicator = this.findMatchingIndicator(event);
    if (!indicator) {
      return { status: 'allow', guard: this.name() };
    }

    const triggeredBy = this.extractValue(event);
    const message = `HONEYPOT TRIGGERED: ${triggeredBy}`;
    const severity = this.mapSeverity(indicator.severity);

    if (this.config.onTrigger === 'block' || this.config.onTrigger === 'terminate') {
      return { status: 'deny', reason: message, severity, guard: this.name() };
    }

    return { status: 'warn', reason: message, guard: this.name() };
  }

  private initializePatterns(): void {
    // Load defaults
    if (this.config.useDefaults) {
      this.loadDefaultIndicators();
    }

    // Add custom indicators
    for (const indicator of this.config.indicators) {
      this.addIndicator(indicator);
    }
  }

  private loadDefaultIndicators(): void {
    const defaults: HoneypotIndicator[] = [
      {
        type: 'path',
        pattern: '**/honeypot-credentials/**',
        description: 'Honeypot credential directory',
        severity: 'critical',
        tags: ['credentials', 'default'],
      },
      {
        type: 'path',
        pattern: '**/.secret-admin-key',
        description: 'Fake admin key file',
        severity: 'critical',
        tags: ['credentials', 'default'],
      },
      {
        type: 'path',
        pattern: '**/backup-passwords.txt',
        description: 'Decoy password backup',
        severity: 'high',
        tags: ['credentials', 'default'],
      },
      {
        type: 'domain',
        pattern: 'internal-admin.*.local',
        description: 'Fake internal admin service',
        severity: 'high',
        tags: ['internal', 'admin'],
      },
      {
        type: 'domain',
        pattern: 'vault-backup.*.internal',
        description: 'Fake Vault backup service',
        severity: 'critical',
        tags: ['secrets', 'vault'],
      },
    ];

    for (const indicator of defaults) {
      this.addIndicator(indicator);
    }
  }

  private addIndicator(indicator: HoneypotIndicator): void {
    if (indicator.type === 'path') {
      const regex = this.globToRegex(indicator.pattern);
      this.pathPatterns.push({ regex, indicator });
    } else if (indicator.type === 'domain') {
      const regex = this.globToRegex(indicator.pattern);
      this.domainPatterns.push({ regex, indicator });
    }
  }

  private globToRegex(pattern: string): RegExp {
    const escaped = pattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '.*')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '.');
    return new RegExp(`^${escaped}$`, 'i');
  }

  private findMatchingIndicator(event: PolicyEvent): HoneypotIndicator | null {
    if (event.data.type === 'file') {
      for (const { regex, indicator } of this.pathPatterns) {
        if (regex.test(event.data.path)) {
          return indicator;
        }
      }
    } else if (event.data.type === 'network') {
      for (const { regex, indicator } of this.domainPatterns) {
        if (regex.test(event.data.host)) {
          return indicator;
        }
      }
    }
    return null;
  }

  private extractValue(event: PolicyEvent): string {
    if (event.data.type === 'file') {
      return event.data.path;
    } else if (event.data.type === 'network') {
      return event.data.host;
    }
    return 'unknown';
  }

  private recordHit(sessionId: string, value: string): { isScanning: boolean; hitCount: number } {
    if (!this.config.trackSession) {
      return { isScanning: false, hitCount: 1 };
    }

    const now = new Date();
    const windowMs = this.config.scanWindowSecs * 1000;

    let state = this.sessions.get(sessionId);
    if (!state) {
      state = { hits: [] };
      this.sessions.set(sessionId, state);
    }

    // Add this hit
    state.hits.push({ timestamp: now, value });

    // Clean old hits
    state.hits = state.hits.filter(
      (h) => now.getTime() - h.timestamp.getTime() < windowMs
    );

    const hitCount = state.hits.length;
    const isScanning = hitCount >= this.config.scanThreshold;

    return { isScanning, hitCount };
  }

  private mapSeverity(severity: HoneypotAlertSeverity): 'low' | 'medium' | 'high' | 'critical' {
    switch (severity) {
      case 'info':
        return 'low';
      case 'warning':
        return 'medium';
      case 'high':
        return 'high';
      case 'critical':
        return 'critical';
    }
  }

  private async sendWebhookAlert(hit: HoneypotHit): Promise<void> {
    if (!this.config.alertWebhook) return;

    try {
      await fetch(this.config.alertWebhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(hit),
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      // Webhook failures are non-fatal
    }
  }
}
```

---

## 4. Data Models and Schemas

### 4.1 Policy Configuration Schema

```yaml
# JSON Schema for honeypot configuration
$schema: http://json-schema.org/draft-07/schema#
title: HoneypotConfig
type: object
properties:
  enabled:
    type: boolean
    default: true
  indicators:
    type: array
    items:
      $ref: '#/definitions/HoneypotIndicator'
  use_defaults:
    type: boolean
    default: true
  on_trigger:
    type: string
    enum: [block, terminate, allow_and_alert, log_only]
    default: block
  track_session:
    type: boolean
    default: true
  scan_threshold:
    type: integer
    minimum: 1
    default: 3
  scan_window_secs:
    type: integer
    minimum: 1
    default: 60
  alert_webhook:
    type: string
    format: uri

definitions:
  HoneypotIndicator:
    oneOf:
      - type: object
        properties:
          type: { const: path }
          pattern: { type: string }
          description: { type: string }
          severity: { $ref: '#/definitions/HoneypotAlertSeverity' }
          tags: { type: array, items: { type: string } }
        required: [type, pattern, severity]
      - type: object
        properties:
          type: { const: domain }
          pattern: { type: string }
          description: { type: string }
          severity: { $ref: '#/definitions/HoneypotAlertSeverity' }
          tags: { type: array, items: { type: string } }
        required: [type, pattern, severity]
      - type: object
        properties:
          type: { const: ip_range }
          cidr: { type: string }
          description: { type: string }
          severity: { $ref: '#/definitions/HoneypotAlertSeverity' }
          tags: { type: array, items: { type: string } }
        required: [type, cidr, severity]
      - type: object
        properties:
          type: { const: url_pattern }
          pattern: { type: string }
          description: { type: string }
          severity: { $ref: '#/definitions/HoneypotAlertSeverity' }
          tags: { type: array, items: { type: string } }
        required: [type, pattern, severity]

  HoneypotAlertSeverity:
    type: string
    enum: [info, warning, high, critical]
```

### 4.2 Alert Event Schema

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "HoneypotAlert",
  "type": "object",
  "properties": {
    "alert_id": { "type": "string", "format": "uuid" },
    "timestamp": { "type": "string", "format": "date-time" },
    "indicator": { "$ref": "#/definitions/HoneypotIndicator" },
    "triggered_by": { "type": "string" },
    "session_id": { "type": "string" },
    "agent_id": { "type": "string" },
    "part_of_scan": { "type": "boolean" },
    "session_hit_count": { "type": "integer" },
    "context": {
      "type": "object",
      "properties": {
        "working_directory": { "type": "string" },
        "previous_actions": { "type": "array", "items": { "type": "string" } }
      }
    }
  },
  "required": ["alert_id", "timestamp", "indicator", "triggered_by"]
}
```

---

## 5. Integration Points

### 5.1 Guard System Integration

```rust
// In policy.rs - add HoneypotConfig to GuardConfigs
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct GuardConfigs {
    // ... existing guards ...

    /// Honeypot guard config
    #[serde(default)]
    pub honeypot: Option<HoneypotConfig>,
}
```

### 5.2 Engine Integration

```rust
// In engine.rs - add HoneypotGuard to the guard chain
impl HushEngine {
    pub fn with_policy(policy: Policy) -> Self {
        let guards = PolicyGuards {
            // ... existing guards ...
            honeypot: policy.guards.honeypot
                .clone()
                .map(HoneypotGuard::with_config)
                .unwrap_or_default(),
        };
        // ...
    }
}
```

### 5.3 Audit Log Integration

```rust
// Honeypot events are logged with special classification
impl AuditLogger {
    pub fn log_honeypot_hit(&self, hit: &HoneypotHit) {
        self.log_event(AuditEvent {
            event_type: AuditEventType::SecurityAlert,
            severity: AuditSeverity::Critical,
            category: "honeypot",
            data: serde_json::to_value(hit).unwrap(),
            // Mark as non-repudiable
            require_signature: true,
        });
    }
}
```

---

## 6. Performance Considerations

### 6.1 Pattern Matching Optimization

| Technique | Description | Benefit |
|-----------|-------------|---------|
| Trie-based path matching | Use prefix tree for path honeypots | O(m) lookup where m = path length |
| Aho-Corasick for multi-pattern | Single pass through input for all patterns | Avoid per-pattern scans |
| Bloom filter pre-check | Fast negative lookup | Skip detailed checks for non-matches |

### 6.2 Memory Management

```rust
// Session state cleanup to prevent memory leaks
impl HoneypotGuard {
    pub async fn cleanup_expired_sessions(&self) {
        let now = chrono::Utc::now();
        let expiry = chrono::Duration::minutes(30);

        let mut sessions = self.sessions.write().await;
        sessions.retain(|_, state| {
            state.hits.last()
                .map(|(ts, _)| now - *ts < expiry)
                .unwrap_or(false)
        });
    }
}
```

### 6.3 Latency Targets

| Operation | Target | Implementation |
|-----------|--------|----------------|
| Path check | < 1ms | Compiled glob patterns |
| Domain check | < 1ms | Pre-compiled regexes |
| Session update | < 5ms | In-memory with async lock |
| Webhook dispatch | Non-blocking | Fire-and-forget with timeout |

---

## 7. Security Considerations

### 7.1 Honeypot Enumeration Prevention

- Honeypot patterns should not be exposed in error messages
- API responses should not distinguish honeypot blocks from regular blocks
- Configuration files should be protected from agent access

### 7.2 False Positive Mitigation

- Honeypot paths should be obviously non-functional names
- Avoid honeypots that could match legitimate resources
- Provide exception mechanisms for legitimate access

### 7.3 Alert Fatigue Prevention

- Aggregate related alerts within time windows
- Rate-limit webhook notifications
- Distinguish single probes from systematic scans

---

## 8. Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)

- [ ] HoneypotConfig data structure
- [ ] Path pattern matching with glob
- [ ] Domain pattern matching
- [ ] Basic GuardResult integration

### Phase 2: Session Tracking (Week 2-3)

- [ ] Session state management
- [ ] Scan detection algorithm
- [ ] Session cleanup mechanisms

### Phase 3: Alerting (Week 3-4)

- [ ] Webhook integration
- [ ] Alert deduplication
- [ ] Audit log integration

### Phase 4: Testing and Hardening (Week 4)

- [ ] Unit tests for all indicator types
- [ ] Integration tests with engine
- [ ] Performance benchmarks
- [ ] Security review

---

## 9. Testing Strategy

### 9.1 Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_path_honeypot_match() {
        let guard = HoneypotGuard::default();
        assert!(guard.check_path("/var/honeypot-credentials/admin.json").is_some());
        assert!(guard.check_path("/app/src/main.rs").is_none());
    }

    #[test]
    fn test_domain_honeypot_match() {
        let guard = HoneypotGuard::default();
        assert!(guard.check_domain("internal-admin.prod.local").is_some());
        assert!(guard.check_domain("api.github.com").is_none());
    }

    #[tokio::test]
    async fn test_scan_detection() {
        let config = HoneypotConfig {
            scan_threshold: 3,
            scan_window_secs: 60,
            track_session: true,
            ..Default::default()
        };
        let guard = HoneypotGuard::with_config(config);

        // First two hits - not a scan
        let (is_scan, _) = guard.record_hit("session-1", "/path1").await;
        assert!(!is_scan);
        let (is_scan, _) = guard.record_hit("session-1", "/path2").await;
        assert!(!is_scan);

        // Third hit - scan detected
        let (is_scan, count) = guard.record_hit("session-1", "/path3").await;
        assert!(is_scan);
        assert_eq!(count, 3);
    }
}
```

### 9.2 Integration Tests

```rust
#[tokio::test]
async fn test_honeypot_guard_in_engine() {
    let policy = Policy::from_yaml(r#"
        version: "1.0.0"
        guards:
          honeypot:
            enabled: true
            indicators:
              - type: path
                pattern: "**/test-honeypot/**"
                description: "Test honeypot"
                severity: critical
    "#).unwrap();

    let engine = HushEngine::with_policy(policy);
    let context = GuardContext::new();

    let result = engine
        .check_file_access("/var/test-honeypot/secret.txt", &context)
        .await
        .unwrap();

    assert!(!result.allowed);
    assert_eq!(result.guard, "honeypot");
}
```

---

## 10. Related Documents

- [overview.md](./overview.md) - Threat Intelligence Subsystem Overview
- [blast-radius.md](./blast-radius.md) - Blast Radius Estimation Design
- [blocklists.md](./blocklists.md) - Blocklist Management Architecture
