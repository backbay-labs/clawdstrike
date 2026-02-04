# YARA Rule Integration Design

## Document Information

| Field | Value |
|-------|-------|
| Version | 1.0.0-draft |
| Status | Proposal |
| Component | YaraGuard, YaraScanner |
| Last Updated | 2026-02-02 |

---

## 1. Problem Statement

### 1.1 The Need for Content Scanning

Current guards analyze paths, domains, and metadata but cannot inspect file content for malicious patterns. This leaves gaps:

1. **Malware Detection**: Downloaded files or generated code may contain malware signatures
2. **Sensitive Data**: Content may contain embedded credentials, PII, or classified data
3. **Attack Patterns**: Shell commands or scripts may contain known exploit patterns
4. **Policy Compliance**: Content may violate organizational policies (license headers, banned patterns)

### 1.2 Why YARA?

YARA is the industry standard for pattern matching in security:

- **Proven**: Used by antivirus vendors, incident responders, and threat researchers
- **Expressive**: Powerful pattern language with logic operators
- **Extensible**: Large ecosystem of community rules
- **Performant**: Optimized for high-throughput scanning

### 1.3 Goals

- Integrate YARA scanning into the guard pipeline
- Support built-in and custom rule sets
- Minimize latency impact on agent operations
- Provide detailed match information for forensics

---

## 2. Architecture

### 2.1 System Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           YaraGuard                                      │
│  - Handles file_write, patch_apply, command_exec events                 │
│  - Extracts content for scanning                                        │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    v
┌─────────────────────────────────────────────────────────────────────────┐
│                        YaraScanner                                       │
│                                                                         │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐        │
│  │  Rule Compiler  │  │  Rule Manager   │  │  Match Engine   │        │
│  │                 │  │                 │  │                 │        │
│  │ - Compile rules │  │ - Load rulesets │  │ - Scan content  │        │
│  │ - Validate      │  │ - Hot reload    │  │ - Return matches│        │
│  │ - Cache         │  │ - Versioning    │  │ - Timeout       │        │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘        │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                     Compiled Rules Cache                         │   │
│  │  - In-memory compiled rules                                      │   │
│  │  - LRU eviction for custom rules                                │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└───────────────────────────────────┬─────────────────────────────────────┘
                                    │
                                    v
┌─────────────────────────────────────────────────────────────────────────┐
│                         Rule Sources                                     │
│                                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐   │
│  │ Clawdstrike │  │  Community  │  │   Custom    │  │   Policy    │   │
│  │   Default   │  │   Rules     │  │   Rules     │  │   Inline    │   │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

```
                        Content Input
                    (file, patch, command)
                             │
                             v
              ┌──────────────────────────────┐
              │       Size Check             │
              │  - Skip if > max_scan_size   │
              │  - Truncate if needed        │
              └──────────────────────────────┘
                             │
                             v
              ┌──────────────────────────────┐
              │     Content Preparation      │
              │  - Decode if needed          │
              │  - Extract text from diff    │
              │  - Normalize line endings    │
              └──────────────────────────────┘
                             │
                             v
              ┌──────────────────────────────┐
              │       Rule Selection         │
              │  - Select applicable rules   │
              │  - Based on file type/tags   │
              └──────────────────────────────┘
                             │
                             v
              ┌──────────────────────────────┐
              │        YARA Scan             │
              │  - Run with timeout          │
              │  - Collect all matches       │
              └──────────────────────────────┘
                             │
                             v
              ┌──────────────────────────────┐
              │      Match Processing        │
              │  - Filter by severity        │
              │  - Deduplicate               │
              │  - Extract context           │
              └──────────────────────────────┘
                             │
                             v
                     Guard Decision
```

---

## 3. API Design

### 3.1 Rust Interface

```rust
//! YARA Integration for Clawdstrike
//!
//! Content scanning using YARA rules for malware and policy detection.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::guards::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// YARA match severity
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum YaraSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

/// A YARA rule definition
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct YaraRule {
    /// Rule name
    pub name: String,
    /// Rule source (YARA syntax)
    pub source: String,
    /// Severity when matched
    pub severity: YaraSeverity,
    /// Tags for categorization
    pub tags: Vec<String>,
    /// Description
    pub description: Option<String>,
    /// Whether match should block
    pub blocking: bool,
    /// File patterns this rule applies to (glob)
    pub file_patterns: Vec<String>,
}

/// A YARA ruleset (collection of rules)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct YaraRuleset {
    /// Ruleset identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// Version
    pub version: String,
    /// Rules in this set
    pub rules: Vec<YaraRule>,
    /// Ruleset-level tags
    pub tags: Vec<String>,
}

/// Source for YARA rules
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum YaraRuleSource {
    /// Built-in Clawdstrike rules
    Builtin {
        name: String,
    },
    /// Local file or directory
    File {
        path: String,
    },
    /// Remote URL
    Remote {
        url: String,
        #[serde(default)]
        auth: Option<String>,
    },
    /// Inline rules in policy
    Inline {
        rules: Vec<YaraRule>,
    },
}

/// Configuration for YARA guard
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct YaraConfig {
    /// Whether YARA scanning is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Rule sources to load
    #[serde(default = "default_sources")]
    pub rule_sources: Vec<YaraRuleSource>,

    /// Maximum content size to scan (bytes)
    #[serde(default = "default_max_size")]
    pub max_scan_bytes: usize,

    /// Scan timeout (milliseconds)
    #[serde(default = "default_timeout")]
    pub scan_timeout_ms: u64,

    /// Maximum rules to load
    #[serde(default = "default_max_rules")]
    pub max_rules: usize,

    /// Severity threshold for blocking
    #[serde(default = "default_block_severity")]
    pub block_severity: YaraSeverity,

    /// Severity threshold for warning
    #[serde(default = "default_warn_severity")]
    pub warn_severity: YaraSeverity,

    /// File patterns to always scan (glob)
    #[serde(default)]
    pub scan_patterns: Vec<String>,

    /// File patterns to never scan (glob)
    #[serde(default = "default_skip_patterns")]
    pub skip_patterns: Vec<String>,

    /// Rule tags to enable (empty = all)
    #[serde(default)]
    pub enabled_tags: Vec<String>,

    /// Rule tags to disable
    #[serde(default)]
    pub disabled_tags: Vec<String>,

    /// Scan shell commands
    #[serde(default = "default_true")]
    pub scan_commands: bool,

    /// Scan patches/diffs
    #[serde(default = "default_true")]
    pub scan_patches: bool,

    /// Include match context in results
    #[serde(default = "default_true")]
    pub include_context: bool,

    /// Context bytes before/after match
    #[serde(default = "default_context_bytes")]
    pub context_bytes: usize,
}

fn default_true() -> bool { true }
fn default_sources() -> Vec<YaraRuleSource> {
    vec![YaraRuleSource::Builtin { name: "default".to_string() }]
}
fn default_max_size() -> usize { 10 * 1024 * 1024 } // 10 MB
fn default_timeout() -> u64 { 5000 } // 5 seconds
fn default_max_rules() -> usize { 1000 }
fn default_block_severity() -> YaraSeverity { YaraSeverity::High }
fn default_warn_severity() -> YaraSeverity { YaraSeverity::Medium }
fn default_skip_patterns() -> Vec<String> {
    vec![
        "*.jpg".to_string(),
        "*.png".to_string(),
        "*.gif".to_string(),
        "*.ico".to_string(),
        "*.woff".to_string(),
        "*.woff2".to_string(),
        "*.ttf".to_string(),
        "*.eot".to_string(),
    ]
}
fn default_context_bytes() -> usize { 64 }

impl Default for YaraConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rule_sources: default_sources(),
            max_scan_bytes: default_max_size(),
            scan_timeout_ms: default_timeout(),
            max_rules: default_max_rules(),
            block_severity: default_block_severity(),
            warn_severity: default_warn_severity(),
            scan_patterns: vec![],
            skip_patterns: default_skip_patterns(),
            enabled_tags: vec![],
            disabled_tags: vec![],
            scan_commands: true,
            scan_patches: true,
            include_context: true,
            context_bytes: default_context_bytes(),
        }
    }
}

/// A YARA match result
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct YaraMatch {
    /// Rule name that matched
    pub rule: String,
    /// Rule tags
    pub tags: Vec<String>,
    /// Match severity
    pub severity: YaraSeverity,
    /// String matches within the rule
    pub strings: Vec<StringMatch>,
    /// Rule metadata
    pub metadata: HashMap<String, String>,
    /// Whether this match blocks
    pub blocking: bool,
}

/// A string match within a YARA rule
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StringMatch {
    /// String identifier (e.g., "$s1")
    pub identifier: String,
    /// Offset in content
    pub offset: usize,
    /// Matched bytes (may be redacted for sensitive matches)
    pub matched_data: Option<String>,
    /// Context before match
    pub context_before: Option<String>,
    /// Context after match
    pub context_after: Option<String>,
}

/// Result of a YARA scan
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct YaraScanResult {
    /// All matches found
    pub matches: Vec<YaraMatch>,
    /// Number of rules checked
    pub rules_checked: usize,
    /// Scan duration in milliseconds
    pub scan_duration_ms: u64,
    /// Whether scan completed (vs. timeout/size limit)
    pub complete: bool,
    /// Bytes scanned
    pub bytes_scanned: usize,
    /// Highest severity match
    pub max_severity: YaraSeverity,
}

impl YaraScanResult {
    pub fn empty() -> Self {
        Self {
            matches: vec![],
            rules_checked: 0,
            scan_duration_ms: 0,
            complete: true,
            bytes_scanned: 0,
            max_severity: YaraSeverity::Info,
        }
    }

    pub fn has_blocking_match(&self) -> bool {
        self.matches.iter().any(|m| m.blocking)
    }

    /// Generate summary message
    pub fn summary(&self) -> String {
        if self.matches.is_empty() {
            return "No YARA rules matched".to_string();
        }

        let blocking_count = self.matches.iter().filter(|m| m.blocking).count();
        let rule_names: Vec<&str> = self.matches.iter().map(|m| m.rule.as_str()).collect();

        if blocking_count > 0 {
            format!(
                "{} YARA rules matched ({} blocking): {}",
                self.matches.len(),
                blocking_count,
                rule_names.join(", ")
            )
        } else {
            format!(
                "{} YARA rules matched: {}",
                self.matches.len(),
                rule_names.join(", ")
            )
        }
    }
}

/// YARA scanner errors
#[derive(Debug, thiserror::Error)]
pub enum YaraError {
    #[error("Compilation failed: {0}")]
    CompilationError(String),
    #[error("Scan failed: {0}")]
    ScanError(String),
    #[error("Timeout after {0}ms")]
    Timeout(u64),
    #[error("Content too large: {0} bytes")]
    ContentTooLarge(usize),
    #[error("Rule load failed: {0}")]
    RuleLoadError(String),
}

/// YARA scanner trait
#[async_trait]
pub trait YaraScanner: Send + Sync {
    /// Scan content with all loaded rules
    async fn scan(&self, content: &[u8]) -> Result<YaraScanResult, YaraError>;

    /// Scan content with specific rules
    async fn scan_with_rules(
        &self,
        content: &[u8],
        rule_names: &[String],
    ) -> Result<YaraScanResult, YaraError>;

    /// Load additional rules
    async fn load_rules(&self, source: &YaraRuleSource) -> Result<usize, YaraError>;

    /// Get loaded rule count
    fn rule_count(&self) -> usize;

    /// Get rule names
    fn rule_names(&self) -> Vec<String>;
}

/// Default YARA scanner implementation using yara-rust
pub struct DefaultYaraScanner {
    config: YaraConfig,
    /// Compiled rules
    rules: Arc<RwLock<yara::Rules>>,
    /// Rule metadata
    rule_metadata: Arc<RwLock<HashMap<String, YaraRule>>>,
}

impl DefaultYaraScanner {
    pub fn new(config: YaraConfig) -> Result<Self, YaraError> {
        let mut compiler = yara::Compiler::new()
            .map_err(|e| YaraError::CompilationError(e.to_string()))?;

        // Load built-in rules
        for source in &config.rule_sources {
            Self::add_rules_to_compiler(&mut compiler, source)?;
        }

        let rules = compiler
            .compile_rules()
            .map_err(|e| YaraError::CompilationError(e.to_string()))?;

        Ok(Self {
            config,
            rules: Arc::new(RwLock::new(rules)),
            rule_metadata: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    fn add_rules_to_compiler(
        compiler: &mut yara::Compiler,
        source: &YaraRuleSource,
    ) -> Result<(), YaraError> {
        match source {
            YaraRuleSource::Builtin { name } => {
                let rules_str = Self::get_builtin_rules(name)?;
                compiler
                    .add_rules_str(&rules_str)
                    .map_err(|e| YaraError::CompilationError(e.to_string()))?;
            }
            YaraRuleSource::File { path } => {
                let path = Path::new(path);
                if path.is_dir() {
                    for entry in std::fs::read_dir(path)
                        .map_err(|e| YaraError::RuleLoadError(e.to_string()))?
                    {
                        let entry = entry.map_err(|e| YaraError::RuleLoadError(e.to_string()))?;
                        let path = entry.path();
                        if path.extension().map(|e| e == "yar" || e == "yara").unwrap_or(false) {
                            compiler
                                .add_rules_file(&path)
                                .map_err(|e| YaraError::CompilationError(e.to_string()))?;
                        }
                    }
                } else {
                    compiler
                        .add_rules_file(path)
                        .map_err(|e| YaraError::CompilationError(e.to_string()))?;
                }
            }
            YaraRuleSource::Inline { rules } => {
                for rule in rules {
                    compiler
                        .add_rules_str(&rule.source)
                        .map_err(|e| YaraError::CompilationError(e.to_string()))?;
                }
            }
            YaraRuleSource::Remote { url, auth } => {
                // Fetch and compile remote rules
                let client = reqwest::blocking::Client::new();
                let mut request = client.get(url);
                if let Some(auth_header) = auth {
                    request = request.header("Authorization", auth_header);
                }
                let response = request
                    .send()
                    .map_err(|e| YaraError::RuleLoadError(e.to_string()))?;
                let rules_str = response
                    .text()
                    .map_err(|e| YaraError::RuleLoadError(e.to_string()))?;
                compiler
                    .add_rules_str(&rules_str)
                    .map_err(|e| YaraError::CompilationError(e.to_string()))?;
            }
        }
        Ok(())
    }

    fn get_builtin_rules(name: &str) -> Result<String, YaraError> {
        match name {
            "default" => Ok(include_str!("../rules/default.yar").to_string()),
            "malware" => Ok(include_str!("../rules/malware.yar").to_string()),
            "secrets" => Ok(include_str!("../rules/secrets.yar").to_string()),
            "webshells" => Ok(include_str!("../rules/webshells.yar").to_string()),
            "exploits" => Ok(include_str!("../rules/exploits.yar").to_string()),
            _ => Err(YaraError::RuleLoadError(format!("Unknown builtin ruleset: {}", name))),
        }
    }

    fn extract_matches(
        &self,
        yara_matches: &[yara::Match],
        content: &[u8],
    ) -> Vec<YaraMatch> {
        yara_matches
            .iter()
            .map(|m| {
                let strings: Vec<StringMatch> = m
                    .strings
                    .iter()
                    .map(|s| {
                        let offset = s.matches.first().map(|m| m.offset).unwrap_or(0);
                        let matched_data = s.matches.first().map(|m| {
                            String::from_utf8_lossy(&m.data).to_string()
                        });

                        // Extract context
                        let (context_before, context_after) = if self.config.include_context {
                            let start = offset.saturating_sub(self.config.context_bytes);
                            let end = (offset + self.config.context_bytes).min(content.len());

                            let before = if start < offset {
                                Some(String::from_utf8_lossy(&content[start..offset]).to_string())
                            } else {
                                None
                            };

                            let match_end = s.matches.first()
                                .map(|m| offset + m.data.len())
                                .unwrap_or(offset);
                            let after = if match_end < end {
                                Some(String::from_utf8_lossy(&content[match_end..end]).to_string())
                            } else {
                                None
                            };

                            (before, after)
                        } else {
                            (None, None)
                        };

                        StringMatch {
                            identifier: s.identifier.clone(),
                            offset,
                            matched_data,
                            context_before,
                            context_after,
                        }
                    })
                    .collect();

                // Parse metadata from rule tags
                let severity = m.tags.iter()
                    .find_map(|t| match t.as_str() {
                        "critical" => Some(YaraSeverity::Critical),
                        "high" => Some(YaraSeverity::High),
                        "medium" => Some(YaraSeverity::Medium),
                        "low" => Some(YaraSeverity::Low),
                        _ => None,
                    })
                    .unwrap_or(YaraSeverity::Medium);

                let blocking = m.tags.iter().any(|t| t == "blocking");

                YaraMatch {
                    rule: m.identifier.clone(),
                    tags: m.tags.clone(),
                    severity,
                    strings,
                    metadata: HashMap::new(),
                    blocking,
                }
            })
            .collect()
    }
}

#[async_trait]
impl YaraScanner for DefaultYaraScanner {
    async fn scan(&self, content: &[u8]) -> Result<YaraScanResult, YaraError> {
        let start = std::time::Instant::now();

        // Check size limit
        if content.len() > self.config.max_scan_bytes {
            return Err(YaraError::ContentTooLarge(content.len()));
        }

        let rules = self.rules.read().await;

        // Run scan with timeout
        let timeout = Duration::from_millis(self.config.scan_timeout_ms);
        let scan_result = tokio::time::timeout(timeout, async {
            rules
                .scan_mem(content, 0)
                .map_err(|e| YaraError::ScanError(e.to_string()))
        })
        .await
        .map_err(|_| YaraError::Timeout(self.config.scan_timeout_ms))??;

        let matches = self.extract_matches(&scan_result, content);
        let max_severity = matches
            .iter()
            .map(|m| m.severity)
            .max()
            .unwrap_or(YaraSeverity::Info);

        Ok(YaraScanResult {
            matches,
            rules_checked: rules.get_rules().len(),
            scan_duration_ms: start.elapsed().as_millis() as u64,
            complete: true,
            bytes_scanned: content.len(),
            max_severity,
        })
    }

    async fn scan_with_rules(
        &self,
        content: &[u8],
        _rule_names: &[String],
    ) -> Result<YaraScanResult, YaraError> {
        // For now, scan with all rules and filter
        // A more efficient implementation would compile a subset
        self.scan(content).await
    }

    async fn load_rules(&self, source: &YaraRuleSource) -> Result<usize, YaraError> {
        // This would require recompilation in a real implementation
        // For now, rules must be loaded at construction time
        Err(YaraError::RuleLoadError("Hot reload not yet supported".to_string()))
    }

    fn rule_count(&self) -> usize {
        // Would need to track this during construction
        0
    }

    fn rule_names(&self) -> Vec<String> {
        vec![]
    }
}

/// YARA guard implementation
pub struct YaraGuard {
    config: YaraConfig,
    scanner: Arc<dyn YaraScanner>,
    skip_patterns: Vec<glob::Pattern>,
    scan_patterns: Vec<glob::Pattern>,
}

impl YaraGuard {
    pub fn new(config: YaraConfig) -> Result<Self, YaraError> {
        let scanner = Arc::new(DefaultYaraScanner::new(config.clone())?);

        let skip_patterns = config
            .skip_patterns
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        let scan_patterns = config
            .scan_patterns
            .iter()
            .filter_map(|p| glob::Pattern::new(p).ok())
            .collect();

        Ok(Self {
            config,
            scanner,
            skip_patterns,
            scan_patterns,
        })
    }

    /// Check if a path should be scanned
    fn should_scan_path(&self, path: &str) -> bool {
        // Check skip patterns
        if self.skip_patterns.iter().any(|p| p.matches(path)) {
            return false;
        }

        // If scan_patterns is set, only scan matching paths
        if !self.scan_patterns.is_empty() {
            return self.scan_patterns.iter().any(|p| p.matches(path));
        }

        true
    }

    /// Extract scannable content from action
    fn extract_content<'a>(&self, action: &'a GuardAction<'a>) -> Option<&'a [u8]> {
        match action {
            GuardAction::FileWrite(path, content) => {
                if self.should_scan_path(path) {
                    Some(content)
                } else {
                    None
                }
            }
            GuardAction::Patch(path, diff) => {
                if self.config.scan_patches && self.should_scan_path(path) {
                    Some(diff.as_bytes())
                } else {
                    None
                }
            }
            GuardAction::ShellCommand(cmd) => {
                if self.config.scan_commands {
                    Some(cmd.as_bytes())
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[async_trait]
impl Guard for YaraGuard {
    fn name(&self) -> &str {
        "yara"
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(
            action,
            GuardAction::FileWrite(_, _)
                | GuardAction::Patch(_, _)
                | GuardAction::ShellCommand(_)
        )
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.config.enabled {
            return GuardResult::allow(self.name());
        }

        let content = match self.extract_content(action) {
            Some(c) => c,
            None => return GuardResult::allow(self.name()),
        };

        // Scan content
        let result = match self.scanner.scan(content).await {
            Ok(r) => r,
            Err(YaraError::ContentTooLarge(size)) => {
                return GuardResult::warn(
                    self.name(),
                    format!("Content too large for YARA scan: {} bytes", size),
                );
            }
            Err(YaraError::Timeout(ms)) => {
                return GuardResult::warn(
                    self.name(),
                    format!("YARA scan timed out after {}ms", ms),
                );
            }
            Err(e) => {
                return GuardResult::warn(
                    self.name(),
                    format!("YARA scan failed: {}", e),
                );
            }
        };

        if result.matches.is_empty() {
            return GuardResult::allow(self.name())
                .with_details(serde_json::json!({
                    "rules_checked": result.rules_checked,
                    "scan_duration_ms": result.scan_duration_ms,
                }));
        }

        // Check for blocking matches
        if result.has_blocking_match() || result.max_severity >= self.config.block_severity {
            return GuardResult::block(
                self.name(),
                Severity::Critical,
                result.summary(),
            )
            .with_details(serde_json::to_value(&result).unwrap_or_default());
        }

        // Check for warning matches
        if result.max_severity >= self.config.warn_severity {
            return GuardResult::warn(self.name(), result.summary())
                .with_details(serde_json::to_value(&result).unwrap_or_default());
        }

        GuardResult::allow(self.name())
            .with_details(serde_json::to_value(&result).unwrap_or_default())
    }
}
```

### 3.2 TypeScript Interface

```typescript
/**
 * @clawdstrike/openclaw - YARA Integration
 */

import type { Guard, GuardResult, PolicyEvent, Policy } from '../types.js';

/** YARA match severity */
export type YaraSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

/** YARA rule source */
export type YaraRuleSource =
  | { type: 'builtin'; name: string }
  | { type: 'file'; path: string }
  | { type: 'remote'; url: string; auth?: string }
  | { type: 'inline'; rules: YaraRule[] };

/** YARA rule definition */
export interface YaraRule {
  name: string;
  source: string;
  severity: YaraSeverity;
  tags: string[];
  description?: string;
  blocking: boolean;
  filePatterns: string[];
}

/** YARA configuration */
export interface YaraConfig {
  enabled?: boolean;
  ruleSources?: YaraRuleSource[];
  maxScanBytes?: number;
  scanTimeoutMs?: number;
  maxRules?: number;
  blockSeverity?: YaraSeverity;
  warnSeverity?: YaraSeverity;
  scanPatterns?: string[];
  skipPatterns?: string[];
  enabledTags?: string[];
  disabledTags?: string[];
  scanCommands?: boolean;
  scanPatches?: boolean;
  includeContext?: boolean;
  contextBytes?: number;
}

/** YARA match result */
export interface YaraMatch {
  rule: string;
  tags: string[];
  severity: YaraSeverity;
  strings: StringMatch[];
  metadata: Record<string, string>;
  blocking: boolean;
}

/** String match within a rule */
export interface StringMatch {
  identifier: string;
  offset: number;
  matchedData?: string;
  contextBefore?: string;
  contextAfter?: string;
}

/** YARA scan result */
export interface YaraScanResult {
  matches: YaraMatch[];
  rulesChecked: number;
  scanDurationMs: number;
  complete: boolean;
  bytesScanned: number;
  maxSeverity: YaraSeverity;
}

/**
 * YARA Guard implementation
 */
export class YaraGuard implements Guard {
  private config: Required<YaraConfig>;

  constructor(config: YaraConfig = {}) {
    this.config = {
      enabled: config.enabled ?? true,
      ruleSources: config.ruleSources ?? [{ type: 'builtin', name: 'default' }],
      maxScanBytes: config.maxScanBytes ?? 10 * 1024 * 1024,
      scanTimeoutMs: config.scanTimeoutMs ?? 5000,
      maxRules: config.maxRules ?? 1000,
      blockSeverity: config.blockSeverity ?? 'high',
      warnSeverity: config.warnSeverity ?? 'medium',
      scanPatterns: config.scanPatterns ?? [],
      skipPatterns: config.skipPatterns ?? ['*.jpg', '*.png', '*.gif'],
      enabledTags: config.enabledTags ?? [],
      disabledTags: config.disabledTags ?? [],
      scanCommands: config.scanCommands ?? true,
      scanPatches: config.scanPatches ?? true,
      includeContext: config.includeContext ?? true,
      contextBytes: config.contextBytes ?? 64,
    };
  }

  name(): string {
    return 'yara';
  }

  handles(): Array<import('../types.js').EventType> {
    return ['file_write', 'patch_apply', 'command_exec'];
  }

  isEnabled(): boolean {
    return this.config.enabled;
  }

  async check(event: PolicyEvent, _policy: Policy): Promise<GuardResult> {
    if (!this.config.enabled) {
      return { status: 'allow', guard: this.name() };
    }

    // Extract content to scan
    const content = this.extractContent(event);
    if (!content) {
      return { status: 'allow', guard: this.name() };
    }

    // Perform YARA scan (would use yara-js or similar)
    const result = await this.scan(content);

    if (result.matches.length === 0) {
      return { status: 'allow', guard: this.name() };
    }

    const hasBlocking = result.matches.some((m) => m.blocking);
    const severityOrder: YaraSeverity[] = ['info', 'low', 'medium', 'high', 'critical'];
    const maxSeverityIndex = severityOrder.indexOf(result.maxSeverity);
    const blockIndex = severityOrder.indexOf(this.config.blockSeverity);
    const warnIndex = severityOrder.indexOf(this.config.warnSeverity);

    if (hasBlocking || maxSeverityIndex >= blockIndex) {
      return {
        status: 'deny',
        reason: `${result.matches.length} YARA rules matched`,
        severity: 'critical',
        guard: this.name(),
      };
    }

    if (maxSeverityIndex >= warnIndex) {
      return {
        status: 'warn',
        reason: `${result.matches.length} YARA rules matched`,
        guard: this.name(),
      };
    }

    return { status: 'allow', guard: this.name() };
  }

  private extractContent(event: PolicyEvent): Uint8Array | null {
    if (event.data.type === 'file' && event.data.operation === 'write') {
      // Would need content from the event
      return null;
    }
    if (event.data.type === 'patch') {
      return new TextEncoder().encode(event.data.patchContent);
    }
    if (event.data.type === 'command') {
      return new TextEncoder().encode(event.data.command);
    }
    return null;
  }

  private async scan(content: Uint8Array): Promise<YaraScanResult> {
    // Placeholder - would use yara-js or native bindings
    return {
      matches: [],
      rulesChecked: 0,
      scanDurationMs: 0,
      complete: true,
      bytesScanned: content.length,
      maxSeverity: 'info',
    };
  }
}
```

---

## 4. Built-in Rule Sets

### 4.1 Default Rules (`default.yar`)

```yara
/*
 * Clawdstrike Default YARA Rules
 * Basic detection for common threats and sensitive patterns
 */

rule PrivateKey : secrets blocking critical
{
    meta:
        description = "Detects private key files"
        severity = "critical"

    strings:
        $rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $ec = "-----BEGIN EC PRIVATE KEY-----"
        $openssh = "-----BEGIN OPENSSH PRIVATE KEY-----"
        $dsa = "-----BEGIN DSA PRIVATE KEY-----"

    condition:
        any of them
}

rule AWSCredentials : secrets blocking critical
{
    meta:
        description = "Detects AWS access keys"
        severity = "critical"

    strings:
        $access_key = /AKIA[0-9A-Z]{16}/
        $secret_key = /[A-Za-z0-9\/+=]{40}/ // Often near access key

    condition:
        $access_key
}

rule GenericAPIKey : secrets high
{
    meta:
        description = "Detects potential API keys"
        severity = "high"

    strings:
        $api_key = /api[_-]?key['":\s]*[=:]\s*['"][a-zA-Z0-9]{20,}['"]/i
        $secret = /secret['":\s]*[=:]\s*['"][a-zA-Z0-9]{20,}['"]/i
        $token = /token['":\s]*[=:]\s*['"][a-zA-Z0-9]{20,}['"]/i

    condition:
        any of them
}

rule ShellInjection : exploits blocking high
{
    meta:
        description = "Detects potential shell injection patterns"
        severity = "high"

    strings:
        $backtick = /`[^`]+`/
        $subshell = /\$\([^)]+\)/
        $pipe_chain = /\|\s*(sh|bash|zsh|fish)/
        $eval = /eval\s+['"$]/

    condition:
        any of them
}

rule ReverseShell : exploits blocking critical
{
    meta:
        description = "Detects reverse shell patterns"
        severity = "critical"

    strings:
        $nc = /nc\s+-[a-z]*e\s+/
        $bash_tcp = /bash\s+-i\s+>&\s*\/dev\/tcp/
        $python_socket = /socket\.connect\s*\([^)]*\)\s*.*os\.(dup2|system)/s
        $perl_socket = /socket\s*\(\s*S.*exec.*\/bin\/(sh|bash)/s

    condition:
        any of them
}

rule Base64Encoded : suspicious medium
{
    meta:
        description = "Detects large base64 encoded content that might hide malicious payloads"
        severity = "medium"

    strings:
        $base64 = /[A-Za-z0-9+\/]{100,}={0,2}/

    condition:
        #base64 > 3
}

rule CryptoMiner : malware blocking high
{
    meta:
        description = "Detects cryptocurrency mining indicators"
        severity = "high"

    strings:
        $stratum = "stratum+tcp://"
        $stratum_ssl = "stratum+ssl://"
        $xmrig = "xmrig"
        $monero_addr = /4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}/

    condition:
        any of them
}
```

### 4.2 Webshell Rules (`webshells.yar`)

```yara
/*
 * Webshell Detection Rules
 */

rule PHPWebshell : webshell blocking critical
{
    meta:
        description = "Detects common PHP webshell patterns"
        severity = "critical"

    strings:
        $eval_post = /eval\s*\(\s*\$_(POST|GET|REQUEST)/
        $base64_decode = /base64_decode\s*\(\s*\$_(POST|GET|REQUEST)/
        $system_call = /(system|exec|shell_exec|passthru)\s*\(\s*\$/
        $c99 = "c99shell"
        $r57 = "r57shell"
        $wso = "FilesMan" // WSO shell

    condition:
        any of them
}

rule JSPWebshell : webshell blocking critical
{
    meta:
        description = "Detects JSP webshell patterns"
        severity = "critical"

    strings:
        $runtime_exec = /Runtime\.getRuntime\(\)\.exec\s*\(\s*request\.getParameter/
        $process_builder = /ProcessBuilder.*request\.getParameter/s

    condition:
        any of them
}

rule ASPXWebshell : webshell blocking critical
{
    meta:
        description = "Detects ASPX webshell patterns"
        severity = "critical"

    strings:
        $process_start = /Process\.Start.*Request\[/s
        $cmd_execute = /cmd\.exe.*Request\.Form/s

    condition:
        any of them
}
```

---

## 5. Performance Considerations

### 5.1 Optimization Strategies

| Strategy | Description | Impact |
|----------|-------------|--------|
| Rule compilation caching | Compile rules once, reuse | 10-100x faster scans |
| Size limits | Skip large files | Prevent DoS |
| Timeouts | Abort long scans | Bounded latency |
| Pattern filtering | Only scan relevant files | Reduce scan volume |
| Incremental scanning | Cache previous results | Skip unchanged content |

### 5.2 Latency Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Rule compilation | < 500ms | One-time at startup |
| Small file scan (<1KB) | < 5ms | Most operations |
| Medium file scan (1KB-1MB) | < 50ms | Typical code files |
| Large file scan (1MB-10MB) | < 500ms | With timeout |

### 5.3 Memory Budget

```yaml
yara:
  memory:
    compiled_rules_mb: 50      # Compiled rule cache
    scan_buffer_mb: 10         # Per-scan buffer
    results_cache_mb: 20       # Recent results
    total_mb: 80
```

---

## 6. Security Considerations

### 6.1 Rule Validation

- Validate rule syntax before compilation
- Sandbox rule compilation to prevent DoS
- Limit regex complexity in rules
- Audit third-party rules before use

### 6.2 Match Handling

- Redact sensitive match data in logs
- Limit context extraction size
- Rate-limit alerts to prevent spam

### 6.3 Rule Source Trust

- Only load rules from trusted sources
- Verify cryptographic signatures on remote rule sets
- Audit third-party rules before deployment
- Use allowlists for permitted rule sources in production

### 6.4 Resource Exhaustion Prevention

- Limit maximum compiled rule size
- Enforce scan timeouts to prevent regex catastrophic backtracking
- Cap concurrent scans per session
- Monitor memory usage during rule compilation

---

## 7. Implementation Phases

### Phase 1: Core Scanner (Week 1-2)
- [ ] YARA library integration (yara-rust)
- [ ] Rule compilation and caching
- [ ] Basic scan implementation

### Phase 2: Guard Integration (Week 2-3)
- [ ] YaraGuard implementation
- [ ] Built-in rule sets
- [ ] Policy configuration

### Phase 3: Advanced Features (Week 3-4)
- [ ] Remote rule loading
- [ ] Hot reload support
- [ ] Performance optimization

---

## 8. Related Documents

- [overview.md](./overview.md) - Threat Intelligence Overview
- [blocklists.md](./blocklists.md) - Blocklist Architecture
- [virustotal-integration.md](./virustotal-integration.md) - VirusTotal Integration
