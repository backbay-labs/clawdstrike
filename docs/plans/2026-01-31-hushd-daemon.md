# Hushd Daemon Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a production-ready hushd daemon with HTTP API, SQLite audit ledger, SSE streaming, configuration support, and system integration files.

**Architecture:** Axum-based HTTP server with shared AppState containing HushEngine, SQLite-backed AuditLedger, and broadcast channel for events. The daemon supports hot-reload of policy via SIGHUP. CLI commands in hush-cli interact with running daemon via HTTP.

**Tech Stack:** Rust, axum 0.7, tokio, rusqlite, serde, tracing, clap

---

## Prerequisites

Before starting, ensure you can build the project:

```bash
cd /Users/connor/Medica/clawdstrike-ws8-daemon
cargo build -p hushd
cargo test -p clawdstrike
```

---

## Task 1: Add Dependencies to hushd Cargo.toml

**Files:**
- Modify: `crates/hushd/Cargo.toml`

**Step 1: Add required dependencies**

Edit `crates/hushd/Cargo.toml` to add axum, rusqlite, tower, and other deps:

```toml
[package]
name = "hushd"
description = "Clawdstrike daemon for runtime security enforcement"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
rust-version.workspace = true

[[bin]]
name = "hushd"
path = "src/main.rs"

[dependencies]
hush-core.workspace = true
hush-proxy.workspace = true
clawdstrike.workspace = true
clap.workspace = true
tokio.workspace = true
tracing.workspace = true
tracing-subscriber.workspace = true
serde.workspace = true
serde_json.workspace = true
anyhow.workspace = true
chrono.workspace = true
uuid.workspace = true

# HTTP server
axum = { version = "0.7", features = ["macros"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }

# Database
rusqlite = { version = "0.31", features = ["bundled"] }

# Async utilities
tokio-stream = "0.1"
futures = "0.3"

# Config
toml = "0.8"
dirs = "5.0"

[features]
default = []
```

**Step 2: Update workspace Cargo.toml**

Add new deps to workspace if not present. Edit root `Cargo.toml`:

```toml
# Add under [workspace.dependencies]
axum = { version = "0.7", features = ["macros"] }
tower = "0.4"
tower-http = { version = "0.5", features = ["cors", "trace"] }
rusqlite = { version = "0.31", features = ["bundled"] }
tokio-stream = "0.1"
futures = "0.3"
toml = "0.8"
dirs = "5.0"
```

**Step 3: Verify build**

Run: `cargo build -p hushd`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add Cargo.toml crates/hushd/Cargo.toml
git commit -m "chore(hushd): add axum, rusqlite, tower dependencies"
```

---

## Task 2: Create Config Module

**Files:**
- Create: `crates/hushd/src/config.rs`
- Modify: `crates/hushd/src/main.rs` (add mod declaration)

**Step 1: Create config.rs**

Create `crates/hushd/src/config.rs`:

```rust
//! Configuration for hushd daemon

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// TLS configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to certificate file
    pub cert_path: PathBuf,
    /// Path to private key file
    pub key_path: PathBuf,
}

/// Daemon configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    /// Listen address (e.g., "0.0.0.0:8080")
    #[serde(default = "default_listen")]
    pub listen: String,

    /// Path to policy YAML file
    #[serde(default)]
    pub policy_path: Option<PathBuf>,

    /// Ruleset name (if policy_path not set)
    #[serde(default = "default_ruleset")]
    pub ruleset: String,

    /// Path to SQLite audit database
    #[serde(default = "default_audit_db")]
    pub audit_db: PathBuf,

    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Optional TLS configuration
    #[serde(default)]
    pub tls: Option<TlsConfig>,

    /// Path to signing key file
    #[serde(default)]
    pub signing_key: Option<PathBuf>,

    /// Enable CORS for browser access
    #[serde(default = "default_cors")]
    pub cors_enabled: bool,

    /// Maximum audit log entries to keep (0 = unlimited)
    #[serde(default)]
    pub max_audit_entries: usize,
}

fn default_listen() -> String {
    "127.0.0.1:9876".to_string()
}

fn default_ruleset() -> String {
    "default".to_string()
}

fn default_audit_db() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("hushd")
        .join("audit.db")
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_cors() -> bool {
    true
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            policy_path: None,
            ruleset: default_ruleset(),
            audit_db: default_audit_db(),
            log_level: default_log_level(),
            tls: None,
            signing_key: None,
            cors_enabled: default_cors(),
            max_audit_entries: 0,
        }
    }
}

impl Config {
    /// Load configuration from file
    pub fn from_file(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())?;

        // Support both YAML and TOML based on extension
        let config = if path.as_ref().extension().map_or(false, |e| e == "yaml" || e == "yml") {
            serde_yaml::from_str(&content)?
        } else {
            toml::from_str(&content)?
        };

        Ok(config)
    }

    /// Load from default locations or create default
    pub fn load_default() -> Self {
        // Try standard config locations
        let paths = [
            PathBuf::from("/etc/hushd/config.yaml"),
            PathBuf::from("/etc/hushd/config.toml"),
            dirs::config_dir()
                .map(|d| d.join("hushd/config.yaml"))
                .unwrap_or_default(),
            dirs::config_dir()
                .map(|d| d.join("hushd/config.toml"))
                .unwrap_or_default(),
            PathBuf::from("./hushd.yaml"),
            PathBuf::from("./hushd.toml"),
        ];

        for path in paths {
            if path.exists() {
                if let Ok(config) = Self::from_file(&path) {
                    tracing::info!(path = %path.display(), "Loaded config");
                    return config;
                }
            }
        }

        Self::default()
    }

    /// Get the tracing level filter
    pub fn tracing_level(&self) -> tracing::Level {
        match self.log_level.to_lowercase().as_str() {
            "trace" => tracing::Level::TRACE,
            "debug" => tracing::Level::DEBUG,
            "info" => tracing::Level::INFO,
            "warn" | "warning" => tracing::Level::WARN,
            "error" => tracing::Level::ERROR,
            _ => tracing::Level::INFO,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.listen, "127.0.0.1:9876");
        assert_eq!(config.ruleset, "default");
        assert!(config.cors_enabled);
    }

    #[test]
    fn test_config_from_toml() {
        let toml = r#"
listen = "0.0.0.0:8080"
ruleset = "strict"
log_level = "debug"
"#;
        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.listen, "0.0.0.0:8080");
        assert_eq!(config.ruleset, "strict");
        assert_eq!(config.log_level, "debug");
    }

    #[test]
    fn test_tracing_level() {
        let mut config = Config::default();

        config.log_level = "trace".to_string();
        assert_eq!(config.tracing_level(), tracing::Level::TRACE);

        config.log_level = "debug".to_string();
        assert_eq!(config.tracing_level(), tracing::Level::DEBUG);

        config.log_level = "invalid".to_string();
        assert_eq!(config.tracing_level(), tracing::Level::INFO);
    }
}
```

**Step 2: Add mod declaration to main.rs**

Add at the top of `crates/hushd/src/main.rs` after the doc comment:

```rust
mod config;
```

**Step 3: Run tests**

Run: `cargo test -p hushd`
Expected: All tests pass

**Step 4: Commit**

```bash
git add crates/hushd/src/config.rs crates/hushd/src/main.rs
git commit -m "feat(hushd): add configuration module with YAML/TOML support"
```

---

## Task 3: Create Audit Ledger Module

**Files:**
- Create: `crates/hushd/src/audit/mod.rs`
- Create: `crates/hushd/src/audit/schema.rs`
- Modify: `crates/hushd/src/main.rs` (add mod declaration)

**Step 1: Create audit directory and schema.rs**

Create `crates/hushd/src/audit/schema.rs`:

```rust
//! Database schema for audit ledger

/// SQL to create the audit tables
pub const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS audit_events (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target TEXT,
    decision TEXT NOT NULL,
    guard TEXT,
    severity TEXT,
    message TEXT,
    session_id TEXT,
    agent_id TEXT,
    metadata TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_events(event_type);
CREATE INDEX IF NOT EXISTS idx_audit_session_id ON audit_events(session_id);
CREATE INDEX IF NOT EXISTS idx_audit_decision ON audit_events(decision);

CREATE TABLE IF NOT EXISTS audit_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Insert schema version
INSERT OR REPLACE INTO audit_metadata (key, value) VALUES ('schema_version', '1');
"#;

/// SQL to query events
pub const SELECT_EVENTS: &str = r#"
SELECT id, timestamp, event_type, action_type, target, decision, guard,
       severity, message, session_id, agent_id, metadata
FROM audit_events
WHERE 1=1
"#;

/// SQL to insert an event
pub const INSERT_EVENT: &str = r#"
INSERT INTO audit_events
    (id, timestamp, event_type, action_type, target, decision, guard,
     severity, message, session_id, agent_id, metadata)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
"#;

/// SQL to count events
pub const COUNT_EVENTS: &str = "SELECT COUNT(*) FROM audit_events";

/// SQL to delete old events (keep most recent N)
pub const DELETE_OLD_EVENTS: &str = r#"
DELETE FROM audit_events
WHERE id NOT IN (
    SELECT id FROM audit_events
    ORDER BY timestamp DESC
    LIMIT ?1
)
"#;
```

**Step 2: Create audit/mod.rs**

Create `crates/hushd/src/audit/mod.rs`:

```rust
//! SQLite-backed audit ledger for security events

mod schema;

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use clawdstrike::guards::{GuardResult, Severity};

/// Error type for audit operations
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// Audit event record
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event identifier
    pub id: String,
    /// When the event occurred
    pub timestamp: DateTime<Utc>,
    /// Event type (check, violation, session_start, session_end)
    pub event_type: String,
    /// Action type being checked
    pub action_type: String,
    /// Target of the action (path, host, tool name)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Decision made (allowed, blocked)
    pub decision: String,
    /// Guard that made the decision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guard: Option<String>,
    /// Severity level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// Human-readable message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// Session identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Agent identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    /// Additional metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl AuditEvent {
    /// Create a new check event from a guard result
    pub fn from_guard_result(
        action_type: &str,
        target: Option<&str>,
        result: &GuardResult,
        session_id: Option<&str>,
        agent_id: Option<&str>,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: if result.allowed { "check" } else { "violation" }.to_string(),
            action_type: action_type.to_string(),
            target: target.map(String::from),
            decision: if result.allowed { "allowed" } else { "blocked" }.to_string(),
            guard: Some(result.guard.clone()),
            severity: Some(format!("{:?}", result.severity)),
            message: Some(result.message.clone()),
            session_id: session_id.map(String::from),
            agent_id: agent_id.map(String::from),
            metadata: result.details.clone(),
        }
    }

    /// Create a session start event
    pub fn session_start(session_id: &str, agent_id: Option<&str>) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: "session_start".to_string(),
            action_type: "session".to_string(),
            target: None,
            decision: "allowed".to_string(),
            guard: None,
            severity: None,
            message: Some("Session started".to_string()),
            session_id: Some(session_id.to_string()),
            agent_id: agent_id.map(String::from),
            metadata: None,
        }
    }

    /// Create a session end event
    pub fn session_end(session_id: &str, stats: &SessionStats) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type: "session_end".to_string(),
            action_type: "session".to_string(),
            target: None,
            decision: "allowed".to_string(),
            guard: None,
            severity: None,
            message: Some("Session ended".to_string()),
            session_id: Some(session_id.to_string()),
            agent_id: None,
            metadata: Some(serde_json::to_value(stats).unwrap_or_default()),
        }
    }
}

/// Session statistics for audit
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionStats {
    pub action_count: u64,
    pub violation_count: u64,
    pub duration_secs: u64,
}

/// Filter for querying audit events
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuditFilter {
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by action type
    pub action_type: Option<String>,
    /// Filter by decision
    pub decision: Option<String>,
    /// Filter by session ID
    pub session_id: Option<String>,
    /// Filter by agent ID
    pub agent_id: Option<String>,
    /// Filter events after this time
    pub after: Option<DateTime<Utc>>,
    /// Filter events before this time
    pub before: Option<DateTime<Utc>>,
    /// Maximum number of events to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
}

/// Export format for audit data
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExportFormat {
    Json,
    Csv,
    Jsonl,
}

/// SQLite-backed audit ledger
pub struct AuditLedger {
    conn: Mutex<Connection>,
    max_entries: usize,
}

impl AuditLedger {
    /// Create a new audit ledger
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        // Ensure parent directory exists
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;

        // Enable WAL mode for better concurrent access
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;

        // Create tables
        conn.execute_batch(schema::CREATE_TABLES)?;

        Ok(Self {
            conn: Mutex::new(conn),
            max_entries: 0,
        })
    }

    /// Create an in-memory ledger (for testing)
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(schema::CREATE_TABLES)?;

        Ok(Self {
            conn: Mutex::new(conn),
            max_entries: 0,
        })
    }

    /// Set maximum entries to keep (0 = unlimited)
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    /// Record an audit event
    pub fn record(&self, event: &AuditEvent) -> Result<()> {
        let conn = self.conn.lock().unwrap();

        conn.execute(
            schema::INSERT_EVENT,
            params![
                event.id,
                event.timestamp.to_rfc3339(),
                event.event_type,
                event.action_type,
                event.target,
                event.decision,
                event.guard,
                event.severity,
                event.message,
                event.session_id,
                event.agent_id,
                event.metadata.as_ref().map(|m| serde_json::to_string(m).ok()).flatten(),
            ],
        )?;

        // Prune old entries if max_entries is set
        if self.max_entries > 0 {
            conn.execute(schema::DELETE_OLD_EVENTS, params![self.max_entries])?;
        }

        Ok(())
    }

    /// Query audit events
    pub fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>> {
        let conn = self.conn.lock().unwrap();

        let mut sql = schema::SELECT_EVENTS.to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        if let Some(ref event_type) = filter.event_type {
            sql.push_str(" AND event_type = ?");
            params_vec.push(Box::new(event_type.clone()));
        }
        if let Some(ref action_type) = filter.action_type {
            sql.push_str(" AND action_type = ?");
            params_vec.push(Box::new(action_type.clone()));
        }
        if let Some(ref decision) = filter.decision {
            sql.push_str(" AND decision = ?");
            params_vec.push(Box::new(decision.clone()));
        }
        if let Some(ref session_id) = filter.session_id {
            sql.push_str(" AND session_id = ?");
            params_vec.push(Box::new(session_id.clone()));
        }
        if let Some(ref agent_id) = filter.agent_id {
            sql.push_str(" AND agent_id = ?");
            params_vec.push(Box::new(agent_id.clone()));
        }
        if let Some(after) = filter.after {
            sql.push_str(" AND timestamp > ?");
            params_vec.push(Box::new(after.to_rfc3339()));
        }
        if let Some(before) = filter.before {
            sql.push_str(" AND timestamp < ?");
            params_vec.push(Box::new(before.to_rfc3339()));
        }

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }
        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET {}", offset));
        }

        let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let events = stmt.query_map(params_refs.as_slice(), |row| {
            let metadata_str: Option<String> = row.get(11)?;
            let metadata = metadata_str
                .and_then(|s| serde_json::from_str(&s).ok());

            Ok(AuditEvent {
                id: row.get(0)?,
                timestamp: DateTime::parse_from_rfc3339(&row.get::<_, String>(1)?)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                event_type: row.get(2)?,
                action_type: row.get(3)?,
                target: row.get(4)?,
                decision: row.get(5)?,
                guard: row.get(6)?,
                severity: row.get(7)?,
                message: row.get(8)?,
                session_id: row.get(9)?,
                agent_id: row.get(10)?,
                metadata,
            })
        })?;

        events.collect::<std::result::Result<Vec<_>, _>>().map_err(AuditError::from)
    }

    /// Get event count
    pub fn count(&self) -> Result<usize> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(schema::COUNT_EVENTS, [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Export audit data
    pub fn export(&self, filter: &AuditFilter, format: ExportFormat) -> Result<Vec<u8>> {
        let events = self.query(filter)?;

        match format {
            ExportFormat::Json => {
                Ok(serde_json::to_vec_pretty(&events)?)
            }
            ExportFormat::Jsonl => {
                let mut output = Vec::new();
                for event in events {
                    output.extend(serde_json::to_vec(&event)?);
                    output.push(b'\n');
                }
                Ok(output)
            }
            ExportFormat::Csv => {
                let mut output = "id,timestamp,event_type,action_type,target,decision,guard,severity,message,session_id,agent_id\n".to_string();
                for event in events {
                    output.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{},{},{}\n",
                        event.id,
                        event.timestamp.to_rfc3339(),
                        event.event_type,
                        event.action_type,
                        event.target.unwrap_or_default(),
                        event.decision,
                        event.guard.unwrap_or_default(),
                        event.severity.unwrap_or_default(),
                        event.message.unwrap_or_default().replace(',', ";"),
                        event.session_id.unwrap_or_default(),
                        event.agent_id.unwrap_or_default(),
                    ));
                }
                Ok(output.into_bytes())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ledger_record_and_query() {
        let ledger = AuditLedger::in_memory().unwrap();

        let event = AuditEvent {
            id: "test-1".to_string(),
            timestamp: Utc::now(),
            event_type: "check".to_string(),
            action_type: "file_access".to_string(),
            target: Some("/etc/passwd".to_string()),
            decision: "blocked".to_string(),
            guard: Some("forbidden_path".to_string()),
            severity: Some("Error".to_string()),
            message: Some("Access to sensitive file blocked".to_string()),
            session_id: Some("session-1".to_string()),
            agent_id: None,
            metadata: None,
        };

        ledger.record(&event).unwrap();

        let filter = AuditFilter::default();
        let events = ledger.query(&filter).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].id, "test-1");
        assert_eq!(events[0].decision, "blocked");
    }

    #[test]
    fn test_ledger_filter() {
        let ledger = AuditLedger::in_memory().unwrap();

        // Record multiple events
        for i in 0..5 {
            let event = AuditEvent {
                id: format!("test-{}", i),
                timestamp: Utc::now(),
                event_type: if i % 2 == 0 { "check" } else { "violation" }.to_string(),
                action_type: "file_access".to_string(),
                target: Some(format!("/path/{}", i)),
                decision: if i % 2 == 0 { "allowed" } else { "blocked" }.to_string(),
                guard: Some("test".to_string()),
                severity: Some("Info".to_string()),
                message: None,
                session_id: Some("session-1".to_string()),
                agent_id: None,
                metadata: None,
            };
            ledger.record(&event).unwrap();
        }

        // Filter by event_type
        let filter = AuditFilter {
            event_type: Some("violation".to_string()),
            ..Default::default()
        };
        let events = ledger.query(&filter).unwrap();
        assert_eq!(events.len(), 2);

        // Filter with limit
        let filter = AuditFilter {
            limit: Some(2),
            ..Default::default()
        };
        let events = ledger.query(&filter).unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn test_export_json() {
        let ledger = AuditLedger::in_memory().unwrap();

        let event = AuditEvent {
            id: "export-1".to_string(),
            timestamp: Utc::now(),
            event_type: "check".to_string(),
            action_type: "test".to_string(),
            target: None,
            decision: "allowed".to_string(),
            guard: None,
            severity: None,
            message: None,
            session_id: None,
            agent_id: None,
            metadata: None,
        };
        ledger.record(&event).unwrap();

        let filter = AuditFilter::default();
        let json = ledger.export(&filter, ExportFormat::Json).unwrap();

        let parsed: Vec<AuditEvent> = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].id, "export-1");
    }

    #[test]
    fn test_count() {
        let ledger = AuditLedger::in_memory().unwrap();
        assert_eq!(ledger.count().unwrap(), 0);

        for i in 0..3 {
            let event = AuditEvent {
                id: format!("count-{}", i),
                timestamp: Utc::now(),
                event_type: "check".to_string(),
                action_type: "test".to_string(),
                target: None,
                decision: "allowed".to_string(),
                guard: None,
                severity: None,
                message: None,
                session_id: None,
                agent_id: None,
                metadata: None,
            };
            ledger.record(&event).unwrap();
        }

        assert_eq!(ledger.count().unwrap(), 3);
    }
}
```

**Step 3: Add mod declaration to main.rs**

Add after the `mod config;` line in `crates/hushd/src/main.rs`:

```rust
mod audit;
```

**Step 4: Run tests**

Run: `cargo test -p hushd`
Expected: All tests pass

**Step 5: Commit**

```bash
git add crates/hushd/src/audit/
git commit -m "feat(hushd): add SQLite-backed audit ledger"
```

---

## Task 4: Create Application State

**Files:**
- Create: `crates/hushd/src/state.rs`
- Modify: `crates/hushd/src/main.rs`

**Step 1: Create state.rs**

Create `crates/hushd/src/state.rs`:

```rust
//! Shared application state for the daemon

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use hush_core::Keypair;
use clawdstrike::{HushEngine, Policy, RuleSet};

use crate::audit::{AuditEvent, AuditLedger};
use crate::config::Config;

/// Event broadcast for SSE streaming
#[derive(Clone, Debug)]
pub struct DaemonEvent {
    pub event_type: String,
    pub data: serde_json::Value,
}

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    /// Security engine
    pub engine: Arc<RwLock<HushEngine>>,
    /// Audit ledger
    pub ledger: Arc<AuditLedger>,
    /// Event broadcaster
    pub event_tx: broadcast::Sender<DaemonEvent>,
    /// Configuration
    pub config: Arc<Config>,
    /// Session ID
    pub session_id: String,
    /// Start time
    pub started_at: chrono::DateTime<chrono::Utc>,
}

impl AppState {
    /// Create new application state
    pub fn new(config: Config) -> anyhow::Result<Self> {
        // Load policy
        let policy = if let Some(ref path) = config.policy_path {
            Policy::from_yaml_file(path)?
        } else {
            RuleSet::by_name(&config.ruleset)
                .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", config.ruleset))?
                .policy
        };

        // Create engine
        let mut engine = HushEngine::with_policy(policy);

        // Load signing key
        if let Some(ref key_path) = config.signing_key {
            let key_hex = std::fs::read_to_string(key_path)?.trim().to_string();
            let keypair = Keypair::from_hex(&key_hex)?;
            engine = engine.with_keypair(keypair);
            tracing::info!(path = %key_path.display(), "Loaded signing key");
        } else {
            engine = engine.with_generated_keypair();
            tracing::warn!("Using ephemeral keypair (receipts won't be verifiable across restarts)");
        }

        // Create audit ledger
        let ledger = AuditLedger::new(&config.audit_db)?;
        let ledger = if config.max_audit_entries > 0 {
            ledger.with_max_entries(config.max_audit_entries)
        } else {
            ledger
        };

        // Create event channel
        let (event_tx, _) = broadcast::channel(1024);

        // Generate session ID
        let session_id = uuid::Uuid::new_v4().to_string();

        // Record session start
        let start_event = AuditEvent::session_start(&session_id, None);
        ledger.record(&start_event)?;

        Ok(Self {
            engine: Arc::new(RwLock::new(engine)),
            ledger: Arc::new(ledger),
            event_tx,
            config: Arc::new(config),
            session_id,
            started_at: chrono::Utc::now(),
        })
    }

    /// Broadcast an event
    pub fn broadcast(&self, event: DaemonEvent) {
        // Ignore send errors (no subscribers)
        let _ = self.event_tx.send(event);
    }

    /// Reload policy from config
    pub async fn reload_policy(&self) -> anyhow::Result<()> {
        let policy = if let Some(ref path) = self.config.policy_path {
            Policy::from_yaml_file(path)?
        } else {
            RuleSet::by_name(&self.config.ruleset)
                .ok_or_else(|| anyhow::anyhow!("Unknown ruleset: {}", self.config.ruleset))?
                .policy
        };

        // Get the keypair from current engine
        let mut engine = self.engine.write().await;
        let new_engine = HushEngine::with_policy(policy).with_generated_keypair();
        *engine = new_engine;

        tracing::info!("Policy reloaded");

        self.broadcast(DaemonEvent {
            event_type: "policy_reload".to_string(),
            data: serde_json::json!({"timestamp": chrono::Utc::now().to_rfc3339()}),
        });

        Ok(())
    }

    /// Get daemon uptime in seconds
    pub fn uptime_secs(&self) -> i64 {
        (chrono::Utc::now() - self.started_at).num_seconds()
    }
}
```

**Step 2: Add mod declaration**

Add after the `mod audit;` line in `crates/hushd/src/main.rs`:

```rust
mod state;
```

**Step 3: Verify build**

Run: `cargo build -p hushd`
Expected: Compiles successfully

**Step 4: Commit**

```bash
git add crates/hushd/src/state.rs crates/hushd/src/main.rs
git commit -m "feat(hushd): add shared application state"
```

---

## Task 5: Create HTTP API Handlers

**Files:**
- Create: `crates/hushd/src/api/mod.rs`
- Create: `crates/hushd/src/api/health.rs`
- Create: `crates/hushd/src/api/check.rs`
- Create: `crates/hushd/src/api/policy.rs`
- Create: `crates/hushd/src/api/audit.rs`
- Create: `crates/hushd/src/api/events.rs`
- Modify: `crates/hushd/src/main.rs`

**Step 1: Create api/health.rs**

Create `crates/hushd/src/api/health.rs`:

```rust
//! Health check endpoint

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::state::AppState;

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_secs: i64,
    pub session_id: String,
    pub audit_count: usize,
}

/// GET /health
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let audit_count = state.ledger.count().unwrap_or(0);

    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_secs: state.uptime_secs(),
        session_id: state.session_id.clone(),
        audit_count,
    })
}
```

**Step 2: Create api/check.rs**

Create `crates/hushd/src/api/check.rs`:

```rust
//! Action checking endpoint

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use clawdstrike::guards::{GuardContext, GuardResult};

use crate::audit::AuditEvent;
use crate::state::{AppState, DaemonEvent};

#[derive(Debug, Deserialize)]
pub struct CheckRequest {
    /// Action type: file_access, file_write, egress, shell, mcp_tool, patch
    pub action_type: String,
    /// Target (path, host:port, tool name)
    pub target: String,
    /// Optional content (for file_write, patch)
    #[serde(default)]
    pub content: Option<String>,
    /// Optional arguments (for mcp_tool)
    #[serde(default)]
    pub args: Option<serde_json::Value>,
    /// Optional session ID
    #[serde(default)]
    pub session_id: Option<String>,
    /// Optional agent ID
    #[serde(default)]
    pub agent_id: Option<String>,
}

#[derive(Serialize)]
pub struct CheckResponse {
    pub allowed: bool,
    pub guard: String,
    pub severity: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl From<GuardResult> for CheckResponse {
    fn from(result: GuardResult) -> Self {
        Self {
            allowed: result.allowed,
            guard: result.guard,
            severity: format!("{:?}", result.severity),
            message: result.message,
            details: result.details,
        }
    }
}

/// POST /api/v1/check
pub async fn check_action(
    State(state): State<AppState>,
    Json(request): Json<CheckRequest>,
) -> Result<Json<CheckResponse>, (StatusCode, String)> {
    let engine = state.engine.read().await;

    let context = GuardContext::new()
        .with_session_id(request.session_id.clone().unwrap_or_else(|| state.session_id.clone()));

    let result = match request.action_type.as_str() {
        "file_access" => {
            engine.check_file_access(&request.target, &context).await
        }
        "file_write" => {
            let content = request.content.as_deref().unwrap_or("").as_bytes();
            engine.check_file_write(&request.target, content, &context).await
        }
        "egress" => {
            let parts: Vec<&str> = request.target.split(':').collect();
            let host = parts[0];
            let port: u16 = parts.get(1).and_then(|p| p.parse().ok()).unwrap_or(443);
            engine.check_egress(host, port, &context).await
        }
        "shell" => {
            engine.check_shell(&request.target, &context).await
        }
        "mcp_tool" => {
            let args = request.args.clone().unwrap_or(serde_json::json!({}));
            engine.check_mcp_tool(&request.target, &args, &context).await
        }
        "patch" => {
            let diff = request.content.as_deref().unwrap_or("");
            engine.check_patch(&request.target, diff, &context).await
        }
        _ => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("Unknown action type: {}", request.action_type),
            ));
        }
    };

    let result = result.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Record to audit ledger
    let audit_event = AuditEvent::from_guard_result(
        &request.action_type,
        Some(&request.target),
        &result,
        request.session_id.as_deref(),
        request.agent_id.as_deref(),
    );

    if let Err(e) = state.ledger.record(&audit_event) {
        tracing::warn!(error = %e, "Failed to record audit event");
    }

    // Broadcast event
    state.broadcast(DaemonEvent {
        event_type: if result.allowed { "check" } else { "violation" }.to_string(),
        data: serde_json::json!({
            "action_type": request.action_type,
            "target": request.target,
            "allowed": result.allowed,
            "guard": result.guard,
        }),
    });

    Ok(Json(result.into()))
}
```

**Step 3: Create api/policy.rs**

Create `crates/hushd/src/api/policy.rs`:

```rust
//! Policy management endpoints

use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

use clawdstrike::Policy;

use crate::state::AppState;

#[derive(Serialize)]
pub struct PolicyResponse {
    pub name: String,
    pub version: String,
    pub description: String,
    pub policy_hash: String,
    pub yaml: String,
}

#[derive(Deserialize)]
pub struct UpdatePolicyRequest {
    /// YAML policy content
    pub yaml: String,
}

#[derive(Serialize)]
pub struct UpdatePolicyResponse {
    pub success: bool,
    pub message: String,
}

/// GET /api/v1/policy
pub async fn get_policy(State(state): State<AppState>) -> Result<Json<PolicyResponse>, (StatusCode, String)> {
    let engine = state.engine.read().await;

    // We need to access the policy - let's get the hash first
    let policy_hash = engine.policy_hash()
        .map(|h| h.to_hex())
        .unwrap_or_else(|_| "unknown".to_string());

    // Get the ruleset name from config
    let ruleset = clawdstrike::RuleSet::by_name(&state.config.ruleset)
        .unwrap_or_else(clawdstrike::RuleSet::default_ruleset);

    let yaml = ruleset.policy.to_yaml()
        .unwrap_or_else(|_| "# Unable to serialize policy".to_string());

    Ok(Json(PolicyResponse {
        name: ruleset.name,
        version: ruleset.policy.version,
        description: ruleset.description,
        policy_hash,
        yaml,
    }))
}

/// PUT /api/v1/policy
pub async fn update_policy(
    State(state): State<AppState>,
    Json(request): Json<UpdatePolicyRequest>,
) -> Result<Json<UpdatePolicyResponse>, (StatusCode, String)> {
    // Parse the new policy
    let policy = Policy::from_yaml(&request.yaml)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid policy YAML: {}", e)))?;

    // Update the engine
    let mut engine = state.engine.write().await;
    *engine = clawdstrike::HushEngine::with_policy(policy).with_generated_keypair();

    tracing::info!("Policy updated via API");

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy updated successfully".to_string(),
    }))
}

/// POST /api/v1/policy/reload
pub async fn reload_policy(State(state): State<AppState>) -> Result<Json<UpdatePolicyResponse>, (StatusCode, String)> {
    state.reload_policy().await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(UpdatePolicyResponse {
        success: true,
        message: "Policy reloaded from file".to_string(),
    }))
}
```

**Step 4: Create api/audit.rs**

Create `crates/hushd/src/api/audit.rs`:

```rust
//! Audit log endpoints

use axum::{
    extract::{Query, State},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};

use crate::audit::{AuditEvent, AuditFilter, ExportFormat};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// Filter by event type
    pub event_type: Option<String>,
    /// Filter by action type
    pub action_type: Option<String>,
    /// Filter by decision (allowed, blocked)
    pub decision: Option<String>,
    /// Filter by session ID
    pub session_id: Option<String>,
    /// Maximum events to return
    pub limit: Option<usize>,
    /// Offset for pagination
    pub offset: Option<usize>,
    /// Export format (json, csv, jsonl)
    pub format: Option<String>,
}

#[derive(Serialize)]
pub struct AuditResponse {
    pub events: Vec<AuditEvent>,
    pub total: usize,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Serialize)]
pub struct AuditStatsResponse {
    pub total_events: usize,
    pub violations: usize,
    pub allowed: usize,
    pub session_id: String,
    pub uptime_secs: i64,
}

/// GET /api/v1/audit
pub async fn query_audit(
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let filter = AuditFilter {
        event_type: query.event_type,
        action_type: query.action_type,
        decision: query.decision,
        session_id: query.session_id,
        limit: query.limit,
        offset: query.offset,
        ..Default::default()
    };

    // Handle export formats
    if let Some(format_str) = query.format {
        let format = match format_str.to_lowercase().as_str() {
            "csv" => ExportFormat::Csv,
            "jsonl" => ExportFormat::Jsonl,
            _ => ExportFormat::Json,
        };

        let data = state.ledger.export(&filter, format.clone())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let content_type = match format {
            ExportFormat::Csv => "text/csv",
            ExportFormat::Jsonl => "application/x-ndjson",
            ExportFormat::Json => "application/json",
        };

        return Ok((
            [(header::CONTENT_TYPE, content_type)],
            data,
        ).into_response());
    }

    let events = state.ledger.query(&filter)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let total = state.ledger.count()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AuditResponse {
        events,
        total,
        limit: query.limit,
        offset: query.offset,
    }).into_response())
}

/// GET /api/v1/audit/stats
pub async fn audit_stats(State(state): State<AppState>) -> Result<Json<AuditStatsResponse>, (StatusCode, String)> {
    let total = state.ledger.count()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Count violations
    let violations = state.ledger.query(&AuditFilter {
        decision: Some("blocked".to_string()),
        ..Default::default()
    }).map(|v| v.len())
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let allowed = state.ledger.query(&AuditFilter {
        decision: Some("allowed".to_string()),
        ..Default::default()
    }).map(|v| v.len())
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AuditStatsResponse {
        total_events: total,
        violations,
        allowed,
        session_id: state.session_id.clone(),
        uptime_secs: state.uptime_secs(),
    }))
}
```

**Step 5: Create api/events.rs**

Create `crates/hushd/src/api/events.rs`:

```rust
//! Server-Sent Events (SSE) streaming endpoint

use std::convert::Infallible;

use axum::{
    extract::State,
    response::sse::{Event, Sse},
};
use futures::stream::Stream;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::state::{AppState, DaemonEvent};

/// GET /api/v1/events
pub async fn stream_events(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = state.event_tx.subscribe();

    let stream = BroadcastStream::new(rx)
        .filter_map(|result| {
            result.ok().map(|event: DaemonEvent| {
                Ok(Event::default()
                    .event(event.event_type)
                    .json_data(event.data)
                    .unwrap_or_else(|_| Event::default().data("error")))
            })
        });

    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(30))
            .text("keep-alive"),
    )
}
```

**Step 6: Create api/mod.rs**

Create `crates/hushd/src/api/mod.rs`:

```rust
//! HTTP API for hushd daemon

mod health;
mod check;
mod policy;
mod audit;
mod events;

use axum::{
    routing::{get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

use crate::state::AppState;

pub use health::HealthResponse;
pub use check::{CheckRequest, CheckResponse};
pub use policy::{PolicyResponse, UpdatePolicyRequest};
pub use audit::{AuditQuery, AuditResponse, AuditStatsResponse};

/// Create the API router
pub fn create_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Health check
        .route("/health", get(health::health))

        // Action checking
        .route("/api/v1/check", post(check::check_action))

        // Policy management
        .route("/api/v1/policy", get(policy::get_policy).put(policy::update_policy))
        .route("/api/v1/policy/reload", post(policy::reload_policy))

        // Audit log
        .route("/api/v1/audit", get(audit::query_audit))
        .route("/api/v1/audit/stats", get(audit::audit_stats))

        // Event streaming
        .route("/api/v1/events", get(events::stream_events))

        .layer(TraceLayer::new_for_http())
        .layer(cors)
        .with_state(state)
}
```

**Step 7: Add mod declaration**

Add after `mod state;` in `crates/hushd/src/main.rs`:

```rust
mod api;
```

**Step 8: Verify build**

Run: `cargo build -p hushd`
Expected: Compiles successfully

**Step 9: Commit**

```bash
git add crates/hushd/src/api/
git commit -m "feat(hushd): add HTTP API endpoints (health, check, policy, audit, events)"
```

---

## Task 6: Update Main Entry Point

**Files:**
- Modify: `crates/hushd/src/main.rs`

**Step 1: Rewrite main.rs**

Replace the entire content of `crates/hushd/src/main.rs`:

```rust
//! Hushd - Clawdstrike security daemon
//!
//! This daemon provides:
//! - HTTP API for action checking
//! - Policy management and hot-reload
//! - SQLite audit ledger
//! - SSE event streaming

mod api;
mod audit;
mod config;
mod state;

use std::net::SocketAddr;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::config::Config;
use crate::state::AppState;

#[derive(Parser)]
#[command(name = "hushd")]
#[command(about = "Clawdstrike security daemon", long_about = None)]
#[command(version)]
struct Cli {
    /// Verbosity level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Path to configuration file
    #[arg(short, long, global = true)]
    config: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon (default)
    Start {
        /// Bind address
        #[arg(short, long)]
        bind: Option<String>,

        /// Port
        #[arg(short, long)]
        port: Option<u16>,

        /// Ruleset to use
        #[arg(short, long)]
        ruleset: Option<String>,
    },

    /// Show daemon status
    Status {
        /// Daemon URL
        #[arg(default_value = "http://127.0.0.1:9876")]
        url: String,
    },

    /// Show effective configuration
    ShowConfig,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Load configuration
    let mut config = if let Some(ref path) = cli.config {
        Config::from_file(path)?
    } else {
        Config::load_default()
    };

    // Override log level from CLI
    let log_level = match cli.verbose {
        0 => config.tracing_level(),
        1 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };

    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::filter::LevelFilter::from_level(log_level))
        .init();

    match cli.command {
        None | Some(Commands::Start { .. }) => {
            // Apply CLI overrides
            if let Some(Commands::Start { bind, port, ruleset }) = cli.command {
                if let Some(bind) = bind {
                    if let Some(port) = port {
                        config.listen = format!("{}:{}", bind, port);
                    } else {
                        let current_port = config.listen.split(':').last().unwrap_or("9876");
                        config.listen = format!("{}:{}", bind, current_port);
                    }
                } else if let Some(port) = port {
                    let current_host = config.listen.split(':').next().unwrap_or("127.0.0.1");
                    config.listen = format!("{}:{}", current_host, port);
                }
                if let Some(ruleset) = ruleset {
                    config.ruleset = ruleset;
                }
            }

            run_daemon(config).await
        }

        Some(Commands::Status { url }) => {
            check_status(&url).await
        }

        Some(Commands::ShowConfig) => {
            let yaml = serde_yaml::to_string(&config)?;
            println!("{}", yaml);
            Ok(())
        }
    }
}

async fn run_daemon(config: Config) -> anyhow::Result<()> {
    tracing::info!(
        listen = %config.listen,
        ruleset = %config.ruleset,
        audit_db = %config.audit_db.display(),
        "Starting hushd"
    );

    // Create application state
    let state = AppState::new(config.clone())?;

    // Create router
    let app = api::create_router(state.clone());

    // Parse listen address
    let addr: SocketAddr = config.listen.parse()?;

    // Create listener
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(address = %addr, "Listening");

    // Setup signal handlers for graceful shutdown
    let shutdown_signal = async {
        let ctrl_c = async {
            tokio::signal::ctrl_c()
                .await
                .expect("Failed to install Ctrl+C handler");
        };

        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler")
                .recv()
                .await;
        };

        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();

        tokio::select! {
            _ = ctrl_c => {},
            _ = terminate => {},
        }

        tracing::info!("Shutdown signal received");
    };

    // Run server
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    // Log final stats
    let engine = state.engine.read().await;
    let stats = engine.stats().await;
    tracing::info!(
        actions = stats.action_count,
        violations = stats.violation_count,
        uptime_secs = state.uptime_secs(),
        "Daemon stopped"
    );

    Ok(())
}

async fn check_status(url: &str) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", url))
        .send()
        .await?;

    if resp.status().is_success() {
        let health: api::HealthResponse = resp.json().await?;
        println!("Status: {}", health.status);
        println!("Version: {}", health.version);
        println!("Uptime: {}s", health.uptime_secs);
        println!("Session: {}", health.session_id);
        println!("Audit events: {}", health.audit_count);
    } else {
        println!("Error: {} {}", resp.status(), resp.text().await?);
    }

    Ok(())
}
```

**Step 2: Add reqwest dependency for status command**

Update `crates/hushd/Cargo.toml` to add reqwest:

```toml
# Add under [dependencies]
reqwest = { version = "0.12", features = ["json"] }
```

**Step 3: Verify build**

Run: `cargo build -p hushd`
Expected: Compiles successfully

**Step 4: Test the daemon**

Run: `cargo run -p hushd -- --help`
Expected: Shows help with start, status, show-config subcommands

**Step 5: Commit**

```bash
git add crates/hushd/src/main.rs crates/hushd/Cargo.toml
git commit -m "feat(hushd): implement daemon main with start/status/show-config commands"
```

---

## Task 7: Add Daemon Commands to hush-cli

**Files:**
- Modify: `crates/hush-cli/src/main.rs`
- Modify: `crates/hush-cli/Cargo.toml`

**Step 1: Update hush-cli Cargo.toml**

Add reqwest dependency to `crates/hush-cli/Cargo.toml`:

```toml
[dependencies]
# ... existing deps ...
reqwest = { version = "0.12", features = ["json"] }
```

**Step 2: Add daemon subcommand to hush-cli**

Update `crates/hush-cli/src/main.rs` to add daemon commands. Add after `PolicyCommands`:

```rust
#[derive(Subcommand)]
enum DaemonCommands {
    /// Start the daemon
    Start {
        /// Configuration file
        #[arg(short, long)]
        config: Option<String>,
        /// Bind address
        #[arg(short, long, default_value = "127.0.0.1")]
        bind: String,
        /// Port
        #[arg(short, long, default_value = "9876")]
        port: u16,
    },
    /// Stop the daemon
    Stop {
        /// Daemon URL
        #[arg(default_value = "http://127.0.0.1:9876")]
        url: String,
    },
    /// Show daemon status
    Status {
        /// Daemon URL
        #[arg(default_value = "http://127.0.0.1:9876")]
        url: String,
    },
    /// Reload daemon policy
    Reload {
        /// Daemon URL
        #[arg(default_value = "http://127.0.0.1:9876")]
        url: String,
    },
}
```

Add to the `Commands` enum:

```rust
    /// Daemon management commands
    Daemon {
        #[command(subcommand)]
        command: DaemonCommands,
    },
```

Add handler in the match block:

```rust
        Commands::Daemon { command } => match command {
            DaemonCommands::Start { config, bind, port } => {
                use std::process::Command;

                let mut cmd = Command::new("hushd");
                cmd.arg("start")
                    .arg("--bind").arg(&bind)
                    .arg("--port").arg(port.to_string());

                if let Some(config) = config {
                    cmd.arg("--config").arg(&config);
                }

                println!("Starting hushd on {}:{}...", bind, port);

                // Try to spawn the daemon
                match cmd.spawn() {
                    Ok(_) => println!("Daemon started"),
                    Err(e) => {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            eprintln!("Error: hushd not found in PATH. Run 'cargo install --path crates/hushd'");
                        } else {
                            eprintln!("Error starting daemon: {}", e);
                        }
                        std::process::exit(1);
                    }
                }
            }
            DaemonCommands::Stop { url } => {
                println!("Note: Daemon can be stopped with Ctrl+C or SIGTERM");
                println!("Checking status at {}...", url);

                let client = reqwest::blocking::Client::new();
                match client.get(format!("{}/health", url)).send() {
                    Ok(resp) if resp.status().is_success() => {
                        println!("Daemon is running. Send SIGTERM to stop.");
                    }
                    _ => {
                        println!("Daemon is not running.");
                    }
                }
            }
            DaemonCommands::Status { url } => {
                let client = reqwest::blocking::Client::new();
                match client.get(format!("{}/health", url)).send() {
                    Ok(resp) if resp.status().is_success() => {
                        let health: serde_json::Value = resp.json().unwrap_or_default();
                        println!("Status: {}", health.get("status").and_then(|v| v.as_str()).unwrap_or("unknown"));
                        println!("Version: {}", health.get("version").and_then(|v| v.as_str()).unwrap_or("unknown"));
                        println!("Uptime: {}s", health.get("uptime_secs").and_then(|v| v.as_i64()).unwrap_or(0));
                        println!("Session: {}", health.get("session_id").and_then(|v| v.as_str()).unwrap_or("unknown"));
                        println!("Audit events: {}", health.get("audit_count").and_then(|v| v.as_u64()).unwrap_or(0));
                    }
                    _ => {
                        println!("Daemon is not running at {}", url);
                        std::process::exit(1);
                    }
                }
            }
            DaemonCommands::Reload { url } => {
                let client = reqwest::blocking::Client::new();
                match client.post(format!("{}/api/v1/policy/reload", url)).send() {
                    Ok(resp) if resp.status().is_success() => {
                        println!("Policy reloaded successfully");
                    }
                    Ok(resp) => {
                        eprintln!("Error: {} {}", resp.status(), resp.text().unwrap_or_default());
                        std::process::exit(1);
                    }
                    Err(e) => {
                        eprintln!("Error connecting to daemon: {}", e);
                        std::process::exit(1);
                    }
                }
            }
        },
```

**Step 3: Update reqwest to use blocking**

Update `crates/hush-cli/Cargo.toml`:

```toml
reqwest = { version = "0.12", features = ["json", "blocking"] }
```

**Step 4: Test CLI**

Run: `cargo run -p hush-cli -- daemon --help`
Expected: Shows daemon subcommands

**Step 5: Commit**

```bash
git add crates/hush-cli/
git commit -m "feat(hush-cli): add daemon management commands (start/stop/status/reload)"
```

---

## Task 8: Create System Integration Files

**Files:**
- Create: `deploy/hushd.service`
- Create: `deploy/com.clawdstrike.hushd.plist`
- Create: `Dockerfile.hushd`
- Create: `deploy/hushd.yaml.example`

**Step 1: Create deploy directory**

```bash
mkdir -p deploy
```

**Step 2: Create systemd service file**

Create `deploy/hushd.service`:

```ini
[Unit]
Description=Clawdstrike Security Daemon
Documentation=https://github.com/backbay-labs/clawdstrike
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=hushd
Group=hushd
ExecStart=/usr/local/bin/hushd --config /etc/hushd/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

# Allow reading config and writing to data directory
ReadOnlyPaths=/
ReadWritePaths=/var/lib/hushd
ReadWritePaths=/var/log/hushd

# Environment
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

**Step 3: Create launchd plist**

Create `deploy/com.clawdstrike.hushd.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.clawdstrike.hushd</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/hushd</string>
        <string>--config</string>
        <string>/usr/local/etc/hushd/config.yaml</string>
    </array>

    <key>RunAtLoad</key>
    <true/>

    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>/usr/local/var/log/hushd/hushd.log</string>

    <key>StandardErrorPath</key>
    <string>/usr/local/var/log/hushd/hushd.error.log</string>

    <key>WorkingDirectory</key>
    <string>/usr/local/var/lib/hushd</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key>
        <string>info</string>
    </dict>
</dict>
</plist>
```

**Step 4: Create Dockerfile**

Create `Dockerfile.hushd`:

```dockerfile
# Build stage
FROM rust:1.75-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev openssl-libs-static

WORKDIR /build
COPY . .

# Build release binary
RUN cargo build --release -p hushd

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tini

# Create non-root user
RUN addgroup -g 1000 hushd && \
    adduser -u 1000 -G hushd -D -h /var/lib/hushd hushd

# Create directories
RUN mkdir -p /etc/hushd /var/lib/hushd /var/log/hushd && \
    chown -R hushd:hushd /var/lib/hushd /var/log/hushd

# Copy binary
COPY --from=builder /build/target/release/hushd /usr/local/bin/

# Copy default config
COPY deploy/hushd.yaml.example /etc/hushd/config.yaml

USER hushd
WORKDIR /var/lib/hushd

EXPOSE 9876

ENTRYPOINT ["/sbin/tini", "--"]
CMD ["hushd", "--config", "/etc/hushd/config.yaml"]
```

**Step 5: Create example config**

Create `deploy/hushd.yaml.example`:

```yaml
# Hushd Configuration
# Copy to /etc/hushd/config.yaml and customize

# Listen address
listen: "0.0.0.0:9876"

# Policy configuration
# Option 1: Use a named ruleset (default, strict, permissive)
ruleset: default

# Option 2: Use a custom policy file (uncomment)
# policy_path: /etc/hushd/policy.yaml

# Audit database path
audit_db: /var/lib/hushd/audit.db

# Log level: trace, debug, info, warn, error
log_level: info

# Signing key for receipts (optional)
# If not set, an ephemeral key is generated at startup
# signing_key: /etc/hushd/signing.key

# Enable CORS for browser access
cors_enabled: true

# Maximum audit entries to keep (0 = unlimited)
max_audit_entries: 100000

# TLS configuration (optional)
# tls:
#   cert_path: /etc/hushd/cert.pem
#   key_path: /etc/hushd/key.pem
```

**Step 6: Commit**

```bash
git add deploy/ Dockerfile.hushd
git commit -m "feat(deploy): add systemd, launchd, Docker, and example config"
```

---

## Task 9: Add Integration Tests

**Files:**
- Create: `crates/hushd/tests/integration.rs`

**Step 1: Create integration test file**

Create `crates/hushd/tests/integration.rs`:

```rust
//! Integration tests for hushd HTTP API

use std::time::Duration;
use tokio::time::sleep;

// Note: These tests require the daemon to be running
// Run with: cargo test -p hushd --test integration -- --ignored

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_health_endpoint() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:9876/health")
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let health: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(health["status"], "healthy");
    assert!(health["version"].is_string());
    assert!(health["uptime_secs"].is_number());
}

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_check_file_access_allowed() {
    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:9876/api/v1/check")
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/app/src/main.rs"
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["allowed"], true);
}

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_check_file_access_blocked() {
    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:9876/api/v1/check")
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/home/user/.ssh/id_rsa"
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["allowed"], false);
    assert!(result["message"].as_str().unwrap().contains("forbidden"));
}

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_check_egress_allowed() {
    let client = reqwest::Client::new();
    let resp = client
        .post("http://127.0.0.1:9876/api/v1/check")
        .json(&serde_json::json!({
            "action_type": "egress",
            "target": "api.openai.com:443"
        }))
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let result: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(result["allowed"], true);
}

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_get_policy() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:9876/api/v1/policy")
        .send()
        .await
        .expect("Failed to connect to daemon");

    assert!(resp.status().is_success());

    let policy: serde_json::Value = resp.json().await.unwrap();
    assert!(policy["name"].is_string());
    assert!(policy["yaml"].is_string());
    assert!(policy["policy_hash"].is_string());
}

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_audit_query() {
    let client = reqwest::Client::new();

    // First, make some actions to audit
    client
        .post("http://127.0.0.1:9876/api/v1/check")
        .json(&serde_json::json!({
            "action_type": "file_access",
            "target": "/test/file.txt"
        }))
        .send()
        .await
        .expect("Failed to check action");

    // Query audit log
    let resp = client
        .get("http://127.0.0.1:9876/api/v1/audit?limit=10")
        .send()
        .await
        .expect("Failed to query audit");

    assert!(resp.status().is_success());

    let audit: serde_json::Value = resp.json().await.unwrap();
    assert!(audit["events"].is_array());
    assert!(audit["total"].is_number());
}

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_audit_stats() {
    let client = reqwest::Client::new();
    let resp = client
        .get("http://127.0.0.1:9876/api/v1/audit/stats")
        .send()
        .await
        .expect("Failed to get audit stats");

    assert!(resp.status().is_success());

    let stats: serde_json::Value = resp.json().await.unwrap();
    assert!(stats["total_events"].is_number());
    assert!(stats["violations"].is_number());
    assert!(stats["allowed"].is_number());
}

#[tokio::test]
#[ignore = "requires running daemon"]
async fn test_sse_events() {
    let client = reqwest::Client::new();

    // Start listening to events
    let resp = client
        .get("http://127.0.0.1:9876/api/v1/events")
        .send()
        .await
        .expect("Failed to connect to events");

    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers().get("content-type").map(|v| v.to_str().unwrap_or("")),
        Some("text/event-stream")
    );
}

// Unit test that doesn't require daemon
#[test]
fn test_config_default() {
    // This test can run without the daemon
    let config = hushd::config::Config::default();
    assert_eq!(config.listen, "127.0.0.1:9876");
    assert_eq!(config.ruleset, "default");
}
```

**Step 2: Update Cargo.toml for integration tests**

Add to `crates/hushd/Cargo.toml`:

```toml
[dev-dependencies]
reqwest = { version = "0.12", features = ["json"] }
```

**Step 3: Make config module public for tests**

Update `crates/hushd/src/main.rs` - change `mod config;` to `pub mod config;`

**Step 4: Create lib.rs for test access**

Create `crates/hushd/src/lib.rs`:

```rust
//! Hushd library - shared types for testing

pub mod config;
pub mod audit;
pub mod state;
pub mod api;
```

Update `crates/hushd/Cargo.toml` to add lib:

```toml
[lib]
name = "hushd"
path = "src/lib.rs"
```

**Step 5: Verify tests compile**

Run: `cargo test -p hushd --no-run`
Expected: Compiles successfully

**Step 6: Commit**

```bash
git add crates/hushd/
git commit -m "test(hushd): add integration tests for HTTP API"
```

---

## Task 10: Final Verification and Documentation

**Files:**
- Modify: `README.md` (optional, add daemon section)

**Step 1: Build release binary**

Run: `cargo build --release -p hushd`
Expected: Builds successfully

**Step 2: Run unit tests**

Run: `cargo test -p hushd`
Expected: All unit tests pass

**Step 3: Manual verification**

Start the daemon:
```bash
./target/release/hushd start
```

In another terminal, test endpoints:
```bash
# Health check
curl http://127.0.0.1:9876/health

# Check an action
curl -X POST http://127.0.0.1:9876/api/v1/check \
  -H "Content-Type: application/json" \
  -d '{"action_type":"file_access","target":"/home/user/.ssh/id_rsa"}'

# Get policy
curl http://127.0.0.1:9876/api/v1/policy

# Query audit
curl http://127.0.0.1:9876/api/v1/audit?limit=5

# Audit stats
curl http://127.0.0.1:9876/api/v1/audit/stats
```

**Step 4: Test Docker build**

Run: `docker build -f Dockerfile.hushd -t hushd:local .`
Expected: Image builds successfully

**Step 5: Commit final changes**

```bash
git add -A
git commit -m "feat(hushd): complete daemon implementation

- HTTP API: /health, /api/v1/check, /api/v1/policy, /api/v1/audit, /api/v1/events
- SQLite audit ledger with record, query, export
- SSE event streaming
- Configuration file support (YAML/TOML)
- systemd service file
- macOS launchd plist
- Dockerfile
- CLI commands: hush daemon start/stop/status/reload"
```

---

## Summary

This plan implements the full hushd daemon with:

1. **HTTP API** (axum):
   - `GET /health` - Health check
   - `POST /api/v1/check` - Check actions against policy
   - `GET/PUT /api/v1/policy` - View/update policy
   - `POST /api/v1/policy/reload` - Hot-reload policy
   - `GET /api/v1/audit` - Query audit log
   - `GET /api/v1/audit/stats` - Get audit statistics
   - `GET /api/v1/events` - SSE event streaming

2. **SQLite Audit Ledger**:
   - Record events with full context
   - Query with filters
   - Export to JSON, JSONL, CSV

3. **Configuration**:
   - YAML and TOML support
   - Default config locations
   - CLI overrides

4. **System Integration**:
   - systemd service with security hardening
   - macOS launchd plist
   - Dockerfile with multi-stage build
   - Example configuration file

5. **CLI Commands**:
   - `hush daemon start` - Start daemon
   - `hush daemon stop` - Check/stop daemon
   - `hush daemon status` - Show status
   - `hush daemon reload` - Hot-reload policy

Total tasks: 10
Estimated time: 4-6 hours
