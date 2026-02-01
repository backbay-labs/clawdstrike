//! SQLite-backed audit ledger for security events

mod schema;

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use hushclaw::guards::GuardResult;

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
                event
                    .metadata
                    .as_ref()
                    .and_then(|m| serde_json::to_string(m).ok()),
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
            let metadata = metadata_str.and_then(|s| serde_json::from_str(&s).ok());

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

        events
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(AuditError::from)
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
            ExportFormat::Json => Ok(serde_json::to_vec_pretty(&events)?),
            ExportFormat::Jsonl => {
                let mut output = Vec::new();
                for event in events {
                    output.extend(serde_json::to_vec(&event)?);
                    output.push(b'\n');
                }
                Ok(output)
            }
            ExportFormat::Csv => {
                let mut output =
                    "id,timestamp,event_type,action_type,target,decision,guard,severity,message,session_id,agent_id\n"
                        .to_string();
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
