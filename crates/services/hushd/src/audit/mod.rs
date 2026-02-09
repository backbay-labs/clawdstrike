//! SQLite-backed audit ledger for security events

pub mod forward;
mod schema;

use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use clawdstrike::guards::GuardResult;
use ring::aead;
use ring::rand::SystemRandom;

/// Error type for audit operations
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Encryption error: {0}")]
    Crypto(String),
}

pub type Result<T> = std::result::Result<T, AuditError>;

#[derive(Clone)]
struct AuditEncryption {
    key: aead::LessSafeKey,
    rng: SystemRandom,
}

const AEAD_NONCE_LEN: usize = 12;
const AEAD_TAG_LEN: usize = 16;

impl AuditEncryption {
    fn new(key_bytes: [u8; 32]) -> Result<Self> {
        let unbound = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
            .map_err(|_| AuditError::Crypto("invalid encryption key".to_string()))?;
        Ok(Self {
            key: aead::LessSafeKey::new(unbound),
            rng: SystemRandom::new(),
        })
    }

    fn encrypt(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut nonce_bytes = [0u8; AEAD_NONCE_LEN];
        ring::rand::SecureRandom::fill(&self.rng, &mut nonce_bytes)
            .map_err(|_| AuditError::Crypto("failed to generate nonce".to_string()))?;
        let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, aead::Aad::from(aad), &mut in_out)
            .map_err(|_| AuditError::Crypto("encryption failed".to_string()))?;

        let mut out = Vec::with_capacity(AEAD_NONCE_LEN + in_out.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&in_out);
        Ok(out)
    }

    fn decrypt(&self, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        if blob.len() < AEAD_NONCE_LEN + AEAD_TAG_LEN {
            return Err(AuditError::Crypto("ciphertext too short".to_string()));
        }

        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&blob[..AEAD_NONCE_LEN]);
        let nonce = aead::Nonce::assume_unique_for_key(nonce);

        let mut in_out = blob[AEAD_NONCE_LEN..].to_vec();
        let plain = self
            .key
            .open_in_place(nonce, aead::Aad::from(aad), &mut in_out)
            .map_err(|_| AuditError::Crypto("decryption failed".to_string()))?;
        Ok(plain.to_vec())
    }
}

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
            id: Uuid::now_v7().to_string(),
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
            id: Uuid::now_v7().to_string(),
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
            id: Uuid::now_v7().to_string(),
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

fn append_filter_clauses(
    filter: &AuditFilter,
    sql: &mut String,
    params_vec: &mut Vec<Box<dyn rusqlite::ToSql>>,
) {
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
}

fn csv_escape_field(field: &str) -> String {
    // Prevent spreadsheet formula injection by prefixing a single quote.
    let mut field = field.to_string();
    if matches!(
        field.chars().next(),
        Some('=') | Some('+') | Some('-') | Some('@')
    ) {
        field.insert(0, '\'');
    }

    let needs_quotes =
        field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r');
    if !needs_quotes {
        return field;
    }

    let escaped = field.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

/// SQLite-backed audit ledger
pub struct AuditLedger {
    conn: Mutex<Connection>,
    max_entries: usize,
    encryption: Option<AuditEncryption>,
}

impl AuditLedger {
    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }

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
        maybe_add_metadata_enc_column(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            max_entries: 0,
            encryption: None,
        })
    }

    /// Create an in-memory ledger (for testing)
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(schema::CREATE_TABLES)?;
        maybe_add_metadata_enc_column(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
            max_entries: 0,
            encryption: None,
        })
    }

    /// Set maximum entries to keep (0 = unlimited)
    pub fn with_max_entries(mut self, max: usize) -> Self {
        self.max_entries = max;
        self
    }

    pub fn with_encryption_key(mut self, key: [u8; 32]) -> Result<Self> {
        self.encryption = Some(AuditEncryption::new(key)?);
        Ok(self)
    }

    /// Record an audit event
    pub fn record(&self, event: &AuditEvent) -> Result<()> {
        let conn = self.lock_conn();

        let (metadata_str, metadata_enc) = match (event.metadata.as_ref(), self.encryption.as_ref())
        {
            (None, _) => (None, None),
            (Some(v), None) => (Some(serde_json::to_string(v)?), None),
            (Some(v), Some(enc)) => {
                let bytes = serde_json::to_vec(v)?;
                let enc = enc.encrypt(event.id.as_bytes(), &bytes)?;
                (None, Some(enc))
            }
        };

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
                metadata_str,
                metadata_enc,
            ],
        )?;

        // Prune old entries if max_entries is set
        if self.max_entries > 0 {
            conn.execute(
                schema::DELETE_OLD_EVENTS,
                params![i64::try_from(self.max_entries).unwrap_or(i64::MAX)],
            )?;
        }

        Ok(())
    }

    /// Query audit events
    pub fn query(&self, filter: &AuditFilter) -> Result<Vec<AuditEvent>> {
        let conn = self.lock_conn();

        let mut sql = schema::SELECT_EVENTS.to_string();
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![];

        append_filter_clauses(filter, &mut sql, &mut params_vec);

        sql.push_str(" ORDER BY timestamp DESC");

        if let Some(limit) = filter.limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }
        if let Some(offset) = filter.offset {
            sql.push_str(&format!(" OFFSET {}", offset));
        }

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let mut rows = stmt.query(params_refs.as_slice())?;

        let mut events = Vec::new();
        while let Some(row) = rows.next()? {
            let id: String = row.get(0)?;
            let timestamp_str: String = row.get(1)?;
            let timestamp = DateTime::parse_from_rfc3339(&timestamp_str).map_err(|err| {
                AuditError::Database(rusqlite::Error::FromSqlConversionFailure(
                    1,
                    rusqlite::types::Type::Text,
                    Box::new(err),
                ))
            })?;

            let metadata_str: Option<String> = row.get(11)?;
            let metadata_enc: Option<Vec<u8>> = row.get(12)?;

            let metadata = if let Some(enc) = metadata_enc {
                if let Some(ref crypto) = self.encryption {
                    let bytes = crypto.decrypt(id.as_bytes(), &enc)?;
                    Some(serde_json::from_slice(&bytes)?)
                } else {
                    // Encryption disabled; fall back to plaintext if available.
                    metadata_str.and_then(|s| serde_json::from_str(&s).ok())
                }
            } else {
                metadata_str.and_then(|s| serde_json::from_str(&s).ok())
            };

            events.push(AuditEvent {
                id,
                timestamp: timestamp.with_timezone(&Utc),
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
            });
        }

        Ok(events)
    }

    /// Get event count
    pub fn count(&self) -> Result<usize> {
        let conn = self.lock_conn();
        let count: i64 = conn.query_row(schema::COUNT_EVENTS, [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Get event count matching the given filter (ignores limit/offset).
    pub fn count_filtered(&self, filter: &AuditFilter) -> Result<usize> {
        let conn = self.lock_conn();

        let mut sql = format!("{} WHERE 1=1", schema::COUNT_EVENTS);
        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![];
        append_filter_clauses(filter, &mut sql, &mut params_vec);

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let count: i64 = conn.query_row(sql.as_str(), params_refs.as_slice(), |row| row.get(0))?;
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
                let mut output = String::from(
                    "id,timestamp,event_type,action_type,target,decision,guard,severity,message,session_id,agent_id\n",
                );
                for event in events {
                    let fields = [
                        csv_escape_field(&event.id),
                        csv_escape_field(&event.timestamp.to_rfc3339()),
                        csv_escape_field(&event.event_type),
                        csv_escape_field(&event.action_type),
                        csv_escape_field(event.target.as_deref().unwrap_or("")),
                        csv_escape_field(&event.decision),
                        csv_escape_field(event.guard.as_deref().unwrap_or("")),
                        csv_escape_field(event.severity.as_deref().unwrap_or("")),
                        csv_escape_field(event.message.as_deref().unwrap_or("")),
                        csv_escape_field(event.session_id.as_deref().unwrap_or("")),
                        csv_escape_field(event.agent_id.as_deref().unwrap_or("")),
                    ];

                    for (idx, f) in fields.into_iter().enumerate() {
                        if idx > 0 {
                            output.push(',');
                        }
                        output.push_str(&f);
                    }
                    output.push('\n');
                }
                Ok(output.into_bytes())
            }
        }
    }
}

fn maybe_add_metadata_enc_column(conn: &Connection) -> Result<()> {
    let mut stmt = conn.prepare("PRAGMA table_info(audit_events)")?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == "metadata_enc" {
            return Ok(());
        }
    }

    // Existing DB from schema_version=1; migrate in place.
    conn.execute_batch("ALTER TABLE audit_events ADD COLUMN metadata_enc BLOB;")?;
    Ok(())
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
    fn test_ledger_encryption_roundtrip_and_ciphertext_storage() {
        let ledger = AuditLedger::in_memory()
            .unwrap()
            .with_encryption_key([7u8; 32])
            .unwrap();

        let event = AuditEvent {
            id: "enc-1".to_string(),
            timestamp: Utc::now(),
            event_type: "violation".to_string(),
            action_type: "file_write".to_string(),
            target: Some("/tmp/out.txt".to_string()),
            decision: "blocked".to_string(),
            guard: Some("secret_leak".to_string()),
            severity: Some("Critical".to_string()),
            message: Some("Potential secrets detected".to_string()),
            session_id: Some("session-enc".to_string()),
            agent_id: None,
            metadata: Some(serde_json::json!({
                "matches": [{"pattern": "github_token"}],
            })),
        };

        ledger.record(&event).unwrap();
        let events = ledger.query(&AuditFilter::default()).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(
            events[0].metadata.as_ref().unwrap()["matches"][0]["pattern"],
            "github_token"
        );

        // Ensure ciphertext is stored, and plaintext metadata is not.
        let conn = ledger.lock_conn();
        let (plain, enc): (Option<String>, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT metadata, metadata_enc FROM audit_events WHERE id = ?1",
                params![event.id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert!(plain.is_none());
        assert!(enc.is_some());
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
