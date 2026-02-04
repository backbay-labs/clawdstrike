use std::path::Path;
use std::sync::Mutex;

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension as _};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::{Error, Result};

const CREATE_TABLES: &str = r#"
CREATE TABLE IF NOT EXISTS audit_events_v2 (
  event_id TEXT PRIMARY KEY,
  timestamp TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  session_id TEXT NOT NULL,
  agent_id TEXT NULL,
  organization_id TEXT NULL,
  correlation_id TEXT NULL,

  action_type TEXT NOT NULL,
  action_resource TEXT NOT NULL,
  action_parameters TEXT NULL,
  action_result TEXT NULL,

  decision_allowed INTEGER NOT NULL,
  decision_guard TEXT NULL,
  decision_severity TEXT NULL,
  decision_reason TEXT NULL,
  decision_policy_hash TEXT NOT NULL,

  provenance TEXT NULL,
  extensions TEXT NULL,

  content_hash TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  signature TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_v2_org_ts ON audit_events_v2 (organization_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_v2_session_seq ON audit_events_v2 (session_id, sequence);
"#;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEventV2 {
    pub event_id: String,
    pub timestamp: String,
    pub sequence: u64,
    pub session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,

    pub action_type: String,
    pub action_resource: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_parameters: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_result: Option<Value>,

    pub decision_allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_guard: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_severity: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,
    pub decision_policy_hash: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Value>,

    pub content_hash: String,
    pub previous_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl AuditEventV2 {
    /// Render this event into the nested API/export shape.
    pub fn as_spec_json(&self) -> Value {
        let mut root = serde_json::Map::new();
        root.insert("eventId".to_string(), Value::String(self.event_id.clone()));
        root.insert("timestamp".to_string(), Value::String(self.timestamp.clone()));
        root.insert(
            "sequence".to_string(),
            Value::Number(self.sequence.into()),
        );
        root.insert("sessionId".to_string(), Value::String(self.session_id.clone()));
        if let Some(v) = self.agent_id.as_ref() {
            root.insert("agentId".to_string(), Value::String(v.clone()));
        }
        if let Some(v) = self.organization_id.as_ref() {
            root.insert("organizationId".to_string(), Value::String(v.clone()));
        }
        if let Some(v) = self.correlation_id.as_ref() {
            root.insert("correlationId".to_string(), Value::String(v.clone()));
        }

        let mut action = serde_json::Map::new();
        action.insert("type".to_string(), Value::String(self.action_type.clone()));
        action.insert(
            "resource".to_string(),
            Value::String(self.action_resource.clone()),
        );
        if let Some(v) = self.action_parameters.as_ref() {
            action.insert("parameters".to_string(), v.clone());
        }
        if let Some(v) = self.action_result.as_ref() {
            action.insert("result".to_string(), v.clone());
        }
        root.insert("action".to_string(), Value::Object(action));

        let mut decision = serde_json::Map::new();
        decision.insert("allowed".to_string(), Value::Bool(self.decision_allowed));
        if let Some(v) = self.decision_guard.as_ref() {
            decision.insert("guard".to_string(), Value::String(v.clone()));
        }
        if let Some(v) = self.decision_severity.as_ref() {
            decision.insert("severity".to_string(), Value::String(v.clone()));
        }
        if let Some(v) = self.decision_reason.as_ref() {
            decision.insert("reason".to_string(), Value::String(v.clone()));
        }
        decision.insert(
            "policyHash".to_string(),
            Value::String(self.decision_policy_hash.clone()),
        );
        root.insert("decision".to_string(), Value::Object(decision));

        if let Some(v) = self.provenance.as_ref() {
            root.insert("provenance".to_string(), v.clone());
        }
        if let Some(v) = self.extensions.as_ref() {
            root.insert("extensions".to_string(), v.clone());
        }

        root.insert(
            "integrity".to_string(),
            serde_json::json!({
                "previousHash": self.previous_hash,
                "contentHash": self.content_hash,
                "signature": self.signature,
            }),
        );

        Value::Object(root)
    }
}

#[derive(Clone, Debug)]
pub struct NewAuditEventV2 {
    pub session_id: String,
    pub agent_id: Option<String>,
    pub organization_id: Option<String>,
    pub correlation_id: Option<String>,

    pub action_type: String,
    pub action_resource: String,
    pub action_parameters: Option<Value>,
    pub action_result: Option<Value>,

    pub decision_allowed: bool,
    pub decision_guard: Option<String>,
    pub decision_severity: Option<String>,
    pub decision_reason: Option<String>,
    pub decision_policy_hash: String,

    pub provenance: Option<Value>,
    pub extensions: Option<Value>,
}

pub struct AuditLedgerV2 {
    conn: Mutex<Connection>,
}

impl AuditLedgerV2 {
    fn lock_conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|err| err.into_inner())
    }

    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            std::fs::create_dir_all(parent)?;
        }

        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        conn.execute_batch(CREATE_TABLES)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(CREATE_TABLES)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn record(&self, input: NewAuditEventV2) -> Result<AuditEventV2> {
        let conn = self.lock_conn();
        let tx = conn.unchecked_transaction()?;

        let (prev_hash, next_seq) = tx
            .query_row(
                "SELECT content_hash, sequence FROM audit_events_v2 WHERE session_id = ? ORDER BY sequence DESC LIMIT 1",
                params![input.session_id],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()?
            .map(|(hash, seq)| (hash, seq.saturating_add(1)))
            .unwrap_or_else(|| (hex::encode([0u8; 32]), 1));

        let event_id = format!("evt_{}", Uuid::now_v7());
        let timestamp = Utc::now().to_rfc3339_opts(SecondsFormat::Nanos, true);
        let sequence_u64 = u64::try_from(next_seq).unwrap_or(0);

        let canonical_payload = canonical_event_payload(&event_id, &timestamp, sequence_u64, &input)?;
        let content_hash = compute_chain_hash_hex(&prev_hash, canonical_payload.as_bytes())?;

        let event = AuditEventV2 {
            event_id: event_id.clone(),
            timestamp: timestamp.clone(),
            sequence: sequence_u64,
            session_id: input.session_id.clone(),
            agent_id: input.agent_id.clone(),
            organization_id: input.organization_id.clone(),
            correlation_id: input.correlation_id.clone(),
            action_type: input.action_type.clone(),
            action_resource: input.action_resource.clone(),
            action_parameters: input.action_parameters.clone(),
            action_result: input.action_result.clone(),
            decision_allowed: input.decision_allowed,
            decision_guard: input.decision_guard.clone(),
            decision_severity: input.decision_severity.clone(),
            decision_reason: input.decision_reason.clone(),
            decision_policy_hash: input.decision_policy_hash.clone(),
            provenance: input.provenance.clone(),
            extensions: input.extensions.clone(),
            content_hash: content_hash.clone(),
            previous_hash: prev_hash.clone(),
            signature: None,
        };

        tx.execute(
            r#"INSERT INTO audit_events_v2 (
              event_id, timestamp, sequence, session_id, agent_id, organization_id, correlation_id,
              action_type, action_resource, action_parameters, action_result,
              decision_allowed, decision_guard, decision_severity, decision_reason, decision_policy_hash,
              provenance, extensions, content_hash, previous_hash, signature
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"#,
            params![
                event.event_id,
                event.timestamp,
                i64::try_from(event.sequence).unwrap_or(i64::MAX),
                event.session_id,
                event.agent_id,
                event.organization_id,
                event.correlation_id,
                event.action_type,
                event.action_resource,
                event
                    .action_parameters
                    .as_ref()
                    .and_then(|v| serde_json::to_string(v).ok()),
                event
                    .action_result
                    .as_ref()
                    .and_then(|v| serde_json::to_string(v).ok()),
                if event.decision_allowed { 1 } else { 0 },
                event.decision_guard,
                event.decision_severity,
                event.decision_reason,
                event.decision_policy_hash,
                event
                    .provenance
                    .as_ref()
                    .and_then(|v| serde_json::to_string(v).ok()),
                event
                    .extensions
                    .as_ref()
                    .and_then(|v| serde_json::to_string(v).ok()),
                event.content_hash,
                event.previous_hash,
                event.signature,
            ],
        )?;

        tx.commit()?;
        Ok(event)
    }

    pub fn query_by_org_range(
        &self,
        organization_id: &str,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        limit: Option<usize>,
    ) -> Result<Vec<AuditEventV2>> {
        let conn = self.lock_conn();

        let mut sql = String::from(
            "SELECT event_id, timestamp, sequence, session_id, agent_id, organization_id, correlation_id, action_type, action_resource, action_parameters, action_result, decision_allowed, decision_guard, decision_severity, decision_reason, decision_policy_hash, provenance, extensions, content_hash, previous_hash, signature FROM audit_events_v2 WHERE organization_id = ?",
        );

        let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(organization_id.to_string())];

        if let Some(start) = start {
            sql.push_str(" AND timestamp >= ?");
            params_vec.push(Box::new(
                start.to_rfc3339_opts(SecondsFormat::Nanos, true),
            ));
        }
        if let Some(end) = end {
            sql.push_str(" AND timestamp <= ?");
            params_vec.push(Box::new(
                end.to_rfc3339_opts(SecondsFormat::Nanos, true),
            ));
        }

        sql.push_str(" ORDER BY timestamp ASC, sequence ASC");
        if let Some(limit) = limit {
            sql.push_str(&format!(" LIMIT {}", limit));
        }

        let params_refs: Vec<&dyn rusqlite::ToSql> =
            params_vec.iter().map(|p| p.as_ref()).collect();

        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map(params_refs.as_slice(), |row| row_to_event(row))?;
        Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
    }

    pub fn get(&self, event_id: &str) -> Result<Option<AuditEventV2>> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT event_id, timestamp, sequence, session_id, agent_id, organization_id, correlation_id, action_type, action_resource, action_parameters, action_result, decision_allowed, decision_guard, decision_severity, decision_reason, decision_policy_hash, provenance, extensions, content_hash, previous_hash, signature FROM audit_events_v2 WHERE event_id = ?",
        )?;
        let event = stmt
            .query_row(params![event_id], |row| row_to_event(row))
            .optional()?;
        Ok(event)
    }

    pub fn verify_session_chain(&self, session_id: &str) -> Result<bool> {
        let conn = self.lock_conn();
        let mut stmt = conn.prepare(
            "SELECT event_id, timestamp, sequence, session_id, agent_id, organization_id, correlation_id, action_type, action_resource, action_parameters, action_result, decision_allowed, decision_guard, decision_severity, decision_reason, decision_policy_hash, provenance, extensions, content_hash, previous_hash, signature FROM audit_events_v2 WHERE session_id = ? ORDER BY sequence ASC",
        )?;
        let rows = stmt.query_map(params![session_id], |row| row_to_event(row))?;
        let events: Vec<AuditEventV2> = rows.collect::<std::result::Result<Vec<_>, _>>()?;

        let mut prev = hex::encode([0u8; 32]);
        for e in events {
            if e.previous_hash != prev {
                return Ok(false);
            }
            let payload = canonical_event_payload(
                &e.event_id,
                &e.timestamp,
                e.sequence,
                &NewAuditEventV2 {
                    session_id: e.session_id.clone(),
                    agent_id: e.agent_id.clone(),
                    organization_id: e.organization_id.clone(),
                    correlation_id: e.correlation_id.clone(),
                    action_type: e.action_type.clone(),
                    action_resource: e.action_resource.clone(),
                    action_parameters: e.action_parameters.clone(),
                    action_result: e.action_result.clone(),
                    decision_allowed: e.decision_allowed,
                    decision_guard: e.decision_guard.clone(),
                    decision_severity: e.decision_severity.clone(),
                    decision_reason: e.decision_reason.clone(),
                    decision_policy_hash: e.decision_policy_hash.clone(),
                    provenance: e.provenance.clone(),
                    extensions: e.extensions.clone(),
                },
            )?;
            let expected = compute_chain_hash_hex(&prev, payload.as_bytes())?;
            if expected != e.content_hash {
                return Ok(false);
            }
            prev = e.content_hash;
        }

        Ok(true)
    }
}

fn row_to_event(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEventV2> {
    let action_parameters: Option<String> = row.get(9)?;
    let action_result: Option<String> = row.get(10)?;
    let provenance: Option<String> = row.get(16)?;
    let extensions: Option<String> = row.get(17)?;

    Ok(AuditEventV2 {
        event_id: row.get(0)?,
        timestamp: row.get(1)?,
        sequence: row
            .get::<_, i64>(2)?
            .try_into()
            .unwrap_or_default(),
        session_id: row.get(3)?,
        agent_id: row.get(4)?,
        organization_id: row.get(5)?,
        correlation_id: row.get(6)?,
        action_type: row.get(7)?,
        action_resource: row.get(8)?,
        action_parameters: action_parameters.and_then(|s| serde_json::from_str(&s).ok()),
        action_result: action_result.and_then(|s| serde_json::from_str(&s).ok()),
        decision_allowed: row.get::<_, i64>(11)? != 0,
        decision_guard: row.get(12)?,
        decision_severity: row.get(13)?,
        decision_reason: row.get(14)?,
        decision_policy_hash: row.get(15)?,
        provenance: provenance.and_then(|s| serde_json::from_str(&s).ok()),
        extensions: extensions.and_then(|s| serde_json::from_str(&s).ok()),
        content_hash: row.get(18)?,
        previous_hash: row.get(19)?,
        signature: row.get(20)?,
    })
}

fn canonical_event_payload(
    event_id: &str,
    timestamp: &str,
    sequence: u64,
    input: &NewAuditEventV2,
) -> Result<String> {
    let mut root = serde_json::Map::new();
    root.insert("eventId".to_string(), Value::String(event_id.to_string()));
    root.insert("timestamp".to_string(), Value::String(timestamp.to_string()));
    root.insert("sequence".to_string(), Value::Number(sequence.into()));
    root.insert("sessionId".to_string(), Value::String(input.session_id.clone()));
    if let Some(v) = input.agent_id.as_ref() {
        root.insert("agentId".to_string(), Value::String(v.clone()));
    }
    if let Some(v) = input.organization_id.as_ref() {
        root.insert("organizationId".to_string(), Value::String(v.clone()));
    }
    if let Some(v) = input.correlation_id.as_ref() {
        root.insert("correlationId".to_string(), Value::String(v.clone()));
    }

    let mut action = serde_json::Map::new();
    action.insert("type".to_string(), Value::String(input.action_type.clone()));
    action.insert(
        "resource".to_string(),
        Value::String(input.action_resource.clone()),
    );
    if let Some(v) = input.action_parameters.as_ref() {
        action.insert("parameters".to_string(), v.clone());
    }
    if let Some(v) = input.action_result.as_ref() {
        action.insert("result".to_string(), v.clone());
    }
    root.insert("action".to_string(), Value::Object(action));

    let mut decision = serde_json::Map::new();
    decision.insert("allowed".to_string(), Value::Bool(input.decision_allowed));
    if let Some(v) = input.decision_guard.as_ref() {
        decision.insert("guard".to_string(), Value::String(v.clone()));
    }
    if let Some(v) = input.decision_severity.as_ref() {
        decision.insert("severity".to_string(), Value::String(v.clone()));
    }
    if let Some(v) = input.decision_reason.as_ref() {
        decision.insert("reason".to_string(), Value::String(v.clone()));
    }
    decision.insert(
        "policyHash".to_string(),
        Value::String(input.decision_policy_hash.clone()),
    );
    root.insert("decision".to_string(), Value::Object(decision));

    if let Some(v) = input.provenance.as_ref() {
        root.insert("provenance".to_string(), v.clone());
    }
    if let Some(v) = input.extensions.as_ref() {
        root.insert("extensions".to_string(), v.clone());
    }

    let canonical = hush_core::canonicalize_json(&Value::Object(root))?;
    Ok(canonical)
}

fn compute_chain_hash_hex(previous_hash_hex: &str, canonical_bytes: &[u8]) -> Result<String> {
    let prev_hex = previous_hash_hex.strip_prefix("0x").unwrap_or(previous_hash_hex);
    let prev_bytes = hex::decode(prev_hex)
        .map_err(|e| Error::InvalidInput(format!("invalid previous hash hex: {e}")))?;
    let prev_bytes: [u8; 32] = prev_bytes
        .try_into()
        .map_err(|_| Error::InvalidInput("previous hash must be 32 bytes".to_string()))?;

    let mut hasher = Sha256::new();
    hasher.update(prev_bytes);
    hasher.update(canonical_bytes);
    let digest = hasher.finalize();
    Ok(hex::encode(digest))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn hash_chain_detects_tampering() {
        let ledger = AuditLedgerV2::in_memory().unwrap();

        let base = NewAuditEventV2 {
            session_id: "sess_1".to_string(),
            agent_id: Some("agent_1".to_string()),
            organization_id: Some("org_1".to_string()),
            correlation_id: None,
            action_type: "file_access".to_string(),
            action_resource: "/tmp/a".to_string(),
            action_parameters: None,
            action_result: None,
            decision_allowed: true,
            decision_guard: Some("forbidden_path".to_string()),
            decision_severity: Some("info".to_string()),
            decision_reason: Some("Allowed".to_string()),
            decision_policy_hash: "sha256:deadbeef".to_string(),
            provenance: None,
            extensions: None,
        };

        let e1 = ledger.record(base.clone()).unwrap();
        let _e2 = ledger.record(NewAuditEventV2 {
            action_resource: "/tmp/b".to_string(),
            ..base
        }).unwrap();

        assert!(ledger.verify_session_chain("sess_1").unwrap());

        // Tamper with e1 in DB.
        {
            let conn = ledger.lock_conn();
            conn.execute(
                "UPDATE audit_events_v2 SET action_resource = ? WHERE event_id = ?",
                params!["/tmp/tampered", e1.event_id],
            )
            .unwrap();
        }

        assert!(!ledger.verify_session_chain("sess_1").unwrap());
    }
}
