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
    metadata_enc BLOB,
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
INSERT OR REPLACE INTO audit_metadata (key, value) VALUES ('schema_version', '2');
"#;

/// SQL to query events
pub const SELECT_EVENTS: &str = r#"
SELECT id, timestamp, event_type, action_type, target, decision, guard,
       severity, message, session_id, agent_id, metadata, metadata_enc
FROM audit_events
WHERE 1=1
"#;

/// SQL to insert an event
pub const INSERT_EVENT: &str = r#"
INSERT INTO audit_events
    (id, timestamp, event_type, action_type, target, decision, guard,
     severity, message, session_id, agent_id, metadata, metadata_enc)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)
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
