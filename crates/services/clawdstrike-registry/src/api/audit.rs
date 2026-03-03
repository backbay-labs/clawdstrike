//! GET /api/v1/audit/{name}
//!
//! Returns the publish history of a package: all publish and yank events,
//! ordered by timestamp descending.

use axum::extract::{Path, Query, State};
use axum::Json;
use serde::{Deserialize, Serialize};

use crate::error::RegistryError;
use crate::state::AppState;

/// Query parameters for the audit endpoint.
#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// Maximum number of events to return (default: 20).
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    20
}

/// A single audit event in the package history.
#[derive(Clone, Debug, Serialize)]
pub struct AuditEvent {
    /// Package version.
    pub version: String,
    /// Event action: "publish" or "yank".
    pub action: String,
    /// Hex-encoded publisher public key.
    pub publisher_key: String,
    /// ISO-8601 timestamp of the event.
    pub timestamp: String,
    /// SHA-256 checksum of the package archive (for publish events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum: Option<String>,
    /// Hex-encoded registry counter-signature (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_sig: Option<String>,
}

/// Response for the audit endpoint.
#[derive(Clone, Debug, Serialize)]
pub struct AuditResponse {
    /// Package name.
    pub package: String,
    /// Audit events, ordered by timestamp descending.
    pub events: Vec<AuditEvent>,
}

/// GET /api/v1/audit/{name}
pub async fn get_audit(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditResponse>, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    // Verify the package exists.
    db.get_package(&name)?
        .ok_or_else(|| RegistryError::NotFound(format!("package not found: {name}")))?;

    // Get all versions (includes yanked flag).
    let versions = db.list_versions(&name)?;

    // Build audit events from version history.
    // Each version produces a "publish" event, and if yanked, also a "yank" event.
    let mut events: Vec<AuditEvent> = Vec::new();

    for v in &versions {
        // Publish event.
        events.push(AuditEvent {
            version: v.version.clone(),
            action: "publish".into(),
            publisher_key: v.publisher_key.clone(),
            timestamp: v.published_at.clone(),
            checksum: Some(v.checksum.clone()),
            registry_sig: v.registry_sig.clone(),
        });

        // If yanked, add a yank event.
        // Note: we don't have a separate yank timestamp in the current schema,
        // so we use the publish timestamp as a placeholder. In a future version
        // with an audit_events table, this will have its own timestamp.
        if v.yanked {
            events.push(AuditEvent {
                version: v.version.clone(),
                action: "yank".into(),
                publisher_key: v.publisher_key.clone(),
                timestamp: v.published_at.clone(),
                checksum: None,
                registry_sig: None,
            });
        }
    }

    // Sort by timestamp descending.
    events.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    // Apply limit.
    events.truncate(query.limit as usize);

    Ok(Json(AuditResponse {
        package: name,
        events,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_event_serializes() {
        let event = AuditEvent {
            version: "1.0.0".into(),
            action: "publish".into(),
            publisher_key: "pk_hex".into(),
            timestamp: "2026-02-25T10:30:00Z".into(),
            checksum: Some("abc123".into()),
            registry_sig: Some("reg_sig".into()),
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["action"], "publish");
        assert_eq!(json["checksum"], "abc123");
    }

    #[test]
    fn audit_event_yank_omits_optional_fields() {
        let event = AuditEvent {
            version: "1.0.0".into(),
            action: "yank".into(),
            publisher_key: "pk_hex".into(),
            timestamp: "2026-02-25T10:30:00Z".into(),
            checksum: None,
            registry_sig: None,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["action"], "yank");
        assert!(json.get("checksum").is_none());
        assert!(json.get("registry_sig").is_none());
    }

    #[test]
    fn audit_response_serializes() {
        let resp = AuditResponse {
            package: "@acme/guard".into(),
            events: vec![
                AuditEvent {
                    version: "1.2.3".into(),
                    action: "publish".into(),
                    publisher_key: "pk".into(),
                    timestamp: "2026-02-25T10:30:00Z".into(),
                    checksum: Some("abc".into()),
                    registry_sig: None,
                },
                AuditEvent {
                    version: "1.2.2".into(),
                    action: "yank".into(),
                    publisher_key: "pk".into(),
                    timestamp: "2026-02-24T08:00:00Z".into(),
                    checksum: None,
                    registry_sig: None,
                },
            ],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["package"], "@acme/guard");
        assert_eq!(json["events"].as_array().unwrap().len(), 2);
    }
}
