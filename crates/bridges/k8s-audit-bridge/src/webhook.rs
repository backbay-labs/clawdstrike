//! Kubernetes audit event types and axum webhook handler.
//!
//! The K8s API server can be configured with `--audit-webhook-config-file`
//! to POST audit events to an external webhook receiver. Events arrive as
//! either a single `Event` or an `EventList` JSON payload.
//!
//! This module defines the serde types and the axum route handler.

use serde::{Deserialize, Serialize};

/// Kubernetes audit event verb (the operation performed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditVerb {
    Create,
    Update,
    Delete,
    Patch,
    Get,
    List,
    Watch,
    #[serde(rename = "create/exec")]
    Exec,
    #[serde(other)]
    Unknown,
}

impl AuditVerb {
    /// Subject suffix for NATS topic routing.
    pub fn subject_suffix(&self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Patch => "patch",
            Self::Get => "get",
            Self::List => "list",
            Self::Watch => "watch",
            Self::Exec => "exec",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this verb is a mutation (write operation).
    pub fn is_mutation(&self) -> bool {
        matches!(
            self,
            Self::Create | Self::Update | Self::Delete | Self::Patch | Self::Exec
        )
    }
}

/// Kubernetes audit event stage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditStage {
    RequestReceived,
    ResponseStarted,
    ResponseComplete,
    Panic,
    #[serde(other)]
    Unknown,
}

/// Reference to a Kubernetes object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ObjectRef {
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub api_group: String,
    #[serde(default)]
    pub api_version: String,
    #[serde(default)]
    pub subresource: String,
}

/// User information from the audit event.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct UserInfo {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub uid: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

/// Response status from the API server.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ResponseStatus {
    #[serde(default)]
    pub code: u16,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub message: String,
}

/// A single Kubernetes audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    #[serde(default, alias = "auditID")]
    pub audit_id: String,
    pub verb: AuditVerb,
    #[serde(default)]
    pub stage: Option<AuditStage>,
    #[serde(default)]
    pub user: UserInfo,
    #[serde(default)]
    pub impersonated_user: Option<UserInfo>,
    #[serde(default)]
    pub object_ref: Option<ObjectRef>,
    #[serde(default)]
    pub response_status: Option<ResponseStatus>,
    #[serde(default, alias = "requestURI")]
    pub request_uri: String,
    #[serde(default, alias = "sourceIPs")]
    pub source_ips: Vec<String>,
    #[serde(default)]
    pub user_agent: String,
    #[serde(default)]
    pub request_received_timestamp: String,
    #[serde(default)]
    pub stage_timestamp: String,
    // Omit requestObject/responseObject to avoid unbounded payload size.
}

/// Wrapper for a list of audit events (K8s `EventList`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventList {
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub api_version: String,
    #[serde(default)]
    pub items: Vec<AuditEvent>,
}

/// Parse incoming webhook payload as either an EventList or a single Event.
pub fn parse_webhook_payload(
    body: &[u8],
) -> std::result::Result<Vec<AuditEvent>, serde_json::Error> {
    // First try to parse as a raw JSON value to check the "kind" field.
    let value: serde_json::Value = serde_json::from_slice(body)?;

    if value.get("kind").and_then(|k| k.as_str()) == Some("EventList") {
        let list: EventList = serde_json::from_value(value)?;
        Ok(list.items)
    } else if value.get("items").is_some() {
        // EventList without explicit kind
        let list: EventList = serde_json::from_value(value)?;
        Ok(list.items)
    } else {
        // Single event
        let event: AuditEvent = serde_json::from_value(value)?;
        Ok(vec![event])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_single_event() {
        let json = r#"{
            "auditID": "abc-123",
            "verb": "create",
            "stage": "ResponseComplete",
            "user": { "username": "admin", "uid": "1234", "groups": ["system:masters"] },
            "objectRef": { "resource": "pods", "namespace": "default", "name": "test-pod" },
            "responseStatus": { "code": 201, "status": "Success" },
            "requestURI": "/api/v1/namespaces/default/pods",
            "sourceIPs": ["10.0.0.1"],
            "userAgent": "kubectl/v1.28.0",
            "requestReceivedTimestamp": "2024-01-01T00:00:00.000000Z",
            "stageTimestamp": "2024-01-01T00:00:00.100000Z"
        }"#;

        let events = parse_webhook_payload(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].verb, AuditVerb::Create);
        assert_eq!(events[0].user.username, "admin");
        assert_eq!(
            events[0].object_ref.as_ref().map(|r| r.resource.as_str()),
            Some("pods")
        );
        // Verify K8s wire-format fields (auditID, requestURI, sourceIPs) are deserialized
        assert_eq!(events[0].audit_id, "abc-123");
        assert_eq!(events[0].request_uri, "/api/v1/namespaces/default/pods");
        assert_eq!(events[0].source_ips, vec!["10.0.0.1"]);
    }

    #[test]
    fn parse_event_list() {
        let json = r#"{
            "kind": "EventList",
            "apiVersion": "audit.k8s.io/v1",
            "items": [
                {
                    "auditID": "abc-123",
                    "verb": "delete",
                    "user": { "username": "admin" },
                    "objectRef": { "resource": "secrets", "namespace": "kube-system", "name": "tls-cert" }
                },
                {
                    "auditID": "def-456",
                    "verb": "get",
                    "user": { "username": "developer" },
                    "objectRef": { "resource": "pods", "namespace": "default", "name": "my-pod" }
                }
            ]
        }"#;

        let events = parse_webhook_payload(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].verb, AuditVerb::Delete);
        assert_eq!(events[1].verb, AuditVerb::Get);
    }

    #[test]
    fn verb_subject_suffixes() {
        assert_eq!(AuditVerb::Create.subject_suffix(), "create");
        assert_eq!(AuditVerb::Delete.subject_suffix(), "delete");
        assert_eq!(AuditVerb::Exec.subject_suffix(), "exec");
        assert_eq!(AuditVerb::Get.subject_suffix(), "get");
    }

    #[test]
    fn verb_is_mutation() {
        assert!(AuditVerb::Create.is_mutation());
        assert!(AuditVerb::Delete.is_mutation());
        assert!(AuditVerb::Update.is_mutation());
        assert!(AuditVerb::Patch.is_mutation());
        assert!(AuditVerb::Exec.is_mutation());
        assert!(!AuditVerb::Get.is_mutation());
        assert!(!AuditVerb::List.is_mutation());
        assert!(!AuditVerb::Watch.is_mutation());
    }

    #[test]
    fn parse_exec_verb() {
        let json = r#"{
            "auditID": "exec-1",
            "verb": "create/exec",
            "user": { "username": "admin" },
            "objectRef": { "resource": "pods", "namespace": "default", "name": "my-pod", "subresource": "exec" }
        }"#;

        let events = parse_webhook_payload(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].verb, AuditVerb::Exec);
    }

    #[test]
    fn parse_unknown_verb() {
        let json = r#"{
            "auditID": "unknown-1",
            "verb": "some_future_verb",
            "user": { "username": "admin" }
        }"#;

        let events = parse_webhook_payload(json.as_bytes()).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(events[0].verb, AuditVerb::Unknown);
    }
}
