//! Map Kubernetes audit events to Spine fact schemas.
//!
//! Each K8s audit event is mapped to a JSON fact with a well-known schema
//! identifier, severity classification, and structured payload.

use serde_json::{json, Value};

use crate::webhook::AuditEvent;

/// Fact schema for K8s audit events published on the Spine.
pub const FACT_SCHEMA: &str = "clawdstrike.sdr.fact.k8s_audit_event.v1";

/// Severity levels for classified events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Sensitive resource types where mutations raise severity.
const RBAC_RESOURCES: &[&str] = &[
    "roles",
    "rolebindings",
    "clusterroles",
    "clusterrolebindings",
];

/// System namespaces where mutations raise severity.
const SYSTEM_NAMESPACES: &[&str] = &[
    "kube-system",
    "kube-public",
    "kube-node-lease",
    "istio-system",
    "cilium",
    "clawdstrike-system",
];

/// Map a K8s [`AuditEvent`] to a Spine fact JSON value.
pub fn map_event(event: &AuditEvent) -> Value {
    let severity = classify_severity(event);

    let object_ref = event.object_ref.as_ref().map(|r| {
        json!({
            "resource": &r.resource,
            "namespace": &r.namespace,
            "name": &r.name,
            "api_group": &r.api_group,
            "api_version": &r.api_version,
            "subresource": &r.subresource,
        })
    });

    let response_status = event.response_status.as_ref().map(|s| {
        json!({
            "code": s.code,
            "status": &s.status,
            "reason": &s.reason,
        })
    });

    let impersonated_user = event.impersonated_user.as_ref().map(|u| {
        json!({
            "username": &u.username,
            "uid": &u.uid,
            "groups": &u.groups,
        })
    });

    json!({
        "schema": FACT_SCHEMA,
        "event_type": event.verb.subject_suffix(),
        "severity": severity.as_str(),
        "audit_id": &event.audit_id,
        "verb": event.verb.subject_suffix(),
        "user": {
            "username": &event.user.username,
            "uid": &event.user.uid,
            "groups": &event.user.groups,
        },
        "impersonated_user": impersonated_user,
        "object_ref": object_ref,
        "response_status": response_status,
        "request_uri": &event.request_uri,
        "source_ips": &event.source_ips,
        "user_agent": &event.user_agent,
        "timestamp": &event.request_received_timestamp,
    })
}

/// Classify severity based on verb, resource, and namespace.
pub fn classify_severity(event: &AuditEvent) -> Severity {
    let resource = event
        .object_ref
        .as_ref()
        .map(|r| r.resource.as_str())
        .unwrap_or("");
    let namespace = event
        .object_ref
        .as_ref()
        .map(|r| r.namespace.as_str())
        .unwrap_or("");
    let subresource = event
        .object_ref
        .as_ref()
        .map(|r| r.subresource.as_str())
        .unwrap_or("");

    // Pod exec is always high severity.
    if subresource == "exec" || event.verb == crate::webhook::AuditVerb::Exec {
        return Severity::High;
    }

    // Delete secrets or RBAC resources → Critical.
    if event.verb == crate::webhook::AuditVerb::Delete
        && (resource == "secrets" || RBAC_RESOURCES.contains(&resource))
    {
        return Severity::Critical;
    }

    // Create/update RBAC resources → High.
    if event.verb.is_mutation() && RBAC_RESOURCES.contains(&resource) {
        return Severity::High;
    }

    // Mutations in system namespaces → High.
    if event.verb.is_mutation()
        && SYSTEM_NAMESPACES
            .iter()
            .any(|ns| ns.eq_ignore_ascii_case(namespace))
    {
        return Severity::High;
    }

    // Read operations on secrets → Medium.
    if resource == "secrets"
        && matches!(
            event.verb,
            crate::webhook::AuditVerb::Get | crate::webhook::AuditVerb::List
        )
    {
        return Severity::Medium;
    }

    // Normal CRUD → Low.
    Severity::Low
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webhook::{AuditEvent, AuditVerb, ObjectRef, ResponseStatus, UserInfo};

    fn make_event(verb: AuditVerb, resource: &str, namespace: &str) -> AuditEvent {
        AuditEvent {
            audit_id: "test-audit-id".to_string(),
            verb,
            stage: None,
            user: UserInfo {
                username: "admin".to_string(),
                uid: "1234".to_string(),
                groups: vec!["system:masters".to_string()],
            },
            impersonated_user: None,
            object_ref: Some(ObjectRef {
                resource: resource.to_string(),
                namespace: namespace.to_string(),
                name: "test-resource".to_string(),
                api_group: String::new(),
                api_version: "v1".to_string(),
                subresource: String::new(),
            }),
            response_status: Some(ResponseStatus {
                code: 200,
                status: "Success".to_string(),
                reason: String::new(),
                message: String::new(),
            }),
            request_uri: "/api/v1/test".to_string(),
            source_ips: vec!["10.0.0.1".to_string()],
            user_agent: "kubectl/v1.28.0".to_string(),
            request_received_timestamp: "2024-01-01T00:00:00Z".to_string(),
            stage_timestamp: "2024-01-01T00:00:01Z".to_string(),
        }
    }

    fn make_exec_event() -> AuditEvent {
        let mut event = make_event(AuditVerb::Create, "pods", "default");
        if let Some(ref mut obj_ref) = event.object_ref {
            obj_ref.subresource = "exec".to_string();
        }
        event
    }

    #[test]
    fn delete_secrets_is_critical() {
        let event = make_event(AuditVerb::Delete, "secrets", "kube-system");
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn delete_rbac_is_critical() {
        let event = make_event(AuditVerb::Delete, "clusterroles", "");
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn pod_exec_is_high() {
        let event = make_exec_event();
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn create_rbac_is_high() {
        let event = make_event(AuditVerb::Create, "rolebindings", "default");
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn mutation_in_kube_system_is_high() {
        let event = make_event(AuditVerb::Create, "pods", "kube-system");
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn read_secrets_is_medium() {
        let event = make_event(AuditVerb::Get, "secrets", "default");
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn list_secrets_is_medium() {
        let event = make_event(AuditVerb::List, "secrets", "default");
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn normal_crud_is_low() {
        let event = make_event(AuditVerb::Create, "pods", "default");
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn get_pods_is_low() {
        let event = make_event(AuditVerb::Get, "pods", "default");
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn map_event_produces_valid_fact() {
        let event = make_event(AuditVerb::Create, "pods", "default");
        let fact = map_event(&event);
        assert_eq!(fact["schema"], FACT_SCHEMA);
        assert_eq!(fact["event_type"], "create");
        assert_eq!(fact["user"]["username"], "admin");
        assert_eq!(fact["object_ref"]["resource"], "pods");
    }

    #[test]
    fn map_event_includes_severity() {
        let event = make_event(AuditVerb::Delete, "secrets", "kube-system");
        let fact = map_event(&event);
        assert_eq!(fact["severity"], "critical");
    }
}
