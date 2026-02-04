use crate::siem::types::{Outcome, ResourceType, SecurityEvent, SecuritySeverity};

/// Convert a `SecurityEvent` to a lightweight OCSF-like JSON payload.
///
/// Note: This is not a complete OCSF class mapping. It provides a stable, self-describing
/// structure that can be evolved toward full OCSF compliance.
pub fn to_ocsf(event: &SecurityEvent) -> serde_json::Value {
    let (severity_id, severity) = ocsf_severity(&event.decision.severity);
    let status = match event.outcome {
        Outcome::Success => "success",
        Outcome::Failure => "failure",
        Outcome::Unknown => "unknown",
    };

    let mut out = serde_json::json!({
        "time": event.timestamp_rfc3339_nanos(),
        "severity_id": severity_id,
        "severity": severity,
        "status": status,
        "activity_name": format!("{:?}", event.event_type),
        "category_name": format!("{:?}", event.event_category),
        "message": event.decision.reason,
        "metadata": {
            "version": event.schema_version,
            "product": {
                "name": "clawdstrike",
                "version": event.agent.version,
            }
        },
        "actor": {
            "id": event.agent.id,
            "name": event.agent.name,
            "type": event.agent.agent_type,
        },
        "session": {
            "id": event.session.id,
            "tenant_id": event.session.tenant_id,
            "environment": event.session.environment,
        },
        "decision": {
            "allowed": event.decision.allowed,
            "guard": event.decision.guard,
            "severity": format!("{:?}", event.decision.severity),
        },
    });

    match event.resource.resource_type {
        ResourceType::File => {
            out["file"] = serde_json::json!({
                "path": event.resource.path,
                "name": event.resource.name,
            });
        }
        ResourceType::Network => {
            out["network"] = serde_json::json!({
                "host": event.resource.host,
                "port": event.resource.port,
            });
        }
        ResourceType::Process => {
            out["process"] = serde_json::json!({
                "command_line": event.resource.name,
            });
        }
        ResourceType::Tool => {
            out["tool"] = serde_json::json!({
                "name": event.resource.name,
            });
        }
        ResourceType::Configuration => {}
    }

    out
}

fn ocsf_severity(sev: &SecuritySeverity) -> (u8, &'static str) {
    // OCSF severity_id is typically 1-6 (Informational..Critical). Keep a stable mapping.
    match sev {
        SecuritySeverity::Info => (1, "informational"),
        SecuritySeverity::Low => (2, "low"),
        SecuritySeverity::Medium => (3, "medium"),
        SecuritySeverity::High => (4, "high"),
        SecuritySeverity::Critical => (6, "critical"),
    }
}
