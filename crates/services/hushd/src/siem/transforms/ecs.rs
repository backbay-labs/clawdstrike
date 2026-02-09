use crate::siem::types::{EventCategory, Outcome, ResourceType, SecurityEvent, SecurityEventType};

pub fn to_ecs(event: &SecurityEvent) -> serde_json::Value {
    let (ecs_category, ecs_type) = ecs_category_and_type(&event.event_type, &event.event_category);

    let event_outcome = match event.outcome {
        Outcome::Success => "success",
        Outcome::Failure => "failure",
        Outcome::Unknown => "unknown",
    };

    let severity_num = ecs_severity(&event.decision.severity);

    let mut ecs = serde_json::json!({
        "@timestamp": event.timestamp_rfc3339_nanos(),
        "event": {
            "id": event.event_id.to_string(),
            "kind": "event",
            "category": [ecs_category],
            "type": [ecs_type],
            "outcome": event_outcome,
            "action": event.action,
            "severity": severity_num,
        },
        "agent": {
            "id": event.agent.id,
            "name": event.agent.name,
            "version": event.agent.version,
            "type": event.agent.agent_type,
        },
        "session": {
            "id": event.session.id,
        },
        "message": event.decision.reason,
        "rule": {
            "name": event.decision.guard,
        },
        "clawdstrike": {
            "schema_version": event.schema_version,
            "session_id": event.session.id,
            "guard": event.decision.guard,
            "metadata": event.metadata,
        }
    });

    if let Some(tenant) = &event.session.tenant_id {
        ecs["organization"] = serde_json::json!({ "id": tenant });
    }

    if let Some(user) = &event.session.user_id {
        ecs["user"] = serde_json::json!({ "id": user });
    }

    if let Some(policy_hash) = &event.decision.policy_hash {
        ecs["rule"]["id"] = serde_json::json!(policy_hash);
        ecs["clawdstrike"]["policy_hash"] = serde_json::json!(policy_hash);
    }

    if let Some(ruleset) = &event.decision.ruleset {
        ecs["rule"]["ruleset"] = serde_json::json!(ruleset);
        ecs["clawdstrike"]["ruleset"] = serde_json::json!(ruleset);
    }

    if let Some(env) = &event.session.environment {
        ecs["clawdstrike"]["environment"] = serde_json::json!(env);
    }

    if !event.labels.is_empty() {
        ecs["labels"] = serde_json::to_value(&event.labels).unwrap_or_default();
    }

    match event.resource.resource_type {
        ResourceType::File => {
            if let Some(path) = &event.resource.path {
                ecs["file"] = serde_json::json!({
                    "path": path,
                    "name": path.rsplit('/').next().unwrap_or(path),
                });
            }
        }
        ResourceType::Network => {
            if let Some(host) = &event.resource.host {
                ecs["destination"] = serde_json::json!({
                    "domain": host,
                    "port": event.resource.port,
                });
            }
        }
        ResourceType::Process => {
            ecs["process"] = serde_json::json!({
                "command_line": event.resource.name,
            });
        }
        ResourceType::Tool => {
            ecs["process"] = serde_json::json!({
                "name": event.resource.name,
            });
        }
        ResourceType::Configuration => {}
    }

    let mut threat: serde_json::Map<String, serde_json::Value> = serde_json::Map::new();

    if let Some(ind) = &event.threat.indicator {
        threat.insert(
            "indicator".to_string(),
            serde_json::json!({
                "type": format!("{:?}", ind.indicator_type).to_lowercase(),
                "name": ind.value,
            }),
        );
    }

    if let Some(tactic) = &event.threat.tactic {
        threat.insert(
            "tactic".to_string(),
            serde_json::json!({ "name": [tactic] }),
        );
    }

    if let Some(technique) = &event.threat.technique {
        threat.insert(
            "technique".to_string(),
            serde_json::json!({ "id": [technique] }),
        );
    }

    if !threat.is_empty() {
        ecs["threat"] = serde_json::Value::Object(threat);
    }

    ecs
}

fn ecs_category_and_type(
    event_type: &SecurityEventType,
    _category: &EventCategory,
) -> (&'static str, &'static str) {
    match event_type {
        SecurityEventType::SessionStart => ("session", "start"),
        SecurityEventType::SessionEnd => ("session", "end"),
        SecurityEventType::EgressBlocked => ("network", "denied"),
        SecurityEventType::ForbiddenPath => ("file", "denied"),
        SecurityEventType::PatchRejected => ("file", "denied"),
        SecurityEventType::SecretDetected => ("intrusion_detection", "indicator"),
        SecurityEventType::GuardWarn => ("intrusion_detection", "info"),
        SecurityEventType::PolicyAllow => ("intrusion_detection", "allowed"),
        SecurityEventType::PolicyViolation | SecurityEventType::GuardBlock => {
            ("intrusion_detection", "denied")
        }
    }
}

fn ecs_severity(sev: &crate::siem::types::SecuritySeverity) -> u64 {
    match sev {
        crate::siem::types::SecuritySeverity::Info => 1,
        crate::siem::types::SecuritySeverity::Low => 2,
        crate::siem::types::SecuritySeverity::Medium => 3,
        crate::siem::types::SecuritySeverity::High => 4,
        crate::siem::types::SecuritySeverity::Critical => 5,
    }
}
