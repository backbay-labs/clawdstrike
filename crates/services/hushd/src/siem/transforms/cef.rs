use crate::siem::types::{Outcome, ResourceType, SecurityEvent, SecuritySeverity};

/// Convert a `SecurityEvent` to ArcSight-style CEF.
///
/// This is a lightweight mapping intended for log forwarding (not a full CEF dictionary coverage).
pub fn to_cef(event: &SecurityEvent) -> String {
    let version = "0";
    let device_vendor = "Clawdstrike";
    let device_product = "hushd";
    let device_version = event.agent.version.as_str();
    let signature_id = format!("{:?}", event.event_type);
    let name = event.decision.guard.clone();
    let severity = cef_severity(&event.decision.severity);

    let mut ext = vec![
        kv("eventId", &event.event_id.to_string()),
        kv("sessionId", &event.session.id),
        kv(
            "outcome",
            match event.outcome {
                Outcome::Success => "success",
                Outcome::Failure => "failure",
                Outcome::Unknown => "unknown",
            },
        ),
        kv("action", &event.action),
        kv("guard", &event.decision.guard),
        kv("reason", &event.decision.reason),
    ];

    match event.resource.resource_type {
        ResourceType::File => {
            if let Some(path) = &event.resource.path {
                ext.push(kv("filePath", path));
            }
        }
        ResourceType::Network => {
            if let Some(host) = &event.resource.host {
                ext.push(kv("dst", host));
            }
            if let Some(port) = event.resource.port {
                ext.push(kv("dpt", &port.to_string()));
            }
        }
        ResourceType::Process => {
            ext.push(kv("process", &event.resource.name));
        }
        ResourceType::Tool => {
            ext.push(kv("tool", &event.resource.name));
        }
        ResourceType::Configuration => {}
    }

    format!(
        "CEF:{version}|{device_vendor}|{device_product}|{device_version}|{signature_id}|{name}|{severity}|{}",
        ext.join(" ")
    )
}

fn cef_severity(sev: &SecuritySeverity) -> u8 {
    // CEF severity is 0-10.
    match sev {
        SecuritySeverity::Info => 1,
        SecuritySeverity::Low => 3,
        SecuritySeverity::Medium => 5,
        SecuritySeverity::High => 8,
        SecuritySeverity::Critical => 10,
    }
}

fn kv(key: &str, value: &str) -> String {
    // CEF extensions are key=value; escape = and \.
    let v = value.replace('\\', "\\\\").replace('=', "\\=");
    format!("{key}={v}")
}
