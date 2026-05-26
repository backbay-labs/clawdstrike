//! Process and metadata extractors for EndpointSecurity events.

use super::helpers::{
    bad_endpoint_security_event_request, endpoint_security_command_line,
};
use crate::api_server::{
    redact_developer_activity_command_line, redact_endpoint_observation_metadata, trimmed_owned,
};
use crate::edr::dto::{EdrEndpointSecurityEvent, EdrEndpointSecurityEventKind};
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::EndpointProcess;
use std::collections::BTreeMap;

pub(crate) fn endpoint_security_event_process(
    event: &EdrEndpointSecurityEvent,
) -> Result<EndpointProcess, (StatusCode, String)> {
    let mut process = event.process.clone().unwrap_or_default();
    if let Some(command_line) = trimmed_owned(process.command_line.as_deref()) {
        process.command_line = Some(redact_developer_activity_command_line(&command_line));
    }
    if process.pid.is_none() {
        process.pid = event.pid;
    }
    if process.ppid.is_none() {
        process.ppid = event.ppid;
    }
    if trimmed_owned(process.process_guid.as_deref()).is_none() {
        process.process_guid = trimmed_owned(event.process_guid.as_deref());
    }
    if trimmed_owned(process.parent_process_guid.as_deref()).is_none() {
        process.parent_process_guid = trimmed_owned(event.parent_process_guid.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none() {
        process.image = trimmed_owned(event.image.as_deref());
    }
    if trimmed_owned(process.command_line.as_deref()).is_none() {
        process.command_line = trimmed_owned(event.command_line.as_deref())
            .or_else(|| {
                process
                    .image
                    .as_ref()
                    .map(|image| endpoint_security_command_line(image, &event.args))
            })
            .map(|command_line| redact_developer_activity_command_line(&command_line));
    }
    if matches!(event.kind, EdrEndpointSecurityEventKind::EventLoss) {
        if trimmed_owned(process.image.as_deref()).is_none() {
            process.image = Some("macos.endpoint_security".to_string());
        }
        if trimmed_owned(process.command_line.as_deref()).is_none() {
            process.command_line = Some("endpoint_security event_loss".to_string());
        }
    }
    if trimmed_owned(process.cwd.as_deref()).is_none() {
        process.cwd = trimmed_owned(event.cwd.as_deref());
    }
    if trimmed_owned(process.image.as_deref()).is_none()
        && trimmed_owned(process.command_line.as_deref()).is_none()
    {
        return Err(bad_endpoint_security_event_request(
            event,
            "event must provide process.image, image, or commandLine",
        ));
    }
    Ok(process)
}

pub(crate) fn endpoint_security_event_metadata(
    event: &EdrEndpointSecurityEvent,
) -> BTreeMap<String, serde_json::Value> {
    let mut metadata = redact_endpoint_observation_metadata(&event.metadata);
    metadata.insert(
        "collectorKind".to_string(),
        serde_json::Value::String("endpoint_security".to_string()),
    );
    metadata.insert(
        "providerId".to_string(),
        serde_json::Value::String("macos.endpoint_security".to_string()),
    );
    metadata.insert(
        "endpointSecurityEventKind".to_string(),
        serde_json::Value::String(event.kind.as_str().to_string()),
    );
    for (key, value) in [
        ("endpointSecurityReason", event.reason.as_deref()),
        ("operation", event.operation.as_deref()),
        ("decision", event.decision.as_deref()),
    ] {
        if let Some(value) = trimmed_owned(value) {
            metadata.insert(key.to_string(), serde_json::Value::String(value));
        }
    }
    if let Some(value) = event.deadline_missed {
        metadata.insert("deadlineMissed".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.deadline_ms {
        metadata.insert("deadlineMs".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.dropped_event_count {
        metadata.insert("droppedEventCount".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.deadline_miss_count {
        metadata.insert("deadlineMissCount".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.full_disk_access {
        metadata.insert("fullDiskAccess".to_string(), serde_json::json!(value));
    }
    metadata
}
