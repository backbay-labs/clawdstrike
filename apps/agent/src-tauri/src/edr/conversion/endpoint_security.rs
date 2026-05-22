//! Pure conversion helpers for macOS EndpointSecurity event ingestion.
//!
//! These functions convert `EdrEndpointSecurityEvent` wire records into
//! `EndpointObservation` / `EndpointProcess` / `EndpointEvent` domain types.
//! They are stateless: no access to `AgentApiState`.

use crate::api_server::{
    local_stable_id, non_empty, redact_developer_activity_args,
    redact_developer_activity_command_line, redact_endpoint_observation_metadata, trimmed_owned,
};
use crate::edr::dto::{EdrEndpointSecurityEvent, EdrEndpointSecurityEventKind};
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::{
    CredentialKind, EndpointEvent, EndpointObservation, EndpointProcess, EndpointProviderKind,
    EndpointProviderState, EndpointSensorState, FileOperation,
};
use std::collections::BTreeMap;

pub(crate) fn endpoint_security_event_observation(
    event: &EdrEndpointSecurityEvent,
    index: usize,
) -> Result<EndpointObservation, (StatusCode, String)> {
    let process = endpoint_security_event_process(event)?;
    let event_kind = endpoint_security_endpoint_event(event)?;
    let timestamp = event.observed_at.unwrap_or_else(chrono::Utc::now);
    let observation_id = trimmed_owned(event.event_id.as_deref()).unwrap_or_else(|| {
        let index = index.to_string();
        let timestamp = timestamp.to_rfc3339();
        let sequence_hint = endpoint_security_event_sequence_hint(event);
        let primary = event
            .path
            .as_deref()
            .or(event.image.as_deref())
            .or(event.process_guid.as_deref())
            .unwrap_or_default();
        local_stable_id(
            "esevent",
            [
                event.kind.as_str(),
                event.session_id.as_deref().unwrap_or_default(),
                primary,
                sequence_hint.as_deref().unwrap_or_default(),
                timestamp.as_str(),
                index.as_str(),
            ],
        )
    });

    Ok(EndpointObservation {
        observation_id,
        timestamp,
        host_id: trimmed_owned(event.host_id.as_deref()),
        user_id: trimmed_owned(event.user_id.as_deref()),
        session_id: trimmed_owned(event.session_id.as_deref()),
        process,
        event: event_kind,
        metadata: endpoint_security_event_metadata(event),
    })
}

pub(crate) fn endpoint_security_endpoint_event(
    event: &EdrEndpointSecurityEvent,
) -> Result<EndpointEvent, (StatusCode, String)> {
    match event.kind {
        EdrEndpointSecurityEventKind::ProcessExec => {
            let image =
                required_endpoint_security_event_string(event, "image", event.image.as_deref())?;
            Ok(EndpointEvent::ProcessExec {
                image,
                args: redact_developer_activity_args(&event.args),
                env: BTreeMap::new(),
            })
        }
        EdrEndpointSecurityEventKind::FileAccess => {
            let operation = endpoint_security_file_operation(event.operation.as_deref())
                .ok_or_else(|| {
                    bad_endpoint_security_event_request(
                        event,
                        "operation must be read, write, create, delete, rename, execute, or chmod",
                    )
                })?;
            let path =
                required_endpoint_security_event_string(event, "path", event.path.as_deref())?;
            if operation == FileOperation::Read {
                if let Some(kind) = endpoint_security_credential_kind_for_path(&path) {
                    return Ok(EndpointEvent::CredentialAccess {
                        kind,
                        path: Some(path),
                        name: None,
                    });
                }
            }
            Ok(EndpointEvent::FileAccess {
                operation,
                path,
                source_url: None,
                content_preview: None,
            })
        }
        EdrEndpointSecurityEventKind::AuthOpen => {
            let decision = normalized_endpoint_security_decision(event.decision.as_deref())
                .ok_or_else(|| {
                    bad_endpoint_security_event_request(event, "decision must be allow or deny")
                })?;
            Ok(EndpointEvent::PolicyDecision {
                action: "endpoint_security_auth_open".to_string(),
                target: Some(required_endpoint_security_event_string(
                    event,
                    "path",
                    event.path.as_deref(),
                )?),
                decision: decision.to_string(),
                guard: Some("endpoint_security_auth".to_string()),
                severity: Some(
                    if decision == "blocked" {
                        "high"
                    } else {
                        "info"
                    }
                    .to_string(),
                ),
            })
        }
        EdrEndpointSecurityEventKind::EventLoss => Ok(EndpointEvent::Other {
            category: "endpoint_security_event_loss".to_string(),
            fields: endpoint_security_event_loss_fields(event),
        }),
    }
}

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

fn endpoint_security_event_sequence_hint(event: &EdrEndpointSecurityEvent) -> Option<String> {
    for key in [
        "endpointSecurityGlobalSeqNum",
        "endpointSecurityGlobalSequence",
        "endpointSecurityGlobalSequenceNumber",
        "globalSeqNum",
        "globalSequenceNumber",
        "endpointSecuritySeqNum",
        "endpointSecuritySequence",
        "endpointSecuritySequenceNumber",
        "seqNum",
        "sequenceNumber",
    ] {
        let Some(value) = event.metadata.get(key) else {
            continue;
        };
        if let Some(sequence) = value.as_u64() {
            return Some(format!("{key}:{sequence}"));
        }
        if let Some(sequence) = value.as_i64() {
            return Some(format!("{key}:{sequence}"));
        }
        if let Some(sequence) = value.as_str().and_then(|value| trimmed_owned(Some(value))) {
            return Some(format!("{key}:{sequence}"));
        }
    }
    None
}

pub(crate) fn endpoint_security_event_loss_fields(
    event: &EdrEndpointSecurityEvent,
) -> BTreeMap<String, serde_json::Value> {
    let mut fields = BTreeMap::new();
    if let Some(value) = event.dropped_event_count {
        fields.insert("droppedEventCount".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.deadline_miss_count {
        fields.insert("deadlineMissCount".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.deadline_missed {
        fields.insert("deadlineMissed".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.full_disk_access {
        fields.insert("fullDiskAccess".to_string(), serde_json::json!(value));
    }
    if let Some(reason) = trimmed_owned(event.reason.as_deref()) {
        fields.insert("reason".to_string(), serde_json::Value::String(reason));
    }
    fields
}

pub(crate) fn endpoint_security_event_loss_sensor_state(
    events: &[EdrEndpointSecurityEvent],
) -> Option<EndpointSensorState> {
    let mut dropped_event_count = 0_u64;
    let mut deadline_miss_count = 0_u64;
    let mut full_disk_access = None;
    let mut saw_degradation_signal = false;
    let mut degradation_reasons = Vec::new();

    for event in events {
        let dropped_events = event.dropped_event_count.unwrap_or(0);
        let deadline_misses = event.deadline_miss_count.unwrap_or(0);
        dropped_event_count = dropped_event_count.saturating_add(dropped_events);
        deadline_miss_count = deadline_miss_count.saturating_add(deadline_misses);

        let event_loss = matches!(event.kind, EdrEndpointSecurityEventKind::EventLoss);
        if event_loss || dropped_events > 0 || deadline_misses > 0 {
            saw_degradation_signal = true;
        }
        if event_loss {
            degradation_reasons.push("endpoint security event loss reported".to_string());
        }
        if dropped_events > 0 {
            degradation_reasons.push("provider dropped enforcement events".to_string());
        }
        if deadline_misses > 0 {
            degradation_reasons.push("provider authorization deadline misses".to_string());
        }
        if event.deadline_missed == Some(true) {
            saw_degradation_signal = true;
            if event.deadline_miss_count.is_none() {
                deadline_miss_count = deadline_miss_count.saturating_add(1);
            }
            degradation_reasons.push("provider authorization deadline misses".to_string());
        }
        if event.full_disk_access == Some(false) {
            saw_degradation_signal = true;
            full_disk_access = Some(false);
            degradation_reasons.push("missing_full_disk_access".to_string());
        }
        if let Some(reason) = trimmed_owned(event.reason.as_deref()) {
            if event_loss
                || dropped_events > 0
                || deadline_misses > 0
                || event.deadline_missed == Some(true)
                || event.full_disk_access == Some(false)
            {
                degradation_reasons.push(reason);
            }
        }
    }

    if !saw_degradation_signal {
        return None;
    }
    if degradation_reasons.is_empty() {
        degradation_reasons.push("endpoint security provider degraded".to_string());
    }
    degradation_reasons.sort();
    degradation_reasons.dedup();

    Some(EndpointSensorState {
        providers: vec![EndpointProviderState {
            provider_id: "macos.endpoint_security".to_string(),
            provider_kind: EndpointProviderKind::EndpointSecurity,
            installed: true,
            active: true,
            healthy: false,
            degraded: true,
            degradation_reasons,
            dropped_event_count,
            deadline_miss_count,
            full_disk_access,
            last_seen: Some(chrono::Utc::now()),
        }],
    })
}

pub(crate) fn endpoint_security_command_line(image: &str, args: &[String]) -> String {
    if args.is_empty() {
        image.to_string()
    } else {
        format!("{image} {}", args.join(" "))
    }
}

pub(crate) fn endpoint_security_file_operation(value: Option<&str>) -> Option<FileOperation> {
    match value
        .and_then(|value| non_empty(Some(value)))
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("read" | "open" | "auth_open") => Some(FileOperation::Read),
        Some("write") => Some(FileOperation::Write),
        Some("create") => Some(FileOperation::Create),
        Some("delete" | "unlink") => Some(FileOperation::Delete),
        Some("rename" | "move") => Some(FileOperation::Rename),
        Some("execute" | "exec") => Some(FileOperation::Execute),
        Some("chmod") => Some(FileOperation::Chmod),
        _ => None,
    }
}

fn endpoint_security_credential_kind_for_path(path: &str) -> Option<CredentialKind> {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    let basename = path.rsplit('/').next().unwrap_or(path.as_str());

    if path.contains("/.ssh/") || matches!(basename, "id_rsa" | "id_ed25519" | "id_ecdsa") {
        return Some(CredentialKind::SshKey);
    }

    if path.contains("/.aws/")
        || path.contains("/.config/gcloud/")
        || path.contains("/.azure/")
        || path.contains("/.kube/config")
        || path.contains("/.pulumi/credentials.json")
        || path.contains("/.config/pulumi/credentials.json")
        || path.contains("/.terraform.d/credentials.tfrc.json")
        || path.contains("/.terraformrc")
    {
        return Some(CredentialKind::CloudCredential);
    }

    if path.contains("/.npmrc")
        || path.contains("/.pypirc")
        || path.contains("/.netrc")
        || path.contains("/.docker/config.json")
        || path.contains("/.cargo/credentials")
        || path.contains("/.config/pypoetry/auth.toml")
        || path.contains("/library/application support/pypoetry/auth.toml")
        || path.contains("/.config/pip/pip.conf")
        || path.contains("/.pip/pip.conf")
        || path.contains("/pip/pip.ini")
        || path.contains("/.yarnrc.yml")
        || path.contains("/.pnpmrc")
        || path.contains("/.m2/settings.xml")
        || path.contains("/.gradle/gradle.properties")
        || path.contains("/.nuget/nuget/nuget.config")
    {
        return Some(CredentialKind::PackageRegistryToken);
    }

    if path.contains("/.config/gh/hosts.yml")
        || path.contains("/.config/gh/config.yml")
        || path.contains("/.config/glab-cli/hosts.yml")
        || path.contains("/.config/glab-cli/config.yml")
        || path.contains("/.config/hub")
        || path.contains("/.config/git-credential/")
    {
        return Some(CredentialKind::ApiToken);
    }

    if path.contains("/.gnupg/private-keys-v1.d/")
        || path.contains("/.gnupg/secring.gpg")
        || path.contains("/.config/sops/age/keys.txt")
        || path.contains("/.age/key.txt")
    {
        return Some(CredentialKind::SigningKey);
    }

    if basename == "cookies"
        || basename == "login data"
        || basename == "local state"
        || path.contains("/keychains/")
    {
        return Some(CredentialKind::BrowserCookie);
    }

    None
}

pub(crate) fn normalized_endpoint_security_decision(value: Option<&str>) -> Option<&'static str> {
    match value
        .and_then(|value| non_empty(Some(value)))
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("allow" | "allowed" | "permit" | "permitted") => Some("allowed"),
        Some("deny" | "denied" | "block" | "blocked") => Some("blocked"),
        _ => None,
    }
}

pub(crate) fn required_endpoint_security_event_string(
    event: &EdrEndpointSecurityEvent,
    field: &str,
    value: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    trimmed_owned(value).ok_or_else(|| {
        bad_endpoint_security_event_request(
            event,
            &format!(
                "{field} is required for EndpointSecurity {} events",
                event.kind.as_str()
            ),
        )
    })
}

pub(crate) fn bad_endpoint_security_event_request(
    event: &EdrEndpointSecurityEvent,
    message: &str,
) -> (StatusCode, String) {
    let event_id = event
        .event_id
        .as_deref()
        .and_then(|value| non_empty(Some(value)))
        .unwrap_or("unknown");
    (
        StatusCode::BAD_REQUEST,
        format!("invalid EndpointSecurity event {event_id}: {message}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process_exec_event(observed_at: &str) -> EdrEndpointSecurityEvent {
        EdrEndpointSecurityEvent {
            event_id: None,
            kind: EdrEndpointSecurityEventKind::ProcessExec,
            observed_at: Some(
                chrono::DateTime::parse_from_rfc3339(observed_at)
                    .expect("test timestamp")
                    .with_timezone(&chrono::Utc),
            ),
            host_id: Some("host-1".to_string()),
            user_id: Some("user-1".to_string()),
            session_id: Some("session-1".to_string()),
            process: None,
            metadata: BTreeMap::new(),
            pid: Some(42),
            ppid: Some(1),
            process_guid: Some("proc-1".to_string()),
            parent_process_guid: None,
            image: Some("/bin/zsh".to_string()),
            args: vec!["-lc".to_string(), "echo ok".to_string()],
            command_line: None,
            cwd: Some("/tmp".to_string()),
            path: None,
            operation: None,
            decision: None,
            reason: None,
            deadline_missed: None,
            deadline_ms: None,
            dropped_event_count: None,
            deadline_miss_count: None,
            full_disk_access: None,
        }
    }

    fn file_access_event(path: &str, operation: &str) -> EdrEndpointSecurityEvent {
        let mut event = process_exec_event("2026-05-20T12:00:00Z");
        event.kind = EdrEndpointSecurityEventKind::FileAccess;
        event.event_id = Some(format!("file-{operation}-{path}"));
        event.path = Some(path.to_string());
        event.operation = Some(operation.to_string());
        event
    }

    #[test]
    fn fallback_observation_id_includes_durable_timestamp() {
        let first =
            endpoint_security_event_observation(&process_exec_event("2026-05-20T12:00:00Z"), 0)
                .expect("first observation");
        let second =
            endpoint_security_event_observation(&process_exec_event("2026-05-20T12:00:01Z"), 0)
                .expect("second observation");

        assert_ne!(first.observation_id, second.observation_id);
    }

    #[test]
    fn fallback_observation_id_uses_provider_sequence_hint() {
        let mut first = process_exec_event("2026-05-20T12:00:00Z");
        first.metadata.insert(
            "endpointSecurityGlobalSeqNum".to_string(),
            serde_json::json!(1001),
        );
        let mut second = process_exec_event("2026-05-20T12:00:00Z");
        second.metadata.insert(
            "endpointSecurityGlobalSeqNum".to_string(),
            serde_json::json!(1002),
        );

        let first = endpoint_security_event_observation(&first, 0).expect("first observation");
        let second = endpoint_security_event_observation(&second, 0).expect("second observation");

        assert_ne!(first.observation_id, second.observation_id);
    }

    #[test]
    fn endpoint_security_reads_of_developer_secret_paths_become_credential_access() {
        for (path, expected_kind) in [
            (
                "/Users/alice/.aws/credentials",
                CredentialKind::CloudCredential,
            ),
            ("/Users/alice/.npmrc", CredentialKind::PackageRegistryToken),
            ("/Users/alice/.pypirc", CredentialKind::PackageRegistryToken),
            ("/Users/alice/.netrc", CredentialKind::PackageRegistryToken),
            (
                "/Users/alice/.docker/config.json",
                CredentialKind::PackageRegistryToken,
            ),
            ("/Users/alice/.ssh/id_ed25519", CredentialKind::SshKey),
            (
                "/Users/alice/Library/Application Support/Google/Chrome/Default/Cookies",
                CredentialKind::BrowserCookie,
            ),
        ] {
            let observation =
                endpoint_security_event_observation(&file_access_event(path, "read"), 0)
                    .expect("secret read observation");
            match observation.event {
                EndpointEvent::CredentialAccess {
                    kind,
                    path: Some(actual_path),
                    ..
                } => {
                    assert_eq!(kind, expected_kind);
                    assert_eq!(actual_path, path);
                }
                other => panic!("expected credential access for {path}, got {other:?}"),
            }
        }
    }

    #[test]
    fn endpoint_security_secret_path_writes_remain_file_access_events() {
        let observation = endpoint_security_event_observation(
            &file_access_event("/Users/alice/.npmrc", "write"),
            0,
        )
        .expect("secret write observation");

        match observation.event {
            EndpointEvent::FileAccess {
                operation, path, ..
            } => {
                assert_eq!(operation, FileOperation::Write);
                assert_eq!(path, "/Users/alice/.npmrc");
            }
            other => panic!("expected file access for secret write, got {other:?}"),
        }
    }
}
