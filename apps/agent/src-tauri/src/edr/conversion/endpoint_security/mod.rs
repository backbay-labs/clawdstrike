//! Pure conversion helpers for macOS EndpointSecurity event ingestion.
//!
//! These functions convert `EdrEndpointSecurityEvent` wire records into
//! `EndpointObservation` / `EndpointProcess` / `EndpointEvent` domain types.
//! They are stateless: no access to `AgentApiState`.

mod helpers;
mod loss;
mod process;

#[allow(unused_imports)]
pub(crate) use helpers::{
    bad_endpoint_security_event_request, endpoint_security_command_line,
    endpoint_security_file_operation, normalized_endpoint_security_decision,
    required_endpoint_security_event_string,
};
#[allow(unused_imports)]
pub(crate) use loss::{endpoint_security_event_loss_fields, endpoint_security_event_loss_sensor_state};
#[allow(unused_imports)]
pub(crate) use process::{endpoint_security_event_metadata, endpoint_security_event_process};

use crate::api_server::{local_stable_id, trimmed_owned};
use crate::edr::dto::{EdrEndpointSecurityEvent, EdrEndpointSecurityEventKind};
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::{EndpointEvent, EndpointObservation, FileOperation};
use std::collections::BTreeMap;

use self::helpers::endpoint_security_credential_kind_for_path;

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

pub(crate) fn endpoint_security_auth_open_credential_observation(
    event: &EdrEndpointSecurityEvent,
    index: usize,
) -> Result<Option<EndpointObservation>, (StatusCode, String)> {
    if !matches!(event.kind, EdrEndpointSecurityEventKind::AuthOpen) {
        return Ok(None);
    }
    let path = required_endpoint_security_event_string(event, "path", event.path.as_deref())?;
    let Some(kind) = endpoint_security_credential_kind_for_path(&path) else {
        return Ok(None);
    };
    let process = endpoint_security_event_process(event)?;
    let timestamp = event.observed_at.unwrap_or_else(chrono::Utc::now);
    let timestamp_text = timestamp.to_rfc3339();
    let index_text = index.to_string();
    let observation_id = local_stable_id(
        "escredential",
        [
            event.event_id.as_deref().unwrap_or_default(),
            event.session_id.as_deref().unwrap_or_default(),
            path.as_str(),
            timestamp_text.as_str(),
            index_text.as_str(),
        ],
    );
    let mut metadata = endpoint_security_event_metadata(event);
    metadata.insert(
        "derivedFrom".to_string(),
        serde_json::Value::String("endpoint_security_auth_open".to_string()),
    );

    Ok(Some(EndpointObservation {
        observation_id,
        timestamp,
        host_id: trimmed_owned(event.host_id.as_deref()),
        user_id: trimmed_owned(event.user_id.as_deref()),
        session_id: trimmed_owned(event.session_id.as_deref()),
        process,
        event: EndpointEvent::CredentialAccess {
            kind,
            path: Some(path),
            name: None,
        },
        metadata,
    }))
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
                args: crate::api_server::redact_developer_activity_args(&event.args),
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use clawdstrike_policy_event::edr::CredentialKind;

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

    fn auth_open_event(path: &str) -> EdrEndpointSecurityEvent {
        let mut event = process_exec_event("2026-05-20T12:00:00Z");
        event.kind = EdrEndpointSecurityEventKind::AuthOpen;
        event.event_id = Some(format!("auth-open-{path}"));
        event.path = Some(path.to_string());
        event.decision = Some("deny".to_string());
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

    #[test]
    fn endpoint_security_auth_open_secret_paths_emit_derived_credential_observations() {
        let observation = endpoint_security_auth_open_credential_observation(
            &auth_open_event("/Users/alice/.ssh/id_rsa"),
            0,
        )
        .expect("auth open conversion")
        .expect("derived credential observation");

        match observation.event {
            EndpointEvent::CredentialAccess {
                kind,
                path: Some(path),
                ..
            } => {
                assert_eq!(kind, CredentialKind::SshKey);
                assert_eq!(path, "/Users/alice/.ssh/id_rsa");
            }
            other => panic!("expected credential access for auth_open secret, got {other:?}"),
        }
        assert_eq!(
            observation.metadata["derivedFrom"],
            "endpoint_security_auth_open"
        );
    }
}
