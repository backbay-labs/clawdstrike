//! Privacy projection of endpoint observations and events.
//!
//! Maps raw observation fields into redaction-classed telemetry projections so
//! evidence can be correlated by hash or feature without leaking raw artifacts
//! unless the privacy mode explicitly permits it.

#![allow(dead_code)]

use super::{
    normalize_path_string, EndpointEvent, EndpointEvidenceRedactionClass, EndpointObservation,
    EndpointTelemetryFieldProjection, EndpointTelemetryObservationProjection,
    EndpointTelemetryPrivacyMode,
};
use hush_core::sha256;
use std::path::Path;

pub(crate) fn project_observation_privacy(
    observation: &EndpointObservation,
    privacy_mode: &EndpointTelemetryPrivacyMode,
) -> EndpointTelemetryObservationProjection {
    let mut projections = Vec::new();
    push_optional_hash(
        &mut projections,
        "hostId",
        observation.host_id.as_deref(),
        privacy_mode,
        "host identifiers are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "userId",
        observation.user_id.as_deref(),
        privacy_mode,
        "user identifiers are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "sessionId",
        observation.session_id.as_deref(),
        privacy_mode,
        "session identifiers are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "process.image",
        observation.process.image.as_deref(),
        privacy_mode,
        "process paths may include local usernames or project names",
    );
    push_optional_local(
        &mut projections,
        "process.commandLine",
        observation.process.command_line.as_deref(),
        privacy_mode,
        "command lines may contain secrets, prompts, paths, or customer data",
    );
    push_optional_hash(
        &mut projections,
        "process.cwd",
        observation.process.cwd.as_deref(),
        privacy_mode,
        "working directories may include local usernames or repository names",
    );
    push_optional_hash(
        &mut projections,
        "process.processGuid",
        observation.process.process_guid.as_deref(),
        privacy_mode,
        "process identifiers are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "process.parentProcessGuid",
        observation.process.parent_process_guid.as_deref(),
        privacy_mode,
        "parent process identifiers are correlated by hash by default",
    );
    push_optional_metadata(
        &mut projections,
        "process.pid",
        observation.process.pid.map(|value| value.to_string()),
        privacy_mode,
        "numeric process identifiers are low-content local features",
    );
    push_optional_metadata(
        &mut projections,
        "process.ppid",
        observation.process.ppid.map(|value| value.to_string()),
        privacy_mode,
        "numeric parent process identifiers are low-content local features",
    );
    push_metadata(
        &mut projections,
        "process.signing.trust",
        format!("{:?}", observation.process.signing.trust),
        privacy_mode,
        "signature trust is a normalized posture feature",
    );
    push_optional_metadata(
        &mut projections,
        "process.signing.notarized",
        observation
            .process
            .signing
            .notarized
            .map(|value| value.to_string()),
        privacy_mode,
        "notarization state is a normalized posture feature",
    );
    push_optional_hash(
        &mut projections,
        "process.signing.cdhash",
        observation.process.signing.cdhash.as_deref(),
        privacy_mode,
        "code directory hashes are correlated by hash by default",
    );
    push_optional_hash(
        &mut projections,
        "process.signing.expectedCdhash",
        observation.process.signing.expected_cdhash.as_deref(),
        privacy_mode,
        "expected code directory hashes are correlated by hash by default",
    );

    project_event_privacy(&observation.event, privacy_mode, &mut projections);
    if !observation.metadata.is_empty() {
        push_local(
            &mut projections,
            "metadata",
            serde_json::to_string(&observation.metadata).unwrap_or_default(),
            privacy_mode,
            "arbitrary observation metadata may contain raw artifact or tenant data",
        );
    }

    let raw_suppressed_count = projections
        .iter()
        .filter(|projection| {
            projection.raw_value.is_none()
                && projection.value_hash.is_some()
                && matches!(
                    projection.redaction_class,
                    EndpointEvidenceRedactionClass::HashOnly
                        | EndpointEvidenceRedactionClass::LocalOnly
                        | EndpointEvidenceRedactionClass::Redacted
                )
        })
        .count();
    let local_only_count = projections
        .iter()
        .filter(|projection| {
            projection.redaction_class == EndpointEvidenceRedactionClass::LocalOnly
        })
        .count();

    EndpointTelemetryObservationProjection {
        observation_id: observation.observation_id.clone(),
        event_kind: observation.event.kind_name().to_string(),
        field_count: projections.len(),
        raw_suppressed_count,
        local_only_count,
        projections,
    }
}

fn project_event_privacy(
    event: &EndpointEvent,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
) {
    match event {
        EndpointEvent::ProcessExec { image, args, env } => {
            push_hash(
                projections,
                "event.processExec.image",
                image,
                privacy_mode,
                "process paths may include local usernames or project names",
            );
            push_local(
                projections,
                "event.processExec.args",
                args.join(" "),
                privacy_mode,
                "process arguments may contain secrets, prompts, paths, or customer data",
            );
            if !env.is_empty() {
                push_local(
                    projections,
                    "event.processExec.env",
                    serde_json::to_string(env).unwrap_or_default(),
                    privacy_mode,
                    "environment variables may contain credentials",
                );
            }
        }
        EndpointEvent::FileAccess {
            operation,
            path,
            source_url,
            content_preview,
        } => {
            push_metadata(
                projections,
                "event.fileAccess.operation",
                format!("{operation:?}"),
                privacy_mode,
                "file operation is a normalized event feature",
            );
            push_hash(
                projections,
                "event.fileAccess.path",
                path,
                privacy_mode,
                "file paths may include local usernames, project names, or document names",
            );
            push_optional_hash(
                projections,
                "event.fileAccess.sourceUrl",
                source_url.as_deref(),
                privacy_mode,
                "source URLs may contain internal hosts or query strings",
            );
            push_optional_local(
                projections,
                "event.fileAccess.contentPreview",
                content_preview.as_deref(),
                privacy_mode,
                "file content previews are raw artifacts",
            );
        }
        EndpointEvent::NetworkFlow {
            host,
            port,
            protocol,
            url,
        } => {
            push_hash(
                projections,
                "event.networkFlow.host",
                host,
                privacy_mode,
                "network hosts may reveal internal infrastructure",
            );
            push_metadata(
                projections,
                "event.networkFlow.port",
                port.to_string(),
                privacy_mode,
                "network port is a normalized event feature",
            );
            push_optional_metadata(
                projections,
                "event.networkFlow.protocol",
                protocol.clone(),
                privacy_mode,
                "network protocol is a normalized event feature",
            );
            push_optional_hash(
                projections,
                "event.networkFlow.url",
                url.as_deref(),
                privacy_mode,
                "URLs may contain paths, query strings, or tenant data",
            );
        }
        EndpointEvent::DnsLookup {
            query,
            record_type,
            answers,
            resolver,
            status,
        } => {
            push_hash(
                projections,
                "event.dnsLookup.query",
                query,
                privacy_mode,
                "DNS queries may reveal internal infrastructure or customer domains",
            );
            push_optional_metadata(
                projections,
                "event.dnsLookup.recordType",
                record_type.clone(),
                privacy_mode,
                "DNS record type is a normalized event feature",
            );
            if !answers.is_empty() {
                push_hash(
                    projections,
                    "event.dnsLookup.answers",
                    answers.join(","),
                    privacy_mode,
                    "DNS answers may include internal infrastructure",
                );
            }
            push_optional_hash(
                projections,
                "event.dnsLookup.resolver",
                resolver.as_deref(),
                privacy_mode,
                "DNS resolvers may identify internal networks",
            );
            push_optional_metadata(
                projections,
                "event.dnsLookup.status",
                status.clone(),
                privacy_mode,
                "DNS status is a normalized event feature",
            );
        }
        EndpointEvent::PackageScript {
            manager,
            package,
            phase,
            script,
            working_directory,
        } => {
            push_metadata(
                projections,
                "event.packageScript.manager",
                manager.as_str(),
                privacy_mode,
                "package manager is a normalized event feature",
            );
            push_metadata(
                projections,
                "event.packageScript.phase",
                phase,
                privacy_mode,
                "package lifecycle phase is a normalized event feature",
            );
            push_optional_hash(
                projections,
                "event.packageScript.package",
                package.as_deref(),
                privacy_mode,
                "package names may reveal private dependencies",
            );
            push_local(
                projections,
                "event.packageScript.script",
                script,
                privacy_mode,
                "package scripts are raw execution artifacts",
            );
            push_optional_hash(
                projections,
                "event.packageScript.workingDirectory",
                working_directory.as_deref(),
                privacy_mode,
                "working directories may include local usernames or repository names",
            );
        }
        EndpointEvent::DylibLoad {
            path,
            target_image,
            mechanism,
        } => {
            push_hash(
                projections,
                "event.dylibLoad.path",
                path,
                privacy_mode,
                "library paths may include local usernames or project names",
            );
            push_optional_hash(
                projections,
                "event.dylibLoad.targetImage",
                target_image.as_deref(),
                privacy_mode,
                "target image paths may include local usernames or project names",
            );
            push_optional_metadata(
                projections,
                "event.dylibLoad.mechanism",
                mechanism.clone(),
                privacy_mode,
                "load mechanism is a normalized event feature",
            );
        }
        EndpointEvent::LaunchPersistence {
            path,
            label,
            operation,
        } => {
            push_hash(
                projections,
                "event.launchPersistence.path",
                path,
                privacy_mode,
                "persistence paths may include local usernames or app-specific names",
            );
            push_optional_hash(
                projections,
                "event.launchPersistence.label",
                label.as_deref(),
                privacy_mode,
                "launch labels may reveal private tooling",
            );
            push_metadata(
                projections,
                "event.launchPersistence.operation",
                format!("{operation:?}"),
                privacy_mode,
                "persistence operation is a normalized event feature",
            );
        }
        EndpointEvent::BrowserExtensionInstall {
            browser,
            extension_id,
            path,
            source,
        } => {
            push_metadata(
                projections,
                "event.browserExtensionInstall.browser",
                browser,
                privacy_mode,
                "browser family is a normalized event feature",
            );
            push_optional_hash(
                projections,
                "event.browserExtensionInstall.extensionId",
                extension_id.as_deref(),
                privacy_mode,
                "extension IDs are correlated by hash by default",
            );
            push_hash(
                projections,
                "event.browserExtensionInstall.path",
                path,
                privacy_mode,
                "extension paths may include local usernames",
            );
            push_optional_hash(
                projections,
                "event.browserExtensionInstall.source",
                source.as_deref(),
                privacy_mode,
                "extension source may include internal locations",
            );
        }
        EndpointEvent::BrowserDownload {
            browser,
            path,
            source_url,
            content_hash,
            byte_count,
        } => {
            push_metadata(
                projections,
                "event.browserDownload.browser",
                browser,
                privacy_mode,
                "browser family is a normalized event feature",
            );
            push_hash(
                projections,
                "event.browserDownload.path",
                path,
                privacy_mode,
                "download paths may include local usernames or document names",
            );
            push_optional_hash(
                projections,
                "event.browserDownload.sourceUrl",
                source_url.as_deref(),
                privacy_mode,
                "download URLs may contain internal hosts or query strings",
            );
            push_optional_metadata(
                projections,
                "event.browserDownload.contentHash",
                content_hash.clone(),
                privacy_mode,
                "download content hashes are privacy-safe artifact proof",
            );
            push_optional_metadata(
                projections,
                "event.browserDownload.byteCount",
                byte_count.map(|value| value.to_string()),
                privacy_mode,
                "download byte count is a bounded artifact feature",
            );
        }
        EndpointEvent::CredentialAccess { kind, path, name } => {
            push_metadata(
                projections,
                "event.credentialAccess.kind",
                kind.as_str(),
                privacy_mode,
                "credential kind is a normalized event feature",
            );
            push_optional_hash(
                projections,
                "event.credentialAccess.path",
                path.as_deref(),
                privacy_mode,
                "credential paths may include local usernames or secret store names",
            );
            push_optional_hash(
                projections,
                "event.credentialAccess.name",
                name.as_deref(),
                privacy_mode,
                "credential names are correlated by hash by default",
            );
        }
        EndpointEvent::ToolCall {
            tool_name,
            parameters,
        } => {
            push_metadata(
                projections,
                "event.toolCall.toolName",
                tool_name,
                privacy_mode,
                "tool names are normalized agent features",
            );
            push_local(
                projections,
                "event.toolCall.parameters",
                serde_json::to_string(parameters).unwrap_or_default(),
                privacy_mode,
                "tool parameters may contain prompts, file contents, or secrets",
            );
        }
        EndpointEvent::PolicyDecision {
            action,
            target,
            decision,
            guard,
            severity,
        } => {
            push_metadata(
                projections,
                "event.policyDecision.action",
                action.as_str(),
                privacy_mode,
                "policy action is a normalized decision feature",
            );
            push_optional_hash(
                projections,
                "event.policyDecision.target",
                target.as_deref(),
                privacy_mode,
                "policy targets may include paths, hosts, or credential names",
            );
            push_metadata(
                projections,
                "event.policyDecision.decision",
                decision,
                privacy_mode,
                "policy decision is a normalized decision feature",
            );
            push_optional_metadata(
                projections,
                "event.policyDecision.guard",
                guard.clone(),
                privacy_mode,
                "guard identifier is a normalized decision feature",
            );
            push_optional_metadata(
                projections,
                "event.policyDecision.severity",
                severity.clone(),
                privacy_mode,
                "severity is a normalized decision feature",
            );
        }
        EndpointEvent::Other { category, fields } => {
            push_metadata(
                projections,
                "event.other.category",
                category,
                privacy_mode,
                "custom event category is a normalized feature",
            );
            if !fields.is_empty() {
                push_local(
                    projections,
                    "event.other.fields",
                    serde_json::to_string(fields).unwrap_or_default(),
                    privacy_mode,
                    "custom event fields may contain arbitrary raw artifacts",
                );
            }
        }
    }
}

pub(crate) fn count_projection_class(
    observations: &[EndpointTelemetryObservationProjection],
    redaction_class: EndpointEvidenceRedactionClass,
) -> usize {
    observations
        .iter()
        .flat_map(|observation| observation.projections.iter())
        .filter(|projection| projection.redaction_class == redaction_class)
        .count()
}

fn push_optional_metadata(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: Option<String>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    if let Some(value) = value.filter(|value| !value.trim().is_empty()) {
        push_metadata(projections, field_path, value, privacy_mode, reason);
    }
}

fn push_metadata(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: impl AsRef<str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    let value = value.as_ref();
    let redaction_class = if *privacy_mode == EndpointTelemetryPrivacyMode::LocalOnly {
        EndpointEvidenceRedactionClass::LocalOnly
    } else {
        EndpointEvidenceRedactionClass::MetadataOnly
    };
    projections.push(EndpointTelemetryFieldProjection {
        field_path: field_path.into(),
        redaction_class,
        value_hash: Some(sha256(value.as_bytes()).to_hex_prefixed()),
        feature_value: (!matches!(privacy_mode, EndpointTelemetryPrivacyMode::LocalOnly))
            .then(|| value.to_string()),
        raw_value: None,
        reason: reason.into(),
    });
}

fn push_optional_hash(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: Option<&str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        push_hash(projections, field_path, value, privacy_mode, reason);
    }
}

fn push_hash(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: impl AsRef<str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    let value = value.as_ref();
    let redaction_class = if *privacy_mode == EndpointTelemetryPrivacyMode::LocalOnly {
        EndpointEvidenceRedactionClass::LocalOnly
    } else {
        EndpointEvidenceRedactionClass::HashOnly
    };
    projections.push(EndpointTelemetryFieldProjection {
        field_path: field_path.into(),
        redaction_class,
        value_hash: Some(sha256(value.as_bytes()).to_hex_prefixed()),
        feature_value: (!matches!(privacy_mode, EndpointTelemetryPrivacyMode::LocalOnly))
            .then(|| privacy_feature(value)),
        raw_value: None,
        reason: reason.into(),
    });
}

fn push_optional_local(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: Option<&str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    if let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) {
        push_local(projections, field_path, value, privacy_mode, reason);
    }
}

fn push_local(
    projections: &mut Vec<EndpointTelemetryFieldProjection>,
    field_path: impl Into<String>,
    value: impl AsRef<str>,
    privacy_mode: &EndpointTelemetryPrivacyMode,
    reason: impl Into<String>,
) {
    let value = value.as_ref();
    let raw_permitted = privacy_mode.permits_raw_artifacts();
    projections.push(EndpointTelemetryFieldProjection {
        field_path: field_path.into(),
        redaction_class: if raw_permitted {
            EndpointEvidenceRedactionClass::RawArtifactPermitted
        } else {
            EndpointEvidenceRedactionClass::LocalOnly
        },
        value_hash: Some(sha256(value.as_bytes()).to_hex_prefixed()),
        feature_value: (!matches!(privacy_mode, EndpointTelemetryPrivacyMode::LocalOnly))
            .then(|| privacy_feature(value)),
        raw_value: raw_permitted.then(|| value.to_string()),
        reason: reason.into(),
    });
}

fn privacy_feature(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return "empty".to_string();
    }
    if let Some((scheme, _)) = trimmed.split_once("://") {
        return format!("url_scheme:{scheme}");
    }
    if trimmed.contains('/') || trimmed.contains('\\') {
        let normalized = normalize_path_string(trimmed);
        let extension = Path::new(&normalized)
            .extension()
            .and_then(|extension| extension.to_str())
            .filter(|extension| !extension.is_empty());
        return extension
            .map(|extension| format!("path_extension:{extension}"))
            .unwrap_or_else(|| "path".to_string());
    }
    format!("len:{}", trimmed.len())
}
