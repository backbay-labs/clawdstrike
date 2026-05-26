//! Privacy policy and raw-artifact upload approval helpers.
//!
//! Reads the local policy YAML to determine whether raw endpoint artifacts
//! may be uploaded, validates approval IDs and reason hashes, and enforces
//! that resolved local approvals correspond to the expected resource.

use super::super::*;

const EDR_RAW_ARTIFACT_POLICY_PATHS: &[(&[&str], &str)] = &[
    (
        &["edr", "telemetry", "raw_artifact_upload"],
        "edr.telemetry.raw_artifact_upload",
    ),
    (
        &["edr", "telemetry", "rawArtifactUpload"],
        "edr.telemetry.rawArtifactUpload",
    ),
    (
        &["endpoint_telemetry", "raw_artifact_upload"],
        "endpoint_telemetry.raw_artifact_upload",
    ),
    (
        &["endpointTelemetry", "rawArtifactUpload"],
        "endpointTelemetry.rawArtifactUpload",
    ),
];

pub(crate) fn edr_privacy_policy_decision(
    settings: &Settings,
    requested_privacy_mode: EndpointTelemetryPrivacyMode,
    raw_artifact_approval: Option<&EdrRawArtifactApproval>,
) -> Result<EdrPrivacyPolicyDecision> {
    let raw_policy = edr_raw_artifact_upload_policy(settings)?;
    let raw_artifact_upload_requested = requested_privacy_mode.permits_raw_artifacts();
    let raw_artifact_approval_required = raw_artifact_upload_requested && raw_policy.allowed;
    let denied_reason = if raw_artifact_upload_requested && !raw_policy.allowed {
        Some(
            "raw_artifact_permitted was requested, but the local policy does not allow raw artifact upload"
                .to_string(),
        )
    } else if raw_artifact_approval_required && raw_artifact_approval.is_none() {
        Some(
            "raw_artifact_permitted was requested and local policy allows raw artifact upload, but rawArtifactApprovalId and rawArtifactApprovalReason are required"
                .to_string(),
        )
    } else {
        None
    };
    let effective_privacy_mode = if denied_reason.is_some() {
        EndpointTelemetryPrivacyMode::HashesFeatures
    } else {
        requested_privacy_mode.clone()
    };
    let effective_raw_artifact_approval = effective_privacy_mode
        .permits_raw_artifacts()
        .then_some(raw_artifact_approval)
        .flatten();

    Ok(EdrPrivacyPolicyDecision {
        requested_privacy_mode,
        effective_privacy_mode,
        raw_artifact_upload_requested,
        raw_artifact_upload_allowed: raw_policy.allowed,
        raw_artifact_approval_required,
        raw_artifact_approval_provided: raw_artifact_approval.is_some(),
        raw_artifact_approval_id: effective_raw_artifact_approval
            .map(|approval| approval.approval_id.clone()),
        raw_artifact_approval_reason_hash: effective_raw_artifact_approval
            .map(|approval| approval.reason_hash.clone()),
        policy_source: raw_policy.source,
        denied_reason,
    })
}

pub(crate) fn validate_raw_artifact_approval(
    input: &EdrPrivacyReportInput,
) -> Result<Option<EdrRawArtifactApproval>, (StatusCode, String)> {
    validate_raw_artifact_approval_fields(
        input.raw_artifact_approval_id.as_deref(),
        input.raw_artifact_approval_reason.as_deref(),
    )
}

pub(crate) fn validate_raw_artifact_approval_fields(
    approval_id: Option<&str>,
    approval_reason: Option<&str>,
) -> Result<Option<EdrRawArtifactApproval>, (StatusCode, String)> {
    let approval_id = trimmed_owned(approval_id);
    let approval_reason = trimmed_owned(approval_reason);
    if let Some(approval_id) = approval_id.as_deref() {
        if approval_id.len() > EDR_MAX_RAW_ARTIFACT_APPROVAL_ID_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "rawArtifactApprovalId must be at most {EDR_MAX_RAW_ARTIFACT_APPROVAL_ID_BYTES} bytes"
                ),
            ));
        }
    }
    if let Some(reason) = approval_reason.as_deref() {
        if reason.len() > EDR_MAX_RAW_ARTIFACT_APPROVAL_REASON_BYTES {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "rawArtifactApprovalReason must be at most {EDR_MAX_RAW_ARTIFACT_APPROVAL_REASON_BYTES} bytes"
                ),
            ));
        }
    }

    match (approval_id, approval_reason) {
        (Some(approval_id), Some(approval_reason)) => Ok(Some(EdrRawArtifactApproval {
            approval_id,
            reason_hash: sha256(approval_reason.as_bytes()).to_hex_prefixed(),
        })),
        (None, None) => Ok(None),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "rawArtifactApprovalId and rawArtifactApprovalReason must be provided together"
                .to_string(),
        )),
    }
}

pub(crate) fn raw_artifact_approval_resource_for_privacy_report() -> String {
    format!("{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:privacy_report")
}

pub(crate) fn raw_artifact_approval_resource_for_evidence_bundle_fleet_publish(
    bundle_id: &str,
) -> String {
    format!(
        "{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:evidence_bundle_fleet_publish:{}",
        bundle_id.trim()
    )
}

pub(crate) fn raw_artifact_approval_resource_for_control_archive_backfill(
    bundle_id: Option<&str>,
) -> String {
    match bundle_id.and_then(|value| trimmed_owned(Some(value))) {
        Some(bundle_id) => {
            format!("{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:control_archive_backfill:{bundle_id}")
        }
        None => format!("{EDR_RAW_ARTIFACT_UPLOAD_GUARD}:control_archive_backfill_batch"),
    }
}

pub(crate) async fn validate_resolved_raw_artifact_approval(
    state: &AgentApiState,
    raw_artifact_approval: Option<EdrRawArtifactApproval>,
    expected_resource: &str,
) -> Result<Option<EdrRawArtifactApproval>, (StatusCode, String)> {
    let Some(raw_artifact_approval) = raw_artifact_approval else {
        return Ok(None);
    };
    let approval_status = state
        .approval_queue
        .get_status(&raw_artifact_approval.approval_id)
        .await
        .ok_or_else(|| {
            (
                StatusCode::CONFLICT,
                "rawArtifactApprovalId does not reference a local approval request".to_string(),
            )
        })?;
    if approval_status.status != ApprovalStatus::Resolved {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalId must reference a resolved local approval request".to_string(),
        ));
    }
    match approval_status.resolution {
        Some(
            ApprovalResolution::AllowOnce
            | ApprovalResolution::AllowSession
            | ApprovalResolution::AllowAlways,
        ) => {}
        Some(ApprovalResolution::Deny) | None => {
            return Err((
                StatusCode::CONFLICT,
                "rawArtifactApprovalId must reference an allowed local approval request"
                    .to_string(),
            ));
        }
    }
    if !approval_status.resolved_by_trusted_authority {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalId must be resolved by a trusted UI or signed control-plane authority"
                .to_string(),
        ));
    }
    if approval_status.guard != EDR_RAW_ARTIFACT_UPLOAD_GUARD {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalId must reference an endpoint.telemetry.raw_artifact_upload approval"
                .to_string(),
        ));
    }
    if approval_status.resource != expected_resource {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "rawArtifactApprovalId must reference resource {expected_resource} for this raw artifact upload"
            ),
        ));
    }
    let expected_reason_hash = sha256(approval_status.reason.as_bytes()).to_hex_prefixed();
    if raw_artifact_approval.reason_hash != expected_reason_hash {
        return Err((
            StatusCode::CONFLICT,
            "rawArtifactApprovalReason does not match the resolved approval request".to_string(),
        ));
    }
    state
        .approval_queue
        .consume_allow_once(&raw_artifact_approval.approval_id)
        .await
        .map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!("rawArtifactApprovalId could not be consumed: {err}"),
            )
        })?;
    Ok(Some(raw_artifact_approval))
}

pub(crate) fn edr_raw_artifact_upload_policy(
    settings: &Settings,
) -> Result<EdrRawArtifactUploadPolicy> {
    let bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for endpoint telemetry privacy {}",
            settings.policy_path.display()
        )
    })?;
    let policy_prefix = format!("policy:{}#", settings.policy_path.display());
    let value = match serde_yaml::from_slice::<serde_yaml::Value>(&bytes) {
        Ok(value) => value,
        Err(_) => {
            return Ok(EdrRawArtifactUploadPolicy {
                allowed: false,
                source: format!("{policy_prefix}default-deny-invalid-yaml"),
            });
        }
    };

    for (path, label) in EDR_RAW_ARTIFACT_POLICY_PATHS {
        if let Some(allowed) = yaml_bool_at_path(&value, path) {
            return Ok(EdrRawArtifactUploadPolicy {
                allowed,
                source: format!("{policy_prefix}{label}"),
            });
        }
    }

    Ok(EdrRawArtifactUploadPolicy {
        allowed: false,
        source: format!("{policy_prefix}default-deny"),
    })
}

pub(crate) fn yaml_bool_at_path(value: &serde_yaml::Value, path: &[&str]) -> Option<bool> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    yaml_bool_value(current)
}

pub(crate) fn yaml_bool_value(value: &serde_yaml::Value) -> Option<bool> {
    match value {
        serde_yaml::Value::Bool(value) => Some(*value),
        serde_yaml::Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "allow" | "allowed" | "enabled" | "yes" => Some(true),
            "false" | "deny" | "denied" | "disabled" | "no" => Some(false),
            _ => None,
        },
        _ => None,
    }
}
