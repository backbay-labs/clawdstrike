use super::super::*;

pub(crate) fn telemetry_privacy_report_id_from_values(
    privacy_mode: &str,
    raw_artifact_upload_permitted: bool,
    raw_artifact_approval_id: Option<&str>,
    raw_artifact_approval_reason_hash: Option<&str>,
    projection_content_hash: &str,
    count_values: [&str; 7],
) -> String {
    let privacy_mode_hash = sha256(privacy_mode.as_bytes()).to_hex_prefixed();
    let raw_permitted = raw_artifact_upload_permitted.to_string();
    let raw_permitted_hash = sha256(raw_permitted.as_bytes()).to_hex_prefixed();
    let observation_count_hash = sha256(count_values[0].as_bytes()).to_hex_prefixed();
    let field_count_hash = sha256(count_values[1].as_bytes()).to_hex_prefixed();
    let hash_only_count_hash = sha256(count_values[2].as_bytes()).to_hex_prefixed();
    let metadata_only_count_hash = sha256(count_values[3].as_bytes()).to_hex_prefixed();
    let redacted_count_hash = sha256(count_values[4].as_bytes()).to_hex_prefixed();
    let raw_suppressed_count_hash = sha256(count_values[5].as_bytes()).to_hex_prefixed();
    let local_only_count_hash = sha256(count_values[6].as_bytes()).to_hex_prefixed();
    let projection_content_hash_hash = sha256(projection_content_hash.as_bytes()).to_hex_prefixed();
    let mut evidence_hashes = vec![
        privacy_mode_hash.as_str(),
        raw_permitted_hash.as_str(),
        projection_content_hash_hash.as_str(),
        observation_count_hash.as_str(),
        field_count_hash.as_str(),
        hash_only_count_hash.as_str(),
        metadata_only_count_hash.as_str(),
        redacted_count_hash.as_str(),
        raw_suppressed_count_hash.as_str(),
        local_only_count_hash.as_str(),
    ];
    let raw_artifact_approval_id_hash =
        raw_artifact_approval_id.map(|value| sha256(value.as_bytes()).to_hex_prefixed());
    let raw_artifact_approval_reason_hash_hash =
        raw_artifact_approval_reason_hash.map(|value| sha256(value.as_bytes()).to_hex_prefixed());
    let empty_hash = sha256(b"").to_hex_prefixed();
    if raw_artifact_upload_permitted {
        evidence_hashes.push(
            raw_artifact_approval_id_hash
                .as_deref()
                .unwrap_or(empty_hash.as_str()),
        );
        evidence_hashes.push(
            raw_artifact_approval_reason_hash_hash
                .as_deref()
                .unwrap_or(empty_hash.as_str()),
        );
    }
    telemetry_privacy_report_id_from_evidence_hashes(evidence_hashes)
}

pub(crate) fn telemetry_privacy_report_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
) -> Result<String> {
    let raw_artifact_upload_permitted_hash = evidence_value_hash(
        evidence,
        "rawArtifactUploadPermitted",
        "privacy report raw artifact permission evidence",
    )?;
    let mut evidence_hashes = vec![
        evidence_value_hash(evidence, "privacyMode", "privacy report mode evidence")?,
        raw_artifact_upload_permitted_hash,
        evidence_value_hash(
            evidence,
            "projectionContentHash",
            "privacy report projection content hash evidence",
        )?,
        evidence_value_hash(
            evidence,
            "observationCount",
            "privacy report observation count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "fieldCount",
            "privacy report field count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "hashOnlyCount",
            "privacy report hash-only count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "metadataOnlyCount",
            "privacy report metadata-only count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "redactedCount",
            "privacy report redacted count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "rawSuppressedCount",
            "privacy report raw suppressed count evidence",
        )?,
        evidence_value_hash(
            evidence,
            "localOnlyCount",
            "privacy report local-only count evidence",
        )?,
    ];
    let true_hash = sha256(b"true").to_hex_prefixed();
    if hex_strings_match(raw_artifact_upload_permitted_hash, true_hash.as_str()) {
        evidence_hashes.push(evidence_value_hash(
            evidence,
            "rawArtifactApprovalId",
            "privacy report raw artifact approval id evidence",
        )?);
        evidence_hashes.push(evidence_value_hash(
            evidence,
            "rawArtifactApprovalReasonHash",
            "privacy report raw artifact approval reason hash evidence",
        )?);
    }
    Ok(telemetry_privacy_report_id_from_evidence_hashes(
        evidence_hashes,
    ))
}

pub(crate) fn telemetry_privacy_report_id_from_evidence_hashes<'a>(
    evidence_hashes: impl IntoIterator<Item = &'a str>,
) -> String {
    stable_id("telemetry_privacy_report", evidence_hashes)
}

pub(crate) fn require_privacy_report_evidence(
    evidence: &[EndpointReceiptEvidence],
    privacy_report_id: Option<&str>,
) -> Result<()> {
    let privacy_report_id =
        privacy_report_id.ok_or_else(|| anyhow!("privacy report signed id is required"))?;
    require_evidence_value_hash(
        evidence,
        "privacyReportId",
        privacy_report_id,
        "privacy report id evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "privacyMode", "privacy report mode evidence")?;
    require_boolean_hashed_evidence(
        evidence,
        "rawArtifactUploadPermitted",
        "privacy report raw artifact permission evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "projectionContentHash",
        "privacy report projection content hash evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "observationCount",
        "privacy report observation count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "fieldCount",
        "privacy report field count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "hashOnlyCount",
        "privacy report hash-only count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "metadataOnlyCount",
        "privacy report metadata-only count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "redactedCount",
        "privacy report redacted count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "rawSuppressedCount",
        "privacy report raw suppressed count evidence",
    )?;
    require_nonempty_hashed_evidence(
        evidence,
        "localOnlyCount",
        "privacy report local-only count evidence",
    )?;
    let raw_artifact_upload_permitted_hash = evidence_value_hash(
        evidence,
        "rawArtifactUploadPermitted",
        "privacy report raw artifact permission evidence",
    )?;
    let true_hash = sha256(b"true").to_hex_prefixed();
    if hex_strings_match(raw_artifact_upload_permitted_hash, true_hash.as_str()) {
        require_nonempty_hashed_evidence(
            evidence,
            "rawArtifactApprovalId",
            "privacy report raw artifact approval id evidence",
        )?;
        require_nonempty_hashed_evidence(
            evidence,
            "rawArtifactApprovalReasonHash",
            "privacy report raw artifact approval reason hash evidence",
        )?;
    }
    let expected_privacy_report_id = telemetry_privacy_report_id_from_evidence(evidence)?;
    if privacy_report_id != expected_privacy_report_id {
        return Err(anyhow!(
            "privacy report id must match signed mode and count evidence"
        ));
    }
    Ok(())
}
