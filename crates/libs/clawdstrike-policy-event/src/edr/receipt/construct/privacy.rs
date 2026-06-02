use super::super::*;

impl EndpointDecisionReceipt {
    #[must_use]
    pub fn for_telemetry_privacy(input: EndpointTelemetryPrivacyReceiptInput<'_>) -> Self {
        let privacy_mode = input.report.privacy_mode.as_str();
        let mut evidence = vec![
            EndpointReceiptEvidence::hashed("privacyReportId", &input.report.report_id),
            EndpointReceiptEvidence::hashed("privacyMode", privacy_mode),
            EndpointReceiptEvidence::hashed(
                "rawArtifactUploadPermitted",
                input.report.raw_artifact_upload_permitted.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "projectionContentHash",
                input.report.projection_content_hash.as_str(),
            ),
            EndpointReceiptEvidence::hashed(
                "observationCount",
                input.report.observation_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed("fieldCount", input.report.field_count.to_string()),
            EndpointReceiptEvidence::hashed(
                "hashOnlyCount",
                input.report.hash_only_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "metadataOnlyCount",
                input.report.metadata_only_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "redactedCount",
                input.report.redacted_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "rawSuppressedCount",
                input.report.raw_suppressed_count.to_string(),
            ),
            EndpointReceiptEvidence::hashed(
                "localOnlyCount",
                input.report.local_only_count.to_string(),
            ),
        ];
        if input.report.raw_artifact_upload_permitted {
            evidence.push(EndpointReceiptEvidence::hashed(
                "rawArtifactApprovalId",
                input
                    .report
                    .raw_artifact_approval_id
                    .as_deref()
                    .unwrap_or_default(),
            ));
            evidence.push(EndpointReceiptEvidence::hashed(
                "rawArtifactApprovalReasonHash",
                input
                    .report
                    .raw_artifact_approval_reason_hash
                    .as_deref()
                    .unwrap_or_default(),
            ));
        }
        Self {
            schema_version: ENDPOINT_DECISION_RECEIPT_SCHEMA_VERSION.to_string(),
            receipt_family: EndpointDecisionReceiptFamily::PrivacyReport,
            local_sequence: input.local_sequence,
            clock: EndpointClockState::default(),
            signer: EndpointReceiptSigner {
                signer_identity: input.signer_identity.to_string(),
                signer_public_key: None,
            },
            actor: EndpointDecisionActor::with_endpoint_id(input.endpoint_id),
            policy: input.policy,
            sensor_state: input.sensor_state,
            decision: EndpointDecisionRecord {
                observation_id: None,
                finding_id: Some(input.report.report_id.clone()),
                rule_id: Some("endpoint.telemetry_privacy".to_string()),
                title: Some("Endpoint telemetry privacy mode applied".to_string()),
                severity: None,
                confidence: None,
                action: EndpointDecisionAction::Observe,
                passed: true,
                ttl_seconds: None,
                rollback_ref: None,
            },
            graph: EndpointGraphReference::default(),
            evidence,
        }
    }
}
