//! Signed simulation-receipt verification and evidence extraction.

use crate::routes::policies::*;

pub(crate) struct VerifiedPolicyProposalSimulationReceipt {
    pub(crate) signed_receipt: serde_json::Value,
    pub(crate) signed_receipt_sha256: String,
    pub(crate) public_key: String,
    pub(crate) receipt_id: Option<String>,
    pub(crate) endpoint_id: Option<String>,
    pub(crate) policy_epoch: Option<u64>,
    pub(crate) impact_id: Option<String>,
    pub(crate) graph_slice_id: Option<String>,
    pub(crate) evidence_keys: Vec<String>,
    pub(crate) evidence_value_hashes: BTreeMap<String, String>,
}

impl VerifiedPolicyProposalSimulationReceipt {
    fn to_impact_receipt_summary(&self) -> serde_json::Value {
        serde_json::json!({
            "receiptId": self.receipt_id,
            "signedReceiptSha256": self.signed_receipt_sha256,
            "publicKey": self.public_key,
            "receiptFamily": POLICY_PROPOSAL_SIMULATION_RECEIPT_FAMILY,
            "ruleId": POLICY_PROPOSAL_SIMULATION_RULE_ID,
            "endpointId": self.endpoint_id,
            "policyEpoch": self.policy_epoch,
            "impactId": self.impact_id,
            "graphSliceId": self.graph_slice_id,
            "evidenceKeys": self.evidence_keys,
            "evidenceValueHashes": self.evidence_value_hashes.clone(),
            "signedReceipt": self.signed_receipt,
        })
    }
}

pub(crate) fn validate_policy_proposal_simulation_receipt(
    simulation_receipt: Option<serde_json::Value>,
    simulation_receipt_public_key: Option<String>,
) -> Result<Option<VerifiedPolicyProposalSimulationReceipt>, ApiError> {
    let Some(signed_receipt_value) = simulation_receipt else {
        if simulation_receipt_public_key.is_some() {
            return Err(ApiError::BadRequest(
                "simulation_receipt is required when simulation_receipt_public_key is provided"
                    .to_string(),
            ));
        }
        return Ok(None);
    };
    let public_key_hex = simulation_receipt_public_key
        .map(|value| require_non_empty_policy_impact_field("simulation_receipt_public_key", value))
        .transpose()?
        .ok_or_else(|| {
            ApiError::BadRequest(
                "simulation_receipt_public_key is required when simulation_receipt is provided"
                    .to_string(),
            )
        })?;
    validate_policy_proposal_simulation_receipt_value(signed_receipt_value, public_key_hex)
        .map(Some)
}

pub(crate) fn validate_policy_proposal_simulation_receipt_attachments(
    attachments: Vec<PolicyProposalSimulationReceiptAttachment>,
) -> Result<Vec<VerifiedPolicyProposalSimulationReceipt>, ApiError> {
    if attachments.len() > MAX_POLICY_PROPOSAL_SIMULATION_RECEIPTS {
        return Err(ApiError::BadRequest(format!(
            "simulation_receipts must include no more than {MAX_POLICY_PROPOSAL_SIMULATION_RECEIPTS} receipts"
        )));
    }

    attachments
        .into_iter()
        .enumerate()
        .map(|(index, attachment)| {
            let expected_receipt_id = attachment
                .receipt_id
                .map(|value| {
                    require_non_empty_policy_impact_field(
                        &format!("simulation_receipts[{index}].receipt_id"),
                        value,
                    )
                })
                .transpose()?;
            let expected_receipt_sha256 = attachment
                .receipt_sha256
                .map(|value| {
                    normalize_policy_impact_sha256(
                        &format!("simulation_receipts[{index}].receipt_sha256"),
                        &value,
                    )
                })
                .transpose()?;
            let public_key = require_non_empty_policy_impact_field(
                &format!("simulation_receipts[{index}].public_key"),
                attachment.public_key,
            )?;
            let verified =
                validate_policy_proposal_simulation_receipt_value(attachment.receipt, public_key)?;
            validate_policy_proposal_simulation_receipt_expectations(
                &verified,
                expected_receipt_id.as_deref(),
                expected_receipt_sha256.as_deref(),
            )?;
            Ok(verified)
        })
        .collect()
}

pub(crate) fn validate_policy_proposal_simulation_receipt_value(
    signed_receipt_value: serde_json::Value,
    public_key_hex: String,
) -> Result<VerifiedPolicyProposalSimulationReceipt, ApiError> {
    let public_key = PublicKey::from_hex(&public_key_hex).map_err(|_| {
        ApiError::BadRequest(
            "simulation_receipt_public_key must be a valid Ed25519 public key hex".to_string(),
        )
    })?;
    let canonical_signed_receipt = canonicalize_json(&signed_receipt_value).map_err(|err| {
        ApiError::BadRequest(format!(
            "simulation_receipt is not canonicalizable JSON: {err}"
        ))
    })?;
    if canonical_signed_receipt.len() > MAX_POLICY_PROPOSAL_SIMULATION_RECEIPT_BYTES {
        return Err(ApiError::BadRequest(format!(
            "simulation_receipt must be no larger than {MAX_POLICY_PROPOSAL_SIMULATION_RECEIPT_BYTES} bytes"
        )));
    }
    let signed_receipt: SignedReceipt = serde_json::from_value(signed_receipt_value.clone())
        .map_err(|err| ApiError::BadRequest(format!("invalid simulation_receipt: {err}")))?;
    let verification = signed_receipt.verify(&PublicKeySet::new(public_key.clone()));
    if !verification.valid {
        return Err(ApiError::BadRequest(format!(
            "simulation_receipt failed verification: {}",
            verification.errors.join("; ")
        )));
    }

    let endpoint_decision = signed_receipt
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .ok_or_else(|| {
            ApiError::BadRequest(
                "simulation_receipt must include receipt.metadata.endpointDecision".to_string(),
            )
        })?;
    let receipt_family = required_endpoint_decision_string(endpoint_decision, "/receiptFamily")?;
    if receipt_family != POLICY_PROPOSAL_SIMULATION_RECEIPT_FAMILY {
        return Err(ApiError::BadRequest(
            "simulation_receipt endpointDecision.receiptFamily must be simulation".to_string(),
        ));
    }
    let rule_id = required_endpoint_decision_string(endpoint_decision, "/decision/ruleId")?;
    if rule_id != POLICY_PROPOSAL_SIMULATION_RULE_ID {
        return Err(ApiError::BadRequest(
            "simulation_receipt endpointDecision.decision.ruleId must be endpoint.policy_event_impact"
                .to_string(),
        ));
    }
    let process_node_id =
        required_endpoint_decision_string(endpoint_decision, "/graph/processNodeId")?;
    if process_node_id != POLICY_PROPOSAL_SIMULATION_PROCESS_NODE_ID {
        return Err(ApiError::BadRequest(
            "simulation_receipt endpointDecision.graph.processNodeId must be policy_event_stream"
                .to_string(),
        ));
    }

    if let Some(signer_public_key) = endpoint_decision
        .pointer("/signer/signerPublicKey")
        .and_then(serde_json::Value::as_str)
    {
        let metadata_public_key = PublicKey::from_hex(signer_public_key).map_err(|_| {
            ApiError::BadRequest(
                "simulation_receipt endpointDecision.signer.signerPublicKey must be a valid Ed25519 public key hex"
                    .to_string(),
            )
        })?;
        if metadata_public_key.to_hex() != public_key.to_hex() {
            return Err(ApiError::BadRequest(
                "simulation_receipt endpointDecision.signer.signerPublicKey must match simulation_receipt_public_key"
                    .to_string(),
            ));
        }
    }

    let evidence_value_hashes = endpoint_decision_evidence_value_hashes(endpoint_decision)?;
    let evidence_keys = evidence_value_hashes
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    for required_key in [
        "impactId",
        "eventStreamHash",
        "currentResultHash",
        "proposedResultHash",
        "impactHash",
        "proposedPolicyHash",
        "proposedPolicyEpoch",
        "eventCount",
        "changedCount",
        "allowToBlockCount",
        "trackPosture",
    ] {
        if !evidence_keys.contains(required_key) {
            return Err(ApiError::BadRequest(format!(
                "simulation_receipt endpointDecision.evidence must include {required_key}"
            )));
        }
    }

    let signed_receipt_sha256 = sha256(canonical_signed_receipt.as_bytes()).to_hex();
    Ok(VerifiedPolicyProposalSimulationReceipt {
        signed_receipt: signed_receipt_value,
        signed_receipt_sha256,
        public_key: public_key.to_hex(),
        receipt_id: signed_receipt.receipt.receipt_id.clone(),
        endpoint_id: endpoint_decision
            .pointer("/actor/endpointId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        policy_epoch: endpoint_decision
            .pointer("/policy/policyEpoch")
            .and_then(serde_json::Value::as_u64),
        impact_id: endpoint_decision
            .pointer("/decision/findingId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        graph_slice_id: endpoint_decision
            .pointer("/graph/graphSliceId")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string),
        evidence_value_hashes,
        evidence_keys: evidence_keys.into_iter().collect(),
    })
}

pub(crate) fn validate_policy_proposal_simulation_receipt_expectations(
    verified: &VerifiedPolicyProposalSimulationReceipt,
    expected_receipt_id: Option<&str>,
    expected_receipt_sha256: Option<&str>,
) -> Result<(), ApiError> {
    if let (Some(expected), Some(actual)) = (expected_receipt_id, verified.receipt_id.as_deref()) {
        if expected != actual {
            return Err(ApiError::BadRequest(
                "simulation_receipts receipt_id must match the signed receipt receipt_id"
                    .to_string(),
            ));
        }
    }
    if let Some(expected) = expected_receipt_sha256 {
        if expected != verified.signed_receipt_sha256 {
            return Err(ApiError::BadRequest(
                "simulation_receipts receipt_sha256 must match the canonical signed receipt hash"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_unique_policy_proposal_simulation_receipts(
    single_receipt: Option<&VerifiedPolicyProposalSimulationReceipt>,
    batch_receipts: &[VerifiedPolicyProposalSimulationReceipt],
) -> Result<(), ApiError> {
    let mut seen = BTreeSet::new();
    for receipt in single_receipt.into_iter().chain(batch_receipts.iter()) {
        if !seen.insert(receipt.signed_receipt_sha256.as_str()) {
            return Err(ApiError::BadRequest(
                "simulation receipts must not repeat the same signed receipt hash".to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) fn policy_proposal_simulation_receipt_summaries(
    single_receipt: &Option<VerifiedPolicyProposalSimulationReceipt>,
    batch_receipts: &[VerifiedPolicyProposalSimulationReceipt],
) -> Vec<serde_json::Value> {
    single_receipt
        .iter()
        .chain(batch_receipts.iter())
        .map(VerifiedPolicyProposalSimulationReceipt::to_impact_receipt_summary)
        .collect()
}

pub(crate) fn distinct_policy_proposal_receipt_values<'a>(
    receipts: impl Iterator<Item = &'a serde_json::Value>,
    field: &str,
) -> Vec<String> {
    receipts
        .filter_map(|receipt| receipt.get(field))
        .filter_map(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn required_endpoint_decision_string<'a>(
    endpoint_decision: &'a serde_json::Value,
    pointer: &str,
) -> Result<&'a str, ApiError> {
    endpoint_decision
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "simulation_receipt endpointDecision{pointer} must be a non-empty string"
            ))
        })
}

pub(crate) fn endpoint_decision_evidence_keys(
    endpoint_decision: &serde_json::Value,
) -> Result<BTreeSet<String>, ApiError> {
    Ok(endpoint_decision_evidence_value_hashes(endpoint_decision)?
        .keys()
        .cloned()
        .collect())
}

pub(crate) fn endpoint_decision_evidence_value_hashes(
    endpoint_decision: &serde_json::Value,
) -> Result<BTreeMap<String, String>, ApiError> {
    let evidence = endpoint_decision
        .get("evidence")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "simulation_receipt endpointDecision.evidence must be an array".to_string(),
            )
        })?;
    let mut hashes = BTreeMap::new();
    for item in evidence {
        let key = item
            .get("key")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "simulation_receipt endpointDecision.evidence entries must include a non-empty key"
                        .to_string(),
                )
            })?;
        let value_hash = item
            .get("valueHash")
            .and_then(serde_json::Value::as_str)
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| {
                ApiError::BadRequest(
                    "simulation_receipt endpointDecision.evidence entries must include a non-empty valueHash"
                        .to_string(),
                )
            })?;
        hashes.insert(key.to_string(), value_hash.to_string());
    }
    Ok(hashes)
}
