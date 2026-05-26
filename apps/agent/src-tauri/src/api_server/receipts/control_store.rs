//! Conversion from signed endpoint receipts to control-API
//! `ControlStoreReceiptRequest` wire payloads.

use super::super::*;

pub(crate) fn control_store_receipt_from_endpoint_receipt(
    receipt: &SignedReceipt,
) -> Result<ControlStoreReceiptRequest, String> {
    let public_key = receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
        .ok_or_else(|| "endpoint receipt is missing signer public key".to_string())?;
    verify_endpoint_receipt_signature(receipt, "endpoint receipt upload candidate", public_key)?;
    let policy_name = receipt
        .receipt
        .provenance
        .as_ref()
        .and_then(|provenance| non_empty(provenance.ruleset.as_deref()))
        .or_else(|| receipt_endpoint_decision_str(receipt, &["policy", "policyVersion"]))
        .ok_or_else(|| "endpoint receipt is missing policy name".to_string())?;
    let guard = receipt
        .receipt
        .verdict
        .gate_id
        .as_deref()
        .and_then(|value| non_empty(Some(value)))
        .or_else(|| receipt_family(receipt))
        .unwrap_or("endpoint_decision");
    let endpoint_decision = receipt
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .ok_or_else(|| "endpoint receipt is missing endpoint decision metadata".to_string())?;
    let evidence = endpoint_decision
        .get("evidence")
        .and_then(|value| {
            value
                .as_array()
                .filter(|items| !items.is_empty())
                .map(|_| value)
        })
        .cloned();
    let signed_receipt = serde_json::to_value(receipt)
        .map_err(|err| format!("serialize endpoint receipt for upload: {err}"))?;

    Ok(ControlStoreReceiptRequest {
        timestamp: receipt.receipt.timestamp.clone(),
        verdict: control_store_receipt_verdict(receipt).to_string(),
        guard: guard.to_string(),
        policy_name: policy_name.to_string(),
        signature: receipt.signatures.signer.to_hex(),
        public_key: public_key.to_string(),
        chain_hash: None,
        evidence,
        metadata: Some(serde_json::json!({
            "source": "clawdstrike-agent",
            "receiptId": receipt.receipt.receipt_id.as_deref(),
            "receiptFamily": receipt_family(receipt),
            "localSequence": receipt_local_sequence(receipt),
            "endpointId": receipt_endpoint_decision_str(receipt, &["actor", "endpointId"]),
            "policyHash": receipt_endpoint_decision_str(receipt, &["policy", "policyHash"]),
        })),
        signed_receipt,
    })
}

pub(crate) fn control_store_receipt_verdict(receipt: &SignedReceipt) -> &'static str {
    if receipt.receipt.verdict.passed {
        "allow"
    } else if receipt_endpoint_decision_str(receipt, &["decision", "action"]) == Some("warn") {
        "warn"
    } else {
        "deny"
    }
}
