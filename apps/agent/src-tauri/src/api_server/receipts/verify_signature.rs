//! Ed25519 signature verification and canonical-JSON content-hash checks
//! for signed endpoint receipts. Wraps the lower-level `hush_core` verifier
//! with proof-contract conflict mapping.

use super::super::*;

pub(crate) fn verify_proof_receipt_signature(
    receipt: &SignedReceipt,
    label: &str,
    expected_signer_public_key: &str,
) -> Result<(), (StatusCode, String)> {
    verify_endpoint_receipt_signature(receipt, label, expected_signer_public_key).map_err(
        |reason| {
            (
                StatusCode::CONFLICT,
                format!("{label} failed signature verification: {reason}"),
            )
        },
    )
}

pub(crate) fn verify_endpoint_receipt_signature(
    receipt: &SignedReceipt,
    label: &str,
    expected_signer_public_key: &str,
) -> Result<(), String> {
    let public_key = receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
        .ok_or_else(|| format!("{label} is missing signer public key"))?;
    if public_key != expected_signer_public_key {
        return Err(format!("{label} signer public key is not trusted"));
    }
    let public_key = hush_core::PublicKey::from_hex(public_key)
        .map_err(|err| format!("{label} signer public key is invalid: {err}"))?;
    let verification = receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
    if !verification.valid {
        return Err(format!("{label} signature is invalid"));
    }
    let endpoint_decision_value = receipt
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .ok_or_else(|| format!("{label} is missing endpoint decision metadata"))?;
    let canonical_endpoint_decision =
        canonicalize_json(endpoint_decision_value).map_err(|err| {
            format!("{label} endpoint decision metadata is not canonicalizable: {err}")
        })?;
    let expected_content_hash = sha256(canonical_endpoint_decision.as_bytes());
    if receipt.receipt.content_hash != expected_content_hash {
        return Err(format!(
            "{label} endpoint decision metadata content hash does not match receipt content hash"
        ));
    }
    let endpoint_decision: EndpointDecisionReceipt =
        serde_json::from_value(endpoint_decision_value.clone())
            .map_err(|err| format!("{label} endpoint decision metadata is invalid: {err}"))?;
    endpoint_decision
        .validate()
        .map_err(|err| format!("{label} endpoint decision metadata is invalid: {err}"))?;
    let expected_receipt_id = endpoint_decision.receipt_id();
    if receipt.receipt.receipt_id.as_deref() != Some(expected_receipt_id.as_str()) {
        return Err(format!(
            "{label} endpoint decision metadata receipt id does not match receipt id"
        ));
    }
    Ok(())
}
