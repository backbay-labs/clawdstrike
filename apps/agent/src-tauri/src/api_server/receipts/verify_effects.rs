//! Effect-set verification helpers for response receipts, plus the small
//! conflict / required-evidence error builders shared by other `verify_*`
//! modules.

use super::super::*;

pub(crate) fn response_effect_proof_contract_value(
    effect: &EndpointResponseExecutionEffect,
) -> Result<String, (StatusCode, String)> {
    let value = serde_json::to_value(effect)
        .map_err(|err| internal_error(anyhow::anyhow!("serialize response effect: {err}")))?;
    canonicalize_json(&value)
        .map_err(|err| internal_error(anyhow::anyhow!("canonicalize response effect: {err}")))
}

pub(crate) fn verify_response_effects_proof_contract(
    receipt: &SignedReceipt,
    label: &str,
    prefix: &str,
    effects: &[EndpointResponseExecutionEffect],
) -> Result<(), (StatusCode, String)> {
    require_proof_receipt_evidence_hash(
        receipt,
        label,
        "effectCount",
        effects.len().to_string().as_str(),
    )?;
    for effect in effects {
        let effect_value = response_effect_proof_contract_value(effect)?;
        require_proof_receipt_evidence_hash(
            receipt,
            label,
            format!("{prefix}:{}", effect.effect_id).as_str(),
            effect_value.as_str(),
        )?;
        require_proof_receipt_evidence_hash(
            receipt,
            label,
            format!("{prefix}Type:{}", effect.effect_id).as_str(),
            effect.effect_type.as_str(),
        )?;
    }
    Ok(())
}

pub(crate) fn response_proof_contract_conflict(message: impl Into<String>) -> (StatusCode, String) {
    (StatusCode::CONFLICT, message.into())
}

pub(crate) fn require_proof_receipt_decision_str(
    receipt: &SignedReceipt,
    label: &str,
    path: &[&str],
    expected: &str,
) -> Result<(), (StatusCode, String)> {
    if receipt_endpoint_decision_str(receipt, path) == Some(expected) {
        return Ok(());
    }
    Err((
        StatusCode::CONFLICT,
        format!("{label} does not match response execution proof contract"),
    ))
}

pub(crate) fn require_proof_receipt_evidence_hash(
    receipt: &SignedReceipt,
    label: &str,
    key: &str,
    raw_value: &str,
) -> Result<(), (StatusCode, String)> {
    if receipt_evidence_hash_matches(receipt, key, raw_value) {
        return Ok(());
    }
    Err((
        StatusCode::CONFLICT,
        format!("{label} {key} does not match response execution proof contract"),
    ))
}
