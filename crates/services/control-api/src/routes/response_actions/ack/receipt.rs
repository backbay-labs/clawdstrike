//! Signed-receipt verification and the endpoint acknowledgement receipt contract.

use crate::routes::response_actions::*;
pub(crate) async fn validate_endpoint_ack_signed_receipt(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    context: &AckContext,
    ack: &AckSubmission,
) -> Result<(), ApiError> {
    if context.action.action_type == ResponseActionType::PolicyRuleDiffValidation.as_str() {
        if ack.ack_status == "acknowledged" {
            return validate_policy_rule_diff_ack_receipt(tx, context, ack).await;
        }
        validate_policy_rule_diff_error_payload_matches_action(
            ack,
            &context.action.payload,
            &ack.target_id,
        )?;
        return validate_response_ack_signed_receipt(tx, context, ack).await;
    }

    if !requires_endpoint_ack_signed_receipt(&context.action, ack) {
        return Ok(());
    }

    validate_response_ack_signed_receipt(tx, context, ack).await
}

async fn validate_response_ack_signed_receipt(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    context: &AckContext,
    ack: &AckSubmission,
) -> Result<(), ApiError> {
    let public_key =
        load_endpoint_ack_public_key(tx, context.action.tenant_id, &ack.target_id).await?;

    let signed_receipt_value = ack
        .raw_payload
        .get("signedReceipt")
        .or_else(|| ack.raw_payload.get("signed_receipt"))
        .cloned()
        .ok_or_else(|| {
            ApiError::BadRequest(
                "endpoint acknowledgement raw_payload must include signedReceipt".to_string(),
            )
        })?;
    let verified = verify_endpoint_decision_signed_receipt_value(
        signed_receipt_value,
        &public_key,
        "endpoint acknowledgement signedReceipt",
    )?;

    if let Some(local_receipt_hash) = ack
        .raw_payload
        .get("localReceiptHash")
        .and_then(Value::as_str)
    {
        if local_receipt_hash != verified.signed_receipt_hash {
            return Err(ApiError::BadRequest(
                "endpoint acknowledgement localReceiptHash must match signedReceipt".to_string(),
            ));
        }
    }

    validate_endpoint_ack_receipt_contract(&verified, context, ack)
}

pub(crate) async fn load_endpoint_ack_public_key(
    tx: &mut Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    agent_id: &str,
) -> Result<PublicKey, ApiError> {
    let public_key_hex = sqlx::query_scalar::query_scalar::<_, String>(
        r#"SELECT public_key
           FROM agents
           WHERE tenant_id = $1
             AND agent_id = $2"#,
    )
    .bind(tenant_id)
    .bind(agent_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or_else(|| {
        ApiError::BadRequest(
            "endpoint acknowledgement target does not match a registered agent".to_string(),
        )
    })?;
    let public_key = PublicKey::from_hex(public_key_hex.trim()).map_err(|_| {
        ApiError::BadRequest("endpoint acknowledgement agent public_key is invalid".to_string())
    })?;
    Ok(public_key)
}

pub(crate) fn verify_endpoint_decision_signed_receipt_value(
    signed_receipt_value: Value,
    public_key: &PublicKey,
    label: &str,
) -> Result<VerifiedEndpointDecisionReceipt, ApiError> {
    let canonical_signed_receipt = canonicalize_json(&signed_receipt_value).map_err(|err| {
        ApiError::BadRequest(format!("{label} is not canonicalizable JSON: {err}"))
    })?;
    if canonical_signed_receipt.len() > ACK_SIGNED_RECEIPT_MAX_BYTES {
        return Err(ApiError::BadRequest(format!(
            "{label} must be no larger than {ACK_SIGNED_RECEIPT_MAX_BYTES} bytes"
        )));
    }
    let signed_receipt: SignedReceipt = serde_json::from_value(signed_receipt_value.clone())
        .map_err(|err| ApiError::BadRequest(format!("{label} is invalid: {err}")))?;
    let verification = signed_receipt.verify(&PublicKeySet::new(public_key.clone()));
    if !verification.valid {
        let reason = if verification.errors.is_empty() {
            "unknown verification error".to_string()
        } else {
            verification.errors.join("; ")
        };
        return Err(ApiError::BadRequest(format!(
            "{label} failed verification: {reason}"
        )));
    }

    let endpoint_decision_value = signed_receipt
        .receipt
        .metadata
        .as_ref()
        .and_then(|metadata| metadata.get("endpointDecision"))
        .cloned()
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "{label} must include receipt.metadata.endpointDecision"
            ))
        })?;
    let endpoint_decision: EndpointDecisionReceipt =
        serde_json::from_value(endpoint_decision_value.clone()).map_err(|err| {
            ApiError::BadRequest(format!("{label} endpointDecision is invalid: {err}"))
        })?;
    endpoint_decision.validate().map_err(|err| {
        ApiError::BadRequest(format!("{label} endpointDecision failed validation: {err}"))
    })?;

    let canonical_endpoint_decision =
        canonicalize_json(&endpoint_decision_value).map_err(|err| {
            ApiError::BadRequest(format!(
                "{label} endpointDecision is not canonicalizable JSON: {err}"
            ))
        })?;
    let endpoint_decision_hash = sha256(canonical_endpoint_decision.as_bytes());
    if signed_receipt.receipt.content_hash != endpoint_decision_hash {
        return Err(ApiError::BadRequest(format!(
            "{label} content_hash must match receipt.metadata.endpointDecision"
        )));
    }

    let signer_public_key = endpoint_decision
        .signer
        .signer_public_key
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "{label} endpointDecision.signer.signerPublicKey is required"
            ))
        })?;
    let metadata_public_key = PublicKey::from_hex(signer_public_key).map_err(|_| {
        ApiError::BadRequest(format!(
            "{label} endpointDecision.signer.signerPublicKey must be a valid Ed25519 public key hex"
        ))
    })?;
    if metadata_public_key.to_hex() != public_key.to_hex() {
        return Err(ApiError::BadRequest(format!(
            "{label} endpointDecision.signer.signerPublicKey must match registered agent public_key"
        )));
    }

    Ok(VerifiedEndpointDecisionReceipt {
        signed_receipt_hash: sha256(canonical_signed_receipt.as_bytes()).to_hex_prefixed(),
        endpoint_decision,
        endpoint_decision_value,
    })
}

fn validate_endpoint_ack_receipt_contract(
    verified: &VerifiedEndpointDecisionReceipt,
    context: &AckContext,
    ack: &AckSubmission,
) -> Result<(), ApiError> {
    let endpoint_decision = &verified.endpoint_decision;
    if endpoint_decision.receipt_family != EndpointDecisionReceiptFamily::ResponseAcknowledgement {
        return Err(ApiError::BadRequest(
            "endpoint acknowledgement signedReceipt must be a response_acknowledgement receipt"
                .to_string(),
        ));
    }
    if endpoint_decision.actor.endpoint_id != ack.target_id {
        return Err(ApiError::BadRequest(
            "endpoint acknowledgement signedReceipt endpoint id must match target_id".to_string(),
        ));
    }

    let endpoint_decision_value = &verified.endpoint_decision_value;
    require_endpoint_ack_receipt_evidence_hash(
        endpoint_decision_value,
        "controlResponseActionId",
        &context.action.id.to_string(),
    )?;
    require_endpoint_ack_receipt_evidence_hash(
        endpoint_decision_value,
        "controlTargetId",
        &ack.target_id,
    )?;
    require_endpoint_ack_receipt_evidence_hash(
        endpoint_decision_value,
        "controlAckStatus",
        ack.ack_status,
    )?;
    if let Some(resulting_state) = ack.resulting_state.as_deref() {
        require_endpoint_ack_receipt_evidence_hash(
            endpoint_decision_value,
            "controlResultingState",
            resulting_state,
        )?;
    }
    let acknowledged_status = ack
        .resulting_state
        .as_deref()
        .map(endpoint_acknowledged_status_from_resulting_state)
        .unwrap_or(ack.ack_status);
    require_endpoint_ack_receipt_evidence_hash(
        endpoint_decision_value,
        "acknowledgedStatus",
        acknowledged_status,
    )?;
    require_endpoint_ack_receipt_evidence_hash(
        endpoint_decision_value,
        "controlAckTokenHash",
        &sha256(ack.ack_token.as_bytes()).to_hex_prefixed(),
    )?;
    if let Some(local_execution_id) = ack
        .raw_payload
        .get("localExecutionId")
        .and_then(Value::as_str)
    {
        require_endpoint_ack_receipt_evidence_hash(
            endpoint_decision_value,
            "executionId",
            local_execution_id,
        )?;
    }
    Ok(())
}

fn endpoint_acknowledged_status_from_resulting_state(resulting_state: &str) -> &str {
    resulting_state
        .rsplit_once(':')
        .map(|(_, status)| status)
        .unwrap_or(resulting_state)
}

fn require_endpoint_ack_receipt_evidence_hash(
    endpoint_decision: &Value,
    key: &str,
    raw_value: &str,
) -> Result<(), ApiError> {
    let expected_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
    let evidence_hash = endpoint_decision
        .get("evidence")
        .and_then(Value::as_array)
        .and_then(|items| {
            items.iter().find_map(|item| {
                if item.get("key").and_then(Value::as_str) == Some(key) {
                    item.get("valueHash").and_then(Value::as_str)
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| {
            ApiError::BadRequest(format!(
                "endpoint acknowledgement signedReceipt evidence is missing {key}"
            ))
        })?;
    if evidence_hash != expected_hash {
        return Err(ApiError::BadRequest(format!(
            "endpoint acknowledgement signedReceipt evidence {key} does not match acknowledgement"
        )));
    }
    Ok(())
}
