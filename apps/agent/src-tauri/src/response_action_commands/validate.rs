//! Signed-envelope parsing and policy rule-diff command validation.
//!
//! These functions take raw NATS bytes (or a deserialised transport
//! command) and either produce a `PolicyRuleDiffValidationCommand` or a
//! descriptive error explaining why the input must be rejected. Every
//! mismatch is treated as fail-closed.

use anyhow::{Context, Result};
use serde_json::Value;

use super::dto::{
    PolicyRuleDiffActionPayload, PolicyRuleDiffValidationCommand, ResponseActionTransportCommand,
    POLICY_RULE_DIFF_IMPACT_PATH, POLICY_RULE_DIFF_VALIDATION_ACTION,
};

pub(super) fn parse_signed_response_action_payload(
    payload: &[u8],
    trusted_issuer: Option<&str>,
) -> Result<ResponseActionTransportCommand> {
    let raw: Value = serde_json::from_slice(payload)?;
    let envelope = if raw.get("replayed").and_then(Value::as_bool) == Some(true) {
        raw.get("envelope")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("replayed response action missing envelope"))?
    } else {
        raw
    };

    if envelope.get("fact").is_none() {
        anyhow::bail!("response-action command payload must be a signed envelope");
    }

    if !spine::verify_envelope(&envelope)? {
        anyhow::bail!("response-action command signature verification failed");
    }

    let issuer = envelope
        .get("issuer")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("signed response-action command missing issuer"))?;
    let expected = trusted_issuer
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing trusted response-action command issuer"))?;
    if issuer != expected {
        anyhow::bail!("response-action command issuer mismatch: expected {expected}, got {issuer}");
    }

    let fact = envelope
        .get("fact")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("signed response-action command missing fact"))?;
    serde_json::from_value(fact).context("deserialize response-action command fact")
}

pub(super) fn policy_rule_diff_validation_command(
    command: &ResponseActionTransportCommand,
    tenant_id: &str,
    agent_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<PolicyRuleDiffValidationCommand> {
    if command.action_type != POLICY_RULE_DIFF_VALIDATION_ACTION {
        anyhow::bail!(
            "unsupported response-action command type '{}'",
            command.action_type
        );
    }
    uuid::Uuid::parse_str(command.action_id.trim())
        .with_context(|| "response-action command actionId must be a UUID")?;

    require_equal("tenantId", command.tenant_id.trim(), tenant_id)?;
    if !command.require_acknowledgement {
        anyhow::bail!("policy_rule_diff_validation commands must require acknowledgement");
    }
    let expires_at = command
        .expires_at
        .ok_or_else(|| anyhow::anyhow!("response-action command must include expiresAt"))?;
    if expires_at <= now {
        anyhow::bail!("response-action command is expired");
    }
    require_equal("target.kind", command.target.kind.trim(), "endpoint")?;
    require_equal("target.id", command.target.id.trim(), agent_id)?;
    require_equal(
        "delivery.targetKind",
        command.delivery.target_kind.trim(),
        "endpoint",
    )?;
    require_equal(
        "delivery.targetId",
        command.delivery.target_id.trim(),
        agent_id,
    )?;

    let ack_token = required_string("delivery.ackToken", command.delivery.ack_token.as_deref())?;
    let payload: PolicyRuleDiffActionPayload = serde_json::from_value(command.payload.clone())
        .context("deserialize policy rule-diff validation payload")?;
    require_equal(
        "payload.operation",
        payload.operation.trim(),
        POLICY_RULE_DIFF_VALIDATION_ACTION,
    )?;
    require_equal(
        "payload.endpointAgentId",
        payload.endpoint_agent_id.trim(),
        agent_id,
    )?;
    require_equal(
        "payload.request.method",
        payload.request.method.trim(),
        "POST",
    )?;
    require_equal(
        "payload.request.path",
        payload.request.path.trim(),
        POLICY_RULE_DIFF_IMPACT_PATH,
    )?;
    let expected_receipt = payload.expected_receipt.ok_or_else(|| {
        anyhow::anyhow!("payload.expectedReceipt must include proposed policy identity")
    })?;
    let expected_proposed_policy_hash = required_string(
        "payload.expectedReceipt.proposedPolicyHash",
        expected_receipt
            .get("proposedPolicyHash")
            .and_then(Value::as_str),
    )
    .and_then(|value| {
        normalize_policy_rule_diff_sha256("payload.expectedReceipt.proposedPolicyHash", &value)
    })?;
    let expected_proposed_policy_epoch = expected_receipt
        .get("proposedPolicyEpoch")
        .and_then(Value::as_u64)
        .filter(|epoch| *epoch > 0)
        .ok_or_else(|| {
            anyhow::anyhow!("payload.expectedReceipt.proposedPolicyEpoch must be positive")
        })?;

    Ok(PolicyRuleDiffValidationCommand {
        response_action_id: command.action_id.trim().to_string(),
        target_id: command.target.id.trim().to_string(),
        ack_token,
        proposal_id: required_string("payload.proposalId", Some(&payload.proposal_id))?,
        validation_plan_sha256: required_string(
            "payload.validationPlanSha256",
            Some(&payload.validation_plan_sha256),
        )?,
        endpoint_agent_id: payload.endpoint_agent_id.trim().to_string(),
        expected_receipt,
        expected_proposed_policy_hash,
        expected_proposed_policy_epoch,
        request_body: payload.request.body,
    })
}

pub(super) fn validate_policy_rule_diff_expected_receipt(
    command: &PolicyRuleDiffValidationCommand,
    impact: &Value,
    receipt: &Value,
) -> Result<()> {
    let proposed_policy_hash = impact
        .pointer("/proposedPolicy/policyHash")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("local validation impact missing proposedPolicy.policyHash")
        })?;
    let normalized_proposed_policy_hash = normalize_policy_rule_diff_sha256(
        "local impact proposedPolicy.policyHash",
        proposed_policy_hash,
    )?;
    if normalized_proposed_policy_hash != command.expected_proposed_policy_hash {
        anyhow::bail!(
            "local validation proposedPolicy.policyHash does not match dispatched expected receipt"
        );
    }

    let proposed_policy_epoch = impact
        .pointer("/proposedPolicy/policyEpoch")
        .and_then(Value::as_u64)
        .filter(|epoch| *epoch > 0)
        .ok_or_else(|| {
            anyhow::anyhow!("local validation impact missing positive proposedPolicy.policyEpoch")
        })?;
    if proposed_policy_epoch != command.expected_proposed_policy_epoch {
        anyhow::bail!(
            "local validation proposedPolicy.policyEpoch does not match dispatched expected receipt"
        );
    }

    require_policy_rule_diff_receipt_evidence_hash(
        receipt,
        "proposedPolicyHash",
        proposed_policy_hash,
    )?;
    require_policy_rule_diff_receipt_evidence_hash(
        receipt,
        "proposedPolicyEpoch",
        proposed_policy_epoch.to_string(),
    )?;
    Ok(())
}

fn require_policy_rule_diff_receipt_evidence_hash(
    receipt: &Value,
    key: &str,
    expected_value: impl AsRef<str>,
) -> Result<()> {
    let expected_hash = hush_core::sha256(expected_value.as_ref().as_bytes()).to_hex_prefixed();
    let evidence = receipt
        .pointer("/receipt/metadata/endpointDecision/evidence")
        .or_else(|| receipt.pointer("/metadata/endpointDecision/evidence"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!("local validation receipt missing endpointDecision evidence")
        })?;
    let actual_hash = evidence
        .iter()
        .find(|item| item.get("key").and_then(Value::as_str) == Some(key))
        .and_then(|item| item.get("valueHash").and_then(Value::as_str))
        .ok_or_else(|| anyhow::anyhow!("local validation receipt evidence missing {key}"))?;
    if actual_hash != expected_hash {
        anyhow::bail!("local validation receipt evidence {key} does not match impact");
    }
    Ok(())
}

pub(super) fn normalize_policy_rule_diff_sha256(field: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    let digest = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        anyhow::bail!("{field} must be a SHA-256 hex digest");
    }
    Ok(digest.to_ascii_lowercase())
}

pub(super) fn required_string(field: &str, value: Option<&str>) -> Result<String> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{field} must not be empty"))?;
    Ok(value.to_string())
}

pub(super) fn require_equal(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        return Ok(());
    }
    anyhow::bail!("{field} must be '{expected}', got '{actual}'")
}

pub(super) fn truncate_message(message: &str, max_len: usize) -> String {
    if message.len() <= max_len {
        return message.to_string();
    }
    let mut end = max_len;
    while !message.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}...", &message[..end])
}
