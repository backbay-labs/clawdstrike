//! Policy rule-diff validation execution + payload shaping.
//!
//! Given a validated `PolicyRuleDiffValidationCommand`, these helpers call
//! the local Agent API impact-history endpoint, shape success/failure
//! payloads for control acknowledgement postback, and sign the failure
//! variant against the local receipt store via the postback retry sink.

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::{
    EndpointDecisionAction, EndpointResponseAcknowledgementReport,
    EndpointResponseControlCorrelation, EndpointResponseExecutionEffect,
    EndpointResponseExecutionStatus,
};
use serde_json::{json, Value};
use tokio::sync::RwLock;

use crate::api_server::{canonical_json_hash, ControlAckPostbackRetrySink};
use crate::settings::Settings;

use super::dto::{
    ControlAckContext, PolicyRuleDiffValidationCommand, LOCAL_API_RETRY_ATTEMPTS,
    POLICY_RULE_DIFF_IMPACT_PATH,
};
use super::validate::{truncate_message, validate_policy_rule_diff_expected_receipt};

pub(super) async fn execute_policy_rule_diff_validation(
    http_client: &reqwest::Client,
    settings: &RwLock<Settings>,
    local_api_token: &str,
    command: &PolicyRuleDiffValidationCommand,
) -> Result<Value> {
    let agent_api_port = {
        let settings = settings.read().await;
        settings.agent_api_port
    };
    let url = format!("http://127.0.0.1:{agent_api_port}{POLICY_RULE_DIFF_IMPACT_PATH}");
    let mut last_error = None;

    for attempt in 1..=LOCAL_API_RETRY_ATTEMPTS {
        let response = http_client
            .post(&url)
            .bearer_auth(local_api_token)
            .json(&command.request_body)
            .send()
            .await;

        match response {
            Ok(response) => {
                let status = response.status();
                let body = response
                    .bytes()
                    .await
                    .context("read local policy rule-diff validation response body")?;
                if !status.is_success() {
                    let body_text = String::from_utf8_lossy(&body);
                    anyhow::bail!(
                        "local policy rule-diff validation failed with HTTP {}: {}",
                        status.as_u16(),
                        truncate_message(&body_text, 512)
                    );
                }
                let body: Value = serde_json::from_slice(&body)
                    .context("decode local policy rule-diff validation response")?;
                return policy_rule_diff_success_payload(command, &body);
            }
            Err(err) => {
                last_error = Some(err.to_string());
                if attempt < LOCAL_API_RETRY_ATTEMPTS {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        150_u64.saturating_mul(attempt as u64),
                    ))
                    .await;
                }
            }
        }
    }

    anyhow::bail!(
        "local policy rule-diff validation request failed: {}",
        last_error.unwrap_or_else(|| "unknown error".to_string())
    )
}

pub(super) fn policy_rule_diff_success_payload(
    command: &PolicyRuleDiffValidationCommand,
    response: &Value,
) -> Result<Value> {
    let impact = response
        .get("impact")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("local validation response missing impact"))?;
    let receipt = response
        .get("receipt")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("local validation response missing receipt"))?;
    validate_policy_rule_diff_expected_receipt(command, &impact, &receipt)?;
    Ok(json!({
        "policyRuleDiffValidation": {
            "proposalId": command.proposal_id,
            "validationPlanSha256": command.validation_plan_sha256,
            "endpointAgentId": command.endpoint_agent_id,
            "expectedReceipt": command.expected_receipt.clone(),
            "request": {
                "method": "POST",
                "path": POLICY_RULE_DIFF_IMPACT_PATH,
                "body": command.request_body.clone(),
            },
            "impact": impact,
            "receipt": receipt,
        }
    }))
}

pub(super) fn policy_rule_diff_failure_payload(
    command: &PolicyRuleDiffValidationCommand,
    message: &str,
) -> Value {
    json!({
        "policyRuleDiffValidationError": {
            "proposalId": command.proposal_id,
            "validationPlanSha256": command.validation_plan_sha256,
            "endpointAgentId": command.endpoint_agent_id,
            "expectedReceipt": {
                "proposedPolicyHash": command.expected_proposed_policy_hash.as_str(),
                "proposedPolicyEpoch": command.expected_proposed_policy_epoch,
            },
            "request": {
                "method": "POST",
                "path": POLICY_RULE_DIFF_IMPACT_PATH,
                "body": command.request_body.clone(),
            },
            "message": message,
        }
    })
}

pub(super) async fn sign_policy_rule_diff_failure_payload(
    sink: Option<&ControlAckPostbackRetrySink>,
    command: &PolicyRuleDiffValidationCommand,
    context: &ControlAckContext<'_>,
    mut raw_payload: Value,
) -> Result<Value> {
    let sink = sink.ok_or_else(|| {
        anyhow::anyhow!(
            "control acknowledgement signing state is unavailable; refusing unsigned failure ack"
        )
    })?;
    let acknowledgement = policy_rule_diff_failure_acknowledgement(command, context, &raw_payload)?;
    let receipt = sink
        .sign_response_acknowledgement_receipt(&acknowledgement)
        .await
        .context("sign policy rule-diff failure acknowledgement receipt")?;
    let local_receipt_hash = canonical_json_hash(
        &receipt,
        "policy rule-diff failure acknowledgement signed receipt",
    )?;
    let signed_receipt = serde_json::to_value(&receipt)
        .context("serialize policy rule-diff failure acknowledgement signed receipt")?;
    let payload = raw_payload.as_object_mut().ok_or_else(|| {
        anyhow::anyhow!("policy rule-diff failure acknowledgement payload must be an object")
    })?;
    payload.insert(
        "localAcknowledgementId".to_string(),
        Value::String(acknowledgement.acknowledgement_id),
    );
    payload.insert(
        "localExecutionId".to_string(),
        Value::String(acknowledgement.execution_id),
    );
    payload.insert(
        "localActionId".to_string(),
        Value::String(acknowledgement.action_id),
    );
    payload.insert(
        "localGraphSliceId".to_string(),
        Value::String(acknowledgement.graph_slice_id),
    );
    payload.insert(
        "localReceiptHash".to_string(),
        Value::String(local_receipt_hash),
    );
    payload.insert("signedReceipt".to_string(), signed_receipt);
    payload.insert(
        "localEffectCount".to_string(),
        json!(acknowledgement.effects.len()),
    );
    Ok(raw_payload)
}

pub(super) fn policy_rule_diff_failure_acknowledgement(
    command: &PolicyRuleDiffValidationCommand,
    context: &ControlAckContext<'_>,
    raw_payload: &Value,
) -> Result<EndpointResponseAcknowledgementReport> {
    let message = context
        .message
        .unwrap_or("policy rule-diff validation failed");
    let request_hash = canonical_json_hash(
        &json!({
            "method": "POST",
            "path": POLICY_RULE_DIFF_IMPACT_PATH,
            "body": command.request_body.clone(),
        }),
        "policy rule-diff failure validation request",
    )?;
    let failure_payload_hash = canonical_json_hash(
        raw_payload,
        "policy rule-diff failure acknowledgement payload",
    )?;
    let failure_message_hash = hush_core::sha256(message.as_bytes()).to_hex_prefixed();
    let control = EndpointResponseControlCorrelation {
        response_action_id: command.response_action_id.clone(),
        delivery_id: None,
        target_kind: "endpoint".to_string(),
        target_id: command.target_id.clone(),
        ack_token_hash: hush_core::sha256(command.ack_token.as_bytes()).to_hex_prefixed(),
        ack_status: context.status.to_string(),
        resulting_state: context.resulting_state.map(ToString::to_string),
    };
    let effects = vec![
        EndpointResponseExecutionEffect {
            effect_id: "policy-rule-diff-validation-request".to_string(),
            effect_type: "policy_rule_diff_validation_request".to_string(),
            target: command.response_action_id.clone(),
            artifact: Some(POLICY_RULE_DIFF_IMPACT_PATH.to_string()),
            content_hash: Some(request_hash),
            byte_count: None,
        },
        EndpointResponseExecutionEffect {
            effect_id: "policy-rule-diff-validation-error".to_string(),
            effect_type: "policy_rule_diff_validation_error".to_string(),
            target: command.response_action_id.clone(),
            artifact: Some("policyRuleDiffValidationError".to_string()),
            content_hash: Some(failure_payload_hash),
            byte_count: Some(raw_payload.to_string().len() as u64),
        },
        EndpointResponseExecutionEffect {
            effect_id: "policy-rule-diff-validation-error-message".to_string(),
            effect_type: "policy_rule_diff_validation_error_message".to_string(),
            target: command.response_action_id.clone(),
            artifact: Some("policyRuleDiffValidationError.message".to_string()),
            content_hash: Some(failure_message_hash),
            byte_count: Some(message.len() as u64),
        },
    ];
    Ok(EndpointResponseAcknowledgementReport {
        acknowledgement_id: String::new(),
        execution_id: format!("policy-rule-diff-validation:{}", command.response_action_id),
        action_id: command.response_action_id.clone(),
        action: EndpointDecisionAction::Observe,
        status: EndpointResponseExecutionStatus::Failed,
        root_node_id: format!("response-action:{}", command.response_action_id),
        graph_slice_id: format!("policy-rule-diff-validation:{}", command.proposal_id),
        ttl_seconds: 0,
        rollback_ref: "policy-rule-diff-validation".to_string(),
        acknowledged_by: "response-action-command-handler".to_string(),
        note: Some(message.to_string()),
        acknowledged_at: context.observed_at,
        control_correlation: None,
        effects,
        summary: format!(
            "Policy rule-diff validation failed for response action {}.",
            command.response_action_id
        ),
    }
    .with_control_correlation(Some(control)))
}
