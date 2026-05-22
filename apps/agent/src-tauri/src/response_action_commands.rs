//! NATS response-action command handler.
//!
//! The Control API publishes canonical `response_action_v1` envelopes on
//! tenant-scoped response command subjects. This handler executes the endpoint
//! policy rule-diff validation action locally and posts the resulting raw
//! acknowledgement payload back to Control API for proposal collection.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::agent_auth;
use crate::api_server::{ControlAckPostbackRetryRequest, ControlAckPostbackRetrySink};
use crate::nats_client::NatsClient;
use crate::nats_subjects;
use crate::settings::Settings;

const POLICY_RULE_DIFF_VALIDATION_ACTION: &str = "policy_rule_diff_validation";
const POLICY_RULE_DIFF_IMPACT_PATH: &str = "/api/v1/agent/edr/policy-events/impact/history";
const LOCAL_API_RETRY_ATTEMPTS: usize = 3;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseCommandReply {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseActionTransportCommand {
    action_id: String,
    tenant_id: String,
    action_type: String,
    target: ResponseActionTransportTarget,
    #[serde(default)]
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    require_acknowledgement: bool,
    payload: Value,
    delivery: ResponseActionTransportDelivery,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseActionTransportTarget {
    kind: String,
    id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct ResponseActionTransportDelivery {
    target_kind: String,
    target_id: String,
    ack_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyRuleDiffActionPayload {
    operation: String,
    proposal_id: String,
    validation_plan_sha256: String,
    endpoint_agent_id: String,
    request: PolicyRuleDiffLocalRequest,
    #[serde(default)]
    expected_receipt: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PolicyRuleDiffLocalRequest {
    method: String,
    path: String,
    #[serde(default)]
    body: Value,
}

#[derive(Clone, Debug)]
struct PolicyRuleDiffValidationCommand {
    response_action_id: String,
    target_id: String,
    ack_token: String,
    proposal_id: String,
    validation_plan_sha256: String,
    endpoint_agent_id: String,
    expected_receipt: Value,
    expected_proposed_policy_hash: String,
    expected_proposed_policy_epoch: u64,
    request_body: Value,
}

#[derive(Clone)]
struct ControlAckPostbackConfig {
    base_url: String,
    url: String,
    api_key: Option<String>,
}

struct ControlAckContext<'a> {
    status: &'a str,
    observed_at: chrono::DateTime<chrono::Utc>,
    message: Option<&'a str>,
    resulting_state: Option<&'a str>,
    failure_message: &'a str,
}

/// Manages the response-action command subscription lifecycle.
pub struct ResponseActionCommandHandler {
    nats: Arc<NatsClient>,
    settings: Arc<RwLock<Settings>>,
    local_api_token: String,
    control_ack_retry_sink: Option<ControlAckPostbackRetrySink>,
    http_client: reqwest::Client,
}

impl ResponseActionCommandHandler {
    pub fn new(
        nats: Arc<NatsClient>,
        settings: Arc<RwLock<Settings>>,
        local_api_token: String,
        control_ack_retry_sink: Option<ControlAckPostbackRetrySink>,
    ) -> Self {
        Self {
            nats,
            settings,
            local_api_token,
            control_ack_retry_sink,
            http_client: reqwest::Client::new(),
        }
    }

    /// Build the canonical response-action command subject for this endpoint.
    pub fn command_subject(subject_prefix: &str, agent_id: &str) -> String {
        nats_subjects::response_command_subject(subject_prefix, "endpoint", agent_id)
    }

    /// Start listening for response-action commands. Runs until shutdown.
    pub async fn start(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        let subject = Self::command_subject(self.nats.subject_prefix(), self.nats.agent_id());
        tracing::info!(subject = %subject, "Starting response-action command subscriber");

        let mut subscriber = match self.nats.client().subscribe(subject.clone()).await {
            Ok(subscriber) => subscriber,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    subject = %subject,
                    "Failed to subscribe to response-action command subject"
                );
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Response-action command handler shutting down");
                    break;
                }
                msg = crate::nats_client::subscriber_next(&mut subscriber) => {
                    let Some(msg) = msg else {
                        tracing::warn!("Response-action command subscription ended unexpectedly");
                        break;
                    };

                    let reply = msg.reply.clone();
                    let trusted_issuer = {
                        let settings = self.settings.read().await;
                        settings.nats.approval_response_trusted_issuer.clone()
                    };

                    let response = match parse_signed_response_action_payload(
                        &msg.payload,
                        trusted_issuer.as_deref(),
                    ) {
                        Ok(command) => self.handle_command(command).await,
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "Failed to verify signed response-action command"
                            );
                            ResponseCommandReply {
                                status: "error".to_string(),
                                response_action_id: None,
                                message: Some(format!("Invalid signed response action: {err}")),
                            }
                        }
                    };

                    if let Some(reply_subject) = reply {
                        let response_json = serde_json::to_vec(&response)
                            .unwrap_or_else(|_| b"{}".to_vec());
                        if let Err(err) = self.nats.client()
                            .publish(reply_subject, response_json.into())
                            .await
                        {
                            tracing::warn!(
                                error = %err,
                                "Failed to send response-action command reply"
                            );
                        }
                    }
                }
            }
        }
    }

    async fn handle_command(
        &self,
        command: ResponseActionTransportCommand,
    ) -> ResponseCommandReply {
        let response_action_id = command.action_id.clone();
        let validation = match policy_rule_diff_validation_command(
            &command,
            self.nats.tenant_id(),
            self.nats.agent_id(),
            chrono::Utc::now(),
        ) {
            Ok(validation) => validation,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    response_action_id = %response_action_id,
                    "Rejected response-action command"
                );
                return ResponseCommandReply {
                    status: "error".to_string(),
                    response_action_id: Some(response_action_id),
                    message: Some(err.to_string()),
                };
            }
        };

        let local_api_token = current_local_api_token(&self.local_api_token);
        match execute_policy_rule_diff_validation(
            &self.http_client,
            self.settings.as_ref(),
            &local_api_token,
            &validation,
        )
        .await
        {
            Ok(raw_payload) => {
                let retry_raw_payload = raw_payload.clone();
                let observed_at = chrono::Utc::now();
                let ack_context = ControlAckContext {
                    status: "acknowledged",
                    observed_at,
                    message: Some("policy rule-diff validation completed"),
                    resulting_state: Some("policy_rule_diff_validation:succeeded"),
                    failure_message: "",
                };
                let postback = post_control_acknowledgement(
                    &self.http_client,
                    self.settings.as_ref(),
                    &validation,
                    &ack_context,
                    raw_payload,
                )
                .await;
                match postback {
                    Ok(()) => ResponseCommandReply {
                        status: "ok".to_string(),
                        response_action_id: Some(response_action_id),
                        message: Some("policy rule-diff validation acknowledged".to_string()),
                    },
                    Err(err) => {
                        let failure_message = err.to_string();
                        if let Err(queue_err) = enqueue_control_ack_retry(
                            self.control_ack_retry_sink.as_ref(),
                            self.settings.as_ref(),
                            &validation,
                            ControlAckContext {
                                failure_message: &failure_message,
                                ..ack_context
                            },
                            retry_raw_payload,
                        )
                        .await
                        {
                            tracing::warn!(
                                error = %queue_err,
                                response_action_id = %response_action_id,
                                "Failed to queue policy rule-diff acknowledgement postback retry"
                            );
                        }
                        tracing::warn!(
                            error = %err,
                            response_action_id = %response_action_id,
                            "Policy rule-diff validation completed but ack postback failed"
                        );
                        ResponseCommandReply {
                            status: "error".to_string(),
                            response_action_id: Some(response_action_id),
                            message: Some(format!(
                                "policy rule-diff validation completed but ack postback failed: {err}"
                            )),
                        }
                    }
                }
            }
            Err(err) => {
                let message = truncate_message(&err.to_string(), 512);
                let raw_payload = policy_rule_diff_failure_payload(&validation, &message);
                let retry_raw_payload = raw_payload.clone();
                let observed_at = chrono::Utc::now();
                let ack_context = ControlAckContext {
                    status: "failed",
                    observed_at,
                    message: Some(&message),
                    resulting_state: Some("policy_rule_diff_validation:failed"),
                    failure_message: "",
                };
                let postback = post_control_acknowledgement(
                    &self.http_client,
                    self.settings.as_ref(),
                    &validation,
                    &ack_context,
                    raw_payload,
                )
                .await;
                if let Err(postback_err) = postback {
                    let failure_message = postback_err.to_string();
                    if let Err(queue_err) = enqueue_control_ack_retry(
                        self.control_ack_retry_sink.as_ref(),
                        self.settings.as_ref(),
                        &validation,
                        ControlAckContext {
                            failure_message: &failure_message,
                            ..ack_context
                        },
                        retry_raw_payload,
                    )
                    .await
                    {
                        tracing::warn!(
                            error = %queue_err,
                            response_action_id = %response_action_id,
                            "Failed to queue failed policy rule-diff acknowledgement postback retry"
                        );
                    }
                    tracing::warn!(
                        error = %postback_err,
                        response_action_id = %response_action_id,
                        "Policy rule-diff validation failed and failed to post failure ack"
                    );
                }
                ResponseCommandReply {
                    status: "error".to_string(),
                    response_action_id: Some(response_action_id),
                    message: Some(format!("policy rule-diff validation failed: {message}")),
                }
            }
        }
    }
}

fn parse_signed_response_action_payload(
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

fn policy_rule_diff_validation_command(
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

async fn execute_policy_rule_diff_validation(
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

async fn post_control_acknowledgement(
    http_client: &reqwest::Client,
    settings: &RwLock<Settings>,
    command: &PolicyRuleDiffValidationCommand,
    context: &ControlAckContext<'_>,
    raw_payload: Value,
) -> Result<()> {
    let config = {
        let settings = settings.read().await;
        control_ack_postback_config(&settings, &command.response_action_id)?.ok_or_else(|| {
            anyhow::anyhow!("Control API acknowledgement postback is not configured")
        })?
    };
    let payload = control_ack_postback_payload(
        command,
        context.status,
        context.message,
        context.resulting_state,
        context.observed_at,
        raw_payload,
    );

    let mut request = http_client.post(&config.url).json(&payload);
    if let Some(api_key) = config.api_key.as_deref() {
        request = request.header("x-api-key", api_key);
    }
    let response = request
        .send()
        .await
        .context("send Control API acknowledgement postback")?;
    let status_code = response.status();
    let body = response
        .bytes()
        .await
        .context("read Control API acknowledgement postback response")?;
    if !status_code.is_success() {
        anyhow::bail!(
            "Control API acknowledgement postback failed with HTTP {}: {}",
            status_code.as_u16(),
            truncate_message(&String::from_utf8_lossy(&body), 512)
        );
    }
    Ok(())
}

async fn enqueue_control_ack_retry(
    sink: Option<&ControlAckPostbackRetrySink>,
    settings: &RwLock<Settings>,
    command: &PolicyRuleDiffValidationCommand,
    context: ControlAckContext<'_>,
    raw_payload: Value,
) -> Result<bool> {
    let Some(sink) = sink else {
        return Ok(false);
    };
    let config = {
        let settings = settings.read().await;
        control_ack_postback_config(&settings, &command.response_action_id)?.ok_or_else(|| {
            anyhow::anyhow!("Control API acknowledgement postback is not configured")
        })?
    };
    sink.enqueue(ControlAckPostbackRetryRequest {
        control_api_url: config.base_url,
        use_authenticated_route: config.api_key.is_some(),
        response_action_id: command.response_action_id.clone(),
        target_kind: "endpoint".to_string(),
        target_id: command.target_id.clone(),
        ack_token: command.ack_token.clone(),
        status: context.status.to_string(),
        observed_at: context.observed_at,
        message: context.message.map(ToString::to_string),
        resulting_state: context.resulting_state.map(ToString::to_string),
        raw_payload,
        failure_message: context.failure_message.to_string(),
    })
    .await?;
    Ok(true)
}

fn control_ack_postback_payload(
    command: &PolicyRuleDiffValidationCommand,
    status: &str,
    message: Option<&str>,
    resulting_state: Option<&str>,
    observed_at: chrono::DateTime<chrono::Utc>,
    raw_payload: Value,
) -> Value {
    json!({
        "targetKind": "endpoint",
        "targetId": command.target_id,
        "ackToken": command.ack_token,
        "status": status,
        "observedAt": observed_at,
        "message": message,
        "resultingState": resulting_state,
        "rawPayload": raw_payload,
    })
}

fn policy_rule_diff_success_payload(
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

fn policy_rule_diff_failure_payload(
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

fn validate_policy_rule_diff_expected_receipt(
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

fn normalize_policy_rule_diff_sha256(field: &str, value: &str) -> Result<String> {
    let trimmed = value.trim();
    let digest = trimmed.strip_prefix("0x").unwrap_or(trimmed);
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        anyhow::bail!("{field} must be a SHA-256 hex digest");
    }
    Ok(digest.to_ascii_lowercase())
}

fn control_ack_postback_config(
    settings: &Settings,
    response_action_id: &str,
) -> Result<Option<ControlAckPostbackConfig>> {
    if !settings.control_api.enabled {
        return Ok(None);
    }
    let Some(control_api_url) = settings
        .control_api
        .url
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };
    let api_key = settings
        .control_api
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    let path_segment = if api_key.is_some() {
        "acks"
    } else {
        "agent-acks"
    };
    Ok(Some(ControlAckPostbackConfig {
        base_url: control_api_url.to_string(),
        url: control_ack_postback_url(control_api_url, response_action_id, path_segment)?,
        api_key,
    }))
}

fn control_ack_postback_url(
    control_api_url: &str,
    response_action_id: &str,
    path_segment: &str,
) -> Result<String> {
    let trimmed = control_api_url.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        anyhow::bail!("Control API URL must not be empty");
    }
    let parsed = reqwest::Url::parse(trimmed).context("Control API URL is invalid")?;
    if parsed.host_str().is_none() {
        anyhow::bail!("Control API URL must include a host");
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        anyhow::bail!("Control API URL must not contain userinfo");
    }
    match parsed.scheme() {
        "https" => {}
        "http" if control_api_url_is_loopback(&parsed) => {}
        "http" => anyhow::bail!("Control API URL may use http only for loopback hosts"),
        other => anyhow::bail!("Control API URL must use http or https, got {other}"),
    }
    Ok(format!(
        "{trimmed}/api/v1/response-actions/{response_action_id}/{path_segment}"
    ))
}

fn control_api_url_is_loopback(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|addr| addr.is_loopback())
            .unwrap_or(false)
}

fn current_local_api_token(fallback: &str) -> String {
    match agent_auth::read_local_api_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::debug!(
                error = %err,
                "Falling back to startup local API token for response-action command"
            );
            fallback.to_string()
        }
    }
}

fn required_string(field: &str, value: Option<&str>) -> Result<String> {
    let value = value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{field} must not be empty"))?;
    Ok(value.to_string())
}

fn require_equal(field: &str, actual: &str, expected: &str) -> Result<()> {
    if actual == expected {
        return Ok(());
    }
    anyhow::bail!("{field} must be '{expected}', got '{actual}'")
}

fn truncate_message(message: &str, max_len: usize) -> String {
    if message.len() <= max_len {
        return message.to_string();
    }
    let mut end = max_len;
    while !message.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    format!("{}...", &message[..end])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::extract::{Path as AxumPath, State};
    use axum::http::header::AUTHORIZATION;
    use axum::http::HeaderMap;
    use axum::routing::post;
    use axum::{Json, Router};
    use hush_core::{sha256, Keypair};
    use spine::envelope::{build_signed_envelope, now_rfc3339};
    use std::time::Duration;
    use tokio::net::TcpListener;
    use tokio::sync::{broadcast, mpsc};

    const EXPECTED_PROPOSED_POLICY_HASH: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const EXPECTED_PROPOSED_POLICY_EPOCH: u64 = 2;

    #[derive(Debug)]
    struct LocalImpactRequest {
        authorization: Option<String>,
        body: Value,
    }

    #[derive(Debug)]
    struct ControlAckRequest {
        response_action_id: String,
        api_key: Option<String>,
        body: Value,
    }

    fn transport_command() -> ResponseActionTransportCommand {
        serde_json::from_value(json!({
            "actionId": "11111111-1111-4111-8111-111111111111",
            "tenantId": "33333333-3333-4333-8333-333333333333",
            "actionType": POLICY_RULE_DIFF_VALIDATION_ACTION,
            "expiresAt": "2999-01-01T00:00:00Z",
            "requireAcknowledgement": true,
            "target": {
                "kind": "endpoint",
                "id": "agent-1"
            },
            "payload": {
                "operation": POLICY_RULE_DIFF_VALIDATION_ACTION,
                "proposalId": "22222222-2222-4222-8222-222222222222",
                "validationPlanSha256": "sha256:plan",
                "endpointAgentId": "agent-1",
                "request": {
                    "method": "POST",
                    "path": POLICY_RULE_DIFF_IMPACT_PATH,
                    "body": {
                        "limit": 25,
                        "proposedPolicyYaml": "version: 1\n"
                    }
                },
                "expectedReceipt": {
                    "receiptFamily": "policy_event_impact",
                    "ruleId": "endpoint.policy_event.impact",
                    "graphProcessNodeId": "fleet-rule-diff",
                    "proposedPolicyHash": EXPECTED_PROPOSED_POLICY_HASH,
                    "proposedPolicyEpoch": EXPECTED_PROPOSED_POLICY_EPOCH,
                    "requiredEvidenceKeys": [
                        "impactId",
                        "proposedPolicyHash",
                        "proposedPolicyEpoch"
                    ]
                }
            },
            "delivery": {
                "targetKind": "endpoint",
                "targetId": "agent-1",
                "ackToken": "ack-token"
            }
        }))
        .unwrap()
    }

    fn live_env(name: &str) -> String {
        std::env::var(name)
            .unwrap_or_else(|_| panic!("set {name} to run the live NATS dogfood test"))
    }

    async fn spawn_mock_local_policy_impact() -> (
        u16,
        mpsc::Receiver<LocalImpactRequest>,
        tokio::task::JoinHandle<()>,
    ) {
        async fn handler(
            State(tx): State<mpsc::Sender<LocalImpactRequest>>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            let authorization = headers
                .get(AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
            let _ = tx
                .send(LocalImpactRequest {
                    authorization,
                    body,
                })
                .await;
            Json(local_policy_rule_diff_response())
        }

        let (tx, rx) = mpsc::channel(1);
        let app = Router::new()
            .route(POLICY_RULE_DIFF_IMPACT_PATH, post(handler))
            .with_state(tx);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (port, rx, task)
    }

    fn local_policy_rule_diff_response() -> Value {
        let proposed_policy_hash = format!("0x{EXPECTED_PROPOSED_POLICY_HASH}");
        let proposed_policy_epoch = EXPECTED_PROPOSED_POLICY_EPOCH;
        json!({
            "impact": {
                "impactId": "impact-loopback-1",
                "eventStreamHash": "sha256:event-stream",
                "currentResultHash": "sha256:current-result",
                "proposedResultHash": "sha256:proposed-result",
                "impactHash": "sha256:impact",
                "eventCount": 3,
                "changedCount": 1,
                "allowToBlockCount": 0,
                "trackPosture": true,
                "changedEventCount": 3,
                "proposedPolicy": {
                    "policyHash": proposed_policy_hash,
                    "policyEpoch": proposed_policy_epoch,
                }
            },
            "receipt": {
                "receipt_id": "receipt-loopback-1",
                "finding_id": "impact-loopback-1",
                "signature": "signed",
                "receipt": {
                    "metadata": {
                        "endpointDecision": {
                            "evidence": [
                                {
                                    "key": "proposedPolicyHash",
                                    "valueHash": sha256(proposed_policy_hash.as_bytes()).to_hex_prefixed(),
                                    "redactionClass": "hash_only"
                                },
                                {
                                    "key": "proposedPolicyEpoch",
                                    "valueHash": sha256(proposed_policy_epoch.to_string().as_bytes()).to_hex_prefixed(),
                                    "redactionClass": "hash_only"
                                }
                            ]
                        }
                    }
                }
            }
        })
    }

    async fn spawn_mock_control_api_agent_ack() -> (
        String,
        mpsc::Receiver<ControlAckRequest>,
        tokio::task::JoinHandle<()>,
    ) {
        async fn handler(
            AxumPath(response_action_id): AxumPath<String>,
            State(tx): State<mpsc::Sender<ControlAckRequest>>,
            headers: HeaderMap,
            Json(body): Json<Value>,
        ) -> Json<Value> {
            let api_key = headers
                .get("x-api-key")
                .and_then(|value| value.to_str().ok())
                .map(ToString::to_string);
            let _ = tx
                .send(ControlAckRequest {
                    response_action_id,
                    api_key,
                    body,
                })
                .await;
            Json(json!({"accepted": true}))
        }

        let (tx, rx) = mpsc::channel(1);
        let app = Router::new()
            .route("/api/v1/response-actions/{id}/agent-acks", post(handler))
            .with_state(tx);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (base_url, rx, task)
    }

    async fn recv_with_timeout<T>(rx: &mut mpsc::Receiver<T>) -> T {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap()
    }

    #[test]
    fn command_subject_format() {
        assert_eq!(
            ResponseActionCommandHandler::command_subject("tenant-acme.clawdstrike", "agent-1"),
            "tenant-acme.clawdstrike.response.command.endpoint.agent-1"
        );
    }

    #[test]
    fn signed_response_action_accepts_matching_issuer() {
        let kp = Keypair::generate();
        let fact = serde_json::to_value(transport_command()).unwrap();
        let envelope = build_signed_envelope(&kp, 1, None, fact, now_rfc3339()).unwrap();
        let issuer = envelope
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let parsed = parse_signed_response_action_payload(
            &serde_json::to_vec(&envelope).unwrap(),
            Some(&issuer),
        )
        .unwrap();
        assert_eq!(parsed.action_type, POLICY_RULE_DIFF_VALIDATION_ACTION);
        assert_eq!(parsed.target.id, "agent-1");
    }

    #[test]
    fn policy_rule_diff_validation_rejects_wrong_local_path() {
        let mut command = transport_command();
        command.payload["request"]["path"] = json!("/api/v1/agent/edr/findings");
        let err = policy_rule_diff_validation_command(
            &command,
            "33333333-3333-4333-8333-333333333333",
            "agent-1",
            chrono::Utc::now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("payload.request.path"));
    }

    #[test]
    fn policy_rule_diff_validation_rejects_wrong_tenant() {
        let command = transport_command();
        let err = policy_rule_diff_validation_command(
            &command,
            "44444444-4444-4444-8444-444444444444",
            "agent-1",
            chrono::Utc::now(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("tenantId"));
    }

    #[test]
    fn policy_rule_diff_validation_rejects_expired_command() {
        let mut command = transport_command();
        command.expires_at = Some(
            chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let now = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let err = policy_rule_diff_validation_command(
            &command,
            "33333333-3333-4333-8333-333333333333",
            "agent-1",
            now,
        )
        .unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn policy_rule_diff_validation_requires_expiry_to_prevent_unbounded_replay() {
        let mut command = transport_command();
        command.expires_at = None;

        let err = policy_rule_diff_validation_command(
            &command,
            "33333333-3333-4333-8333-333333333333",
            "agent-1",
            chrono::Utc::now(),
        )
        .unwrap_err();

        assert!(err.to_string().contains("expiresAt"));
    }

    #[test]
    fn policy_rule_diff_validation_extracts_ack_contract() {
        let command = policy_rule_diff_validation_command(
            &transport_command(),
            "33333333-3333-4333-8333-333333333333",
            "agent-1",
            chrono::Utc::now(),
        )
        .unwrap();
        assert_eq!(
            command.response_action_id,
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(command.target_id, "agent-1");
        assert_eq!(command.ack_token, "ack-token");
        assert_eq!(command.proposal_id, "22222222-2222-4222-8222-222222222222");
        assert_eq!(command.validation_plan_sha256, "sha256:plan");
        assert_eq!(
            command.expected_proposed_policy_hash,
            EXPECTED_PROPOSED_POLICY_HASH
        );
        assert_eq!(
            command.expected_proposed_policy_epoch,
            EXPECTED_PROPOSED_POLICY_EPOCH
        );
        assert_eq!(command.request_body["limit"], 25);
    }

    #[test]
    fn policy_rule_diff_validation_builds_control_ack_payload() {
        let settings = Settings {
            control_api: crate::settings::ControlApiSettings {
                enabled: true,
                url: Some("http://127.0.0.1:3000".to_string()),
                api_key: None,
            },
            ..Settings::default()
        };
        let command = policy_rule_diff_validation_command(
            &transport_command(),
            "33333333-3333-4333-8333-333333333333",
            "agent-1",
            chrono::Utc::now(),
        )
        .unwrap();
        let raw_payload =
            policy_rule_diff_success_payload(&command, &local_policy_rule_diff_response()).unwrap();
        let observed_at = chrono::DateTime::parse_from_rfc3339("2026-05-18T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let ack = control_ack_postback_payload(
            &command,
            "acknowledged",
            Some("policy rule-diff validation completed"),
            Some("policy_rule_diff_validation:succeeded"),
            observed_at,
            raw_payload,
        );

        assert_eq!(ack["targetKind"], "endpoint");
        assert_eq!(ack["targetId"], "agent-1");
        assert_eq!(ack["ackToken"], "ack-token");
        assert_eq!(ack["status"], "acknowledged");
        assert_eq!(
            ack["rawPayload"]["policyRuleDiffValidation"]["proposalId"],
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(
            ack["rawPayload"]["policyRuleDiffValidation"]["impact"]["impactId"],
            "impact-loopback-1"
        );
        assert_eq!(
            ack["rawPayload"]["policyRuleDiffValidation"]["expectedReceipt"]["proposedPolicyHash"],
            EXPECTED_PROPOSED_POLICY_HASH
        );
        let config = control_ack_postback_config(&settings, &command.response_action_id)
            .unwrap()
            .unwrap();
        assert_eq!(config.base_url, "http://127.0.0.1:3000");
        assert_eq!(
            config.url,
            "http://127.0.0.1:3000/api/v1/response-actions/11111111-1111-4111-8111-111111111111/agent-acks"
        );
        assert!(config.api_key.is_none());
    }

    #[test]
    fn policy_rule_diff_validation_failure_payload_binds_request_context() {
        let command = policy_rule_diff_validation_command(
            &transport_command(),
            "33333333-3333-4333-8333-333333333333",
            "agent-1",
            chrono::Utc::now(),
        )
        .unwrap();
        let raw_payload = policy_rule_diff_failure_payload(&command, "local validation failed");

        assert_eq!(
            raw_payload["policyRuleDiffValidationError"]["proposalId"],
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(
            raw_payload["policyRuleDiffValidationError"]["request"]["path"],
            POLICY_RULE_DIFF_IMPACT_PATH
        );
        assert_eq!(
            raw_payload["policyRuleDiffValidationError"]["request"]["body"]["limit"],
            25
        );
        assert!(raw_payload.get("signedReceipt").is_none());
    }

    #[test]
    fn policy_rule_diff_validation_rejects_mismatched_local_policy_identity() {
        let command = policy_rule_diff_validation_command(
            &transport_command(),
            "33333333-3333-4333-8333-333333333333",
            "agent-1",
            chrono::Utc::now(),
        )
        .unwrap();
        let mut response = local_policy_rule_diff_response();
        response["impact"]["proposedPolicy"]["policyHash"] =
            json!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

        let err = policy_rule_diff_success_payload(&command, &response)
            .unwrap_err()
            .to_string();

        assert!(err.contains("proposedPolicy.policyHash does not match"));
    }

    #[test]
    fn policy_rule_diff_validation_rejects_mismatched_receipt_policy_evidence() {
        let command = policy_rule_diff_validation_command(
            &transport_command(),
            "33333333-3333-4333-8333-333333333333",
            "agent-1",
            chrono::Utc::now(),
        )
        .unwrap();
        let mut response = local_policy_rule_diff_response();
        response["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"][0]
            ["valueHash"] = json!(sha256(b"wrong-policy").to_hex_prefixed());

        let err = policy_rule_diff_success_payload(&command, &response)
            .unwrap_err()
            .to_string();

        assert!(err.contains("receipt evidence proposedPolicyHash"));
    }

    #[tokio::test]
    async fn policy_rule_diff_validation_executes_local_api_and_posts_agent_ack() {
        let (agent_api_port, mut local_rx, local_task) = spawn_mock_local_policy_impact().await;
        let (control_api_url, mut control_rx, control_task) =
            spawn_mock_control_api_agent_ack().await;
        let settings = RwLock::new(Settings {
            agent_api_port,
            control_api: crate::settings::ControlApiSettings {
                enabled: true,
                url: Some(control_api_url),
                api_key: None,
            },
            ..Settings::default()
        });
        let command = policy_rule_diff_validation_command(
            &transport_command(),
            "33333333-3333-4333-8333-333333333333",
            "agent-1",
            chrono::Utc::now(),
        )
        .unwrap();
        let http_client = reqwest::Client::new();

        let raw_payload =
            execute_policy_rule_diff_validation(&http_client, &settings, "local-token", &command)
                .await
                .unwrap();
        let local_request = recv_with_timeout(&mut local_rx).await;
        assert_eq!(
            local_request.authorization.as_deref(),
            Some("Bearer local-token")
        );
        assert_eq!(local_request.body["limit"], 25);
        assert_eq!(
            raw_payload["policyRuleDiffValidation"]["impact"]["impactId"],
            "impact-loopback-1"
        );
        assert_eq!(
            raw_payload["policyRuleDiffValidation"]["receipt"]["receipt_id"],
            "receipt-loopback-1"
        );

        let observed_at = chrono::DateTime::parse_from_rfc3339("2026-05-18T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        post_control_acknowledgement(
            &http_client,
            &settings,
            &command,
            &ControlAckContext {
                status: "acknowledged",
                observed_at,
                message: Some("policy rule-diff validation completed"),
                resulting_state: Some("policy_rule_diff_validation:succeeded"),
                failure_message: "",
            },
            raw_payload,
        )
        .await
        .unwrap();

        let control_request = recv_with_timeout(&mut control_rx).await;
        assert_eq!(
            control_request.response_action_id,
            "11111111-1111-4111-8111-111111111111"
        );
        assert!(control_request.api_key.is_none());
        assert_eq!(control_request.body["ackToken"], "ack-token");
        assert_eq!(control_request.body["targetKind"], "endpoint");
        assert_eq!(control_request.body["targetId"], "agent-1");
        assert_eq!(control_request.body["status"], "acknowledged");
        assert_eq!(
            control_request.body["rawPayload"]["policyRuleDiffValidation"]["proposalId"],
            "22222222-2222-4222-8222-222222222222"
        );
        assert_eq!(
            control_request.body["rawPayload"]["policyRuleDiffValidation"]["impact"]["impactId"],
            "impact-loopback-1"
        );

        local_task.abort();
        control_task.abort();
    }

    #[tokio::test]
    #[ignore = "requires live NATS credentials; set CLAWDSTRIKE_LIVE_NATS_* env vars"]
    async fn live_nats_response_action_command_executes_and_acknowledges() {
        let nats_url = live_env("CLAWDSTRIKE_LIVE_NATS_URL");
        let tenant_id = live_env("CLAWDSTRIKE_LIVE_NATS_TENANT_ID");
        let agent_id = live_env("CLAWDSTRIKE_LIVE_NATS_AGENT_ID");
        let subject_prefix = live_env("CLAWDSTRIKE_LIVE_NATS_SUBJECT_PREFIX");
        let nats_settings = crate::settings::NatsSettings {
            enabled: true,
            nats_url: Some(nats_url),
            token: std::env::var("CLAWDSTRIKE_LIVE_NATS_TOKEN").ok(),
            creds_file: std::env::var("CLAWDSTRIKE_LIVE_NATS_CREDS_FILE").ok(),
            nkey_seed: std::env::var("CLAWDSTRIKE_LIVE_NATS_NKEY_SEED").ok(),
            tenant_id: Some(tenant_id.clone()),
            agent_id: Some(agent_id.clone()),
            subject_prefix: Some(subject_prefix),
            ..crate::settings::NatsSettings::default()
        };

        let (agent_api_port, mut local_rx, local_task) = spawn_mock_local_policy_impact().await;
        let (control_api_url, mut control_rx, control_task) =
            spawn_mock_control_api_agent_ack().await;
        let nats = Arc::new(NatsClient::connect(&nats_settings).await.unwrap());
        let mut command = transport_command();
        command.tenant_id = tenant_id;
        command.target.id = agent_id.clone();
        command.delivery.target_id = agent_id.clone();
        command.payload["endpointAgentId"] = json!(agent_id);

        let kp = Keypair::generate();
        let fact = serde_json::to_value(command).unwrap();
        let envelope = build_signed_envelope(&kp, 1, None, fact, now_rfc3339()).unwrap();
        let issuer = envelope
            .get("issuer")
            .and_then(Value::as_str)
            .unwrap()
            .to_string();
        let settings = Arc::new(RwLock::new(Settings {
            agent_api_port,
            control_api: crate::settings::ControlApiSettings {
                enabled: true,
                url: Some(control_api_url),
                api_key: None,
            },
            nats: crate::settings::NatsSettings {
                approval_response_trusted_issuer: Some(issuer),
                ..nats_settings
            },
            ..Settings::default()
        }));
        let handler = ResponseActionCommandHandler::new(
            nats.clone(),
            settings,
            "local-token".to_string(),
            None,
        );
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        let handler_task = tokio::spawn(async move {
            handler.start(shutdown_rx).await;
        });
        tokio::time::sleep(Duration::from_millis(250)).await;

        let subject =
            ResponseActionCommandHandler::command_subject(nats.subject_prefix(), nats.agent_id());
        let envelope_json = serde_json::to_vec(&envelope).unwrap();
        let mut reply = None;
        let mut last_error = None;
        for _ in 0..20 {
            match tokio::time::timeout(
                Duration::from_secs(2),
                nats.client()
                    .request(subject.clone(), envelope_json.clone().into()),
            )
            .await
            {
                Ok(Ok(message)) => {
                    reply = Some(message);
                    break;
                }
                Ok(Err(err)) => {
                    last_error = Some(err.to_string());
                }
                Err(_) => {
                    last_error = Some("timed out waiting for response-command reply".to_string());
                }
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
        let reply = reply.unwrap_or_else(|| {
            panic!(
                "live NATS response-action command request failed: {}",
                last_error.unwrap_or_else(|| "unknown error".to_string())
            )
        });
        let reply: Value = serde_json::from_slice(&reply.payload).unwrap();
        assert_eq!(reply["status"], "ok");
        assert_eq!(
            reply["responseActionId"],
            "11111111-1111-4111-8111-111111111111"
        );

        let local_request = recv_with_timeout(&mut local_rx).await;
        assert_eq!(local_request.body["limit"], 25);
        let control_request = recv_with_timeout(&mut control_rx).await;
        assert_eq!(
            control_request.response_action_id,
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(control_request.body["ackToken"], "ack-token");
        assert_eq!(control_request.body["status"], "acknowledged");
        assert_eq!(
            control_request.body["rawPayload"]["policyRuleDiffValidation"]["impact"]["impactId"],
            "impact-loopback-1"
        );

        let _ = shutdown_tx.send(());
        handler_task.abort();
        local_task.abort();
        control_task.abort();
    }
}
