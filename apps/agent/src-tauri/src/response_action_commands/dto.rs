//! Data transfer objects for response-action command transport.
//!
//! These types model the canonical `response_action_v1` envelope schema as
//! published by Control API onto the agent's tenant-scoped command subject,
//! along with the internal validated command shape that downstream handler
//! steps operate against.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Wire identifier for the policy rule-diff validation action.
pub(super) const POLICY_RULE_DIFF_VALIDATION_ACTION: &str = "policy_rule_diff_validation";

/// Local API path that hosts the policy rule-diff impact-history endpoint.
pub(super) const POLICY_RULE_DIFF_IMPACT_PATH: &str =
    "/api/v1/agent/edr/policy-events/impact/history";

/// Number of times to retry transient HTTP failures against the local API.
pub(super) const LOCAL_API_RETRY_ATTEMPTS: usize = 3;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResponseCommandReply {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_action_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResponseActionTransportCommand {
    pub action_id: String,
    pub tenant_id: String,
    pub action_type: String,
    pub target: ResponseActionTransportTarget,
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub require_acknowledgement: bool,
    pub payload: Value,
    pub delivery: ResponseActionTransportDelivery,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResponseActionTransportTarget {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ResponseActionTransportDelivery {
    pub target_kind: String,
    pub target_id: String,
    pub ack_token: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PolicyRuleDiffActionPayload {
    pub operation: String,
    pub proposal_id: String,
    pub validation_plan_sha256: String,
    pub endpoint_agent_id: String,
    pub request: PolicyRuleDiffLocalRequest,
    #[serde(default)]
    pub expected_receipt: Option<Value>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PolicyRuleDiffLocalRequest {
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub body: Value,
}

#[derive(Clone, Debug)]
pub(super) struct PolicyRuleDiffValidationCommand {
    pub response_action_id: String,
    pub target_id: String,
    pub ack_token: String,
    pub proposal_id: String,
    pub validation_plan_sha256: String,
    pub endpoint_agent_id: String,
    pub expected_receipt: Value,
    pub expected_proposed_policy_hash: String,
    pub expected_proposed_policy_epoch: u64,
    pub request_body: Value,
}

#[derive(Clone)]
pub(super) struct ControlAckPostbackConfig {
    pub base_url: String,
    pub url: String,
    pub api_key: Option<String>,
}

pub(super) struct ControlAckContext<'a> {
    pub status: &'a str,
    pub observed_at: chrono::DateTime<chrono::Utc>,
    pub message: Option<&'a str>,
    pub resulting_state: Option<&'a str>,
    pub failure_message: &'a str,
}
