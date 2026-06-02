//! Fleet response-action routes and delivery ledger helpers.

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Duration, Utc};
use clawdstrike_policy_event::edr::{EndpointDecisionReceipt, EndpointDecisionReceiptFamily};
use hush_core::receipt::PublicKeySet;
use hush_core::{canonicalize_json, sha256, PublicKey, SignedReceipt};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::row::Row;
use sqlx::transaction::Transaction;
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::error::ApiError;
use crate::models::delegation_graph::RevokeGrantRequest;
use crate::services::delegation_graph as delegation_graph_service;
use crate::services::principal_resolution;
use crate::services::tenant_provisioner::tenant_subject_prefix;
use crate::state::AppState;

const ACK_DEADLINE_MINUTES: i64 = 10;
const ACTION_TYPE_MAX_BYTES: usize = 64;
const TARGET_KIND_MAX_BYTES: usize = 64;
const ACTION_TARGET_ID_MAX_BYTES: usize = 256;
const ACTION_REASON_MAX_BYTES: usize = 2048;
const ACTION_PAYLOAD_MAX_BYTES: usize = 65_536;
const ACK_STATUS_MAX_BYTES: usize = 64;
const ACK_TARGET_ID_MAX_BYTES: usize = 256;
const ACK_TOKEN_MAX_BYTES: usize = 1024;
const ACK_MESSAGE_MAX_BYTES: usize = 2048;
const ACK_RESULTING_STATE_MAX_BYTES: usize = 256;
const ACK_RAW_PAYLOAD_MAX_BYTES: usize = 65_536;
const ACK_SIGNED_RECEIPT_MAX_BYTES: usize = 256 * 1024;
const ACK_OBSERVED_AT_FUTURE_SKEW_SECONDS: i64 = 300;
const ACK_OBSERVED_AT_MAX_AGE_SECONDS: i64 = 3600;
const RESPONSE_TARGET_KIND_ALLOWLIST: &str =
    "endpoint, runtime, session, principal, grant, swarm, project";
const RESPONSE_ACTION_TYPE_ALLOWLIST: &str = "transition_posture, request_policy_reload, \
terminate_session, kill_switch, quarantine_principal, revoke_grant, revoke_principal, \
policy_rule_diff_validation";
const ACK_STATUS_ALLOWLIST: &str = "acknowledged, rejected, failed, expired, rolled_back";

mod access;
mod ack;
mod create;
mod delivery;
mod dto;
mod execute;
mod fetch;
mod handlers;
mod publish;

pub(crate) use access::*;
pub(crate) use ack::*;
pub(crate) use create::*;
pub(crate) use delivery::*;
pub(crate) use dto::*;
pub use dto::{CreateResponseActionRequest, ResponseTargetInput};
pub(crate) use execute::*;
pub(crate) use fetch::*;
pub use handlers::create_and_publish_internal_action;
pub(crate) use handlers::*;
pub(crate) use publish::*;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/response-actions", post(create_action).get(list_actions))
        .route("/response-actions/{id}", get(get_action))
        .route("/response-actions/{id}/approve", post(approve_action))
        .route("/response-actions/{id}/cancel", post(cancel_action))
        .route("/response-actions/{id}/retry", post(retry_action))
        .route("/response-actions/{id}/acks", post(record_ack))
}

pub fn public_ack_router() -> Router<AppState> {
    Router::new().route("/response-actions/{id}/agent-acks", post(record_agent_ack))
}

#[cfg(test)]
mod tests;
