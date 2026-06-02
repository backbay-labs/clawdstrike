use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use hush_core::receipt::PublicKeySet;
use hush_core::{canonicalize_json, sha256, PublicKey, SignedReceipt};
use serde::{Deserialize, Serialize};
use sqlx::row::Row;
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

use crate::auth::AuthenticatedTenant;
use crate::db::PgPool;
use crate::error::ApiError;
use crate::routes::response_actions::{self, CreateResponseActionRequest, ResponseTargetInput};
use crate::services::policy_distribution;
use crate::state::AppState;

const POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS: i64 = 168;
const POLICY_PROPOSAL_HISTORY_LIMIT: i64 = 1000;
const POLICY_PROPOSAL_FLEET_VALIDATION_ENDPOINT_LIMIT: usize = 25;
const POLICY_PROPOSAL_FLEET_VALIDATION_EVENT_ID_LIMIT: usize = 25;
const MAX_POLICY_PROPOSAL_SIMULATION_RECEIPT_BYTES: usize = 256 * 1024;
const MAX_POLICY_PROPOSAL_SIMULATION_RECEIPTS: usize = 64;
const POLICY_PROPOSAL_SIMULATION_RECEIPT_FAMILY: &str = "simulation";
const POLICY_PROPOSAL_SIMULATION_RULE_ID: &str = "endpoint.policy_event_impact";
const POLICY_PROPOSAL_SIMULATION_PROCESS_NODE_ID: &str = "policy_event_stream";

mod deploy;
mod dto;
mod fleet_rule_diff;
mod guard;
mod impact_validation;
mod preview_builder;
mod proposals;
mod yaml_diff;

pub(crate) use deploy::*;
pub(crate) use dto::*;
pub(crate) use fleet_rule_diff::*;
pub(crate) use guard::*;
pub(crate) use impact_validation::*;
pub(crate) use preview_builder::*;
pub(crate) use proposals::*;
pub(crate) use yaml_diff::*;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/policies/deploy", post(deploy_policy))
        .route("/policies/preview", post(preview_policy))
        .route(
            "/policies/proposals",
            get(list_policy_proposals).post(create_policy_proposal),
        )
        .route("/policies/proposals/{id}", get(get_policy_proposal))
        .route(
            "/policies/proposals/{id}/approve-deploy",
            post(approve_policy_proposal),
        )
        .route(
            "/policies/proposals/{id}/impact",
            post(attach_policy_proposal_impact),
        )
        .route(
            "/policies/proposals/{id}/fleet-rule-diff/dispatch",
            post(dispatch_policy_proposal_fleet_rule_diff_validation),
        )
        .route(
            "/policies/proposals/{id}/fleet-rule-diff/collect",
            post(collect_policy_proposal_fleet_rule_diff_validation),
        )
        .route(
            "/policies/proposals/{id}/reject",
            post(reject_policy_proposal),
        )
        .route("/policies/active", get(get_active_policy))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_subject_uses_tenant_prefix_contract() {
        assert_eq!(
            policy_distribution::policy_update_subject("acme"),
            "tenant-acme.clawdstrike.policy.update"
        );
    }

    #[test]
    fn policy_sync_bucket_matches_agent_contract() {
        assert_eq!(
            policy_distribution::policy_sync_bucket("tenant-acme.clawdstrike", "agent-123"),
            "tenant-acme-clawdstrike-policy-sync-agent-123"
        );
    }

    #[test]
    fn policy_sync_key_is_stable() {
        assert_eq!(policy_distribution::POLICY_SYNC_KEY, "policy.yaml");
    }
}
