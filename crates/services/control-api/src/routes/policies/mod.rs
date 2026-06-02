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

// Narrow named re-exports so sibling modules can share these items via the
// `crate::routes::policies` scope without glob re-exports. Visibility is kept
// module-private (`pub(in crate::routes::policies)`); the only externally
// consumed item is `router()`.
pub(in crate::routes::policies) use deploy::{
    distribute_prepared_policy_to_fleet, prepare_active_policy_deployment,
};
pub(in crate::routes::policies) use dto::{
    ApprovePolicyProposalResponse, AttachPolicyProposalImpactRequest,
    CollectPolicyProposalFleetRuleDiffRequest, CollectPolicyProposalFleetRuleDiffResponse,
    CreatePolicyProposalRequest, CreatePolicyProposalResponse, DeployPolicyRequest,
    DeployPolicyResponse, DispatchPolicyProposalFleetRuleDiffRequest,
    DispatchPolicyProposalFleetRuleDiffResponse, PolicyProposalResponse,
    PolicyProposalSimulationReceiptAttachment, PreviewEffectivePolicyResponse,
    PreviewPolicyRequest, PreviewPolicyResponse, ReviewPolicyProposalRequest,
};
pub(in crate::routes::policies) use fleet_rule_diff::{
    latest_policy_rule_diff_receipts_by_endpoint, CollectedPolicyRuleDiffReceipt,
};
pub(in crate::routes::policies) use guard::{
    append_policy_proposal_approval_note, ensure_policy_author, ensure_policy_deployer,
    normalize_policy_impact_sha256, policy_preview_error, require_direct_policy_deploy_break_glass,
    require_non_empty_policy_impact_field, validate_non_negative_policy_impact_count,
};
pub(in crate::routes::policies) use impact_validation::{
    ensure_policy_proposal_deployable_impact, validate_policy_proposal_impact,
    validate_policy_proposal_simulation_receipt_value, VerifiedPolicyProposalSimulationReceipt,
};
pub(in crate::routes::policies) use preview_builder::{
    active_policy_candidate_from_base, build_policy_proposal_preview,
};
pub(in crate::routes::policies) use proposals::{
    fetch_policy_proposal_row, fetch_policy_proposal_row_for_update, policy_proposal_from_row,
    proposal_response_from_row, PolicyProposalRow,
};
pub(in crate::routes::policies) use yaml_diff::top_level_policy_change_summary;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/policies/deploy", post(deploy::deploy_policy))
        .route("/policies/preview", post(deploy::preview_policy))
        .route(
            "/policies/proposals",
            get(proposals::list_policy_proposals).post(proposals::create_policy_proposal),
        )
        .route(
            "/policies/proposals/{id}",
            get(proposals::get_policy_proposal),
        )
        .route(
            "/policies/proposals/{id}/approve-deploy",
            post(proposals::approve_policy_proposal),
        )
        .route(
            "/policies/proposals/{id}/impact",
            post(impact_validation::attach_policy_proposal_impact),
        )
        .route(
            "/policies/proposals/{id}/fleet-rule-diff/dispatch",
            post(fleet_rule_diff::dispatch_policy_proposal_fleet_rule_diff_validation),
        )
        .route(
            "/policies/proposals/{id}/fleet-rule-diff/collect",
            post(fleet_rule_diff::collect_policy_proposal_fleet_rule_diff_validation),
        )
        .route(
            "/policies/proposals/{id}/reject",
            post(proposals::reject_policy_proposal),
        )
        .route("/policies/active", get(deploy::get_active_policy))
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
