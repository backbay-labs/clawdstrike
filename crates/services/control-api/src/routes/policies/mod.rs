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

    fn direct_deploy_request(break_glass: bool, reason: Option<&str>) -> DeployPolicyRequest {
        DeployPolicyRequest {
            policy_yaml: "version: \"1.0.0\"\nrules: []\n".to_string(),
            description: None,
            break_glass,
            break_glass_reason: reason.map(str::to_string),
        }
    }

    #[test]
    fn direct_policy_deploy_requires_break_glass_flag() {
        let req = direct_deploy_request(false, Some("emergency recovery"));

        match require_direct_policy_deploy_break_glass(&req) {
            Err(ApiError::Conflict(message)) => {
                assert!(message.contains("proposal simulation receipts"));
            }
            Ok(_) => panic!("direct deploy without break_glass unexpectedly succeeded"),
            Err(err) => panic!("unexpected direct deploy error: {err}"),
        }
    }

    #[test]
    fn direct_policy_deploy_requires_break_glass_reason() {
        let req = direct_deploy_request(true, Some("   "));

        match require_direct_policy_deploy_break_glass(&req) {
            Err(ApiError::BadRequest(message)) => {
                assert!(message.contains("break_glass_reason"));
            }
            Ok(_) => panic!("direct deploy without reason unexpectedly succeeded"),
            Err(err) => panic!("unexpected direct deploy error: {err}"),
        }
    }

    #[test]
    fn direct_policy_deploy_accepts_explicit_break_glass_reason() {
        let req = direct_deploy_request(true, Some("  emergency recovery  "));

        match require_direct_policy_deploy_break_glass(&req) {
            Ok(reason) => assert_eq!(reason, "emergency recovery"),
            Err(err) => panic!("direct deploy break-glass rejected valid reason: {err}"),
        }
    }

    fn proposal_row_with_impact(impact: serde_json::Value) -> PolicyProposalRow {
        let now = Utc::now();
        PolicyProposalRow {
            id: Uuid::from_u128(1),
            tenant_id: Uuid::from_u128(2),
            policy_yaml: "policy:\n  mode: test\n".to_string(),
            checksum_sha256: "0".repeat(64),
            description: None,
            status: "pending".to_string(),
            base_active_policy_version: 1,
            proposed_policy_version: 2,
            preview: serde_json::json!({}),
            required_approvals: 1,
            approved_by: Vec::new(),
            approval_notes: serde_json::json!([]),
            impact: Some(impact),
            impact_attached_by: Some("test".to_string()),
            impact_attached_at: Some(now),
            deployed_policy_version: None,
            deployment_id: None,
            submitted_by: "test".to_string(),
            reviewed_by: None,
            review_note: None,
            created_at: now,
            updated_at: now,
            reviewed_at: None,
            deployed_at: None,
        }
    }

    #[test]
    fn deployable_impact_rejects_revise_recommendation() {
        let proposal = proposal_row_with_impact(serde_json::json!({
            "simulationReceiptsVerifiedCount": 1,
            "blockingChangeCount": 0,
            "recommendation": "revise"
        }));

        assert!(matches!(
            ensure_policy_proposal_deployable_impact(&proposal),
            Err(ApiError::Conflict(_))
        ));
    }

    #[test]
    fn deployable_impact_rejects_verified_blocking_changes() {
        let proposal = proposal_row_with_impact(serde_json::json!({
            "simulationReceiptsVerifiedCount": 1,
            "blockingChangeCount": 1,
            "recommendation": "observe_only"
        }));

        assert!(matches!(
            ensure_policy_proposal_deployable_impact(&proposal),
            Err(ApiError::Conflict(_))
        ));
    }

    fn receipt_bound_impact(
        proposed_policy_hash: &str,
        proposed_policy_epoch: i64,
    ) -> serde_json::Value {
        serde_json::json!({
            "simulationReceiptsVerifiedCount": 1,
            "blockingChangeCount": 0,
            "recommendation": "observe_only",
            "simulationReceipts": [
                {
                    "evidenceValueHashes": {
                        "proposedPolicyHash": sha256(proposed_policy_hash.as_bytes()).to_hex_prefixed(),
                        "proposedPolicyEpoch": sha256(proposed_policy_epoch.to_string().as_bytes()).to_hex_prefixed()
                    }
                }
            ]
        })
    }

    #[test]
    fn proposal_impact_receipts_must_match_proposal_policy_identity() {
        let proposal = proposal_row_with_impact(receipt_bound_impact(&"0".repeat(64), 2));
        let impact = receipt_bound_impact(&"1".repeat(64), 2);

        assert!(matches!(
            validate_policy_proposal_impact_matches_proposal(&proposal, &impact),
            Err(ApiError::BadRequest(_))
        ));
    }

    #[test]
    fn proposal_impact_receipts_accept_matching_policy_identity() {
        let proposal = proposal_row_with_impact(receipt_bound_impact(&"0".repeat(64), 2));
        let impact = receipt_bound_impact(&"0".repeat(64), 2);

        validate_policy_proposal_impact_matches_proposal(&proposal, &impact)
            .expect("matching proposal receipt binding");
    }

    #[test]
    fn fleet_rule_diff_dispatch_reservation_marks_intent_before_publish() {
        let preview = serde_json::json!({
            "fleetRuleDiffValidation": {
                "status": "ready_for_endpoint_receipt_collection",
                "planSha256": "abc123"
            }
        });
        let reserved = reserve_policy_rule_diff_dispatch(
            preview,
            Some("abc123"),
            &[
                serde_json::json!({ "endpointAgentId": "endpoint-a" }),
                serde_json::json!({ "endpointAgentId": "endpoint-b" }),
            ],
        )
        .expect("dispatch reservation");

        assert_eq!(reserved["fleetRuleDiffValidation"]["status"], "dispatching");
        assert_eq!(
            reserved["fleetRuleDiffValidation"]["dispatchReservation"]["validationPlanSha256"],
            "abc123"
        );
        assert_eq!(
            reserved["fleetRuleDiffValidation"]["dispatchReservation"]["requestedEndpointCount"],
            2
        );
        assert_eq!(
            reserved["fleetRuleDiffValidation"]["dispatchReservation"]["requestedEndpointIds"],
            serde_json::json!(["endpoint-a", "endpoint-b"])
        );
    }

    #[test]
    fn fleet_rule_diff_default_collection_keeps_latest_dispatch_per_endpoint() {
        let old_endpoint_a = Uuid::from_u128(1);
        let endpoint_b = Uuid::from_u128(2);
        let latest_endpoint_a = Uuid::from_u128(3);
        let preview = serde_json::json!({
            "fleetRuleDiffValidation": {
                "dispatches": [
                    {
                        "endpointAgentId": "endpoint-a",
                        "responseActionId": old_endpoint_a
                    },
                    {
                        "endpointAgentId": "endpoint-b",
                        "responseActionId": endpoint_b
                    },
                    {
                        "endpointAgentId": "endpoint-a",
                        "responseActionId": latest_endpoint_a
                    }
                ]
            }
        });

        let ids = policy_rule_diff_dispatch_response_action_ids(&preview)
            .expect("dispatch response action ids");

        assert_eq!(ids, vec![latest_endpoint_a, endpoint_b]);
    }

    #[test]
    fn fleet_rule_diff_collection_aggregates_latest_receipt_per_endpoint() {
        let observed = |seconds| {
            DateTime::parse_from_rfc3339(&format!("2026-05-20T00:00:{seconds:02}Z"))
                .expect("timestamp")
                .with_timezone(&Utc)
        };
        let receipt_for =
            |response_action_id: Uuid, endpoint_agent_id: &str, observed_at: DateTime<Utc>| {
                CollectedPolicyRuleDiffReceipt {
                    response_action_id,
                    endpoint_agent_id: endpoint_agent_id.to_string(),
                    observed_at,
                    impact: serde_json::json!({}),
                    receipt: serde_json::json!({}),
                    public_key: "public-key".to_string(),
                }
            };

        let endpoint_a_old = Uuid::from_u128(10);
        let endpoint_a_latest = Uuid::from_u128(11);
        let endpoint_b = Uuid::from_u128(12);
        let receipts = latest_policy_rule_diff_receipts_by_endpoint(vec![
            receipt_for(endpoint_a_old, "endpoint-a", observed(1)),
            receipt_for(endpoint_b, "endpoint-b", observed(2)),
            receipt_for(endpoint_a_latest, "endpoint-a", observed(3)),
        ]);

        assert_eq!(receipts.len(), 2);
        assert_eq!(receipts[0].response_action_id, endpoint_b);
        assert_eq!(receipts[1].response_action_id, endpoint_a_latest);
    }
}
