//! Live response action dispatch.
//!
//! Provides the entry-point switch over `EndpointDecisionAction` that routes
//! each supported live action to its `execute::*` implementation, plus the
//! `supported_*` predicates used by handlers to reject unsupported actions.

use super::*;

pub(crate) fn supported_edr_simulation_action(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::Block
            | EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
    )
}

pub(crate) fn supported_edr_response_action(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
            | EndpointDecisionAction::CollectEvidence
    )
}

pub(crate) fn default_response_action_reason(
    action: &EndpointDecisionAction,
    dry_run: bool,
) -> &'static str {
    if dry_run {
        return "endpoint response dry run";
    }
    match action {
        EndpointDecisionAction::CollectEvidence => "collect endpoint evidence",
        EndpointDecisionAction::RestrictEgress => "restrict endpoint egress",
        EndpointDecisionAction::QuarantineFile => "quarantine endpoint file",
        EndpointDecisionAction::DisablePersistence => "disable endpoint persistence item",
        EndpointDecisionAction::RevokeGrant => "revoke local endpoint grant",
        EndpointDecisionAction::SuspendProcessTree => "suspend endpoint process tree",
        EndpointDecisionAction::TerminateProcessTree => "terminate endpoint process tree",
        _ => "execute endpoint response",
    }
}

pub(crate) async fn execute_edr_response_action(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    match plan.action {
        EndpointDecisionAction::CollectEvidence => {
            execute_collect_evidence_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::RestrictEgress => {
            execute_restrict_egress_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::QuarantineFile => {
            execute_quarantine_file_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::DisablePersistence => {
            execute_disable_persistence_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::RevokeGrant => {
            execute_revoke_grant_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::SuspendProcessTree => {
            execute_suspend_process_tree_response(state, plan, graph, actor).await
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported endpoint response action for live executor: {}",
                plan.action.as_str()
            ),
        )),
    }
}
