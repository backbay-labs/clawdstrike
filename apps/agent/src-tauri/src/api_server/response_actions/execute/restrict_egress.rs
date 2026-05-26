//! Execute the `restrict_egress` response action.

use super::super::*;

pub(crate) async fn execute_restrict_egress_response(
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
    let targets = restrict_egress_targets(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid egress restriction target: {err}"),
        )
    })?;
    ensure_network_extension_ready_for_restrict_egress(state).await?;
    let execution = EndpointResponseExecutionReport::restrict_egress(plan, graph, &targets)
        .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_restrict_egress",
    )
    .await?;
    let reload_proof = append_edr_egress_restrictions(state, &execution, &targets).await?;
    ensure_network_extension_reload_proof_succeeded(&reload_proof).map_err(|message| {
        (
            StatusCode::CONFLICT,
            format!("NetworkExtension did not activate egress restrictions: {message}"),
        )
    })?;
    let additional_evidence = network_extension_reload_request_evidence(&reload_proof);
    persist_edr_response_execution_with_evidence(
        state,
        execution,
        graph,
        actor,
        &additional_evidence,
    )
    .await
}
