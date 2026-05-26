//! Execute the `collect_evidence` response action.

use super::super::*;

pub(crate) async fn execute_collect_evidence_response(
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
    let execution =
        EndpointResponseExecutionReport::collect_evidence(plan, graph).map_err(internal_error)?;
    persist_edr_response_execution(state, execution, graph, actor).await
}
