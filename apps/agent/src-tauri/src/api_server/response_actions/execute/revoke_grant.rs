//! Execute the `revoke_grant` response action.

use super::super::*;

pub(crate) async fn execute_revoke_grant_response(
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
    let grant_target = revoke_grant_target(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid revoke grant target: {err}"),
        )
    })?;
    let (grant_target, revoked_grant_hash) = match grant_target {
        RevokeGrantTarget::LocalApiAuthToken => {
            return Err((
                StatusCode::CONFLICT,
                "local API auth token revocation is not safe for autonomous response without durable replacement-token handoff and recovery"
                    .to_string(),
            ));
        }
        RevokeGrantTarget::BrokerCapability { capability_id } => {
            let revocation = revoke_broker_capability_grant(state, &capability_id).await?;
            let revoked_grant_hash =
                canonical_json_hash(&revocation, "broker capability revoke result")
                    .map_err(internal_error)?;
            (
                format!("broker_capability:{capability_id}"),
                revoked_grant_hash,
            )
        }
        RevokeGrantTarget::LocalIntegrationSecret { secret } => {
            let revocation = revoke_local_integration_secret_grant(state, secret).await?;
            let revoked_grant_hash =
                canonical_json_hash(&revocation, "local integration secret revoke result")
                    .map_err(internal_error)?;
            (
                format!("local_integration_secret:{}", secret.target_suffix()),
                revoked_grant_hash,
            )
        }
    };
    let execution = EndpointResponseExecutionReport::revoke_grant(
        plan,
        graph,
        grant_target,
        revoked_grant_hash,
    )
    .map_err(internal_error)?;
    persist_edr_response_execution(state, execution, graph, actor).await
}
