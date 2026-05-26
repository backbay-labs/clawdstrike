//! Roll back the `restrict_egress` response action.

use super::super::*;

pub(crate) async fn execute_restrict_egress_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let rollback =
        EndpointResponseRollbackReport::restrict_egress(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    {
        let mut ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger
            .deactivate_execution(&execution.execution_id, rollback.completed_at)
            .map_err(internal_error)?;
    }
    sync_edr_network_extension_egress_policy(state, rollback.completed_at).await?;
    Ok(rollback)
}
