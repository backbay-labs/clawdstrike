//! TTL-expiration dispatcher for response execution rollback.

use super::super::*;

pub(crate) fn response_execution_expires_with_rollback(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        &EndpointDecisionAction::RestrictEgress
            | &EndpointDecisionAction::QuarantineFile
            | &EndpointDecisionAction::DisablePersistence
            | &EndpointDecisionAction::SuspendProcessTree
    )
}

pub(crate) async fn execute_response_expiration_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let reason = format!("response execution {} TTL expired", execution.execution_id);
    match execution.action {
        EndpointDecisionAction::RestrictEgress => {
            execute_restrict_egress_rollback(state, execution, &reason).await
        }
        EndpointDecisionAction::QuarantineFile => {
            execute_quarantine_file_rollback(state, execution, &reason)
        }
        EndpointDecisionAction::DisablePersistence => {
            execute_disable_persistence_rollback(state, execution, &reason)
        }
        EndpointDecisionAction::SuspendProcessTree => {
            execute_suspend_process_tree_rollback(execution, &reason)
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "response execution {} is not rollback-capable at expiration time",
                execution.execution_id
            ),
        )),
    }
}
