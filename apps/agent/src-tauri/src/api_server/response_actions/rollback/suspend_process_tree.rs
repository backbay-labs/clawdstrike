//! Roll back the `suspend_process_tree` response action.

use super::super::*;

pub(crate) fn execute_suspend_process_tree_rollback(
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let effect = suspend_process_tree_effect(execution).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid process tree execution effect: {err}"),
        )
    })?;
    let targets = process_tree_effect_signal_targets(effect).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid process tree pid set: {err}"),
        )
    })?;
    let rollback =
        EndpointResponseRollbackReport::suspend_process_tree(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    for target in &targets {
        validate_process_effect_signal_target_before_signal(target).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!(
                    "process {} identity changed before resume signal: {err}",
                    target.pid
                ),
            )
        })?;
        signal_process(target.pid, process_resume_signal()).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!("failed to resume suspended process {}: {err}", target.pid),
            )
        })?;
    }
    Ok(rollback)
}
