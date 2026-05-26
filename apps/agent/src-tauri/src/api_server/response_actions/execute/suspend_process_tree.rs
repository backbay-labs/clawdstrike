//! Execute the `suspend_process_tree` response action.

use super::super::*;

pub(crate) async fn execute_suspend_process_tree_response(
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
    let targets = suspend_process_tree_targets(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid process tree target: {err}"),
        )
    })?;
    validate_process_signal_targets(&targets).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe process tree target: {err}"),
        )
    })?;
    for target in &targets {
        validate_process_signal_target_before_signal(target).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!("process {} cannot be signalled safely: {err}", target.pid),
            )
        })?;
    }

    let root_pid = targets.first().map(|target| target.pid).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "process tree target is empty".to_string(),
        )
    })?;
    let identity_bindings = targets
        .iter()
        .map(|target| EndpointResponseProcessIdentityBinding {
            pid: target.pid,
            process_identity_key: target.process_identity_key.clone(),
        })
        .collect::<Vec<_>>();
    let execution = EndpointResponseExecutionReport::suspend_process_tree_with_identity_bindings(
        plan,
        graph,
        root_pid,
        &identity_bindings,
    )
    .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_suspend_process_tree",
    )
    .await?;

    let mut suspended = Vec::new();
    for target in targets.iter().rev() {
        validate_process_signal_target_before_signal(target).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!(
                    "process {} identity changed before suspend signal: {err}",
                    target.pid
                ),
            )
        })?;
        if let Err(err) = signal_process(target.pid, process_suspend_signal()) {
            let mut resume_errors = Vec::new();
            for pid in &suspended {
                if let Err(resume_err) = signal_process(*pid, process_resume_signal()) {
                    resume_errors.push(format!(
                        "failed to resume partially suspended pid {pid}: {resume_err}"
                    ));
                }
            }
            let cleanup_reason = format!(
                "suspend process tree failed while signalling pid {}; partial suspend cleanup ran",
                target.pid
            );
            if resume_errors.is_empty() {
                let compensated = EndpointResponseExecutionReport::rolled_back_from(
                    &execution,
                    cleanup_reason.as_str(),
                    chrono::Utc::now(),
                );
                {
                    let mut ledger = state.edr_response_execution_ledger.lock().await;
                    ledger.append(&compensated).map_err(internal_error)?;
                }
                let _ = emit_edr_response_execution_receipt(
                    state,
                    &compensated,
                    graph,
                    compensated.actor.clone(),
                    &[EndpointReceiptEvidence::hashed(
                        "partialSuspendCleanupForExecutionId",
                        execution.execution_id.as_str(),
                    )],
                )
                .await;
            } else {
                let failure = resume_errors.join("; ");
                let _ = record_edr_response_rollback_failure(
                    state,
                    &execution,
                    cleanup_reason.as_str(),
                    failure.as_str(),
                    graph,
                )
                .await;
            }
            let cleanup_suffix = if resume_errors.is_empty() {
                "; partially suspended processes were resumed and a rollback transition was recorded".to_string()
            } else {
                format!(
                    "; partial suspend cleanup failed and remains rollbackable: {}",
                    resume_errors.join("; ")
                )
            };
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "failed to suspend process {}: {err}{cleanup_suffix}",
                    target.pid
                ),
            ));
        }
        suspended.push(target.pid);
    }
    persist_edr_response_execution(state, execution, graph, actor).await
}
