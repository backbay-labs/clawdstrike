//! Response action and execution handlers.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::{Path, Query, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use clawdstrike_policy_event::event::PolicyEvent;
#[allow(unused_imports)]
use hush_core::SignedReceipt;
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet, HashMap};
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_response_action(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrResponseActionInput>,
) -> Result<Json<EdrResponseActionResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let dry_run = input.dry_run.unwrap_or(true);
    if !dry_run
        && !matches!(
            input.action,
            EndpointDecisionAction::CollectEvidence
                | EndpointDecisionAction::RestrictEgress
                | EndpointDecisionAction::QuarantineFile
                | EndpointDecisionAction::DisablePersistence
                | EndpointDecisionAction::RevokeGrant
                | EndpointDecisionAction::SuspendProcessTree
        )
    {
        return Err((
            StatusCode::BAD_REQUEST,
            "only collect_evidence, restrict_egress, quarantine_file, disable_persistence, revoke_grant, and suspend_process_tree can execute locally in this safe response-engine slice"
                .to_string(),
        ));
    }
    if !supported_edr_response_action(&input.action) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported endpoint response action for dry-run executor: {}",
                input.action.as_str()
            ),
        ));
    }
    validate_response_action_actor_fields(input.actor.as_ref())?;
    if !dry_run {
        validate_response_action_actor(input.actor.as_ref())?;
    }

    let root_node_id =
        resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())?;
    let ttl_seconds = validate_response_action_ttl_seconds(input.ttl_seconds)?;
    let reason = validate_response_reason(
        "response action",
        input.reason.as_deref(),
        default_response_action_reason(&input.action, dry_run),
    )?;

    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let subgraph = graph
        .causal_subgraph_from(root_node_id.as_str(), EDR_MAX_CAUSAL_SUBGRAPH_DEPTH)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("response action target not found in causal graph: {root_node_id}"),
            )
        })?;
    let actor = {
        let settings = state.settings.read().await.clone();
        let session_state = state.session_manager.state().await;
        endpoint_response_actor_from_action_input(
            &settings,
            &session_state,
            "agent-api",
            input.actor.as_ref(),
        )
    };
    let plan = if dry_run {
        EndpointResponsePlan::dry_run(
            input.action.clone(),
            root_node_id,
            &subgraph,
            ttl_seconds,
            reason.clone(),
        )
    } else {
        match input.action {
            EndpointDecisionAction::CollectEvidence => {
                EndpointResponsePlan::collect_evidence_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            EndpointDecisionAction::RestrictEgress => {
                EndpointResponsePlan::restrict_egress_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            EndpointDecisionAction::QuarantineFile => {
                EndpointResponsePlan::quarantine_file_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            EndpointDecisionAction::DisablePersistence => {
                EndpointResponsePlan::disable_persistence_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            EndpointDecisionAction::RevokeGrant => EndpointResponsePlan::revoke_grant_execution(
                root_node_id,
                &subgraph,
                ttl_seconds,
                reason.clone(),
            ),
            EndpointDecisionAction::SuspendProcessTree => {
                EndpointResponsePlan::suspend_process_tree_execution(
                    root_node_id,
                    &subgraph,
                    ttl_seconds,
                    reason.clone(),
                )
            }
            _ => unreachable!("non-dry-run response action was validated above"),
        }
    };
    let receipt = emit_edr_response_receipt(&state, actor.clone(), &plan, &subgraph)
        .await
        .map_err(internal_error)?;
    let (execution, evidence_bundle_artifact, execution_receipt, evidence_bundle_receipt) =
        if dry_run {
            (None, None, None, None)
        } else {
            let (execution, stored_bundle, receipt, bundle_receipt) =
                match execute_edr_response_action(&state, &plan, &subgraph, actor.clone()).await {
                    Ok(result) => result,
                    Err((status, message)) => {
                        let message = sanitize_response_execution_failure(&message);
                        let failure = record_failed_edr_response_execution(
                            &state,
                            &plan,
                            &subgraph,
                            actor,
                            message.as_str(),
                        )
                        .await;
                        return Err(response_action_failure_error(status, message, failure));
                    }
                };
            (
                Some(execution),
                Some(EdrEvidenceBundleArtifact::from_stored(&stored_bundle)),
                Some(receipt),
                Some(bundle_receipt),
            )
        };
    let affected_identities = affected_identities_for_causal_impact(&subgraph);
    let affected_identity_count = affected_identities.count();
    let affected_tools = affected_tools_for_causal_impact(&subgraph);
    let affected_tool_count = affected_tools.len();

    Ok(Json(EdrResponseActionResponse {
        plan,
        graph: subgraph,
        affected_identity_count,
        affected_tool_count,
        affected_identities,
        affected_tools,
        receipt,
        execution,
        evidence_bundle_artifact,
        execution_receipt,
        evidence_bundle_receipt,
    }))
}

pub(crate) async fn agent_edr_response_executions(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrResponseExecutionQuery>,
) -> Result<Json<EdrResponseExecutionsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit(
        "limit",
        query.limit,
        EDR_DEFAULT_RESPONSE_EXECUTION_QUERY_LIMIT,
        EDR_MAX_RESPONSE_EXECUTION_QUERY_LIMIT,
    )?;
    let (path, executions) = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let executions = ledger.read_recent(limit).map_err(internal_error)?;
        (path, executions)
    };
    let executions =
        response_execution_records_with_attribution(state.as_ref(), executions).await?;
    Ok(Json(EdrResponseExecutionsResponse {
        path,
        execution_count: executions.len(),
        executions,
    }))
}

pub(crate) async fn agent_edr_response_execution(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
) -> Result<Json<EdrResponseExecutionResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }

    let (path, execution) = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let execution = ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?;
        (path, execution)
    };
    let execution = response_execution_record_with_attribution(state.as_ref(), execution).await?;

    Ok(Json(EdrResponseExecutionResponse { path, execution }))
}

pub(crate) async fn agent_edr_response_execution_proof(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
) -> Result<Json<EdrResponseExecutionProofResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }

    let (execution_path, execution) = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let execution = ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?;
        (path, execution)
    };

    let (
        receipt_path,
        request_receipt,
        execution_receipt,
        evidence_bundle_receipt,
        transition_receipts,
        rollback_receipts,
        acknowledgement_receipts,
    ) = {
        let ledger = state.edr_receipt_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let request_receipt = latest_required_receipt(
            &ledger,
            "response_request",
            execution.action_id.as_str(),
            "response request receipt",
        )?;
        let execution_receipt = latest_required_receipt(
            &ledger,
            "response_execution",
            execution.execution_id.as_str(),
            "response execution receipt",
        )
        .or_else(|err| {
            if err.0 == StatusCode::NOT_FOUND {
                latest_required_receipt_by_execution_id(
                    &ledger,
                    "response_execution",
                    execution.execution_id.as_str(),
                    "response execution receipt",
                )
            } else {
                Err(err)
            }
        })?;
        let evidence_bundle_receipt = latest_required_receipt(
            &ledger,
            "evidence_bundle_manifest",
            execution.evidence_bundle.bundle_id.as_str(),
            "evidence bundle manifest receipt",
        )?;
        let lifecycle_receipts = response_execution_lifecycle_receipts(&ledger, &execution)?;
        verify_response_execution_proof_actor_continuity(
            &execution,
            &request_receipt,
            &execution_receipt,
            &lifecycle_receipts.transition_receipts,
        )?;
        verify_response_execution_proof_contract(
            &execution,
            &request_receipt,
            &execution_receipt,
            &evidence_bundle_receipt,
            &lifecycle_receipts.transition_receipts,
            &lifecycle_receipts.rollback_receipts,
            &lifecycle_receipts.acknowledgement_receipts,
        )?;
        (
            path,
            request_receipt,
            execution_receipt,
            evidence_bundle_receipt,
            lifecycle_receipts.transition_receipts,
            lifecycle_receipts.rollback_receipts,
            lifecycle_receipts.acknowledgement_receipts,
        )
    };
    let graph = receipt_endpoint_decision_graph(&execution_receipt).map_err(internal_error)?;
    let provider_state =
        receipt_endpoint_decision_sensor_state(&execution_receipt).map_err(internal_error)?;
    let (evidence_bundle_artifact, affected_identities, affected_tools) = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        let stored = store
            .load(&execution.evidence_bundle.bundle_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for response execution proof not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?;
        verify_response_execution_proof_evidence_bundle(&execution, &stored)?;
        let affected_identities = affected_identities_for_causal_impact(&stored.graph);
        let affected_tools = affected_tools_for_causal_impact(&stored.graph);
        (
            EdrEvidenceBundleArtifact::from_stored(&stored),
            affected_identities,
            affected_tools,
        )
    };
    let affected_identity_count = affected_identities.count();
    let affected_tool_count = affected_tools.len();

    Ok(Json(EdrResponseExecutionProofResponse {
        execution_path,
        receipt_path,
        execution: EdrResponseExecutionRecord::from_execution(execution),
        graph,
        affected_identity_count,
        affected_tool_count,
        affected_identities,
        affected_tools,
        provider_state,
        evidence_bundle_artifact,
        request_receipt,
        execution_receipt,
        evidence_bundle_receipt,
        transition_receipts,
        rollback_receipts,
        acknowledgement_receipts,
    }))
}

pub(crate) async fn agent_edr_response_execution_expire(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<EdrResponseExecutionExpireResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let response = expire_edr_response_executions(&state).await?;
    Ok(Json(response))
}

pub(crate) async fn expire_edr_response_executions(
    state: &Arc<AgentApiState>,
) -> Result<EdrResponseExecutionExpireResponse, (StatusCode, String)> {
    let now = chrono::Utc::now();
    let (path, pending) = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let pending = ledger
            .pending_expiring_executions(now)
            .map_err(internal_error)?;
        (path, pending)
    };

    let mut graphs = HashMap::with_capacity(pending.len());
    for execution in &pending {
        let graph = {
            let mut store = state.edr_evidence_bundle_store.lock().await;
            store
                .load(&execution.evidence_bundle.bundle_id)
                .map_err(internal_error)?
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        format!(
                            "evidence bundle for expired response execution not found: {}",
                            execution.evidence_bundle.bundle_id
                        ),
                    )
                })?
                .graph
        };
        graphs.insert(execution.evidence_bundle.bundle_id.clone(), graph);
    }

    let mut rollbacks = Vec::new();
    let mut rollback_receipts = Vec::new();
    for execution in pending
        .iter()
        .filter(|execution| response_execution_expires_with_rollback(&execution.action))
    {
        let graph = graphs
            .get(&execution.evidence_bundle.bundle_id)
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for expired response execution not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?;
        let reason = format!("response execution {} TTL expired", execution.execution_id);
        let (_rollback_intent, _rollback_intent_receipt) =
            record_edr_response_rollback_intent(&state, execution, &reason, graph).await?;
        let rollback = match execute_response_expiration_rollback(&state, execution).await {
            Ok(rollback) => rollback,
            Err((status, err)) => {
                let record_message = sanitize_response_execution_failure(&err);
                let record_result = record_edr_response_rollback_failure(
                    &state,
                    execution,
                    &reason,
                    record_message.as_str(),
                    graph,
                )
                .await;
                let suffix = match record_result {
                    Ok((failed, receipt)) => {
                        let receipt = receipt
                            .receipt
                            .receipt_id
                            .unwrap_or_else(|| "unknown".to_string());
                        format!(
                            "; rollback failure recorded as {} with receipt {}",
                            failed.execution_id, receipt
                        )
                    }
                    Err((_, record_err)) => {
                        format!("; rollback failure recording also failed: {record_err}")
                    }
                };
                return Err((
                    status,
                    format!(
                        "failed to roll back expired response execution {}: {err}{suffix}",
                        execution.execution_id
                    ),
                ));
            }
        };
        let receipt = emit_edr_response_rollback_receipt(&state, &rollback, graph)
            .await
            .map_err(internal_error)?;
        rollbacks.push(rollback);
        rollback_receipts.push(receipt);
    }

    let expired = {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger.expire_due(now).map_err(internal_error)?
    };
    deactivate_expired_egress_restrictions(&state, &expired, now).await?;

    let mut records = Vec::with_capacity(expired.len());
    let mut receipts = Vec::with_capacity(expired.len());
    for execution in expired {
        let graph = graphs
            .get(&execution.evidence_bundle.bundle_id)
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for expired response execution not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?;
        let receipt = emit_edr_response_execution_receipt(
            &state,
            &execution,
            graph,
            execution.actor.clone(),
            &[],
        )
        .await
        .map_err(internal_error)?;
        receipts.push(receipt);
        records.push(EdrResponseExecutionRecord::from_execution(execution));
    }

    Ok(EdrResponseExecutionExpireResponse {
        path,
        expired_count: records.len(),
        executions: records,
        receipts,
        rollback_count: rollbacks.len(),
        rollbacks,
        rollback_receipts,
    })
}

pub(crate) async fn agent_edr_response_execution_cancel(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
    Json(input): Json<EdrResponseExecutionCancelInput>,
) -> Result<Json<EdrResponseExecutionCancelResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }
    let reason = validate_response_reason(
        "response execution cancel",
        input.reason.as_deref(),
        "local response execution cancelled",
    )?;

    let now = chrono::Utc::now();
    let (path, execution) = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let execution = ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?;
        (path, execution)
    };
    if !matches!(
        execution.action,
        EndpointDecisionAction::CollectEvidence | EndpointDecisionAction::RestrictEgress
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "response execution {execution_id} cannot be cancelled safely; use rollback for rollback-capable local side-effect actions"
            ),
        ));
    }
    if !matches!(
        execution.status,
        EndpointResponseExecutionStatus::Succeeded
            | EndpointResponseExecutionStatus::Partial
            | EndpointResponseExecutionStatus::RollbackPending
            | EndpointResponseExecutionStatus::RollbackFailed
    ) {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "response execution {execution_id} cannot be cancelled from status {}",
                execution.status.as_str()
            ),
        ));
    }
    if now > execution.expires_at() {
        return Err((
            StatusCode::CONFLICT,
            format!("response execution {execution_id} TTL already expired"),
        ));
    }

    let graph = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        store
            .load(&execution.evidence_bundle.bundle_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for response execution not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?
            .graph
    };

    let cancelled = {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger
            .cancel(&execution, &reason, now)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    format!("response execution {execution_id} already has a terminal transition"),
                )
            })?
    };
    if cancelled.action == EndpointDecisionAction::RestrictEgress {
        deactivate_egress_restrictions_if_active(&state, &cancelled.action_id, now).await?;
    }
    let receipt = emit_edr_response_execution_receipt(
        &state,
        &cancelled,
        &graph,
        cancelled.actor.clone(),
        &[],
    )
    .await
    .map_err(internal_error)?;

    Ok(Json(EdrResponseExecutionCancelResponse {
        path,
        execution: EdrResponseExecutionRecord::from_execution(cancelled),
        receipt,
    }))
}

pub(crate) async fn agent_edr_response_execution_rollback(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
    Json(input): Json<EdrResponseExecutionRollbackInput>,
) -> Result<Json<EdrResponseExecutionRollbackResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }
    let reason = validate_response_reason(
        "response execution rollback",
        input.reason.as_deref(),
        "local response execution rollback",
    )?;

    let (path, execution) = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        let path = ledger.path().map(|path| path.display().to_string());
        let execution = ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?;
        (path, execution)
    };
    if !matches!(
        execution.action,
        EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::DisablePersistence
            | EndpointDecisionAction::SuspendProcessTree
    ) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "response execution {execution_id} is not a rollback-capable restrict_egress, quarantine_file, disable_persistence, or suspend_process_tree execution"
            ),
        ));
    }
    if !matches!(
        execution.status,
        EndpointResponseExecutionStatus::Succeeded | EndpointResponseExecutionStatus::Partial
    ) {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "response execution {execution_id} cannot be rolled back from status {}",
                execution.status.as_str()
            ),
        ));
    }
    {
        let ledger = state.edr_response_execution_ledger.lock().await;
        if ledger
            .has_terminal_transition_for(&execution)
            .map_err(internal_error)?
        {
            return Err((
                StatusCode::CONFLICT,
                format!("response execution {execution_id} already has a terminal transition"),
            ));
        }
    }

    let graph = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        store
            .load(&execution.evidence_bundle.bundle_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for response execution not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?
            .graph
    };

    let (_rollback_intent, _rollback_intent_receipt) =
        record_edr_response_rollback_intent(&state, &execution, &reason, &graph).await?;

    let rollback_result = match execution.action {
        EndpointDecisionAction::RestrictEgress => {
            execute_restrict_egress_rollback(&state, &execution, &reason).await
        }
        EndpointDecisionAction::QuarantineFile => {
            execute_quarantine_file_rollback(&state, &execution, &reason)
        }
        EndpointDecisionAction::DisablePersistence => {
            execute_disable_persistence_rollback(&state, &execution, &reason)
        }
        EndpointDecisionAction::SuspendProcessTree => {
            execute_suspend_process_tree_rollback(&execution, &reason)
        }
        _ => unreachable!("rollback-capable action was validated above"),
    };
    let rollback = match rollback_result {
        Ok(rollback) => rollback,
        Err((status, err)) => {
            let record_message = sanitize_response_execution_failure(&err);
            let record_result = record_edr_response_rollback_failure(
                &state,
                &execution,
                &reason,
                record_message.as_str(),
                &graph,
            )
            .await;
            let suffix = match record_result {
                Ok((failed, receipt)) => {
                    let receipt = receipt
                        .receipt
                        .receipt_id
                        .unwrap_or_else(|| "unknown".to_string());
                    format!(
                        "; rollback failure recorded as {} with receipt {}",
                        failed.execution_id, receipt
                    )
                }
                Err((_, record_err)) => {
                    format!("; rollback failure recording also failed: {record_err}")
                }
            };
            return Err((
                status,
                format!("failed to roll back response execution {execution_id}: {err}{suffix}"),
            ));
        }
    };
    let receipt = emit_edr_response_rollback_receipt(&state, &rollback, &graph)
        .await
        .map_err(internal_error)?;
    let rollback_transition = {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger
            .roll_back(&execution, &reason, rollback.completed_at)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::CONFLICT,
                    format!("response execution {execution_id} already has a terminal transition"),
                )
            })?
    };
    let transition_receipt = emit_edr_response_execution_receipt(
        &state,
        &rollback_transition,
        &graph,
        rollback_transition.actor.clone(),
        &[],
    )
    .await
    .map_err(internal_error)?;

    Ok(Json(EdrResponseExecutionRollbackResponse {
        path,
        execution: EdrResponseExecutionRecord::from_execution(execution),
        rollback_transition: EdrResponseExecutionRecord::from_execution(rollback_transition),
        rollback,
        receipt,
        transition_receipt,
    }))
}

pub(crate) async fn agent_edr_response_execution_acknowledge(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(execution_id): Path<String>,
    Json(input): Json<EdrResponseExecutionAcknowledgeInput>,
) -> Result<Json<EdrResponseExecutionAcknowledgeResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let execution_id = execution_id.trim();
    if execution_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "response execution id must not be empty".to_string(),
        ));
    }
    let acknowledged_by = input
        .acknowledged_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local-agent");
    if acknowledged_by.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "response acknowledgement actor must be at most 256 bytes".to_string(),
        ));
    }
    let note = input
        .note
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    if note.as_deref().is_some_and(|value| value.len() > 2048) {
        return Err((
            StatusCode::BAD_REQUEST,
            "response acknowledgement note must be at most 2048 bytes".to_string(),
        ));
    }

    let execution = {
        let ledger = state.edr_response_execution_ledger.lock().await;
        ledger
            .get(execution_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("response execution not found: {execution_id}"),
                )
            })?
    };
    let graph = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        store
            .load(&execution.evidence_bundle.bundle_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!(
                        "evidence bundle for response execution not found: {}",
                        execution.evidence_bundle.bundle_id
                    ),
                )
            })?
            .graph
    };
    let control_correlation =
        endpoint_response_control_correlation(input.control.as_ref(), &execution)?;
    let acknowledgement = EndpointResponseAcknowledgementReport::from_execution(
        &execution,
        acknowledged_by,
        note,
        chrono::Utc::now(),
    )
    .with_control_correlation(control_correlation);
    let path = append_edr_response_acknowledgement(&state, &acknowledgement).await?;
    let receipt = emit_edr_response_acknowledgement_receipt(&state, &acknowledgement, &graph)
        .await
        .map_err(internal_error)?;
    let control_postback = match input.control.as_ref() {
        Some(control) => {
            post_control_response_acknowledgement(&state, control, &acknowledgement, &receipt)
                .await?
        }
        None => None,
    };

    Ok(Json(EdrResponseExecutionAcknowledgeResponse {
        path,
        execution: EdrResponseExecutionRecord::from_execution(execution),
        acknowledgement,
        receipt,
        control_postback,
    }))
}

pub(crate) async fn agent_edr_response_acknowledgements(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrResponseAcknowledgementQuery>,
) -> Result<Json<EdrResponseAcknowledgementsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", query.limit, 50, EDR_MAX_STORED_FINDINGS)?;
    let ledger = state.edr_response_acknowledgement_ledger.lock().await;
    let path = ledger.path().map(|path| path.display().to_string());
    let acknowledgements = ledger
        .read_recent(limit)
        .map_err(internal_error)?
        .into_iter()
        .map(EdrResponseAcknowledgementRecord::from_acknowledgement)
        .collect::<Vec<_>>();
    Ok(Json(EdrResponseAcknowledgementsResponse {
        path,
        count: acknowledgements.len(),
        acknowledgements,
    }))
}
