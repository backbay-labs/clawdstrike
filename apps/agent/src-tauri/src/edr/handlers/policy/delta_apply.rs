//! Policy delta application handler with backup, rollback, and enforcement verification.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use anyhow::Context;
#[allow(unused_imports)]
use axum::extract::{Path, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use std::fs;
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_policy_delta_apply(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(policy_delta_id): Path<String>,
    Json(input): Json<EdrPolicyDeltaApplyInput>,
) -> Result<Json<EdrPolicyDeltaApplyResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let policy_delta_id = policy_delta_id.trim();
    if policy_delta_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "policy delta id must not be empty".to_string(),
        ));
    }
    let dry_run = input.dry_run.unwrap_or(true);
    let allow_base_policy_drift = input.allow_base_policy_drift.unwrap_or(false);
    let reload_daemon_policy = input.reload_daemon_policy.unwrap_or(!dry_run);
    let restart_daemon = input.restart_daemon.unwrap_or(false);
    let verify_protection_state = input.verify_protection_state.unwrap_or(!dry_run);
    let provider_ack_timeout_ms = if dry_run || !verify_protection_state {
        0
    } else {
        bounded_provider_timeout_ms("providerAckTimeoutMs", input.provider_ack_timeout_ms)?
    };
    if dry_run && input.reload_daemon_policy.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            "reloadDaemonPolicy cannot be true for dryRun".to_string(),
        ));
    }
    if dry_run && restart_daemon {
        return Err((
            StatusCode::BAD_REQUEST,
            "restartDaemon cannot be true for dryRun".to_string(),
        ));
    }
    if dry_run && input.verify_protection_state.unwrap_or(false) {
        return Err((
            StatusCode::BAD_REQUEST,
            "verifyProtectionState cannot be true for dryRun".to_string(),
        ));
    }
    if dry_run && input.provider_ack_timeout_ms.unwrap_or(0) > 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "providerAckTimeoutMs cannot be set for dryRun".to_string(),
        ));
    }
    if !dry_run && !verify_protection_state {
        return Err((
            StatusCode::BAD_REQUEST,
            "verifyProtectionState must be true for live policy delta apply".to_string(),
        ));
    }
    if !dry_run && !reload_daemon_policy && !restart_daemon {
        return Err((
            StatusCode::BAD_REQUEST,
            "live policy delta apply requires reloadDaemonPolicy or restartDaemon".to_string(),
        ));
    }
    validate_response_action_actor_fields(input.actor.as_ref())?;
    if !dry_run {
        validate_response_action_actor(input.actor.as_ref())?;
    }
    let applied_by = input
        .applied_by
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("local-agent");
    if applied_by.len() > 256 {
        return Err((
            StatusCode::BAD_REQUEST,
            "applied_by must be at most 256 bytes".to_string(),
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
            "policy delta apply note must be at most 2048 bytes".to_string(),
        ));
    }

    let policy_delta = {
        let store = state.edr_policy_delta_store.lock().await;
        store
            .read_by_id(policy_delta_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("policy delta not found: {policy_delta_id}"),
                )
            })?
    };
    verify_policy_delta_record_before_apply(state.as_ref(), &policy_delta).await?;
    let settings = state.settings.read().await.clone();
    let local_endpoint_id = endpoint_id_for_settings(&settings);
    let policy_delta_actor = if input.actor.is_some() || !dry_run {
        let session_state = state.session_manager.state().await;
        let mut actor = endpoint_response_actor_from_action_input(
            &settings,
            &session_state,
            "agent-api",
            input.actor.as_ref(),
        );
        actor.endpoint_id = local_endpoint_id;
        Some(actor)
    } else {
        None
    };
    let policy_path = settings.policy_path.clone();
    let current_bytes = fs::read(&policy_path).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("read local policy {}: {err}", policy_path.display()),
        )
    })?;
    let previous_snapshot =
        endpoint_policy_snapshot_from_policy_bytes(&current_bytes, &policy_path)
            .map_err(internal_error)?;
    if !dry_run && policy_epoch_from_yaml(&current_bytes).is_none() {
        return Err((
            StatusCode::CONFLICT,
            "live policy delta apply requires the current policy to declare a positive policy_epoch"
                .to_string(),
        ));
    }
    let expected_base_policy_hash = policy_delta.artifact.target_policy.base_policy_hash.clone();
    if previous_snapshot.policy_hash != expected_base_policy_hash && !allow_base_policy_drift {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "policy delta base hash mismatch: expected {}, current {}",
                expected_base_policy_hash, previous_snapshot.policy_hash
            ),
        ));
    }

    let new_bytes =
        apply_policy_delta_patch_to_policy(&current_bytes, &policy_delta.artifact.policy_patch)
            .map_err(internal_error)?;
    let new_snapshot = endpoint_policy_snapshot_from_policy_bytes(&new_bytes, &policy_path)
        .map_err(internal_error)?;
    if !dry_run && policy_epoch_from_yaml(&new_bytes).is_none() {
        return Err((
            StatusCode::CONFLICT,
            "live policy delta apply requires the target policy to declare a positive policy_epoch"
                .to_string(),
        ));
    }
    if new_snapshot.policy_epoch <= previous_snapshot.policy_epoch {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "policy delta target epoch {} is not newer than current policy epoch {}",
                new_snapshot.policy_epoch, previous_snapshot.policy_epoch
            ),
        ));
    }
    let applied_at = chrono::Utc::now();
    let backup_path = if dry_run {
        None
    } else {
        let backup_path = policy_delta_backup_path(&policy_path, policy_delta_id, applied_at);
        if let Some(parent) = backup_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("create policy backup directory {}: {err}", parent.display()),
                )
            })?;
        }
        fs::copy(&policy_path, &backup_path).map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "backup local policy {} to {}: {err}",
                    policy_path.display(),
                    backup_path.display()
                ),
            )
        })?;
        Some(backup_path.display().to_string())
    };

    let mut record = EdrPolicyDeltaApplyRecord {
        policy_delta_id: policy_delta.policy_delta_id.clone(),
        applied_at,
        apply_status: Some(if dry_run { "dry_run" } else { "prepared" }.to_string()),
        failure_reason: None,
        applied_by: applied_by.to_string(),
        actor: policy_delta_actor.clone(),
        note,
        dry_run,
        applied: false,
        allow_base_policy_drift,
        cross_window_impact_hash: policy_delta
            .artifact
            .rollout
            .cross_window_impact_hash
            .clone(),
        cross_window_recommendation_hash: policy_delta
            .artifact
            .rollout
            .cross_window_recommendation_hash
            .clone(),
        policy_path: policy_path.display().to_string(),
        backup_path: backup_path.clone(),
        expected_base_policy_hash,
        previous_policy_hash: previous_snapshot.policy_hash.clone(),
        new_policy_hash: new_snapshot.policy_hash.clone(),
        previous_policy_epoch: previous_snapshot.policy_epoch,
        new_policy_epoch: new_snapshot.policy_epoch,
    };

    let prepared_receipt = if dry_run {
        None
    } else {
        let sensor_state =
            endpoint_sensor_state_from_macos_host(&state.macos_host.snapshot().await);
        let mut ledger = state.edr_receipt_ledger.lock().await;
        Some(
            ledger
                .sign_policy_delta_receipt(
                    &settings,
                    new_snapshot.clone(),
                    sensor_state,
                    EdrPolicyDeltaReceiptSigningInput {
                        artifact: &policy_delta.artifact,
                        artifact_hash: &policy_delta.artifact_hash,
                        operation: "prepared",
                        actor: policy_delta_actor.clone(),
                        previous_policy_hash: Some(previous_snapshot.policy_hash.as_str()),
                        new_policy_hash: Some(new_snapshot.policy_hash.as_str()),
                        backup_path: backup_path.as_deref(),
                    },
                )
                .map_err(internal_error)?,
        )
    };

    if !dry_run {
        append_policy_delta_apply_record(state.as_ref(), &record).await?;
    }

    if !dry_run {
        crate::security::fs::write_private_atomic(
            &policy_path,
            &new_bytes,
            "endpoint policy delta applied policy",
        )
        .map_err(internal_error)?;
        record.apply_status = Some("policy_written".to_string());
        record.applied = true;
    }

    let receipt = if dry_run {
        None
    } else {
        let sensor_state =
            endpoint_sensor_state_from_macos_host(&state.macos_host.snapshot().await);
        let mut ledger = state.edr_receipt_ledger.lock().await;
        match ledger.sign_policy_delta_receipt(
            &settings,
            new_snapshot.clone(),
            sensor_state,
            EdrPolicyDeltaReceiptSigningInput {
                artifact: &policy_delta.artifact,
                artifact_hash: &policy_delta.artifact_hash,
                operation: "applied",
                actor: policy_delta_actor.clone(),
                previous_policy_hash: Some(previous_snapshot.policy_hash.as_str()),
                new_policy_hash: Some(new_snapshot.policy_hash.as_str()),
                backup_path: backup_path.as_deref(),
            },
        ) {
            Ok(receipt) => Some(receipt),
            Err(err) => {
                rollback_policy_delta_apply_after_failure(
                    state.as_ref(),
                    &mut record,
                    &policy_path,
                    "applied receipt signing failed",
                )
                .await?;
                return Err(internal_error(err));
            }
        }
    };
    let post_apply_enforcement = if !dry_run
        && (verify_protection_state || reload_daemon_policy || restart_daemon)
    {
        match build_policy_delta_apply_enforcement_proof(
            &state,
            PolicyDeltaApplyEnforcementProofInput {
                settings: &settings,
                local_policy: new_snapshot.clone(),
                policy_delta_artifact: Some(&policy_delta.artifact),
                cross_window_impact_hash: policy_delta
                    .artifact
                    .rollout
                    .cross_window_impact_hash
                    .as_deref(),
                cross_window_recommendation_hash: policy_delta
                    .artifact
                    .rollout
                    .cross_window_recommendation_hash
                    .as_deref(),
                daemon_policy_reload_requested: reload_daemon_policy,
                daemon_restart_requested: restart_daemon,
                provider_ack_timeout_ms,
            },
        )
        .await
        {
            Ok(proof) => {
                if let Err(message) = validate_policy_delta_apply_enforcement_for_live_apply(&proof)
                {
                    rollback_policy_delta_apply_after_failure(
                        state.as_ref(),
                        &mut record,
                        &policy_path,
                        "post-apply enforcement verification failed",
                    )
                    .await?;
                    return Err((
                            StatusCode::CONFLICT,
                            format!(
                                "post-apply enforcement verification failed: {message}; policy rollback completed"
                            ),
                        ));
                }
                Some(proof)
            }
            Err(err) => {
                rollback_policy_delta_apply_after_failure(
                    state.as_ref(),
                    &mut record,
                    &policy_path,
                    "post-apply enforcement proof failed",
                )
                .await?;
                return Err(internal_error(err));
            }
        }
    } else {
        None
    };

    if !dry_run {
        record.apply_status = Some("complete".to_string());
        record.failure_reason = None;
        record.applied = true;
        if let Err((status, message)) =
            append_policy_delta_apply_record(state.as_ref(), &record).await
        {
            let rollback_reason = "complete apply record append failed";
            return match rollback_policy_delta_apply_after_failure(
                state.as_ref(),
                &mut record,
                &policy_path,
                rollback_reason,
            )
            .await
            {
                Ok(()) => Err((
                    status,
                    format!("{message}; policy rollback completed after durable apply record failure"),
                )),
                Err((rollback_status, rollback_message)) => Err((
                    rollback_status,
                    format!(
                        "{message}; rollback after durable apply record failure failed: {rollback_message}"
                    ),
                )),
            };
        }
    }

    Ok(Json(EdrPolicyDeltaApplyResponse {
        record,
        policy_delta,
        prepared_receipt,
        receipt,
        post_apply_enforcement,
    }))
}

async fn append_policy_delta_apply_record(
    state: &AgentApiState,
    record: &EdrPolicyDeltaApplyRecord,
) -> Result<(), (StatusCode, String)> {
    let mut store = state.edr_policy_delta_store.lock().await;
    store.append_apply(record).map_err(internal_error)
}

async fn rollback_policy_delta_apply_after_failure(
    state: &AgentApiState,
    record: &mut EdrPolicyDeltaApplyRecord,
    policy_path: &std::path::Path,
    reason: &str,
) -> Result<(), (StatusCode, String)> {
    let rollback_result = restore_policy_delta_backup(policy_path, record.backup_path.as_deref());
    record.applied = false;
    match &rollback_result {
        Ok(()) => {
            record.apply_status = Some("failed_rolled_back".to_string());
            record.failure_reason = Some(reason.to_string());
        }
        Err((_, rollback_error)) => {
            record.apply_status = Some("failed_rollback_failed".to_string());
            record.failure_reason = Some(format!("{reason}; rollback failed: {rollback_error}"));
        }
    }
    append_policy_delta_apply_record(state, record).await?;
    rollback_result
}

fn restore_policy_delta_backup(
    policy_path: &std::path::Path,
    backup_path: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let backup_path = backup_path.map(std::path::PathBuf::from).ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "cannot rollback policy delta apply without a backup path".to_string(),
        )
    })?;
    let backup_bytes = fs::read(&backup_path)
        .with_context(|| format!("read policy delta backup {}", backup_path.display()))
        .map_err(internal_error)?;
    crate::security::fs::write_private_atomic(
        policy_path,
        &backup_bytes,
        "endpoint policy delta rollback policy",
    )
    .map_err(internal_error)
}
