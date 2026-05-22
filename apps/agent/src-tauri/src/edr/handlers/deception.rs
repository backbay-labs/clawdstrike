//! Deception plan handlers.
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

pub(crate) async fn agent_edr_deception_plan(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrDeceptionPlanInput>,
) -> Result<Json<EdrDeceptionPlanResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let root = input.root.trim();
    let endpoint_id = input.endpoint_id.trim();
    if root.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "root must not be empty".to_string(),
        ));
    }
    if endpoint_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "endpoint_id must not be empty".to_string(),
        ));
    }

    let plan = DeceptionPlan::standard(root, endpoint_id);
    Ok(Json(EdrDeceptionPlanResponse {
        artifact_count: plan.artifacts.len(),
        plan,
    }))
}

pub(crate) async fn agent_edr_materialize_deception_plan(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrMaterializeDeceptionPlanInput>,
) -> Result<Json<EdrMaterializeDeceptionPlanResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    if input.plan.artifacts.len() > EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "too many honey artifacts: max {}",
                EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST
            ),
        ));
    }
    let plan = input.plan;
    let artifacts = plan.artifacts.clone();
    let materialize_plan = plan.clone();
    let report = tokio::task::spawn_blocking(move || materialize_plan.materialize())
        .await
        .map_err(|err| internal_error(err.into()))?
        .map_err(map_deception_materialization_error)?;
    let mut registry = state.edr_honey_registry.lock().await;
    let registered_artifact_count = registry.register(&artifacts).map_err(internal_error)?;
    let registry_path = registry.path().map(|path| path.display().to_string());
    drop(registry);
    let receipt = emit_edr_deception_materialization_receipt(
        &state,
        &plan,
        &report,
        registered_artifact_count,
    )
    .await
    .map_err(internal_error)?;

    Ok(Json(EdrMaterializeDeceptionPlanResponse {
        report,
        registered_artifact_count,
        registry_path,
        receipt,
    }))
}

pub(crate) async fn agent_edr_cleanup_deception_plan(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrCleanupDeceptionPlanInput>,
) -> Result<Json<EdrCleanupDeceptionPlanResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    if input.plan.artifacts.len() > EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "too many honey artifacts: max {}",
                EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST
            ),
        ));
    }
    validate_deception_cleanup_plan(&input.plan)
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;

    let dry_run = input.dry_run.unwrap_or(true);
    let plan = input.plan;
    let registered_ids = {
        let registry = state.edr_honey_registry.lock().await;
        registry
            .load()
            .map_err(internal_error)?
            .into_iter()
            .map(|artifact| artifact.artifact_id)
            .collect::<BTreeSet<_>>()
    };

    let cleanup_plan = plan.clone();
    let cleanup_registered_ids = registered_ids.clone();
    let (report, artifact_ids_to_deregister) = tokio::task::spawn_blocking(move || {
        cleanup_deception_plan(&cleanup_plan, &cleanup_registered_ids, dry_run)
    })
    .await
    .map_err(|err| internal_error(err.into()))?
    .map_err(internal_error)?;

    let mut registry = state.edr_honey_registry.lock().await;
    let deregistered_artifact_count = if dry_run {
        0
    } else {
        registry
            .unregister(&artifact_ids_to_deregister)
            .map_err(internal_error)?
    };
    let remaining_registered_artifact_count = registry.load().map_err(internal_error)?.len();
    let registry_path = registry.path().map(|path| path.display().to_string());
    drop(registry);

    let receipt = emit_edr_deception_cleanup_receipt(
        &state,
        &plan,
        &report,
        deregistered_artifact_count,
        remaining_registered_artifact_count,
    )
    .await
    .map_err(internal_error)?;

    Ok(Json(EdrCleanupDeceptionPlanResponse {
        report,
        deregistered_artifact_count,
        remaining_registered_artifact_count,
        registry_path,
        receipt,
    }))
}

pub(crate) async fn agent_edr_rotate_deception_plan(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrRotateDeceptionPlanInput>,
) -> Result<Json<EdrRotateDeceptionPlanResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    if input.old_plan.artifacts.len() > EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST
        || input.new_plan.artifacts.len() > EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "too many honey artifacts: max {} per plan",
                EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST
            ),
        ));
    }
    validate_deception_cleanup_plan(&input.old_plan)
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;
    validate_deception_cleanup_plan(&input.new_plan)
        .map_err(|message| (StatusCode::BAD_REQUEST, message))?;

    let dry_run = input.dry_run.unwrap_or(true);
    let old_plan = input.old_plan;
    let new_plan = input.new_plan;
    let registered_ids = {
        let registry = state.edr_honey_registry.lock().await;
        registry
            .load()
            .map_err(internal_error)?
            .into_iter()
            .map(|artifact| artifact.artifact_id)
            .collect::<BTreeSet<_>>()
    };

    let preflight_old_plan = old_plan.clone();
    let preflight_registered_ids = registered_ids.clone();
    let (preflight_cleanup, _) = tokio::task::spawn_blocking(move || {
        cleanup_deception_plan(&preflight_old_plan, &preflight_registered_ids, true)
    })
    .await
    .map_err(|err| internal_error(err.into()))?
    .map_err(internal_error)?;
    if !preflight_cleanup.refused.is_empty() {
        return Err((
            StatusCode::CONFLICT,
            "deception rotation cleanup preflight refused one or more artifacts".to_string(),
        ));
    }

    if dry_run {
        let registry = state.edr_honey_registry.lock().await;
        let remaining_registered_artifact_count = registry.load().map_err(internal_error)?.len();
        let registry_path = registry.path().map(|path| path.display().to_string());
        drop(registry);
        let report = DeceptionRotationReport {
            dry_run,
            cleanup: preflight_cleanup,
            materialization: None,
            deregistered_artifact_count: 0,
            registered_artifact_count: 0,
            remaining_registered_artifact_count,
        };
        let cleanup_receipt = emit_edr_deception_cleanup_receipt(
            &state,
            &old_plan,
            &report.cleanup,
            0,
            remaining_registered_artifact_count,
        )
        .await
        .map_err(internal_error)?;
        let rotation_receipt =
            emit_edr_deception_rotation_receipt(&state, &old_plan, &new_plan, &report)
                .await
                .map_err(internal_error)?;

        return Ok(Json(EdrRotateDeceptionPlanResponse {
            deregistered_artifact_count: report.deregistered_artifact_count,
            registered_artifact_count: report.registered_artifact_count,
            remaining_registered_artifact_count: report.remaining_registered_artifact_count,
            registry_path,
            cleanup_receipt,
            materialization_receipt: None,
            rotation_receipt,
            report,
        }));
    }

    let cleanup_old_plan = old_plan.clone();
    let cleanup_registered_ids = registered_ids.clone();
    let (cleanup_report, artifact_ids_to_deregister) = tokio::task::spawn_blocking(move || {
        cleanup_deception_plan(&cleanup_old_plan, &cleanup_registered_ids, false)
    })
    .await
    .map_err(|err| internal_error(err.into()))?
    .map_err(internal_error)?;
    if !cleanup_report.refused.is_empty() {
        return Err((
            StatusCode::CONFLICT,
            "deception rotation cleanup refused one or more artifacts".to_string(),
        ));
    }

    let mut registry = state.edr_honey_registry.lock().await;
    let deregistered_artifact_count = registry
        .unregister(&artifact_ids_to_deregister)
        .map_err(internal_error)?;
    let remaining_after_cleanup = registry.load().map_err(internal_error)?.len();
    let registry_path = registry.path().map(|path| path.display().to_string());
    drop(registry);

    let cleanup_receipt = emit_edr_deception_cleanup_receipt(
        &state,
        &old_plan,
        &cleanup_report,
        deregistered_artifact_count,
        remaining_after_cleanup,
    )
    .await
    .map_err(internal_error)?;

    let materialize_plan = new_plan.clone();
    let materialization_report =
        tokio::task::spawn_blocking(move || materialize_plan.materialize())
            .await
            .map_err(|err| internal_error(err.into()))?
            .map_err(map_deception_materialization_error)?;
    let mut registry = state.edr_honey_registry.lock().await;
    let registered_artifact_count = registry
        .register(&new_plan.artifacts)
        .map_err(internal_error)?;
    let remaining_registered_artifact_count = registry.load().map_err(internal_error)?.len();
    drop(registry);

    let materialization_receipt = emit_edr_deception_materialization_receipt(
        &state,
        &new_plan,
        &materialization_report,
        registered_artifact_count,
    )
    .await
    .map_err(internal_error)?;
    let report = DeceptionRotationReport {
        dry_run,
        cleanup: cleanup_report,
        materialization: Some(materialization_report),
        deregistered_artifact_count,
        registered_artifact_count,
        remaining_registered_artifact_count,
    };
    let rotation_receipt =
        emit_edr_deception_rotation_receipt(&state, &old_plan, &new_plan, &report)
            .await
            .map_err(internal_error)?;

    Ok(Json(EdrRotateDeceptionPlanResponse {
        deregistered_artifact_count,
        registered_artifact_count,
        remaining_registered_artifact_count,
        registry_path,
        cleanup_receipt,
        materialization_receipt: Some(materialization_receipt),
        rotation_receipt,
        report,
    }))
}

fn map_deception_materialization_error(err: anyhow::Error) -> (StatusCode, String) {
    let message = err.to_string();
    if message.contains("pre-existing non-honey") {
        return (StatusCode::CONFLICT, message);
    }
    internal_error(err)
}
