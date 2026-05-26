//! Local API token rotation HTTP handler and background drain loops.
//!
//! Holds the on-demand token rotation route plus the long-running tokio tasks
//! that periodically rotate the agent's local auth token, drain control-api
//! acknowledgement and receipt upload retry queues, and sweep expired
//! response executions.

use super::super::*;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;

pub(crate) async fn rotate_local_api_token_route(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<RotateLocalApiTokenResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let grace_secs = rotate_local_api_token_with_grace(&state)?;

    Ok(Json(RotateLocalApiTokenResponse {
        rotated: true,
        previous_token_valid_for_seconds: grace_secs,
    }))
}

pub(crate) async fn token_rotation_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    loop {
        let interval_hours = {
            let settings = state.settings.read().await;
            settings
                .local_api_security
                .token_rotation_interval_hours
                .max(1)
        };
        let sleep_for = Duration::from_secs(u64::from(interval_hours) * 60 * 60);
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("Local API token rotation loop shutting down");
                break;
            }
            _ = tokio::time::sleep(sleep_for) => {}
        }

        match rotate_local_api_token_with_grace(&state) {
            Ok(grace_secs) => {
                tracing::info!(grace_secs, "Rotated local API auth token on schedule");
            }
            Err((status, err)) => {
                tracing::warn!(
                    status = %status,
                    error = %err,
                    "Scheduled local API token rotation failed"
                );
            }
        }
    }
}

pub(crate) async fn control_ack_postback_retry_drain_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    loop {
        match drain_control_ack_postback_retries(
            &state,
            EDR_CONTROL_ACK_RETRY_BACKGROUND_LIMIT,
            false,
        )
        .await
        {
            Ok(response) if response.attempted > 0 => {
                if response.failed > 0 {
                    tracing::warn!(
                        attempted = response.attempted,
                        delivered = response.delivered,
                        failed = response.failed,
                        pending = response.pending,
                        "Control API acknowledgement retry drain completed with failures"
                    );
                } else {
                    tracing::info!(
                        attempted = response.attempted,
                        delivered = response.delivered,
                        pending = response.pending,
                        "Drained queued Control API acknowledgement postbacks"
                    );
                }
            }
            Ok(_) => {}
            Err((status, err)) => {
                tracing::warn!(
                    status = %status,
                    error = %err,
                    "Scheduled Control API acknowledgement retry drain failed"
                );
            }
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("Control API acknowledgement retry drain loop shutting down");
                break;
            }
            _ = tokio::time::sleep(EDR_CONTROL_ACK_RETRY_DRAIN_INTERVAL) => {}
        }
    }
}

pub(crate) async fn control_receipt_upload_retry_drain_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    loop {
        match drain_control_receipt_upload_retries(
            &state,
            EDR_CONTROL_RECEIPT_UPLOAD_BACKGROUND_LIMIT,
            false,
        )
        .await
        {
            Ok(response) if response.attempted > 0 => {
                if response.failed > 0 {
                    tracing::warn!(
                        attempted = response.attempted,
                        delivered = response.delivered,
                        failed = response.failed,
                        pending = response.pending,
                        "Control API receipt upload retry drain completed with failures"
                    );
                } else {
                    tracing::info!(
                        attempted = response.attempted,
                        delivered = response.delivered,
                        pending = response.pending,
                        "Drained queued Control API receipt uploads"
                    );
                }
            }
            Ok(_) => {}
            Err((status, err)) => {
                tracing::warn!(
                    status = %status,
                    error = %err,
                    "Scheduled Control API receipt upload retry drain failed"
                );
            }
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("Control API receipt upload retry drain loop shutting down");
                break;
            }
            _ = tokio::time::sleep(EDR_CONTROL_ACK_RETRY_DRAIN_INTERVAL) => {}
        }
    }
}

pub(crate) async fn response_execution_expiration_sweep_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    loop {
        match expire_edr_response_executions(&state).await {
            Ok(response) if response.expired_count > 0 || response.rollback_count > 0 => {
                tracing::info!(
                    expired_count = response.expired_count,
                    rollback_count = response.rollback_count,
                    "Expired due EDR response executions"
                );
            }
            Ok(_) => {}
            Err((status, err)) => {
                tracing::warn!(
                    status = %status,
                    error = %err,
                    "Scheduled EDR response execution expiration sweep failed"
                );
            }
        }

        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("EDR response execution expiration sweep loop shutting down");
                break;
            }
            _ = tokio::time::sleep(EDR_RESPONSE_EXPIRATION_SWEEP_INTERVAL) => {}
        }
    }
}
