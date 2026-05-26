//! NATS enterprise connectivity bootstrap.
//!
//! When NATS is enabled in settings this module connects, validates the
//! configuration, and spawns the long-running policy-sync / approval-sync /
//! telemetry / posture subscribers. The successful result is a small bundle
//! of handles the rest of `run_agent` needs (approval outbox, fleet hunt
//! publisher, and the NATS client itself for response-action dispatch).

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::api_server;
use crate::approval::ApprovalQueue;
use crate::approval_outbox;
use crate::approval_sync;
use crate::daemon::{DaemonManager, PolicyCache};
use crate::nats_client;
use crate::policy_sync;
use crate::posture_commands;
use crate::session::SessionManager;
use crate::settings::Settings;
use crate::tasks::heartbeats::nats_heartbeat_loop;
use crate::telemetry_publisher;
use crate::tray::TrayManager;

use super::{is_nats_auth_failure, validate_nats_security_settings};

#[derive(Default)]
pub(super) struct NatsBootstrapResult {
    pub approval_request_outbox: Option<Arc<approval_outbox::ApprovalRequestOutbox>>,
    pub fleet_hunt_publisher: Option<Arc<dyn api_server::FleetHuntEventPublisher>>,
    pub response_action_nats: Option<Arc<nats_client::NatsClient>>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn setup_nats<R: tauri::Runtime>(
    daemon_manager: &Arc<DaemonManager>,
    session_manager: &Arc<SessionManager>,
    approval_queue: &Arc<ApprovalQueue>,
    policy_cache: &Arc<PolicyCache>,
    settings: &Arc<RwLock<Settings>>,
    shutdown_tx: &broadcast::Sender<()>,
    tray_manager: &Arc<TrayManager<R>>,
) -> NatsBootstrapResult {
    let mut result = NatsBootstrapResult::default();

    let nats_enabled = {
        let guard = settings.read().await;
        guard.nats.enabled
    };
    if !nats_enabled {
        return result;
    }

    let nats_settings = {
        let guard = settings.read().await;
        guard.nats.clone()
    };
    if let Err(err) = validate_nats_security_settings(&nats_settings) {
        tracing::error!(
            error = %err,
            "Enterprise NATS connectivity disabled due to unsafe configuration"
        );
        tray_manager
            .set_session_info(Some(format!("NATS disabled: {}", err)))
            .await;
        return result;
    }

    match nats_client::NatsClient::connect(&nats_settings).await {
        Ok(nats) => {
            let nats = Arc::new(nats);

            // Policy sync: watch KV for policy updates and reload hushd.
            let policy_path = {
                let guard = settings.read().await;
                guard.policy_path.clone()
            };
            let policy_sync = policy_sync::PolicySync::new(nats.clone(), policy_path);
            let (policy_update_tx, mut policy_update_rx) = tokio::sync::mpsc::channel::<()>(16);
            let policy_sync_shutdown = shutdown_tx.subscribe();
            tokio::spawn(async move {
                policy_sync
                    .start(policy_sync_shutdown, Some(policy_update_tx))
                    .await;
            });

            // On policy file change from NATS sync, signal hushd reload.
            let daemon_for_nats = daemon_manager.clone();
            tokio::spawn(async move {
                while policy_update_rx.recv().await.is_some() {
                    tracing::info!("Policy updated via NATS sync; reloading hushd");
                    if let Err(err) = daemon_for_nats.restart().await {
                        tracing::warn!(
                            error = %err,
                            "Failed to reload hushd after NATS policy sync"
                        );
                    }
                }
            });

            // Telemetry publisher.
            let telemetry = Arc::new(telemetry_publisher::TelemetryPublisher::new(nats.clone()));
            tracing::info!("NATS telemetry publisher initialized");
            let fleet_publisher: Arc<dyn api_server::FleetHuntEventPublisher> = telemetry.clone();
            result.fleet_hunt_publisher = Some(fleet_publisher);

            // Posture command handler.
            let posture_handler = posture_commands::PostureCommandHandler::new(
                nats.clone(),
                session_manager.clone(),
                daemon_manager.clone(),
                settings.clone(),
            );
            let posture_shutdown = shutdown_tx.subscribe();
            tokio::spawn(async move {
                posture_handler.start(posture_shutdown).await;
            });

            result.response_action_nats = Some(nats.clone());

            // Approval sync: ingest cloud decisions and apply them to local queue.
            let approval_sync = approval_sync::ApprovalSync::new(
                nats.clone(),
                approval_queue.clone(),
                nats_settings.require_signed_approval_responses,
                nats_settings.approval_response_trusted_issuer.clone(),
            );
            let approval_sync_shutdown = shutdown_tx.subscribe();
            tokio::spawn(async move {
                approval_sync.start(approval_sync_shutdown).await;
            });

            // Durable approval-request outbox (agent -> cloud).
            let outbox = Arc::new(approval_outbox::ApprovalRequestOutbox::load_default());
            if outbox.len().await > 0 {
                match outbox.flush_due(nats.as_ref()).await {
                    Ok(sent) if sent > 0 => {
                        tracing::info!(
                            sent,
                            "Flushed persisted approval-request outbox on startup"
                        );
                    }
                    Ok(_) => {}
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "Failed to flush approval-request outbox on startup"
                        );
                    }
                }
            }
            outbox.clone().start(nats.clone(), shutdown_tx.subscribe());
            result.approval_request_outbox = Some(outbox);

            // Publish periodic NATS heartbeats alongside the existing HTTP heartbeats.
            let telemetry_for_heartbeat = telemetry.clone();
            let session_for_nats_hb = session_manager.clone();
            let policy_cache_for_nats_hb = policy_cache.clone();
            let nats_hb_shutdown = shutdown_tx.subscribe();
            tokio::spawn(async move {
                nats_heartbeat_loop(
                    telemetry_for_heartbeat,
                    session_for_nats_hb,
                    policy_cache_for_nats_hb,
                    nats_hb_shutdown,
                )
                .await;
            });
        }
        Err(err) => {
            tracing::error!(
                error = %err,
                "Failed to connect to NATS; enterprise features disabled"
            );
            if is_nats_auth_failure(&err.to_string()) {
                tracing::warn!(
                    "NATS connect failed with authentication/authorization error; preserving enrollment identity and existing NATS config for automatic recovery"
                );
            }
        }
    }

    result
}
