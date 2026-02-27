#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]
// Scaffold crate: many types/services are defined but not yet fully wired into routes.
#![allow(dead_code)]

mod auth;
mod config;
mod crypto;
mod db;
mod error;
#[cfg(test)]
mod integration_tests;
mod models;
mod routes;
mod services;
mod state;

use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

use crate::config::Config;
use crate::services::agent_heartbeat_consumer;
use crate::services::alerter::AlerterService;
use crate::services::approval_request_consumer;
use crate::services::approval_resolution_outbox;
use crate::services::audit_consumer;
use crate::services::metering::MeteringService;
use crate::services::retention::RetentionService;
use crate::services::stale_agent_detector::{self, StaleAgentConfig};
use crate::services::tenant_provisioner::TenantProvisioner;
use crate::state::AppState;

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    if let Err(e) = run().await {
        tracing::error!(error = %e, "Fatal error");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config::from_env()?;
    tracing::info!(addr = %config.listen_addr, "Starting ClawdStrike Cloud API");

    let signing_keypair = resolve_approval_signing_keypair(
        config.approval_signing_enabled,
        config.approval_signing_keypair_path.as_deref(),
    );

    // Connect to PostgreSQL
    let pool = db::create_pool(&config.database_url).await?;
    tracing::info!("Connected to PostgreSQL");

    // Connect to NATS
    let nats = async_nats::connect(&config.nats_url).await?;
    tracing::info!(url = %config.nats_url, "Connected to NATS");

    // Initialize services
    let provisioner = TenantProvisioner::new(
        pool.clone(),
        config.nats_url.clone(),
        &config.nats_provisioning_mode,
        config.nats_provisioner_base_url.clone(),
        config.nats_provisioner_api_token.clone(),
        config.nats_allow_insecure_mock_provisioner,
    )?;
    let metering = MeteringService::new(pool.clone());
    let alerter = AlerterService::new(pool.clone());
    let retention = RetentionService::new(pool.clone());

    let state = AppState {
        config: config.clone(),
        db: pool,
        nats,
        provisioner,
        metering,
        alerter,
        retention,
        signing_keypair,
    };

    // Background service shutdown channels.
    let (stale_shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(8);
    let (audit_shutdown_tx, audit_shutdown_rx) = tokio::sync::watch::channel(false);
    let (approval_shutdown_tx, approval_shutdown_rx) = tokio::sync::watch::channel(false);
    let (approval_outbox_shutdown_tx, approval_outbox_shutdown_rx) =
        tokio::sync::watch::channel(false);
    let (heartbeat_shutdown_tx, heartbeat_shutdown_rx) = tokio::sync::watch::channel(false);

    if config.stale_detector_enabled {
        let db = state.db.clone();
        let stale_cfg = StaleAgentConfig {
            check_interval: Duration::from_secs(config.stale_check_interval_secs),
            stale_threshold_secs: config.stale_threshold_secs,
            dead_threshold_secs: config.dead_threshold_secs,
        };
        let stale_shutdown_rx = stale_shutdown_tx.subscribe();
        tokio::spawn(async move {
            stale_agent_detector::run(db, stale_cfg, stale_shutdown_rx).await;
        });
        tracing::info!(
            interval_secs = config.stale_check_interval_secs,
            stale_secs = config.stale_threshold_secs,
            dead_secs = config.dead_threshold_secs,
            "Stale agent detector enabled"
        );
    }

    if config.audit_consumer_enabled {
        let nats = state.nats.clone();
        let subject_filter = config.audit_subject_filter.clone();
        let stream_name = config.audit_stream_name.clone();
        let consumer_name = config.audit_consumer_name.clone();
        let shutdown_rx = audit_shutdown_rx.clone();
        tokio::spawn(async move {
            audit_consumer::run(
                nats,
                &subject_filter,
                &stream_name,
                &consumer_name,
                shutdown_rx,
            )
            .await;
        });
        tracing::info!(
            subject = %config.audit_subject_filter,
            stream = %config.audit_stream_name,
            consumer = %config.audit_consumer_name,
            "Audit consumer enabled"
        );
    }

    if config.approval_consumer_enabled {
        let nats = state.nats.clone();
        let db = state.db.clone();
        let subject_filter = config.approval_subject_filter.clone();
        let stream_subjects = stream_subjects_for_consumer(
            &config.approval_stream_name,
            &config.approval_subject_filter,
            config.heartbeat_consumer_enabled,
            &config.heartbeat_stream_name,
            &config.heartbeat_subject_filter,
        );
        let stream_name = config.approval_stream_name.clone();
        let consumer_name = config.approval_consumer_name.clone();
        let shutdown_rx = approval_shutdown_rx.clone();
        tokio::spawn(async move {
            approval_request_consumer::run(
                nats,
                db,
                &subject_filter,
                &stream_subjects,
                &stream_name,
                &consumer_name,
                shutdown_rx,
            )
            .await;
        });
        tracing::info!(
            subject = %config.approval_subject_filter,
            stream = %config.approval_stream_name,
            consumer = %config.approval_consumer_name,
            "Approval request consumer enabled"
        );
    }

    if config.approval_resolution_outbox_enabled {
        let nats = state.nats.clone();
        let db = state.db.clone();
        let poll = Duration::from_secs(config.approval_resolution_outbox_poll_interval_secs);
        let shutdown_rx = approval_outbox_shutdown_rx.clone();
        tokio::spawn(async move {
            approval_resolution_outbox::run(nats, db, poll, shutdown_rx).await;
        });
        tracing::info!(
            poll_secs = config.approval_resolution_outbox_poll_interval_secs,
            "Approval resolution outbox worker enabled"
        );
    }

    if config.heartbeat_consumer_enabled {
        let nats = state.nats.clone();
        let db = state.db.clone();
        let subject_filter = config.heartbeat_subject_filter.clone();
        let stream_subjects = stream_subjects_for_consumer(
            &config.heartbeat_stream_name,
            &config.heartbeat_subject_filter,
            config.approval_consumer_enabled,
            &config.approval_stream_name,
            &config.approval_subject_filter,
        );
        let stream_name = config.heartbeat_stream_name.clone();
        let consumer_name = config.heartbeat_consumer_name.clone();
        let shutdown_rx = heartbeat_shutdown_rx.clone();
        tokio::spawn(async move {
            agent_heartbeat_consumer::run(
                nats,
                db,
                &subject_filter,
                &stream_subjects,
                &stream_name,
                &consumer_name,
                shutdown_rx,
            )
            .await;
        });
        tracing::info!(
            subject = %config.heartbeat_subject_filter,
            stream = %config.heartbeat_stream_name,
            consumer = %config.heartbeat_consumer_name,
            "Agent heartbeat consumer enabled"
        );
    }

    let app = routes::router(state.clone())
        .layer(TraceLayer::new_for_http())
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;
    tracing::info!(addr = %config.listen_addr, "Listening");

    let stale_shutdown_tx_signal = stale_shutdown_tx.clone();
    let audit_shutdown_tx_signal = audit_shutdown_tx.clone();
    let approval_shutdown_tx_signal = approval_shutdown_tx.clone();
    let approval_outbox_shutdown_tx_signal = approval_outbox_shutdown_tx.clone();
    let heartbeat_shutdown_tx_signal = heartbeat_shutdown_tx.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            tokio::signal::ctrl_c().await.ok();
            let _ = stale_shutdown_tx_signal.send(());
            let _ = audit_shutdown_tx_signal.send(true);
            let _ = approval_shutdown_tx_signal.send(true);
            let _ = approval_outbox_shutdown_tx_signal.send(true);
            let _ = heartbeat_shutdown_tx_signal.send(true);
            tracing::info!("Received shutdown signal");
        })
        .await?;

    tracing::info!("Shut down cleanly");
    Ok(())
}

fn stream_subjects_for_consumer(
    consumer_stream_name: &str,
    consumer_subject_filter: &str,
    sibling_consumer_enabled: bool,
    sibling_stream_name: &str,
    sibling_subject_filter: &str,
) -> Vec<String> {
    let mut subjects = vec![consumer_subject_filter.to_string()];
    if sibling_consumer_enabled && consumer_stream_name == sibling_stream_name {
        subjects.push(sibling_subject_filter.to_string());
    }
    subjects.sort();
    subjects.dedup();
    subjects
}

fn resolve_approval_signing_keypair(
    signing_enabled: bool,
    keypair_path: Option<&str>,
) -> Option<Arc<hush_core::Keypair>> {
    if !signing_enabled {
        return None;
    }

    if let Some(path) = keypair_path {
        match load_approval_signing_keypair(path) {
            Ok(keypair) => {
                tracing::info!(path = %path, "Loaded approval signing keypair from disk");
                return Some(Arc::new(keypair));
            }
            Err(err) => {
                tracing::warn!(
                    path = %path,
                    error = %err,
                    "Failed to load approval signing keypair; falling back to an ephemeral keypair"
                );
            }
        }
    } else {
        tracing::warn!(
            "APPROVAL_SIGNING_ENABLED is true but APPROVAL_SIGNING_KEYPAIR_PATH is not set; falling back to an ephemeral keypair"
        );
    }

    tracing::warn!(
        "Using ephemeral approval signing keypair; configure APPROVAL_SIGNING_KEYPAIR_PATH for stable signatures across restarts"
    );
    Some(Arc::new(hush_core::Keypair::generate()))
}

fn load_approval_signing_keypair(path: &str) -> Result<hush_core::Keypair, String> {
    let key_hex = std::fs::read_to_string(path)
        .map_err(|err| format!("failed to read keypair file: {err}"))?;
    hush_core::Keypair::from_hex(key_hex.trim())
        .map_err(|err| format!("failed to parse keypair: {err}"))
}

#[cfg(test)]
mod tests {
    use super::{
        load_approval_signing_keypair, resolve_approval_signing_keypair,
        stream_subjects_for_consumer,
    };

    #[test]
    fn signing_keypair_disabled_returns_none() {
        assert!(resolve_approval_signing_keypair(false, None).is_none());
    }

    #[test]
    fn missing_key_path_uses_ephemeral_signing_keypair() {
        assert!(resolve_approval_signing_keypair(true, None).is_some());
    }

    #[test]
    fn configured_keypair_path_loads_keypair() {
        let keypair = hush_core::Keypair::generate();
        let path = std::env::temp_dir().join(format!(
            "clawdstrike-approval-signing-{}-{}.key",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        std::fs::write(&path, keypair.to_hex()).unwrap();
        let parsed = load_approval_signing_keypair(path.to_str().unwrap()).unwrap();
        std::fs::remove_file(path).unwrap();

        assert_eq!(parsed.public_key(), keypair.public_key());
    }

    #[test]
    fn shared_stream_consumer_subjects_include_both_filters() {
        let subjects = stream_subjects_for_consumer(
            "adaptive-ingress",
            "tenant-*.clawdstrike.approval.request.*",
            true,
            "adaptive-ingress",
            "tenant-*.clawdstrike.agent.heartbeat.*",
        );
        assert_eq!(
            subjects,
            vec![
                "tenant-*.clawdstrike.agent.heartbeat.*".to_string(),
                "tenant-*.clawdstrike.approval.request.*".to_string(),
            ]
        );
    }

    #[test]
    fn separate_stream_consumer_subjects_keep_single_filter() {
        let subjects = stream_subjects_for_consumer(
            "approval-ingress",
            "tenant-*.clawdstrike.approval.request.*",
            true,
            "heartbeat-ingress",
            "tenant-*.clawdstrike.agent.heartbeat.*",
        );
        assert_eq!(
            subjects,
            vec!["tenant-*.clawdstrike.approval.request.*".to_string()]
        );
    }

    #[test]
    fn shared_stream_does_not_add_sibling_subject_when_sibling_consumer_disabled() {
        let subjects = stream_subjects_for_consumer(
            "adaptive-ingress",
            "tenant-*.clawdstrike.approval.request.*",
            false,
            "adaptive-ingress",
            "tenant-*.clawdstrike.agent.heartbeat.*",
        );
        assert_eq!(
            subjects,
            vec!["tenant-*.clawdstrike.approval.request.*".to_string()]
        );
    }
}
