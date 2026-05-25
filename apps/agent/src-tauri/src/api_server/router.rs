//! Router wiring and listener for the agent API server.
//!
//! `AgentApiServer::start` builds the axum router (109 routes across daemon
//! proxy, broker proxy, agent management, EDR ingest/policy/causal/evidence/
//! response/protection, OpenClaw, approvals, enrollment, UI bootstrap, and the
//! `/ui` static fallback), binds the TCP listener, spawns the background loops
//! (token rotation, control-ack/receipt retry drain, fleet-secret-touch sync),
//! and serves until shutdown_rx fires.
//!
//! Handlers and helpers live in `api_server.rs` (and `crate::edr::handlers::*`)
//! for now; relocating them is a follow-up commit set, not this one.

use std::net::SocketAddr;

use anyhow::{Context, Result};
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, patch, post, put};
use axum::Router;
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tower_http::services::{ServeDir, ServeFile};

use super::auth::{attach_ui_auth_cookie, rotate_local_api_token_route, token_rotation_loop};
use super::constants::AGENT_API_MAX_BODY_BYTES;
use super::daemon_proxy::{proxy_daemon_events, proxy_daemon_get, proxy_daemon_mutation};
use super::rate_limit::route_rate_limit;
use super::state::AgentApiServer;
use super::ui_bootstrap::{
    agent_web_ui_fallback, resolve_control_console_dist, start_ui_bootstrap, ui_bootstrap_page,
    ui_bootstrap_verify,
};

// Handlers and the two retry-drain loops still live in `api_server.rs`; they
// reach this module via `super` because router is a submodule of api_server.
use super::{
    agent_edr_agent_secret_touches, agent_edr_agent_secret_touches_fleet_publish,
    agent_edr_causal_context, agent_edr_causal_graph, agent_edr_causal_subgraph,
    agent_edr_cleanup_deception_plan, agent_edr_control_ack_postbacks_retry,
    agent_edr_control_archive_uploads_backfill, agent_edr_control_archive_uploads_retry,
    agent_edr_control_receipt_uploads_retry, agent_edr_deception_plan,
    agent_edr_detection_candidate, agent_edr_developer_activity,
    agent_edr_endpoint_security_events, agent_edr_evidence_bundle,
    agent_edr_evidence_bundle_archive, agent_edr_evidence_bundle_archive_verify,
    agent_edr_evidence_bundle_fleet_publish, agent_edr_evidence_bundles,
    agent_edr_evidence_bundles_compact, agent_edr_finding_groups, agent_edr_findings,
    agent_edr_fleet_hunt_events_retry, agent_edr_flight_recorder,
    agent_edr_flight_recorder_compact, agent_edr_graph_search, agent_edr_graph_slice_export,
    agent_edr_materialize_deception_plan, agent_edr_network_extension_egress_policy_proof,
    agent_edr_network_extension_events, agent_edr_package_manager_events, agent_edr_policy_delta,
    agent_edr_policy_delta_apply, agent_edr_policy_deltas, agent_edr_policy_events,
    agent_edr_policy_events_impact, agent_edr_policy_events_impact_history,
    agent_edr_policy_events_jsonl, agent_edr_policy_events_replay,
    agent_edr_policy_events_replay_history, agent_edr_policy_events_replay_jsonl,
    agent_edr_policy_replay, agent_edr_policy_simulation, agent_edr_privacy_report,
    agent_edr_protection_state, agent_edr_receipts, agent_edr_receipts_compact,
    agent_edr_receipts_upload, agent_edr_response_acknowledgements, agent_edr_response_action,
    agent_edr_response_execution, agent_edr_response_execution_acknowledge,
    agent_edr_response_execution_cancel, agent_edr_response_execution_expire,
    agent_edr_response_execution_proof, agent_edr_response_execution_rollback,
    agent_edr_response_executions, agent_edr_rotate_deception_plan, agent_edr_stage_detection,
    agent_edr_staged_detections, agent_health, agent_policy_check, connect_gateway,
    control_ack_postback_retry_drain_loop, control_receipt_upload_retry_drain_loop,
    create_approval_request, create_diagnostics_bundle, create_gateway, delete_gateway,
    discover_gateways, disconnect_gateway, enroll_agent, enrollment_status,
    fleet_agent_secret_touch_sync_loop, gateway_request, get_approval_status,
    get_integrations_settings, get_ota_status, get_settings, import_desktop_gateways,
    list_gateways, list_pending_approvals, list_runtime_agents, openclaw_events, patch_gateway,
    probe_gateway, register_runtime_agent_route, resolve_approval, set_active_gateway,
    test_integration_delivery, trigger_ota_apply, trigger_ota_check, update_integrations_settings,
    update_settings,
};

impl AgentApiServer {
    pub async fn start(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let mut app = Router::new()
            .route("/health", get(proxy_daemon_get))
            .route("/api/v1/audit", get(proxy_daemon_get))
            .route("/api/v1/audit/stats", get(proxy_daemon_get))
            .route("/api/v1/policy", get(proxy_daemon_get))
            .route("/api/v1/agents/status", get(proxy_daemon_get))
            .route("/api/v1/events", get(proxy_daemon_events))
            .route("/api/v1/siem/exporters", get(proxy_daemon_get))
            .route("/api/v1/broker/public-key", get(proxy_daemon_get))
            .route(
                "/api/v1/broker/capabilities",
                get(proxy_daemon_get).post(proxy_daemon_mutation),
            )
            .route(
                "/api/v1/broker/previews",
                get(proxy_daemon_get).post(proxy_daemon_mutation),
            )
            .route(
                "/api/v1/broker/capabilities/revoke-all",
                post(proxy_daemon_mutation),
            )
            .route("/api/v1/broker/capabilities/{id}", get(proxy_daemon_get))
            .route(
                "/api/v1/broker/capabilities/{id}/status",
                get(proxy_daemon_get),
            )
            .route(
                "/api/v1/broker/capabilities/{id}/replay",
                post(proxy_daemon_mutation),
            )
            .route(
                "/api/v1/broker/capabilities/{id}/bundle",
                get(proxy_daemon_get),
            )
            .route(
                "/api/v1/broker/capabilities/{id}/revoke",
                post(proxy_daemon_mutation),
            )
            .route("/api/v1/broker/previews/{id}", get(proxy_daemon_get))
            .route(
                "/api/v1/broker/previews/{id}/approve",
                post(proxy_daemon_mutation),
            )
            .route("/api/v1/broker/providers/freeze", get(proxy_daemon_get))
            .route(
                "/api/v1/broker/providers/{provider}/freeze",
                post(proxy_daemon_mutation).delete(proxy_daemon_mutation),
            )
            .route("/api/v1/agent/health", get(agent_health))
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .route("/api/v1/agent/runtimes", get(list_runtime_agents))
            .route(
                "/api/v1/agent/runtimes/register",
                post(register_runtime_agent_route),
            )
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .route(
                "/api/v1/agent/integrations/test",
                post(test_integration_delivery),
            )
            .route("/api/v1/agent/ota/status", get(get_ota_status))
            .route("/api/v1/agent/ota/check", post(trigger_ota_check))
            .route("/api/v1/agent/ota/apply", post(trigger_ota_apply))
            .route(
                "/api/v1/agent/diagnostics/bundle",
                post(create_diagnostics_bundle),
            )
            .route(
                "/api/v1/agent/security/token/rotate",
                post(rotate_local_api_token_route),
            )
            .route("/api/v1/agent/policy-check", post(agent_policy_check))
            .route("/api/v1/agent/edr/findings", post(agent_edr_findings))
            .route(
                "/api/v1/agent/edr/developer-activity",
                post(agent_edr_developer_activity),
            )
            .route(
                "/api/v1/agent/edr/package-manager/events",
                post(agent_edr_package_manager_events),
            )
            .route(
                "/api/v1/agent/edr/endpoint-security/events",
                post(agent_edr_endpoint_security_events),
            )
            .route(
                "/api/v1/agent/edr/network-extension/events",
                post(agent_edr_network_extension_events),
            )
            .route(
                "/api/v1/agent/edr/policy-events",
                post(agent_edr_policy_events),
            )
            .route(
                "/api/v1/agent/edr/policy-events/jsonl",
                post(agent_edr_policy_events_jsonl),
            )
            .route(
                "/api/v1/agent/edr/policy-events/replay",
                post(agent_edr_policy_events_replay),
            )
            .route(
                "/api/v1/agent/edr/policy-events/replay/jsonl",
                post(agent_edr_policy_events_replay_jsonl),
            )
            .route(
                "/api/v1/agent/edr/policy-events/replay/history",
                post(agent_edr_policy_events_replay_history),
            )
            .route(
                "/api/v1/agent/edr/policy-events/impact",
                post(agent_edr_policy_events_impact),
            )
            .route(
                "/api/v1/agent/edr/policy-events/impact/history",
                post(agent_edr_policy_events_impact_history),
            )
            .route(
                "/api/v1/agent/edr/finding-groups",
                get(agent_edr_finding_groups),
            )
            .route(
                "/api/v1/agent/edr/flight-recorder",
                get(agent_edr_flight_recorder),
            )
            .route(
                "/api/v1/agent/edr/flight-recorder/compact",
                post(agent_edr_flight_recorder_compact),
            )
            .route(
                "/api/v1/agent/edr/protection-state",
                get(agent_edr_protection_state),
            )
            .route(
                "/api/v1/agent/edr/privacy-report",
                post(agent_edr_privacy_report),
            )
            .route("/api/v1/agent/edr/receipts", get(agent_edr_receipts))
            .route(
                "/api/v1/agent/edr/receipts/upload",
                post(agent_edr_receipts_upload),
            )
            .route(
                "/api/v1/agent/edr/receipts/compact",
                post(agent_edr_receipts_compact),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles",
                get(agent_edr_evidence_bundles),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/compact",
                post(agent_edr_evidence_bundles_compact),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/archive/verify",
                post(agent_edr_evidence_bundle_archive_verify),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/fleet-publish",
                post(agent_edr_evidence_bundle_fleet_publish),
            )
            .route(
                "/api/v1/agent/edr/fleet-hunt-events/retry",
                post(agent_edr_fleet_hunt_events_retry),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}",
                get(agent_edr_evidence_bundle),
            )
            .route(
                "/api/v1/agent/edr/evidence-bundles/{bundle_id}/archive",
                get(agent_edr_evidence_bundle_archive),
            )
            .route(
                "/api/v1/agent/edr/causal-graph",
                post(agent_edr_causal_graph),
            )
            .route(
                "/api/v1/agent/edr/causal-subgraph",
                post(agent_edr_causal_subgraph),
            )
            .route(
                "/api/v1/agent/edr/causal-context",
                post(agent_edr_causal_context),
            )
            .route(
                "/api/v1/agent/edr/graph-search",
                post(agent_edr_graph_search),
            )
            .route(
                "/api/v1/agent/edr/graph-slices/export",
                post(agent_edr_graph_slice_export),
            )
            .route(
                "/api/v1/agent/edr/agent-secret-touches",
                post(agent_edr_agent_secret_touches),
            )
            .route(
                "/api/v1/agent/edr/agent-secret-touches/fleet-publish",
                post(agent_edr_agent_secret_touches_fleet_publish),
            )
            .route(
                "/api/v1/agent/edr/policy-simulation",
                post(agent_edr_policy_simulation),
            )
            .route(
                "/api/v1/agent/edr/policy-replay",
                post(agent_edr_policy_replay),
            )
            .route(
                "/api/v1/agent/edr/detection-candidate",
                post(agent_edr_detection_candidate),
            )
            .route(
                "/api/v1/agent/edr/staged-detections",
                get(agent_edr_staged_detections).post(agent_edr_stage_detection),
            )
            .route(
                "/api/v1/agent/edr/policy-deltas",
                get(agent_edr_policy_deltas).post(agent_edr_policy_delta),
            )
            .route(
                "/api/v1/agent/edr/policy-deltas/{policy_delta_id}/apply",
                post(agent_edr_policy_delta_apply),
            )
            .route(
                "/api/v1/agent/edr/network-extension/egress-policy/proof",
                post(agent_edr_network_extension_egress_policy_proof),
            )
            .route(
                "/api/v1/agent/edr/response-action",
                post(agent_edr_response_action),
            )
            .route(
                "/api/v1/agent/edr/response-executions",
                get(agent_edr_response_executions),
            )
            .route(
                "/api/v1/agent/edr/response-executions/expire",
                post(agent_edr_response_execution_expire),
            )
            .route(
                "/api/v1/agent/edr/response-acknowledgements",
                get(agent_edr_response_acknowledgements),
            )
            .route(
                "/api/v1/agent/edr/control-ack-postbacks/retry",
                post(agent_edr_control_ack_postbacks_retry),
            )
            .route(
                "/api/v1/agent/edr/control-archive-uploads/retry",
                post(agent_edr_control_archive_uploads_retry),
            )
            .route(
                "/api/v1/agent/edr/control-receipt-uploads/retry",
                post(agent_edr_control_receipt_uploads_retry),
            )
            .route(
                "/api/v1/agent/edr/control-archive-uploads/backfill",
                post(agent_edr_control_archive_uploads_backfill),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/cancel",
                post(agent_edr_response_execution_cancel),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/rollback",
                post(agent_edr_response_execution_rollback),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/acknowledge",
                post(agent_edr_response_execution_acknowledge),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}/proof",
                get(agent_edr_response_execution_proof),
            )
            .route(
                "/api/v1/agent/edr/response-executions/{execution_id}",
                get(agent_edr_response_execution),
            )
            .route(
                "/api/v1/agent/edr/deception-plan",
                post(agent_edr_deception_plan),
            )
            .route(
                "/api/v1/agent/edr/deception-plan/materialize",
                post(agent_edr_materialize_deception_plan),
            )
            .route(
                "/api/v1/agent/edr/deception-plan/cleanup",
                post(agent_edr_cleanup_deception_plan),
            )
            .route(
                "/api/v1/agent/edr/deception-plan/rotate",
                post(agent_edr_rotate_deception_plan),
            )
            .route(
                "/api/v1/openclaw/gateways",
                get(list_gateways).post(create_gateway),
            )
            .route(
                "/api/v1/openclaw/gateways/{id}",
                patch(patch_gateway).delete(delete_gateway),
            )
            .route(
                "/api/v1/openclaw/gateways/{id}/connect",
                post(connect_gateway),
            )
            .route(
                "/api/v1/openclaw/gateways/{id}/disconnect",
                post(disconnect_gateway),
            )
            .route("/api/v1/openclaw/active-gateway", put(set_active_gateway))
            .route("/api/v1/openclaw/discover", post(discover_gateways))
            .route("/api/v1/openclaw/probe", post(probe_gateway))
            .route("/api/v1/openclaw/request", post(gateway_request))
            .route(
                "/api/v1/openclaw/import-desktop-gateways",
                post(import_desktop_gateways),
            )
            .route("/api/v1/openclaw/events", get(openclaw_events))
            .route("/api/v1/approval/request", post(create_approval_request))
            .route("/api/v1/approval/{id}/status", get(get_approval_status))
            .route("/api/v1/approval/{id}/resolve", post(resolve_approval))
            .route("/api/v1/approval/pending", get(list_pending_approvals))
            .route("/api/v1/enroll", post(enroll_agent))
            .route("/api/v1/enrollment-status", get(enrollment_status))
            .route("/api/v1/ui/bootstrap/start", post(start_ui_bootstrap))
            .route(
                "/ui/bootstrap",
                get(ui_bootstrap_page).post(ui_bootstrap_verify),
            )
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                route_rate_limit,
            ))
            .layer(DefaultBodyLimit::max(AGENT_API_MAX_BODY_BYTES))
            .with_state(self.state.clone());

        if let Some(dashboard_dist) = resolve_control_console_dist() {
            tracing::info!(
                path = %dashboard_dist.display(),
                "Serving control console from bundled assets"
            );
            let index_file = dashboard_dist.join("index.html");
            let ui_router = Router::new()
                .fallback_service(
                    ServeDir::new(dashboard_dist).not_found_service(ServeFile::new(index_file)),
                )
                .layer(axum::middleware::from_fn_with_state(
                    self.state.clone(),
                    attach_ui_auth_cookie,
                ));
            app = app.nest("/ui", ui_router);
        } else {
            tracing::warn!(
                "Control console assets were not found; serving fallback diagnostics page at /ui"
            );
            let ui_router = Router::new()
                .route("/", get(agent_web_ui_fallback))
                .route("/{*path}", get(agent_web_ui_fallback))
                .layer(axum::middleware::from_fn_with_state(
                    self.state.clone(),
                    attach_ui_auth_cookie,
                ));
            app = app.nest("/ui", ui_router);
        }

        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind agent API server to {}", addr))?;

        {
            let settings = self.state.settings.read().await;
            if settings.local_api_security.mtls_enabled {
                let cert = settings
                    .local_api_security
                    .mtls_server_cert_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                let key = settings
                    .local_api_security
                    .mtls_server_key_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                let ca = settings
                    .local_api_security
                    .mtls_client_ca_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                if cert && key && ca {
                    tracing::info!(
                        mtls_port = settings.local_api_security.mtls_port,
                        "Local API mTLS settings are configured"
                    );
                } else {
                    tracing::warn!(
                        "Local API mTLS is enabled but cert/key/CA files are missing or unreadable"
                    );
                }
            }
        }

        tracing::info!(address = %addr, "Agent API server listening");

        let rotation_state = self.state.clone();
        let mut token_rotation_shutdown = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            token_rotation_loop(rotation_state, &mut token_rotation_shutdown).await;
        });

        let retry_drain_state = self.state.clone();
        let mut retry_drain_shutdown = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            control_ack_postback_retry_drain_loop(retry_drain_state, &mut retry_drain_shutdown)
                .await;
        });

        let receipt_upload_drain_state = self.state.clone();
        let mut receipt_upload_drain_shutdown = shutdown_rx.resubscribe();
        tokio::spawn(async move {
            control_receipt_upload_retry_drain_loop(
                receipt_upload_drain_state,
                &mut receipt_upload_drain_shutdown,
            )
            .await;
        });

        if self.state.fleet_hunt_publisher.is_some() {
            let sync_state = self.state.clone();
            let mut sync_shutdown = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                fleet_agent_secret_touch_sync_loop(sync_state, &mut sync_shutdown).await;
            });
        }

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
                tracing::info!("Agent API server shutting down");
            })
            .await
            .with_context(|| "Agent API server error")?;

        Ok(())
    }
}
