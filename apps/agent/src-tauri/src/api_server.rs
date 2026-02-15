//! Authenticated local API server for agent control and OpenClaw transport.

use crate::approval::{
    ApprovalQueue, ApprovalRequestInput, ApprovalResolveInput, ApprovalStatusResponse,
};
use crate::daemon::{DaemonManager, DaemonStatus};
use crate::openclaw::{
    GatewayDiscoverInput, GatewayRequestInput, GatewayUpsertRequest, ImportGatewayRequest,
    OpenClawManager,
};
use crate::policy::{evaluate_policy_check, PolicyCheckInput, PolicyCheckOutput};
use crate::session::SessionManager;
use crate::settings::Settings;
use anyhow::{Context, Result};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::IntoResponse;
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use futures::{Stream, StreamExt};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, RwLock};
use tokio_stream::wrappers::BroadcastStream;

#[derive(Clone)]
pub struct AgentApiServer {
    port: u16,
    state: Arc<AgentApiState>,
}

#[derive(Clone)]
struct AgentApiState {
    settings: Arc<RwLock<Settings>>,
    daemon_manager: Arc<DaemonManager>,
    session_manager: Arc<SessionManager>,
    approval_queue: Arc<ApprovalQueue>,
    openclaw: OpenClawManager,
    auth_token: String,
    http_client: reqwest::Client,
}

impl AgentApiServer {
    pub fn new(
        port: u16,
        settings: Arc<RwLock<Settings>>,
        daemon_manager: Arc<DaemonManager>,
        session_manager: Arc<SessionManager>,
        approval_queue: Arc<ApprovalQueue>,
        openclaw: OpenClawManager,
        auth_token: String,
    ) -> Self {
        Self {
            port,
            state: Arc::new(AgentApiState {
                settings,
                daemon_manager,
                session_manager,
                approval_queue,
                openclaw,
                auth_token,
                http_client: reqwest::Client::new(),
            }),
        }
    }

    pub async fn start(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let app = Router::new()
            .route("/api/v1/agent/health", get(agent_health))
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .route("/api/v1/agent/policy-check", post(agent_policy_check))
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
            .with_state(self.state.clone());

        let addr = SocketAddr::from(([127, 0, 0, 1], self.port));
        let listener = TcpListener::bind(addr)
            .await
            .with_context(|| format!("Failed to bind agent API server to {}", addr))?;

        tracing::info!(address = %addr, "Agent API server listening");

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

#[derive(Debug, Serialize)]
struct AgentHealthResponse {
    status: &'static str,
    daemon: DaemonStatus,
    session: crate::session::SessionState,
    openclaw: serde_json::Value,
    version: &'static str,
}

#[derive(Debug, Serialize)]
struct AgentSettingsResponse {
    daemon_port: u16,
    mcp_port: u16,
    agent_api_port: u16,
    enabled: bool,
    auto_start: bool,
    notifications_enabled: bool,
    notification_severity: String,
    debug_include_daemon_error_body: bool,
    openclaw_active_gateway_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AgentSettingsUpdate {
    enabled: Option<bool>,
    auto_start: Option<bool>,
    notifications_enabled: Option<bool>,
    notification_severity: Option<String>,
    debug_include_daemon_error_body: Option<bool>,
    #[serde(default, deserialize_with = "deserialize_optional_string_field")]
    openclaw_active_gateway_id: Option<Option<String>>,
}

#[derive(Debug, Deserialize)]
struct GatewayPatchInput {
    label: Option<String>,
    gateway_url: Option<String>,
    token: Option<String>,
    device_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ActiveGatewayUpdateInput {
    active_gateway_id: Option<String>,
}

async fn agent_health(
    State(state): State<Arc<AgentApiState>>,
) -> Result<Json<AgentHealthResponse>, (StatusCode, String)> {
    let daemon = state.daemon_manager.status().await;
    let session = state.session_manager.state().await;
    let openclaw = state.openclaw.list_gateways().await;

    Ok(Json(AgentHealthResponse {
        status: "ok",
        daemon,
        session,
        openclaw: serde_json::to_value(openclaw)
            .unwrap_or_else(|_| serde_json::json!({"error":"serialize_failed"})),
        version: env!("CARGO_PKG_VERSION"),
    }))
}

async fn get_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<AgentSettingsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings = state.settings.read().await;

    Ok(Json(AgentSettingsResponse {
        daemon_port: settings.daemon_port,
        mcp_port: settings.mcp_port,
        agent_api_port: settings.agent_api_port,
        enabled: settings.enabled,
        auto_start: settings.auto_start,
        notifications_enabled: settings.notifications_enabled,
        notification_severity: settings.notification_severity.clone(),
        debug_include_daemon_error_body: settings.debug_include_daemon_error_body,
        openclaw_active_gateway_id: settings.openclaw.active_gateway_id.clone(),
    }))
}

async fn update_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<AgentSettingsUpdate>,
) -> Result<Json<AgentSettingsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    {
        let mut settings = state.settings.write().await;

        if let Some(value) = input.enabled {
            settings.enabled = value;
        }
        if let Some(value) = input.auto_start {
            settings.auto_start = value;
        }
        if let Some(value) = input.notifications_enabled {
            settings.notifications_enabled = value;
        }
        if let Some(value) = input.notification_severity {
            settings.notification_severity = value;
        }
        if let Some(value) = input.debug_include_daemon_error_body {
            settings.debug_include_daemon_error_body = value;
        }
        if let Some(value) = input.openclaw_active_gateway_id {
            settings.openclaw.active_gateway_id = value;
        }

        settings
            .save()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    }

    get_settings(State(state), headers).await
}

async fn agent_policy_check(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<PolicyCheckInput>,
) -> Result<Json<PolicyCheckOutput>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let session_id = state.session_manager.session_id().await;
    let output = evaluate_policy_check(
        state.settings.clone(),
        &state.http_client,
        input,
        session_id,
    )
    .await;
    Ok(Json(output))
}

async fn list_gateways(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<crate::openclaw::GatewayListResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    Ok(Json(state.openclaw.list_gateways().await))
}

async fn create_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<GatewayUpsertRequest>,
) -> Result<Json<crate::openclaw::manager::GatewayView>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let created = state
        .openclaw
        .upsert_gateway(input)
        .await
        .map_err(internal_error)?;
    Ok(Json(created))
}

async fn patch_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(patch): Json<GatewayPatchInput>,
) -> Result<Json<crate::openclaw::manager::GatewayView>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let current = state
        .openclaw
        .list_gateways()
        .await
        .gateways
        .into_iter()
        .find(|g| g.id == id)
        .ok_or_else(|| (StatusCode::NOT_FOUND, "gateway not found".to_string()))?;

    let updated = state
        .openclaw
        .upsert_gateway(GatewayUpsertRequest {
            id: Some(current.id),
            label: patch.label.unwrap_or(current.label),
            gateway_url: patch.gateway_url.unwrap_or(current.gateway_url),
            token: patch.token,
            device_token: patch.device_token,
        })
        .await
        .map_err(internal_error)?;

    Ok(Json(updated))
}

async fn delete_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .openclaw
        .delete_gateway(&id)
        .await
        .map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn connect_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .openclaw
        .connect_gateway(&id)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn disconnect_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .openclaw
        .disconnect_gateway(&id)
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn set_active_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<ActiveGatewayUpdateInput>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .openclaw
        .set_active_gateway(input.active_gateway_id.clone())
        .await
        .map_err(internal_error)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "active_gateway_id": input.active_gateway_id,
    })))
}

async fn discover_gateways(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<GatewayDiscoverInput>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let payload = state
        .openclaw
        .gateway_discover(input.timeout_ms)
        .await
        .map_err(internal_error)?;
    Ok(Json(payload))
}

async fn probe_gateway(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<GatewayDiscoverInput>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let payload = state
        .openclaw
        .gateway_probe(input.timeout_ms)
        .await
        .map_err(internal_error)?;
    Ok(Json(payload))
}

async fn gateway_request(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<GatewayRequestInput>,
) -> Result<Json<Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let timeout_ms = input.timeout_ms.unwrap_or(12_000);

    let payload = state
        .openclaw
        .request_gateway(&input.gateway_id, input.method, input.params, timeout_ms)
        .await
        .map_err(internal_error)?;

    Ok(Json(payload))
}

async fn import_desktop_gateways(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(payload): Json<ImportGatewayRequest>,
) -> Result<Json<crate::openclaw::ImportGatewayResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let result = state
        .openclaw
        .import_desktop_gateways(payload)
        .await
        .map_err(internal_error)?;
    Ok(Json(result))
}

async fn openclaw_events(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let rx = state.openclaw.subscribe();
    let stream = sse_stream(rx);

    Ok(Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(Duration::from_secs(15))
            .text("keepalive"),
    ))
}

fn sse_stream(
    rx: broadcast::Receiver<crate::openclaw::OpenClawAgentEvent>,
) -> impl Stream<Item = Result<Event, std::convert::Infallible>> {
    BroadcastStream::new(rx).filter_map(|msg| async move {
        match msg {
            Ok(event) => {
                let payload = serde_json::to_string(&event)
                    .unwrap_or_else(|_| "{\"type\":\"serialize_error\"}".to_string());
                Some(Ok(Event::default().data(payload)))
            }
            Err(_) => None,
        }
    })
}

async fn create_approval_request(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<ApprovalRequestInput>,
) -> Result<Json<ApprovalStatusResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    // Reject critical severity actions -- they are not approvable.
    if input.severity.eq_ignore_ascii_case("critical") {
        return Err((
            StatusCode::UNPROCESSABLE_ENTITY,
            "Critical severity actions are not approvable".to_string(),
        ));
    }

    let request = state
        .approval_queue
        .submit(input)
        .await
        .map_err(|err| match err {
            crate::approval::ApprovalError::QueueFull => {
                (StatusCode::SERVICE_UNAVAILABLE, err.to_string())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;
    Ok(Json(ApprovalStatusResponse::from(&request)))
}

async fn get_approval_status(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApprovalStatusResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let status = state.approval_queue.get_status(&id).await.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "Approval request not found".to_string(),
        )
    })?;

    Ok(Json(status))
}

async fn resolve_approval(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(input): Json<ApprovalResolveInput>,
) -> Result<Json<ApprovalStatusResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let result = state
        .approval_queue
        .resolve(&id, input.resolution)
        .await
        .map_err(|err| match err {
            crate::approval::ApprovalError::NotFound => (
                StatusCode::NOT_FOUND,
                "Approval request not found".to_string(),
            ),
            crate::approval::ApprovalError::AlreadyResolved => (
                StatusCode::CONFLICT,
                "Approval request already resolved".to_string(),
            ),
            crate::approval::ApprovalError::Expired => {
                (StatusCode::GONE, "Approval request expired".to_string())
            }
            crate::approval::ApprovalError::QueueFull => (
                StatusCode::SERVICE_UNAVAILABLE,
                "Approval queue is full".to_string(),
            ),
        })?;

    Ok(Json(result))
}

async fn list_pending_approvals(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<ApprovalStatusResponse>>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let pending = state.approval_queue.list_pending().await;
    Ok(Json(pending))
}

fn require_auth(headers: &HeaderMap, state: &AgentApiState) -> Result<(), (StatusCode, String)> {
    let Some(auth) = headers.get("authorization").and_then(|v| v.to_str().ok()) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "missing authorization header".to_string(),
        ));
    };

    let Some(token) = auth.strip_prefix("Bearer ") else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid authorization scheme".to_string(),
        ));
    };

    if token.trim() != state.auth_token {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid authorization token".to_string(),
        ));
    }

    Ok(())
}

fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    tracing::error!(error = %err, "Agent API error");
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn deserialize_optional_string_field<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    match value {
        None => Ok(Some(None)),
        Some(serde_json::Value::String(value)) => Ok(Some(Some(value))),
        Some(other) => Err(serde::de::Error::custom(format!(
            "expected string or null, got {}",
            other
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::DaemonConfig;
    use std::path::PathBuf;
    use tower::ServiceExt;

    fn test_state() -> AgentApiState {
        let settings = Arc::new(RwLock::new(Settings::default()));
        let daemon_manager = Arc::new(DaemonManager::new(DaemonConfig {
            binary_path: PathBuf::from("/tmp/hushd"),
            port: 9876,
            policy_path: PathBuf::from("/tmp/policy.yaml"),
        }));
        let session_manager = Arc::new(crate::session::SessionManager::new());
        let approval_queue = Arc::new(crate::approval::ApprovalQueue::new());
        let openclaw = OpenClawManager::new(settings.clone());

        AgentApiState {
            settings,
            daemon_manager,
            session_manager,
            approval_queue,
            openclaw,
            auth_token: "test-token".to_string(),
            http_client: reqwest::Client::new(),
        }
    }

    #[test]
    fn auth_accepts_bearer_token() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer test-token"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build authorization header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_ok());
    }

    #[test]
    fn auth_rejects_missing_headers() {
        let state = test_state();
        let headers = HeaderMap::new();
        let result = require_auth(&headers, &state);
        assert!(result.is_err());
    }

    #[test]
    fn auth_rejects_invalid_tokens() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            "Bearer wrong-token"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build authorization header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_err());
    }

    #[test]
    fn settings_update_distinguishes_absent_vs_null_active_gateway_id() {
        let absent: AgentSettingsUpdate = match serde_json::from_str("{}") {
            Ok(value) => value,
            Err(err) => panic!("failed to parse absent payload: {}", err),
        };
        assert!(absent.openclaw_active_gateway_id.is_none());

        let explicit_null: AgentSettingsUpdate =
            match serde_json::from_str(r#"{"openclaw_active_gateway_id":null}"#) {
                Ok(value) => value,
                Err(err) => panic!("failed to parse null payload: {}", err),
            };
        assert!(matches!(
            explicit_null.openclaw_active_gateway_id,
            Some(None)
        ));

        let explicit_value: AgentSettingsUpdate =
            match serde_json::from_str(r#"{"openclaw_active_gateway_id":"gw-1"}"#) {
                Ok(value) => value,
                Err(err) => panic!("failed to parse value payload: {}", err),
            };
        assert!(matches!(
            explicit_value.openclaw_active_gateway_id,
            Some(Some(value)) if value == "gw-1"
        ));
    }

    #[tokio::test]
    async fn approval_status_route_matches_uuid_path() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/approval/{id}/status", get(get_approval_status))
            .with_state(state);

        let request = axum::http::Request::builder()
            .uri("/api/v1/approval/550e8400-e29b-41d4-a716-446655440000/status")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));

        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));

        // Should be 404 (approval not found) rather than 405/routing failure.
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "Route should match the UUID path param and return 404 (not found), not a routing error"
        );
    }
}
