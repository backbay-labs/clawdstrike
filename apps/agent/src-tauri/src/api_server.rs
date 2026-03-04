//! Authenticated local API server for agent control and OpenClaw transport.

use crate::agent_auth::rotate_local_api_token;
use crate::approval::{
    ApprovalQueue, ApprovalRequestInput, ApprovalResolveInput, ApprovalStatusResponse,
};
use crate::daemon::{AuditQueue, DaemonManager, DaemonStatus};
use crate::openclaw::{
    GatewayDiscoverInput, GatewayRequestInput, GatewayUpsertRequest, ImportGatewayRequest,
    OpenClawManager,
};
use crate::policy::{evaluate_policy_check, PolicyCheckInput, PolicyCheckOutput};
use crate::runtime_registry::{
    register_runtime_agent, resolve_effective_endpoint_agent_id, RuntimeRegistrationInput,
};
use crate::security::auth::constant_time_eq_token;
use crate::session::SessionManager;
use crate::settings::{IntegrationSettings, RuntimeAgentRegistration, Settings};
use crate::updater::{HushdUpdater, OtaStatus};
use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::DefaultBodyLimit;
use axum::extract::{Form, Path, Request, State};
use axum::http::header::{
    ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE,
};
use axum::http::{uri::Authority, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::Html;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use axum::{Json, Router};
use futures::{Stream, StreamExt, TryStreamExt};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex, RwLock as StdRwLock};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::{broadcast, Mutex, RwLock};
use tokio_stream::wrappers::BroadcastStream;
use tower_http::services::{ServeDir, ServeFile};

const HUSHD_AUTHORIZATION_HEADER: &str = "x-hushd-authorization";
const AGENT_AUTH_COOKIE_NAME: &str = "clawdstrike_agent_auth";
const POLICY_VERSION_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(5);
const POLICY_VERSION_FETCH_TIMEOUT: Duration = Duration::from_millis(200);
const POLICY_VERSION_REFRESH_IN_FLIGHT_TIMEOUT: Duration = Duration::from_secs(20);
const AGENT_API_MAX_BODY_BYTES: usize = 256 * 1024;
const APPROVAL_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const APPROVAL_RATE_LIMIT_BURST_WINDOW: Duration = Duration::from_secs(1);
const APPROVAL_RATE_LIMIT_PER_MINUTE: usize = 30;
const APPROVAL_RATE_LIMIT_BURST: usize = 10;
const ROUTE_RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const ROUTE_RATE_LIMIT_UI_BOOTSTRAP_START: usize = 20;
const ROUTE_RATE_LIMIT_UI_BOOTSTRAP_VERIFY: usize = 60;
const ROUTE_RATE_LIMIT_POLICY_CHECK: usize = 1200;
const ROUTE_RATE_LIMIT_INTEGRATION_TEST: usize = 30;
const ROUTE_RATE_LIMIT_OPENCLAW_REQUEST: usize = 120;
const UI_BOOTSTRAP_TTL: Duration = Duration::from_secs(60);
const UI_BOOTSTRAP_MAX_ATTEMPTS: u8 = 5;
const UI_BOOTSTRAP_MAX_SESSIONS: usize = 32;

#[derive(Clone)]
pub struct AgentApiServer {
    port: u16,
    state: Arc<AgentApiState>,
}

#[derive(Clone)]
pub struct AgentApiServerDeps {
    pub settings: Arc<RwLock<Settings>>,
    pub daemon_manager: Arc<DaemonManager>,
    pub session_manager: Arc<SessionManager>,
    pub approval_queue: Arc<ApprovalQueue>,
    pub audit_queue: Arc<AuditQueue>,
    pub openclaw: OpenClawManager,
    pub updater: Arc<HushdUpdater>,
    pub auth_token: String,
}

#[derive(Clone)]
struct AgentApiState {
    settings: Arc<RwLock<Settings>>,
    daemon_manager: Arc<DaemonManager>,
    session_manager: Arc<SessionManager>,
    approval_queue: Arc<ApprovalQueue>,
    audit_queue: Arc<AuditQueue>,
    openclaw: OpenClawManager,
    updater: Arc<HushdUpdater>,
    auth_token: Arc<StdRwLock<String>>,
    previous_auth_token: Arc<StdMutex<Option<PreviousAuthToken>>>,
    token_grace_minutes: Arc<StdRwLock<u32>>,
    http_client: reqwest::Client,
    policy_version_cache: Arc<RwLock<PolicyVersionCache>>,
    approval_rate_limiter: Arc<Mutex<ApprovalSubmissionLimiter>>,
    ui_bootstrap_start_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    ui_bootstrap_verify_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    policy_check_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    integration_test_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    openclaw_request_rate_limiter: Arc<Mutex<RouteRateLimiter>>,
    ui_bootstrap_sessions: Arc<Mutex<HashMap<String, UiBootstrapSession>>>,
}

#[derive(Debug, Default)]
struct PolicyVersionCache {
    value: Option<String>,
    last_refresh_at: Option<std::time::Instant>,
    refresh_in_flight: bool,
    refresh_started_at: Option<std::time::Instant>,
}

impl PolicyVersionCache {
    fn mark_refresh_started_if_due(&mut self, now: std::time::Instant) -> bool {
        if self.refresh_in_flight {
            let stuck = self
                .refresh_started_at
                .map(|started| {
                    now.duration_since(started) >= POLICY_VERSION_REFRESH_IN_FLIGHT_TIMEOUT
                })
                .unwrap_or(true);

            if stuck {
                self.refresh_in_flight = false;
                self.refresh_started_at = None;
            }
        }

        let stale = self
            .last_refresh_at
            .map(|last| now.duration_since(last) >= POLICY_VERSION_CACHE_REFRESH_INTERVAL)
            .unwrap_or(true);

        if !stale || self.refresh_in_flight {
            return false;
        }

        self.refresh_in_flight = true;
        self.refresh_started_at = Some(now);
        // Mark immediately to avoid concurrent /health calls all spawning refresh tasks.
        self.last_refresh_at = Some(now);
        true
    }

    fn finish_refresh(&mut self, fetched: Option<String>, now: std::time::Instant) {
        if let Some(version) = fetched {
            self.value = Some(version);
        }
        self.last_refresh_at = Some(now);
        self.refresh_in_flight = false;
        self.refresh_started_at = None;
    }
}

#[derive(Debug, Default)]
struct ApprovalSubmissionLimiter {
    minute_events: VecDeque<Instant>,
    burst_events: VecDeque<Instant>,
}

#[derive(Debug, Clone)]
struct UiBootstrapSession {
    code_normalized: String,
    next_path: String,
    created_at: Instant,
    expires_at: Instant,
    attempts: u8,
}

#[derive(Debug, Clone)]
struct PreviousAuthToken {
    token: String,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct RouteRateLimiter {
    events: VecDeque<Instant>,
}

#[derive(Debug, Deserialize)]
struct UiBootstrapStartInput {
    #[serde(default)]
    next_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct UiBootstrapStartResponse {
    session_id: String,
    user_code: String,
    expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
struct UiBootstrapVerifyInput {
    session_id: String,
    user_code: String,
}

impl ApprovalSubmissionLimiter {
    fn allow_now(&mut self, now: Instant) -> std::result::Result<(), u64> {
        while self
            .minute_events
            .front()
            .is_some_and(|ts| now.duration_since(*ts) >= APPROVAL_RATE_LIMIT_WINDOW)
        {
            let _ = self.minute_events.pop_front();
        }
        while self
            .burst_events
            .front()
            .is_some_and(|ts| now.duration_since(*ts) >= APPROVAL_RATE_LIMIT_BURST_WINDOW)
        {
            let _ = self.burst_events.pop_front();
        }

        if self.minute_events.len() >= APPROVAL_RATE_LIMIT_PER_MINUTE {
            if let Some(oldest) = self.minute_events.front().copied() {
                let retry_after = APPROVAL_RATE_LIMIT_WINDOW
                    .saturating_sub(now.duration_since(oldest))
                    .as_secs()
                    .max(1);
                return Err(retry_after);
            }
            return Err(1);
        }

        if self.burst_events.len() >= APPROVAL_RATE_LIMIT_BURST {
            if let Some(oldest) = self.burst_events.front().copied() {
                let retry_after = APPROVAL_RATE_LIMIT_BURST_WINDOW
                    .saturating_sub(now.duration_since(oldest))
                    .as_secs()
                    .max(1);
                return Err(retry_after);
            }
            return Err(1);
        }

        self.minute_events.push_back(now);
        self.burst_events.push_back(now);
        Ok(())
    }
}

impl RouteRateLimiter {
    fn allow_now(&mut self, now: Instant, window: Duration, limit: usize) -> std::result::Result<(), u64> {
        while self
            .events
            .front()
            .is_some_and(|ts| now.duration_since(*ts) >= window)
        {
            let _ = self.events.pop_front();
        }

        if self.events.len() >= limit {
            if let Some(oldest) = self.events.front().copied() {
                let retry_after = window
                    .saturating_sub(now.duration_since(oldest))
                    .as_secs()
                    .max(1);
                return Err(retry_after);
            }
            return Err(1);
        }

        self.events.push_back(now);
        Ok(())
    }
}

impl AgentApiServer {
    pub fn new(port: u16, deps: AgentApiServerDeps) -> Self {
        let token_grace_minutes = deps
            .settings
            .try_read()
            .map(|settings| settings.local_api_security.token_grace_minutes.max(1))
            .unwrap_or(15);
        Self {
            port,
            state: Arc::new(AgentApiState {
                settings: deps.settings,
                daemon_manager: deps.daemon_manager,
                session_manager: deps.session_manager,
                approval_queue: deps.approval_queue,
                audit_queue: deps.audit_queue,
                openclaw: deps.openclaw,
                updater: deps.updater,
                auth_token: Arc::new(StdRwLock::new(deps.auth_token)),
                previous_auth_token: Arc::new(StdMutex::new(None)),
                token_grace_minutes: Arc::new(StdRwLock::new(token_grace_minutes)),
                http_client: reqwest::Client::new(),
                policy_version_cache: Arc::new(RwLock::new(PolicyVersionCache::default())),
                approval_rate_limiter: Arc::new(Mutex::new(ApprovalSubmissionLimiter::default())),
                ui_bootstrap_start_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                ui_bootstrap_verify_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                policy_check_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                integration_test_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                openclaw_request_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
                ui_bootstrap_sessions: Arc::new(Mutex::new(HashMap::new())),
            }),
        }
    }

    pub async fn start(self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<()> {
        let mut app = Router::new()
            .route("/health", get(proxy_daemon_get))
            .route("/api/v1/audit", get(proxy_daemon_get))
            .route("/api/v1/audit/stats", get(proxy_daemon_get))
            .route("/api/v1/policy", get(proxy_daemon_get))
            .route("/api/v1/agents/status", get(proxy_daemon_get))
            .route("/api/v1/events", get(proxy_daemon_events))
            .route("/api/v1/siem/exporters", get(proxy_daemon_get))
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

async fn agent_web_ui_fallback() -> Html<&'static str> {
    Html(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawdstrike Agent Web UI</title>
  <style>
    :root {
      color-scheme: light dark;
      --bg: #0d1117;
      --fg: #e6edf3;
      --muted: #8b949e;
      --accent: #2f81f7;
      --card: #161b22;
      --line: #30363d;
    }
    body {
      margin: 0;
      padding: 24px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--fg);
    }
    main {
      max-width: 760px;
      margin: 0 auto;
      border: 1px solid var(--line);
      background: var(--card);
      border-radius: 10px;
      padding: 20px;
    }
    h1 { margin-top: 0; font-size: 1.4rem; }
    p { color: var(--muted); line-height: 1.5; }
    code {
      background: rgba(255, 255, 255, 0.08);
      border-radius: 6px;
      padding: 2px 6px;
    }
    .tabs {
      display: flex;
      gap: 8px;
      margin: 14px 0 16px;
      flex-wrap: wrap;
    }
    .tab {
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 6px 12px;
      font-size: 0.9rem;
      color: var(--muted);
      text-decoration: none;
    }
    .tab.active {
      border-color: var(--accent);
      color: #d7e8ff;
      background: rgba(47, 129, 247, 0.12);
    }
    .hidden {
      display: none;
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 14px;
      background: rgba(255, 255, 255, 0.03);
    }
    h2 {
      margin: 0 0 8px;
      font-size: 1.05rem;
    }
    ul { margin: 0.75rem 0 0; padding-left: 1.2rem; }
    a { color: var(--accent); text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <main>
    <h1>Clawdstrike Agent Web UI</h1>
    <p>This is the local fallback UI. If you expected the control console on <code>localhost:3100</code>, start it manually during development.</p>

    <nav class="tabs" aria-label="Agent web UI sections">
      <a href="#/" class="tab" data-route="/">Overview</a>
      <a href="#/settings/siem" class="tab" data-route="/settings/siem">SIEM Export</a>
      <a href="#/settings/webhooks" class="tab" data-route="/settings/webhooks">Webhooks</a>
    </nav>

    <section class="panel" data-view="/">
      <h2>Overview</h2>
      <ul>
        <li>Agent health (auth required): <a href="/api/v1/agent/health"><code>/api/v1/agent/health</code></a></li>
        <li>Agent settings (auth required): <a href="/api/v1/agent/settings"><code>/api/v1/agent/settings</code></a></li>
      </ul>
    </section>

    <section class="panel hidden" data-view="/settings/siem">
      <h2>SIEM Export</h2>
      <p>Configure SIEM providers from the control console when available. This fallback page confirms the requested route and keeps agent diagnostics available.</p>
      <ul>
        <li>Requested route: <code>#/settings/siem</code></li>
        <li>Preferred full dashboard URL: <code>http://127.0.0.1:3100/settings/siem</code></li>
      </ul>
    </section>

    <section class="panel hidden" data-view="/settings/webhooks">
      <h2>Webhooks</h2>
      <p>Configure webhook forwarding from the control console when available. This fallback page confirms the requested route and keeps agent diagnostics available.</p>
      <ul>
        <li>Requested route: <code>#/settings/webhooks</code></li>
        <li>Preferred full dashboard URL: <code>http://127.0.0.1:3100/settings/webhooks</code></li>
      </ul>
    </section>
  </main>
  <script>
    function normalizeRoute(hash) {
      if (!hash || hash === "#") return "/";
      const raw = hash.startsWith("#") ? hash.slice(1) : hash;
      return raw.startsWith("/") ? raw : `/${raw}`;
    }

    function renderRoute() {
      const route = normalizeRoute(window.location.hash);
      const tabs = document.querySelectorAll("[data-route]");
      const views = document.querySelectorAll("[data-view]");
      const knownRoutes = new Set(["/", "/settings/siem", "/settings/webhooks"]);
      const activeRoute = knownRoutes.has(route) ? route : "/";

      tabs.forEach((tab) => {
        tab.classList.toggle("active", tab.dataset.route === activeRoute);
      });
      views.forEach((view) => {
        view.classList.toggle("hidden", view.dataset.view !== activeRoute);
      });
    }

    window.addEventListener("hashchange", renderRoute);
    renderRoute();
  </script>
</body>
</html>"##,
    )
}

fn control_console_dist_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(override_path) = std::env::var("CLAWDSTRIKE_CONTROL_CONSOLE_DIST") {
        candidates.push(PathBuf::from(override_path));
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            candidates.push(exe_dir.join("control-console"));
            candidates.push(exe_dir.join("resources").join("control-console"));

            if let Some(contents_dir) = exe_dir.parent() {
                candidates.push(contents_dir.join("Resources").join("control-console"));
                candidates.push(
                    contents_dir
                        .join("Resources")
                        .join("resources")
                        .join("control-console"),
                );
            }
        }
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let root = PathBuf::from(manifest_dir);
        candidates.push(root.join("resources").join("control-console"));
        candidates.push(root.join("../../control-console/dist"));
    }

    candidates
}

fn resolve_control_console_dist() -> Option<PathBuf> {
    control_console_dist_candidates()
        .into_iter()
        .find(|candidate| candidate.join("index.html").is_file())
}

fn build_daemon_proxy_target(daemon_url: &str, uri: &Uri) -> Result<String, (StatusCode, String)> {
    let path_and_query = uri
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or_else(|| uri.path());

    if !path_and_query.starts_with('/') {
        return Err((StatusCode::BAD_REQUEST, "invalid proxy path".to_string()));
    }

    Ok(format!(
        "{}{}",
        daemon_url.trim_end_matches('/'),
        path_and_query
    ))
}

fn merged_authorization_header(
    request_headers: &HeaderMap,
    daemon_api_key: Option<&str>,
) -> Option<String> {
    if let Some(value) = request_headers
        .get(HUSHD_AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_string());
    }

    if let Some(value) = request_headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_string());
    }

    daemon_api_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|key| format!("Bearer {}", key))
}

fn auth_cookie_header_value(auth_token: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict{}",
        AGENT_AUTH_COOKIE_NAME, auth_token, secure_flag
    )
}

fn set_ui_auth_cookie(response: &mut Response, auth_token: &str, secure: bool) {
    match HeaderValue::from_str(&auth_cookie_header_value(auth_token, secure)) {
        Ok(value) => {
            response.headers_mut().append(SET_COOKIE, value);
        }
        Err(err) => {
            tracing::warn!(error = %err, "Failed to build UI auth cookie header");
        }
    }
}

fn request_is_secure_uri(headers: &HeaderMap, uri: &Uri) -> bool {
    if uri.scheme_str() == Some("https") {
        return true;
    }
    if !is_local_host_header(headers) {
        return false;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

fn request_is_secure(headers: &HeaderMap, request: &Request) -> bool {
    request_is_secure_uri(headers, request.uri())
}

fn is_local_host_header(headers: &HeaderMap) -> bool {
    let Some(host) = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return false;
    };

    let host_only = host
        .parse::<Authority>()
        .map(|authority| authority.host().to_ascii_lowercase())
        .unwrap_or_else(|_| host.to_ascii_lowercase());
    let host_only = host_only
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    host_only == "localhost" || host_only == "127.0.0.1" || host_only == "::1"
}

fn has_query_param(uri: &Uri, param_name: &str) -> bool {
    let Some(query) = uri.query() else {
        return false;
    };

    query.split('&').any(|pair| {
        if pair.is_empty() {
            return false;
        }
        let (name, _) = pair.split_once('=').unwrap_or((pair, ""));
        name == param_name
    })
}

async fn attach_ui_auth_cookie(
    State(state): State<Arc<AgentApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let secure_cookie = request_is_secure(request.headers(), &request);
    if !secure_cookie && !is_local_host_header(request.headers()) {
        return (
            StatusCode::FORBIDDEN,
            "Non-localhost dashboard access requires HTTPS",
        )
            .into_response();
    }

    if has_query_param(request.uri(), "agent_token") {
        tracing::warn!(
            path = %request.uri().path(),
            "Rejected deprecated query-based UI bootstrap token"
        );
        return (
            StatusCode::BAD_REQUEST,
            "Query-based UI bootstrap is disabled",
        )
            .into_response();
    }

    if require_auth(request.headers(), &state).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            "Missing authorization token for /ui",
        )
            .into_response();
    }

    let mut response = next.run(request).await;
    let token = current_auth_token(&state);
    set_ui_auth_cookie(&mut response, &token, secure_cookie);
    response
}

fn query_param(uri: &Uri, param_name: &str) -> Option<String> {
    let query = uri.query()?;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name == param_name {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return None;
            }
            return Some(trimmed.to_string());
        }
    }
    None
}

fn sanitize_ui_next_path(candidate: Option<&str>) -> String {
    let raw = candidate.unwrap_or("/ui").trim();
    if raw.is_empty() {
        return "/ui".to_string();
    }
    if raw.contains('\n') || raw.contains('\r') {
        return "/ui".to_string();
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return "/ui".to_string();
    }
    if !raw.starts_with("/ui") {
        return "/ui".to_string();
    }
    raw.to_string()
}

fn normalize_bootstrap_code(raw: &str) -> Option<String> {
    let normalized: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if normalized.len() != 8 {
        return None;
    }
    Some(normalized)
}

fn generate_ui_bootstrap_code() -> (String, String) {
    let random = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .to_ascii_uppercase();
    let normalized = random.chars().take(8).collect::<String>();
    let display = format!("{}-{}", &normalized[..4], &normalized[4..]);
    (normalized, display)
}

fn is_valid_bootstrap_session_id(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 64
        && candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn prune_ui_bootstrap_sessions(sessions: &mut HashMap<String, UiBootstrapSession>, now: Instant) {
    sessions.retain(|_, session| {
        session.expires_at > now && session.attempts < UI_BOOTSTRAP_MAX_ATTEMPTS
    });
    while sessions.len() > UI_BOOTSTRAP_MAX_SESSIONS {
        let Some((oldest_key, _)) = sessions
            .iter()
            .min_by_key(|(_, session)| session.created_at)
            .map(|(id, session)| (id.clone(), session.created_at))
        else {
            break;
        };
        let _ = sessions.remove(&oldest_key);
    }
}

async fn start_ui_bootstrap(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<UiBootstrapStartInput>,
) -> Result<Json<UiBootstrapStartResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let now = Instant::now();
    let session_id = uuid::Uuid::new_v4().to_string();
    let (code_normalized, user_code) = generate_ui_bootstrap_code();
    let next_path = sanitize_ui_next_path(input.next_path.as_deref());

    {
        let mut sessions = state.ui_bootstrap_sessions.lock().await;
        prune_ui_bootstrap_sessions(&mut sessions, now);
        sessions.insert(
            session_id.clone(),
            UiBootstrapSession {
                code_normalized,
                next_path,
                created_at: now,
                expires_at: now + UI_BOOTSTRAP_TTL,
                attempts: 0,
            },
        );
    }

    Ok(Json(UiBootstrapStartResponse {
        session_id,
        user_code,
        expires_in_seconds: UI_BOOTSTRAP_TTL.as_secs(),
    }))
}

async fn ui_bootstrap_page(uri: Uri) -> impl IntoResponse {
    let session_id = query_param(&uri, "session_id");
    let valid_session = session_id
        .as_deref()
        .map(is_valid_bootstrap_session_id)
        .unwrap_or(false);
    if !valid_session {
        return (
            StatusCode::BAD_REQUEST,
            "Missing or invalid bootstrap session id",
        )
            .into_response();
    }

    Html(
        r##"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Clawdstrike Agent Login</title>
  <style>
    body {
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 24px;
      box-sizing: border-box;
    }
    .card {
      width: 100%;
      max-width: 420px;
      background: #111827;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 12px 28px rgba(2, 6, 23, 0.35);
    }
    h1 {
      margin: 0 0 10px 0;
      font-size: 1.25rem;
    }
    p {
      margin: 0 0 14px 0;
      color: #94a3b8;
      line-height: 1.4;
    }
    label {
      display: block;
      font-weight: 600;
      margin-bottom: 8px;
    }
    input[type="text"] {
      width: 100%;
      box-sizing: border-box;
      border: 1px solid #475569;
      background: #0b1220;
      color: #e2e8f0;
      border-radius: 8px;
      font-size: 1rem;
      padding: 10px 12px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }
    button {
      margin-top: 14px;
      width: 100%;
      border: 0;
      border-radius: 8px;
      padding: 10px 12px;
      font-size: 0.95rem;
      font-weight: 600;
      background: #2563eb;
      color: #f8fafc;
      cursor: pointer;
    }
    .hint {
      margin-top: 12px;
      font-size: 0.85rem;
      color: #64748b;
    }
  </style>
</head>
<body>
  <main class="card">
    <h1>Verify Local Browser Session</h1>
    <p>Enter the one-time code shown by the agent tray to sign in.</p>
    <form method="post" action="/ui/bootstrap">
      <input id="session_id" type="hidden" name="session_id" />
      <label for="user_code">One-time code</label>
      <input id="user_code" name="user_code" type="text" required autocomplete="one-time-code" inputmode="latin-prose" />
      <button type="submit">Continue to Dashboard</button>
    </form>
    <div class="hint">Codes expire after 60 seconds and can only be used once.</div>
  </main>
  <script>
    const params = new URLSearchParams(window.location.search);
    const sessionId = params.get("session_id") || "";
    const field = document.getElementById("session_id");
    if (field) field.value = sessionId;
  </script>
</body>
</html>"##,
    )
    .into_response()
}

async fn ui_bootstrap_verify(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    uri: Uri,
    Form(input): Form<UiBootstrapVerifyInput>,
) -> Response {
    let secure_cookie = request_is_secure_uri(&headers, &uri);
    if !secure_cookie && !is_local_host_header(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "Non-localhost dashboard access requires HTTPS",
        )
            .into_response();
    }

    if !is_valid_bootstrap_session_id(input.session_id.trim()) {
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired bootstrap code",
        )
            .into_response();
    }
    let Some(code_normalized) = normalize_bootstrap_code(&input.user_code) else {
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired bootstrap code",
        )
            .into_response();
    };

    let now = Instant::now();
    let session_id = input.session_id.trim().to_string();

    let next_path = {
        let mut sessions = state.ui_bootstrap_sessions.lock().await;
        prune_ui_bootstrap_sessions(&mut sessions, now);

        let Some(session) = sessions.get_mut(&session_id) else {
            return (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired bootstrap code",
            )
                .into_response();
        };
        if !constant_time_eq_token(&code_normalized, &session.code_normalized) {
            session.attempts = session.attempts.saturating_add(1);
            if session.attempts >= UI_BOOTSTRAP_MAX_ATTEMPTS {
                let _ = sessions.remove(&session_id);
            }
            return (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired bootstrap code",
            )
                .into_response();
        }
        let next = session.next_path.clone();
        let _ = sessions.remove(&session_id);
        next
    };

    let mut response = StatusCode::SEE_OTHER.into_response();
    match HeaderValue::from_str(&next_path) {
        Ok(value) => {
            response.headers_mut().insert(LOCATION, value);
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                location = %next_path,
                "Failed to build bootstrap redirect location"
            );
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_static("/ui"));
        }
    }
    let token = current_auth_token(&state);
    set_ui_auth_cookie(&mut response, &token, secure_cookie);
    response
}

async fn send_daemon_get_request(
    state: &AgentApiState,
    request_headers: &HeaderMap,
    uri: &Uri,
) -> Result<reqwest::Response, (StatusCode, String)> {
    let (daemon_url, daemon_api_key) = {
        let settings = state.settings.read().await;
        (settings.daemon_url(), settings.api_key.clone())
    };

    let target_url = build_daemon_proxy_target(&daemon_url, uri)?;
    let mut request = state.http_client.get(target_url);

    if let Some(value) = request_headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
    {
        request = request.header(ACCEPT.as_str(), value);
    }

    if let Some(auth_header) =
        merged_authorization_header(request_headers, daemon_api_key.as_deref())
    {
        request = request.header(AUTHORIZATION.as_str(), auth_header);
    }

    request
        .send()
        .await
        .map_err(|err| internal_error(err.into()))
}

async fn proxy_http_response(
    response: reqwest::Response,
) -> Result<Response, (StatusCode, String)> {
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = response.headers().get(CONTENT_TYPE).cloned();
    let body = response
        .bytes()
        .await
        .map_err(|err| internal_error(err.into()))?;

    let mut headers = HeaderMap::new();
    if let Some(value) = content_type {
        headers.insert(CONTENT_TYPE, value);
    }

    Ok((status, headers, body).into_response())
}

async fn proxy_daemon_get(
    State(state): State<Arc<AgentApiState>>,
    mut headers: HeaderMap,
    uri: Uri,
) -> Result<Response, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    // Do not forward the local agent auth token to hushd.
    // A caller can provide a daemon token via `X-Hushd-Authorization`; otherwise we
    // fall back to the configured daemon API key from settings.
    headers.remove(AUTHORIZATION);
    let response = send_daemon_get_request(&state, &headers, &uri).await?;
    proxy_http_response(response).await
}

async fn proxy_daemon_events(
    State(state): State<Arc<AgentApiState>>,
    mut headers: HeaderMap,
    uri: Uri,
) -> Result<Response, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    // Do not forward the local agent auth token to hushd.
    // A caller can provide a daemon token via `X-Hushd-Authorization`; otherwise we
    // fall back to the configured daemon API key from settings.
    headers.remove(AUTHORIZATION);
    let response = send_daemon_get_request(&state, &headers, &uri).await?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);

    if !status.is_success() {
        return proxy_http_response(response).await;
    }

    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .cloned()
        .unwrap_or_else(|| HeaderValue::from_static("text/event-stream"));
    let stream = response.bytes_stream().map_err(std::io::Error::other);
    let body = Body::from_stream(stream);

    let mut out_headers = HeaderMap::new();
    out_headers.insert(CONTENT_TYPE, content_type);
    out_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));
    out_headers.insert(CONNECTION, HeaderValue::from_static("keep-alive"));

    Ok((status, out_headers, body).into_response())
}

fn normalize_integration_settings(settings: &mut IntegrationSettings) {
    settings.siem.provider = settings.siem.provider.trim().to_ascii_lowercase();
    if settings.siem.provider.is_empty() {
        settings.siem.provider = "datadog".to_string();
    }
    settings.siem.endpoint = settings.siem.endpoint.trim().to_string();
    settings.siem.api_key = settings.siem.api_key.trim().to_string();
    settings.webhooks.url = settings.webhooks.url.trim().to_string();
    settings.webhooks.secret = settings.webhooks.secret.trim().to_string();

    if settings.siem.endpoint.is_empty() && settings.siem.api_key.is_empty() {
        settings.siem.enabled = false;
    }
    if settings.webhooks.url.is_empty() {
        settings.webhooks.enabled = false;
    }
}

fn validate_integration_settings(
    settings: &IntegrationSettings,
) -> std::result::Result<(), String> {
    let provider = settings.siem.provider.as_str();
    let provider_supported = matches!(
        provider,
        "datadog" | "splunk" | "elastic" | "sumo_logic" | "custom"
    );
    if !provider_supported {
        return Err(format!(
            "Unsupported SIEM provider '{}'",
            settings.siem.provider
        ));
    }

    if settings.siem.enabled {
        if settings.siem.endpoint.is_empty() {
            return Err("SIEM endpoint is required when SIEM is enabled".to_string());
        }
        let key_required = matches!(provider, "datadog" | "splunk" | "elastic");
        if key_required && settings.siem.api_key.is_empty() {
            return Err(format!(
                "SIEM API key is required for provider '{}'",
                settings.siem.provider
            ));
        }
    }

    if settings.webhooks.enabled && settings.webhooks.url.is_empty() {
        return Err("Webhook URL is required when webhook forwarding is enabled".to_string());
    }

    Ok(())
}

async fn fetch_daemon_exporter_status(state: &AgentApiState) -> Option<Value> {
    let (daemon_url, daemon_api_key) = {
        let settings = state.settings.read().await;
        (settings.daemon_url(), settings.api_key.clone())
    };

    let url = format!("{}/api/v1/siem/exporters", daemon_url.trim_end_matches('/'));
    let mut request = state.http_client.get(url);

    if let Some(key) = daemon_api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", key));
    }

    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    response.json::<Value>().await.ok()
}

async fn fetch_daemon_policy_version(state: &AgentApiState) -> Option<String> {
    let (daemon_url, daemon_api_key) = {
        let settings = state.settings.read().await;
        (settings.daemon_url(), settings.api_key.clone())
    };

    let url = format!("{}/api/v1/policy", daemon_url.trim_end_matches('/'));
    let mut request = state.http_client.get(url);

    if let Some(key) = daemon_api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", key));
    }

    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    let json = response.json::<Value>().await.ok()?;
    json.get("version")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

async fn cached_policy_version_for_health(state: &Arc<AgentApiState>) -> Option<String> {
    let (cached_value, should_refresh) = {
        let mut cache = state.policy_version_cache.write().await;
        let should_refresh = cache.mark_refresh_started_if_due(std::time::Instant::now());
        (cache.value.clone(), should_refresh)
    };

    if should_refresh {
        let state = state.clone();
        tokio::spawn(async move {
            let fetched = tokio::time::timeout(
                POLICY_VERSION_FETCH_TIMEOUT,
                fetch_daemon_policy_version(state.as_ref()),
            )
            .await
            .ok()
            .flatten();

            let mut cache = state.policy_version_cache.write().await;
            cache.finish_refresh(fetched, std::time::Instant::now());
        });
    }

    cached_value
}

#[derive(Debug, Serialize)]
struct AgentHealthResponse {
    status: &'static str,
    daemon: DaemonStatus,
    session: crate::session::SessionState,
    openclaw: serde_json::Value,
    runtime_agents: usize,
    last_policy_version: Option<String>,
    endpoint_agent_id: String,
    last_heartbeat_at: Option<String>,
    heartbeat_age_secs: Option<i64>,
    endpoint_online: Option<bool>,
    policy_drift: Option<bool>,
    daemon_drift: Option<bool>,
    stale: Option<bool>,
    version: &'static str,
}

#[derive(Debug, Deserialize)]
struct DaemonAgentStatusResponse {
    endpoints: Vec<DaemonEndpointStatus>,
}

#[derive(Debug, Deserialize)]
struct DaemonEndpointStatus {
    #[serde(default)]
    last_heartbeat_at: Option<String>,
    #[serde(default)]
    seconds_since_heartbeat: Option<i64>,
    #[serde(default)]
    online: Option<bool>,
    #[serde(default)]
    drift: Option<DaemonEndpointDrift>,
}

#[derive(Debug, Deserialize)]
struct DaemonEndpointDrift {
    #[serde(default)]
    policy_drift: Option<bool>,
    #[serde(default)]
    daemon_drift: Option<bool>,
    #[serde(default)]
    stale: Option<bool>,
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
    dashboard_url: String,
    debug_include_daemon_error_body: bool,
    openclaw_active_gateway_id: Option<String>,
    ota_enabled: bool,
    ota_mode: String,
    ota_channel: String,
    ota_manifest_url: Option<String>,
    ota_allow_fallback_to_default: bool,
    ota_check_interval_minutes: u32,
    ota_pinned_public_keys: Vec<String>,
    ota_last_check_at: Option<String>,
    ota_last_result: Option<String>,
    ota_current_hushd_version: Option<String>,
    local_api_security: LocalApiSecurityResponse,
}

#[derive(Debug, Serialize)]
struct LocalApiSecurityResponse {
    token_rotation_interval_hours: u32,
    token_grace_minutes: u32,
    mtls_enabled: bool,
    mtls_port: u16,
    mtls_server_cert_path: Option<String>,
    mtls_server_key_path: Option<String>,
    mtls_client_ca_path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RuntimeRegisterInput {
    runtime_agent_kind: String,
    #[serde(default)]
    runtime_agent_id: Option<String>,
    #[serde(default)]
    endpoint_agent_id: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    metadata: Option<Value>,
}

#[derive(Debug, Serialize)]
struct RuntimeRegisterResponse {
    endpoint_agent_id: String,
    runtime_agent_id: String,
    runtime_agent_kind: String,
    external_runtime_id: Option<String>,
    first_seen_at: String,
    last_seen_at: String,
}

#[derive(Debug, Deserialize)]
struct AgentSettingsUpdate {
    enabled: Option<bool>,
    auto_start: Option<bool>,
    notifications_enabled: Option<bool>,
    notification_severity: Option<String>,
    dashboard_url: Option<String>,
    debug_include_daemon_error_body: Option<bool>,
    ota_enabled: Option<bool>,
    ota_mode: Option<String>,
    ota_channel: Option<String>,
    ota_manifest_url: Option<Option<String>>,
    ota_allow_fallback_to_default: Option<bool>,
    ota_check_interval_minutes: Option<u32>,
    ota_pinned_public_keys: Option<Vec<String>>,
    ota_last_check_at: Option<Option<String>>,
    ota_last_result: Option<Option<String>>,
    ota_current_hushd_version: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_optional_string_field")]
    openclaw_active_gateway_id: Option<Option<String>>,
    local_api_security: Option<LocalApiSecurityUpdate>,
}

#[derive(Debug, Deserialize)]
struct LocalApiSecurityUpdate {
    token_rotation_interval_hours: Option<u32>,
    token_grace_minutes: Option<u32>,
    mtls_enabled: Option<bool>,
    mtls_port: Option<u16>,
    mtls_server_cert_path: Option<Option<String>>,
    mtls_server_key_path: Option<Option<String>>,
    mtls_client_ca_path: Option<Option<String>>,
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

#[derive(Debug, Deserialize)]
struct IntegrationsSettingsUpdateInput {
    #[serde(default)]
    siem: Option<SiemIntegrationUpdateInput>,
    #[serde(default)]
    webhooks: Option<WebhookIntegrationUpdateInput>,
    #[serde(default = "default_apply_integrations_changes")]
    apply: bool,
}

#[derive(Debug, Deserialize)]
struct SiemIntegrationUpdateInput {
    provider: Option<String>,
    endpoint: Option<String>,
    api_key: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct WebhookIntegrationUpdateInput {
    url: Option<String>,
    secret: Option<String>,
    enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
struct IntegrationsApplyResponse {
    integrations: IntegrationSettings,
    restarted: bool,
    daemon: DaemonStatus,
    exporter_status: Option<Value>,
    warning: Option<String>,
}

#[derive(Debug, Deserialize)]
struct IntegrationTestInput {
    target: String,
    #[serde(default)]
    max_retries: Option<u8>,
}

#[derive(Debug, Serialize)]
struct IntegrationTestResponse {
    target: String,
    endpoint: String,
    delivered: bool,
    status_code: Option<u16>,
    attempts: u8,
    retry_count: u8,
    latency_ms: u64,
    last_error: Option<String>,
    tested_at: String,
}

#[derive(Debug, Serialize)]
struct RotateLocalApiTokenResponse {
    rotated: bool,
    previous_token_valid_for_seconds: u64,
}

#[derive(Debug, Deserialize, Default)]
struct DiagnosticsBundleInput {
    #[serde(default)]
    include_logs: Option<bool>,
    #[serde(default)]
    log_lines: Option<usize>,
}

#[derive(Debug, Serialize)]
struct DiagnosticsBundleResponse {
    bundle_path: String,
    generated_at: String,
}

fn default_apply_integrations_changes() -> bool {
    true
}

fn resolve_endpoint_agent_id_for_health(settings: &Settings) -> String {
    settings
        .nats
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            settings
                .enrollment
                .agent_uuid
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
        })
        .or_else(|| {
            settings
                .local_agent_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| format!("endpoint-{}", crate::settings::hostname_best_effort()))
}

async fn fetch_daemon_endpoint_status_for_health(
    state: &Arc<AgentApiState>,
    settings: &Settings,
    endpoint_agent_id: &str,
    expected_policy_version: Option<&str>,
    expected_daemon_version: Option<&str>,
) -> Option<DaemonEndpointStatus> {
    let mut url = reqwest::Url::parse(&format!("{}/api/v1/agents/status", settings.daemon_url()))
        .ok()?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("endpoint_agent_id", endpoint_agent_id);
        query.append_pair("limit", "1");
        query.append_pair("include_stale", "true");
        if let Some(policy_version) = expected_policy_version {
            query.append_pair("expected_policy_version", policy_version);
        }
        if let Some(daemon_version) = expected_daemon_version {
            query.append_pair("expected_daemon_version", daemon_version);
        }
    }

    let mut request = state.http_client.get(url);
    if let Some(api_key) = settings
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", api_key));
    }

    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    let payload = response.json::<DaemonAgentStatusResponse>().await.ok()?;
    payload.endpoints.into_iter().next()
}

fn redact_settings_json(raw: &mut Value) {
    let Some(obj) = raw.as_object_mut() else {
        return;
    };

    for key in ["api_key", "token", "nkey_seed", "enrollment_token", "secret"] {
        if let Some(value) = obj.get_mut(key) {
            *value = Value::String("[REDACTED]".to_string());
        }
    }

    if let Some(integrations) = obj.get_mut("integrations").and_then(Value::as_object_mut) {
        if let Some(siem) = integrations.get_mut("siem").and_then(Value::as_object_mut) {
            if let Some(value) = siem.get_mut("api_key") {
                *value = Value::String("[REDACTED]".to_string());
            }
        }
        if let Some(webhooks) = integrations
            .get_mut("webhooks")
            .and_then(Value::as_object_mut)
        {
            if let Some(value) = webhooks.get_mut("secret") {
                *value = Value::String("[REDACTED]".to_string());
            }
        }
    }

    if let Some(nats) = obj.get_mut("nats").and_then(Value::as_object_mut) {
        for key in ["token", "nkey_seed", "creds_file"] {
            if let Some(value) = nats.get_mut(key) {
                *value = Value::String("[REDACTED]".to_string());
            }
        }
    }
}

fn trim_tail_lines(content: &str, lines: usize) -> String {
    if lines == 0 {
        return String::new();
    }
    let mut collected = content
        .lines()
        .rev()
        .take(lines)
        .collect::<Vec<_>>();
    collected.reverse();
    collected.join("\n")
}

async fn write_diagnostics_bundle(
    state: Arc<AgentApiState>,
    input: DiagnosticsBundleInput,
) -> Result<DiagnosticsBundleResponse, (StatusCode, String)> {
    let include_logs = input.include_logs.unwrap_or(true);
    let log_lines = input.log_lines.unwrap_or(500).clamp(10, 5000);
    let settings_snapshot = state.settings.read().await.clone();
    let daemon_status = state.daemon_manager.status().await;
    let session_state = state.session_manager.state().await;
    let audit_queue_depth = state.audit_queue.len().await;
    let pending_approvals = state.approval_queue.pending_count().await;
    let last_policy_version = cached_policy_version_for_health(&state).await;
    let runtime_agents = settings_snapshot.runtime_registry.runtimes.clone();

    let mut settings_json = serde_json::to_value(&settings_snapshot)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    redact_settings_json(&mut settings_json);

    let daemon_url = settings_snapshot.daemon_url();
    let mut health_request = state.http_client.get(format!("{}/health", daemon_url));
    if let Some(api_key) = settings_snapshot
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        health_request = health_request.header(AUTHORIZATION.as_str(), format!("Bearer {}", api_key));
    }
    let daemon_health = match health_request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            serde_json::json!({
                "reachable": status < 500,
                "status_code": status,
                "body_preview": trim_tail_lines(&body, 20),
            })
        }
        Err(err) => serde_json::json!({
            "reachable": false,
            "error": err.to_string(),
        }),
    };

    let diagnostics_root = crate::settings::get_config_dir().join("diagnostics");
    let generated_at = chrono::Utc::now();
    let bundle_dir = diagnostics_root.join(format!(
        "bundle-{}",
        generated_at.format("%Y%m%dT%H%M%SZ")
    ));
    let bundle_dir_for_write = bundle_dir.clone();
    let manifest = serde_json::json!({
        "generated_at": generated_at.to_rfc3339(),
        "agent_version": env!("CARGO_PKG_VERSION"),
        "bundle_dir": bundle_dir.display().to_string(),
    });
    let connectivity = serde_json::json!({
        "daemon_health": daemon_health,
        "session": {
            "session_id": session_state.session_id,
            "posture": session_state.posture,
        },
    });
    let version_matrix = serde_json::json!({
        "agent_version": env!("CARGO_PKG_VERSION"),
        "daemon_version": daemon_status.version,
        "last_policy_version": last_policy_version,
        "runtime_registry_count": runtime_agents.len(),
    });
    let queue_state = serde_json::json!({
        "audit_outbox_depth": audit_queue_depth,
        "pending_approvals": pending_approvals,
    });

    let agent_log_path = crate::settings::get_config_dir().join("logs").join("agent.log");
    let hushd_log_path = crate::settings::get_config_dir().join("logs").join("hushd.log");
    let agent_log = if include_logs {
        std::fs::read_to_string(&agent_log_path)
            .map(|content| trim_tail_lines(&content, log_lines))
            .unwrap_or_else(|_| "agent.log unavailable".to_string())
    } else {
        "logs omitted by request".to_string()
    };
    let hushd_log = if include_logs {
        std::fs::read_to_string(&hushd_log_path)
            .map(|content| trim_tail_lines(&content, log_lines))
            .unwrap_or_else(|_| "hushd.log unavailable".to_string())
    } else {
        "logs omitted by request".to_string()
    };

    tokio::task::spawn_blocking(move || -> Result<(), (StatusCode, String)> {
        std::fs::create_dir_all(bundle_dir_for_write.join("logs"))
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("settings.redacted.json"),
            serde_json::to_vec_pretty(&settings_json)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("runtime_registry.json"),
            serde_json::to_vec_pretty(&runtime_agents)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("connectivity_checks.json"),
            serde_json::to_vec_pretty(&connectivity)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("version_matrix.json"),
            serde_json::to_vec_pretty(&version_matrix)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("queue_state.json"),
            serde_json::to_vec_pretty(&queue_state)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("logs").join("agent.tail.log"),
            agent_log,
        )
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("logs").join("hushd.tail.log"),
            hushd_log,
        )
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        Ok(())
    })
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))??;

    Ok(DiagnosticsBundleResponse {
        bundle_path: bundle_dir.display().to_string(),
        generated_at: generated_at.to_rfc3339(),
    })
}

async fn create_diagnostics_bundle(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    payload: Option<Json<DiagnosticsBundleInput>>,
) -> Result<Json<DiagnosticsBundleResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let input = payload.map(|value| value.0).unwrap_or_default();
    let response = write_diagnostics_bundle(state, input).await?;
    Ok(Json(response))
}

async fn agent_health(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<AgentHealthResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings_snapshot = state.settings.read().await.clone();
    let endpoint_agent_id = resolve_endpoint_agent_id_for_health(&settings_snapshot);
    let daemon = state.daemon_manager.status().await;
    let session = state.session_manager.state().await;
    let openclaw = state.openclaw.list_gateways().await;
    let runtime_agents = settings_snapshot.runtime_registry.runtimes.len();
    let last_policy_version = cached_policy_version_for_health(&state).await;
    let daemon_status = fetch_daemon_endpoint_status_for_health(
        &state,
        &settings_snapshot,
        &endpoint_agent_id,
        last_policy_version.as_deref(),
        daemon.version.as_deref(),
    )
    .await;
    let (last_heartbeat_at, heartbeat_age_secs, endpoint_online, policy_drift, daemon_drift, stale) =
        if let Some(status) = daemon_status {
            (
                status.last_heartbeat_at,
                status.seconds_since_heartbeat,
                status.online,
                status.drift.as_ref().and_then(|value| value.policy_drift),
                status.drift.as_ref().and_then(|value| value.daemon_drift),
                status.drift.as_ref().and_then(|value| value.stale),
            )
        } else {
            (None, None, None, None, None, None)
        };

    Ok(Json(AgentHealthResponse {
        status: "ok",
        daemon,
        session,
        openclaw: serde_json::to_value(openclaw)
            .unwrap_or_else(|_| serde_json::json!({"error":"serialize_failed"})),
        runtime_agents,
        last_policy_version,
        endpoint_agent_id,
        last_heartbeat_at,
        heartbeat_age_secs,
        endpoint_online,
        policy_drift,
        daemon_drift,
        stale,
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
        dashboard_url: settings.dashboard_url.clone(),
        debug_include_daemon_error_body: settings.debug_include_daemon_error_body,
        openclaw_active_gateway_id: settings.openclaw.active_gateway_id.clone(),
        ota_enabled: settings.ota_enabled,
        ota_mode: settings.ota_mode.clone(),
        ota_channel: settings.ota_channel.clone(),
        ota_manifest_url: settings.ota_manifest_url.clone(),
        ota_allow_fallback_to_default: settings.ota_allow_fallback_to_default,
        ota_check_interval_minutes: settings.ota_check_interval_minutes,
        ota_pinned_public_keys: settings.ota_pinned_public_keys.clone(),
        ota_last_check_at: settings.ota_last_check_at.clone(),
        ota_last_result: settings.ota_last_result.clone(),
        ota_current_hushd_version: settings.ota_current_hushd_version.clone(),
        local_api_security: LocalApiSecurityResponse {
            token_rotation_interval_hours: settings
                .local_api_security
                .token_rotation_interval_hours,
            token_grace_minutes: settings.local_api_security.token_grace_minutes,
            mtls_enabled: settings.local_api_security.mtls_enabled,
            mtls_port: settings.local_api_security.mtls_port,
            mtls_server_cert_path: settings
                .local_api_security
                .mtls_server_cert_path
                .as_ref()
                .map(|path| path.display().to_string()),
            mtls_server_key_path: settings
                .local_api_security
                .mtls_server_key_path
                .as_ref()
                .map(|path| path.display().to_string()),
            mtls_client_ca_path: settings
                .local_api_security
                .mtls_client_ca_path
                .as_ref()
                .map(|path| path.display().to_string()),
        },
    }))
}

async fn list_runtime_agents(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<RuntimeAgentRegistration>>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let mut runtimes = {
        let settings = state.settings.read().await;
        settings.runtime_registry.runtimes.clone()
    };
    runtimes.sort_by(|a, b| b.last_seen_at.cmp(&a.last_seen_at));
    Ok(Json(runtimes))
}

async fn register_runtime_agent_route(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<RuntimeRegisterInput>,
) -> Result<Json<RuntimeRegisterResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    if input.runtime_agent_kind.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "runtime_agent_kind must be a non-empty string".to_string(),
        ));
    }

    let registration = {
        let mut settings = state.settings.write().await;
        let endpoint_agent_id =
            resolve_effective_endpoint_agent_id(&mut settings, input.endpoint_agent_id.as_deref());
        let registration = register_runtime_agent(
            &mut settings,
            RuntimeRegistrationInput {
                endpoint_agent_id,
                runtime_agent_kind: input.runtime_agent_kind.clone(),
                external_runtime_id: input.runtime_agent_id.clone(),
                display_name: input.display_name,
                metadata: input.metadata,
            },
        );
        settings
            .save()
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        registration
    };

    Ok(Json(RuntimeRegisterResponse {
        endpoint_agent_id: registration.endpoint_agent_id,
        runtime_agent_id: registration.runtime_agent_id,
        runtime_agent_kind: registration.runtime_agent_kind,
        external_runtime_id: registration.external_runtime_id,
        first_seen_at: registration.first_seen_at,
        last_seen_at: registration.last_seen_at,
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
        if let Some(value) = input.dashboard_url {
            settings.dashboard_url = value;
        }
        if let Some(value) = input.debug_include_daemon_error_body {
            settings.debug_include_daemon_error_body = value;
        }
        if let Some(value) = input.ota_enabled {
            settings.ota_enabled = value;
        }
        if let Some(value) = input.ota_mode {
            settings.ota_mode = value;
        }
        if let Some(value) = input.ota_channel {
            settings.ota_channel = value;
        }
        if let Some(value) = input.ota_manifest_url {
            settings.ota_manifest_url = value;
        }
        if let Some(value) = input.ota_allow_fallback_to_default {
            settings.ota_allow_fallback_to_default = value;
        }
        if let Some(value) = input.ota_check_interval_minutes {
            settings.ota_check_interval_minutes = value;
        }
        if let Some(value) = input.ota_pinned_public_keys {
            settings.ota_pinned_public_keys = value;
        }
        if let Some(value) = input.ota_last_check_at {
            settings.ota_last_check_at = value;
        }
        if let Some(value) = input.ota_last_result {
            settings.ota_last_result = value;
        }
        if let Some(value) = input.ota_current_hushd_version {
            settings.ota_current_hushd_version = value;
        }
        if let Some(value) = input.openclaw_active_gateway_id {
            settings.openclaw.active_gateway_id = value;
        }
        if let Some(local_api_security) = input.local_api_security {
            if let Some(value) = local_api_security.token_rotation_interval_hours {
                settings.local_api_security.token_rotation_interval_hours = value.clamp(1, 24 * 30);
            }
            if let Some(value) = local_api_security.token_grace_minutes {
                settings.local_api_security.token_grace_minutes = value.clamp(1, 120);
            }
            if let Some(value) = local_api_security.mtls_enabled {
                settings.local_api_security.mtls_enabled = value;
            }
            if let Some(value) = local_api_security.mtls_port {
                settings.local_api_security.mtls_port = value.max(1024);
            }
            if let Some(value) = local_api_security.mtls_server_cert_path {
                settings.local_api_security.mtls_server_cert_path = value
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty())
                    .map(PathBuf::from);
            }
            if let Some(value) = local_api_security.mtls_server_key_path {
                settings.local_api_security.mtls_server_key_path = value
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty())
                    .map(PathBuf::from);
            }
            if let Some(value) = local_api_security.mtls_client_ca_path {
                settings.local_api_security.mtls_client_ca_path = value
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty())
                    .map(PathBuf::from);
            }

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
                if !(cert && key && ca) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "mTLS enabled requires valid cert/key/CA file paths".to_string(),
                    ));
                }
            }
        }

        settings
            .save()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        set_token_grace_minutes(
            &state,
            settings.local_api_security.token_grace_minutes.max(1),
        );
    }

    get_settings(State(state), headers).await
}

async fn get_integrations_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<IntegrationSettings>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings = state.settings.read().await;
    Ok(Json(settings.integrations.clone()))
}

async fn update_integrations_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<IntegrationsSettingsUpdateInput>,
) -> Result<Json<IntegrationsApplyResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    {
        let mut settings = state.settings.write().await;
        let mut next_integrations = settings.integrations.clone();

        if let Some(siem) = input.siem {
            if let Some(value) = siem.provider {
                next_integrations.siem.provider = value;
            }
            if let Some(value) = siem.endpoint {
                next_integrations.siem.endpoint = value;
            }
            if let Some(value) = siem.api_key {
                next_integrations.siem.api_key = value;
            }
            if let Some(value) = siem.enabled {
                next_integrations.siem.enabled = value;
            }
        }

        if let Some(webhooks) = input.webhooks {
            if let Some(value) = webhooks.url {
                next_integrations.webhooks.url = value;
            }
            if let Some(value) = webhooks.secret {
                next_integrations.webhooks.secret = value;
            }
            if let Some(value) = webhooks.enabled {
                next_integrations.webhooks.enabled = value;
            }
        }

        normalize_integration_settings(&mut next_integrations);
        validate_integration_settings(&next_integrations)
            .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
        settings.integrations = next_integrations;

        settings
            .save()
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    }

    let mut restarted = false;
    let mut warning = None;

    if input.apply {
        state
            .daemon_manager
            .restart()
            .await
            .map_err(internal_error)?;
        restarted = true;
    }

    let daemon = state.daemon_manager.status().await;
    let exporter_status = fetch_daemon_exporter_status(&state).await;
    let integrations = {
        let settings = state.settings.read().await;
        settings.integrations.clone()
    };
    if input.apply {
        if exporter_status.is_none() {
            warning = Some("hushd restarted but exporter status could not be fetched".to_string());
        } else {
            let export_enabled = exporter_status
                .as_ref()
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let exporter_count = exporter_status
                .as_ref()
                .and_then(|v| v.get("exporters"))
                .and_then(|v| v.as_array())
                .map(|v| v.len())
                .unwrap_or(0);

            let expected_exporters = integrations.siem.enabled || integrations.webhooks.enabled;
            if expected_exporters && (!export_enabled || exporter_count == 0) {
                warning = Some(
                    "Integration settings were saved, but hushd reports no active exporters after restart."
                        .to_string(),
                );
            }
        }
    }

    Ok(Json(IntegrationsApplyResponse {
        integrations,
        restarted,
        daemon,
        exporter_status,
        warning,
    }))
}

fn truncate_delivery_error(message: &str) -> String {
    const MAX_LEN: usize = 240;
    if message.chars().count() <= MAX_LEN {
        return message.to_string();
    }
    let mut out = message.chars().take(MAX_LEN.saturating_sub(3)).collect::<String>();
    out.push_str("...");
    out
}

async fn test_integration_delivery(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<IntegrationTestInput>,
) -> Result<Json<IntegrationTestResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let target = input.target.trim().to_ascii_lowercase();
    let max_retries = input.max_retries.unwrap_or(2).min(5);

    let (endpoint, enabled, provider, siem_api_key, webhook_secret, agent_id) = {
        let settings = state.settings.read().await;
        let integrations = &settings.integrations;
        let endpoint_agent_id = settings
            .local_agent_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "unknown-agent".to_string());

        match target.as_str() {
            "siem" => (
                integrations.siem.endpoint.clone(),
                integrations.siem.enabled,
                integrations.siem.provider.clone(),
                integrations.siem.api_key.clone(),
                String::new(),
                endpoint_agent_id,
            ),
            "webhook" | "webhooks" => (
                integrations.webhooks.url.clone(),
                integrations.webhooks.enabled,
                "webhook".to_string(),
                String::new(),
                integrations.webhooks.secret.clone(),
                endpoint_agent_id,
            ),
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("unsupported test target '{}'", other),
                ))
            }
        }
    };

    if !enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{} delivery is disabled", target),
        ));
    }

    if endpoint.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{} endpoint is empty", target),
        ));
    }

    let normalized_endpoint = endpoint.trim().to_string();
    let payload = serde_json::json!({
        "event_type": "integration_test_delivery",
        "target": target,
        "provider": provider,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "endpoint_agent_id": agent_id,
        "message": "ClawdStrike integration delivery test event"
    });
    let payload_bytes = serde_json::to_vec(&payload).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize test payload: {err}"),
        )
    })?;

    let started_at = Instant::now();
    let tested_at = chrono::Utc::now().to_rfc3339();
    let mut attempts: u8 = 0;
    let mut status_code: Option<u16> = None;
    let mut last_error: Option<String> = None;
    let mut delivered = false;

    for attempt in 0..=max_retries {
        attempts = attempt + 1;

        let mut request = state
            .http_client
            .post(normalized_endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .header("x-clawdstrike-test-delivery", "1")
            .body(payload_bytes.clone());

        if target == "siem" && !siem_api_key.is_empty() {
            let auth_header = if provider.trim().eq_ignore_ascii_case("splunk") {
                format!("Splunk {}", siem_api_key)
            } else {
                format!("Bearer {}", siem_api_key)
            };
            request = request
                .header(AUTHORIZATION, auth_header)
                .header("dd-api-key", siem_api_key.clone());
        }

        if target.starts_with("webhook") && !webhook_secret.is_empty() {
            request = request
                .header("x-clawdstrike-secret-configured", "true")
                .header("x-clawdstrike-signature-scheme", "hmac-sha256");
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status();
                status_code = Some(status.as_u16());
                if status.is_success() {
                    delivered = true;
                    last_error = None;
                    break;
                }
                let body = response.text().await.unwrap_or_default();
                let reason = if body.trim().is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    format!("HTTP {}: {}", status.as_u16(), body.trim())
                };
                last_error = Some(truncate_delivery_error(&reason));
            }
            Err(err) => {
                last_error = Some(truncate_delivery_error(&err.to_string()));
            }
        }

        if attempt < max_retries {
            let backoff_ms = 250u64.saturating_mul((attempt + 1) as u64);
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }
    }

    let elapsed_ms_u128 = started_at.elapsed().as_millis();
    let latency_ms = elapsed_ms_u128.min(u128::from(u64::MAX)) as u64;

    Ok(Json(IntegrationTestResponse {
        target: if target == "webhooks" {
            "webhook".to_string()
        } else {
            target
        },
        endpoint: normalized_endpoint,
        delivered,
        status_code,
        attempts,
        retry_count: attempts.saturating_sub(1),
        latency_ms,
        last_error,
        tested_at,
    }))
}

async fn get_ota_status(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<OtaStatus>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    Ok(Json(state.updater.status().await))
}

async fn trigger_ota_check(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<OtaStatus>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .updater
        .check_now()
        .await
        .map(Json)
        .map_err(internal_error)
}

async fn trigger_ota_apply(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<OtaStatus>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    state
        .updater
        .apply_now()
        .await
        .map(Json)
        .map_err(internal_error)
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
        Some(state.audit_queue.clone()),
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
        .map_err(map_openclaw_error)?;
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
        .map_err(map_openclaw_error)?;

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
    let session_id = state.session_manager.session_id().await;
    let policy = evaluate_policy_check(
        state.settings.clone(),
        &state.http_client,
        PolicyCheckInput {
            action_type: "mcp_tool".to_string(),
            target: format!("openclaw.{}", input.method.trim().to_ascii_lowercase()),
            content: None,
            args: Some({
                let mut args = std::collections::HashMap::new();
                args.insert(
                    "gateway_id".to_string(),
                    serde_json::Value::String(input.gateway_id.clone()),
                );
                args.insert(
                    "method".to_string(),
                    serde_json::Value::String(input.method.clone()),
                );
                if let Some(params) = input.params.as_ref() {
                    args.insert("params".to_string(), params.clone());
                }
                args
            }),
            agent_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: Some(format!("gateway:{}", input.gateway_id)),
            runtime_agent_kind: Some("openclaw".to_string()),
        },
        session_id,
        Some(state.audit_queue.clone()),
    )
    .await;
    if !policy.allowed {
        let message = policy
            .message
            .unwrap_or_else(|| "OpenClaw request blocked by policy".to_string());
        return Err((StatusCode::FORBIDDEN, message));
    }

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
        .map_err(map_openclaw_error)?;
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

    let retry_after_secs = {
        let mut limiter = state.approval_rate_limiter.lock().await;
        limiter.allow_now(Instant::now()).err()
    };
    if let Some(retry_after) = retry_after_secs {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "Approval request rate limit exceeded; retry in {}s",
                retry_after
            ),
        ));
    }

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

// --- Enrollment endpoints ---

#[derive(Deserialize)]
struct EnrollAgentInput {
    control_api_url: String,
    enrollment_token: String,
}

async fn enroll_agent(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EnrollAgentInput>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let manager = crate::enrollment::EnrollmentManager::new(state.settings.clone());
    match manager
        .enroll(&input.control_api_url, &input.enrollment_token)
        .await
    {
        Ok(result) => {
            tracing::info!(
                agent_uuid = %result.agent_uuid,
                "Enrollment complete — agent restart required to activate NATS enterprise features"
            );
            Ok(Json(serde_json::json!({
                "status": "enrolled",
                "agent_uuid": result.agent_uuid,
                "tenant_id": result.tenant_id,
                "restart_required": true,
                "message": "Restart the agent to activate enterprise features (policy sync, telemetry, posture commands)",
            })))
        }
        Err(err) => Err((
            StatusCode::BAD_REQUEST,
            format!("Enrollment failed: {}", err),
        )),
    }
}

async fn enrollment_status(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let settings = state.settings.read().await;
    let enrollment = &settings.enrollment;
    Ok(Json(serde_json::json!({
        "enrolled": enrollment.enrolled,
        "agent_uuid": enrollment.agent_uuid,
        "tenant_id": enrollment.tenant_id,
        "enrollment_in_progress": enrollment.enrollment_in_progress,
    })))
}

fn current_auth_token(state: &AgentApiState) -> String {
    let guard = state
        .auth_token
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
}

fn current_token_grace_minutes(state: &AgentApiState) -> u32 {
    let guard = state
        .token_grace_minutes
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    (*guard).max(1)
}

fn set_token_grace_minutes(state: &AgentApiState, value: u32) {
    let mut guard = state
        .token_grace_minutes
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = value.max(1);
}

fn rotate_local_api_token_with_grace(state: &AgentApiState) -> Result<u64, (StatusCode, String)> {
    let old_token = current_auth_token(state);
    let new_token = rotate_local_api_token().map_err(internal_error)?;
    {
        let mut guard = state
            .auth_token
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = new_token;
    }

    let grace_secs = u64::from(current_token_grace_minutes(state)) * 60;
    {
        let mut previous = state
            .previous_auth_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *previous = Some(PreviousAuthToken {
            token: old_token,
            expires_at: Instant::now() + Duration::from_secs(grace_secs),
        });
    }

    Ok(grace_secs)
}

fn auth_token_matches(candidate: &str, state: &AgentApiState) -> bool {
    let current = state
        .auth_token
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if constant_time_eq_token(candidate, current.as_str()) {
        return true;
    }
    drop(current);

    let mut previous = state
        .previous_auth_token
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(prev) = previous.as_ref() {
        if Instant::now() > prev.expires_at {
            *previous = None;
            return false;
        }
        return constant_time_eq_token(candidate, &prev.token);
    }

    false
}

async fn route_rate_limit(
    State(state): State<Arc<AgentApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    let method = request.method().clone();
    let now = Instant::now();

    let limited = if path == "/api/v1/ui/bootstrap/start" {
        let mut limiter = state.ui_bootstrap_start_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_UI_BOOTSTRAP_START,
            )
            .err()
    } else if path == "/ui/bootstrap" && method == axum::http::Method::POST {
        let mut limiter = state.ui_bootstrap_verify_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_UI_BOOTSTRAP_VERIFY,
            )
            .err()
    } else if path == "/api/v1/agent/policy-check" {
        let mut limiter = state.policy_check_rate_limiter.lock().await;
        limiter
            .allow_now(now, ROUTE_RATE_LIMIT_WINDOW, ROUTE_RATE_LIMIT_POLICY_CHECK)
            .err()
    } else if path == "/api/v1/agent/integrations/test" {
        let mut limiter = state.integration_test_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_INTEGRATION_TEST,
            )
            .err()
    } else if path == "/api/v1/openclaw/request" {
        let mut limiter = state.openclaw_request_rate_limiter.lock().await;
        limiter
            .allow_now(
                now,
                ROUTE_RATE_LIMIT_WINDOW,
                ROUTE_RATE_LIMIT_OPENCLAW_REQUEST,
            )
            .err()
    } else {
        None
    };

    if let Some(retry_after) = limited {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            format!("Rate limit exceeded; retry in {}s", retry_after),
        )
            .into_response();
    }

    next.run(request).await
}

async fn rotate_local_api_token_route(
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

async fn token_rotation_loop(
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
                tracing::info!(
                    grace_secs,
                    "Rotated local API auth token on schedule"
                );
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

fn auth_token_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let Some((name, value)) = cookie.trim().split_once('=') else {
            continue;
        };
        if name.trim() == AGENT_AUTH_COOKIE_NAME {
            let token = value.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

fn require_auth(headers: &HeaderMap, state: &AgentApiState) -> Result<(), (StatusCode, String)> {
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim);

    if let Some(auth) = auth_header {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if auth_token_matches(token.trim(), state) {
                return Ok(());
            }
        }
    }

    if let Some(cookie_token) = auth_token_from_cookie(headers) {
        if auth_token_matches(cookie_token.trim(), state) {
            return Ok(());
        }
    }

    let err = match auth_header {
        None => "missing authorization header".to_string(),
        Some(auth) if !auth.starts_with("Bearer ") => "invalid authorization scheme".to_string(),
        Some(_) => "invalid authorization token".to_string(),
    };
    Err((StatusCode::UNAUTHORIZED, err))
}

fn internal_error(err: anyhow::Error) -> (StatusCode, String) {
    tracing::error!(error = %err, "Agent API error");
    (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
}

fn map_openclaw_error(err: anyhow::Error) -> (StatusCode, String) {
    let message = err.to_string();
    if message.contains("gateway_url")
        || message.contains("wss://")
        || message.contains("private/link-local")
        || message.contains("failed to resolve gateway host")
        || message.contains("pinned allowlist")
    {
        return (StatusCode::BAD_REQUEST, message);
    }
    internal_error(err)
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
    use crate::daemon::{AuditQueue, DaemonConfig};
    use std::path::PathBuf;
    use tower::ServiceExt;

    fn test_state() -> AgentApiState {
        let settings = Arc::new(RwLock::new(Settings::default()));
        let daemon_manager = Arc::new(DaemonManager::new(DaemonConfig {
            binary_path: PathBuf::from("/tmp/hushd"),
            port: 9876,
            policy_path: PathBuf::from("/tmp/policy.yaml"),
            settings: Some(settings.clone()),
        }));
        let session_manager = Arc::new(crate::session::SessionManager::new());
        let approval_queue = Arc::new(crate::approval::ApprovalQueue::new());
        let audit_queue = Arc::new(AuditQueue::new_test_isolated());
        let openclaw = OpenClawManager::new(settings.clone());
        let updater = Arc::new(crate::updater::HushdUpdater::new(
            settings.clone(),
            daemon_manager.clone(),
        ));

        AgentApiState {
            settings,
            daemon_manager,
            session_manager,
            approval_queue,
            audit_queue,
            openclaw,
            updater,
            auth_token: Arc::new(StdRwLock::new("test-token".to_string())),
            previous_auth_token: Arc::new(StdMutex::new(None)),
            token_grace_minutes: Arc::new(StdRwLock::new(15)),
            http_client: reqwest::Client::new(),
            policy_version_cache: Arc::new(RwLock::new(PolicyVersionCache::default())),
            approval_rate_limiter: Arc::new(Mutex::new(ApprovalSubmissionLimiter::default())),
            ui_bootstrap_start_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            ui_bootstrap_verify_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            policy_check_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            integration_test_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            openclaw_request_rate_limiter: Arc::new(Mutex::new(RouteRateLimiter::default())),
            ui_bootstrap_sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    #[test]
    fn policy_version_cache_marks_refresh_in_flight_once_per_interval() {
        let mut cache = PolicyVersionCache::default();
        let now = std::time::Instant::now();
        assert!(cache.mark_refresh_started_if_due(now));
        assert!(!cache.mark_refresh_started_if_due(now));
    }

    #[test]
    fn policy_version_cache_finish_refresh_updates_value_and_clears_in_flight() {
        let mut cache = PolicyVersionCache::default();
        let started = std::time::Instant::now();
        assert!(cache.mark_refresh_started_if_due(started));
        assert!(cache.refresh_in_flight);
        assert_eq!(cache.refresh_started_at, Some(started));

        cache.finish_refresh(Some("42".to_string()), started);
        assert_eq!(cache.value.as_deref(), Some("42"));
        assert!(!cache.refresh_in_flight);
        assert!(cache.refresh_started_at.is_none());
    }

    #[test]
    fn policy_version_cache_recovers_when_refresh_task_stalls() {
        let mut cache = PolicyVersionCache::default();
        let started = std::time::Instant::now();
        assert!(cache.mark_refresh_started_if_due(started));
        assert!(!cache.mark_refresh_started_if_due(started + POLICY_VERSION_CACHE_REFRESH_INTERVAL));

        let after_timeout =
            started + POLICY_VERSION_REFRESH_IN_FLIGHT_TIMEOUT + Duration::from_millis(1);
        assert!(cache.mark_refresh_started_if_due(after_timeout));
        assert!(cache.refresh_in_flight);
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
    fn auth_accepts_cookie_token_without_authorization_header() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            format!("{}={}", AGENT_AUTH_COOKIE_NAME, current_auth_token(&state))
                .parse()
                .unwrap_or_else(|_| panic!("failed to build cookie header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_ok());
    }

    #[test]
    fn auth_allows_cookie_fallback_when_authorization_is_invalid() {
        let state = test_state();
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer wrong-token"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build authorization header")),
        );
        headers.insert(
            COOKIE,
            format!("{}={}", AGENT_AUTH_COOKIE_NAME, current_auth_token(&state))
                .parse()
                .unwrap_or_else(|_| panic!("failed to build cookie header")),
        );

        let result = require_auth(&headers, &state);
        assert!(result.is_ok());
    }

    #[test]
    fn local_host_header_accepts_ipv6_loopback_with_port() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "[::1]:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        assert!(is_local_host_header(&headers));
    }

    #[test]
    fn local_host_header_rejects_public_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "example.com:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        assert!(!is_local_host_header(&headers));
    }

    #[test]
    fn local_host_header_rejects_missing_header() {
        let headers = HeaderMap::new();
        assert!(!is_local_host_header(&headers));
    }

    #[test]
    fn map_openclaw_error_classifies_dns_resolution_failure_as_bad_request() {
        let err = anyhow::anyhow!("failed to resolve gateway host bad.example:443");
        let (status, message) = map_openclaw_error(err);
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(message.contains("failed to resolve gateway host"));
    }

    #[test]
    fn request_is_secure_uri_accepts_https_scheme_without_proxy_header() {
        let headers = HeaderMap::new();
        let uri = "https://localhost/ui/bootstrap"
            .parse::<Uri>()
            .unwrap_or_else(|_| panic!("failed to parse https uri for secure check"));
        assert!(request_is_secure_uri(&headers, &uri));
    }

    #[test]
    fn request_is_secure_uri_rejects_forwarded_proto_for_non_local_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "example.com:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        headers.insert(
            "x-forwarded-proto",
            "https"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build x-forwarded-proto header")),
        );
        let uri = "/ui/bootstrap"
            .parse::<Uri>()
            .unwrap_or_else(|_| panic!("failed to parse relative uri for secure check"));
        assert!(!request_is_secure_uri(&headers, &uri));
    }

    #[test]
    fn request_is_secure_uri_accepts_forwarded_proto_for_local_host() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "host",
            "127.0.0.1:9878"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build host header")),
        );
        headers.insert(
            "x-forwarded-proto",
            "https"
                .parse()
                .unwrap_or_else(|_| panic!("failed to build x-forwarded-proto header")),
        );
        let uri = "/ui/bootstrap"
            .parse::<Uri>()
            .unwrap_or_else(|_| panic!("failed to parse relative uri for secure check"));
        assert!(request_is_secure_uri(&headers, &uri));
    }

    #[tokio::test]
    async fn ui_routes_require_auth_and_bootstrap_with_one_time_code() {
        let state = Arc::new(test_state());
        let ui_router = Router::new().route("/", get(|| async { "ok" })).layer(
            axum::middleware::from_fn_with_state(state.clone(), attach_ui_auth_cookie),
        );
        let app = Router::new()
            .route("/api/v1/ui/bootstrap/start", post(start_ui_bootstrap))
            .route("/ui/bootstrap", post(ui_bootstrap_verify))
            .nest("/ui", ui_router)
            .with_state(state);

        let unauth_req = axum::http::Request::builder()
            .method("GET")
            .uri("/ui")
            .header("host", "127.0.0.1:9878")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build unauth request: {e}"));
        let unauth_resp = app
            .clone()
            .oneshot(unauth_req)
            .await
            .unwrap_or_else(|e| panic!("unauth request failed: {e}"));
        assert_eq!(unauth_resp.status(), StatusCode::UNAUTHORIZED);
        assert!(unauth_resp.headers().get(SET_COOKIE).is_none());

        let deprecated_query_req = axum::http::Request::builder()
            .method("GET")
            .uri("/ui?agent_token=test-token")
            .header("host", "127.0.0.1:9878")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build deprecated query request: {e}"));
        let deprecated_query_resp = app
            .clone()
            .oneshot(deprecated_query_req)
            .await
            .unwrap_or_else(|e| panic!("deprecated query request failed: {e}"));
        assert_eq!(deprecated_query_resp.status(), StatusCode::BAD_REQUEST);

        let start_req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/ui/bootstrap/start")
            .header(AUTHORIZATION, "Bearer test-token")
            .header(CONTENT_TYPE, "application/json")
            .body(axum::body::Body::from(
                r#"{"next_path":"/ui/settings/siem"}"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build bootstrap start request: {e}"));
        let start_resp = app
            .clone()
            .oneshot(start_req)
            .await
            .unwrap_or_else(|e| panic!("bootstrap start request failed: {e}"));
        assert_eq!(start_resp.status(), StatusCode::OK);
        let start_bytes = axum::body::to_bytes(start_resp.into_body(), 64 * 1024)
            .await
            .unwrap_or_else(|e| panic!("failed to read bootstrap start body: {e}"));
        let payload: UiBootstrapStartResponse = serde_json::from_slice(&start_bytes)
            .unwrap_or_else(|e| panic!("failed to decode bootstrap start payload: {e}"));

        let verify_body = format!(
            "session_id={}&user_code={}",
            payload.session_id, payload.user_code
        );
        let verify_req = axum::http::Request::builder()
            .method("POST")
            .uri("/ui/bootstrap")
            .header("host", "127.0.0.1:9878")
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(verify_body))
            .unwrap_or_else(|e| panic!("failed to build bootstrap verify request: {e}"));
        let bootstrap_resp = app
            .clone()
            .oneshot(verify_req)
            .await
            .unwrap_or_else(|e| panic!("bootstrap verify request failed: {e}"));
        assert_eq!(bootstrap_resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            bootstrap_resp
                .headers()
                .get(LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/ui/settings/siem")
        );
        assert!(bootstrap_resp.headers().get(SET_COOKIE).is_some());

        let cookie_req = axum::http::Request::builder()
            .method("GET")
            .uri("/ui")
            .header("host", "127.0.0.1:9878")
            .header(COOKIE, format!("{AGENT_AUTH_COOKIE_NAME}=test-token"))
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build cookie request: {e}"));
        let cookie_resp = app
            .oneshot(cookie_req)
            .await
            .unwrap_or_else(|e| panic!("cookie request failed: {e}"));
        assert_eq!(cookie_resp.status(), StatusCode::OK);
    }

    #[test]
    fn approval_submission_limiter_enforces_burst_limit() {
        let mut limiter = ApprovalSubmissionLimiter::default();
        let now = Instant::now();
        for _ in 0..APPROVAL_RATE_LIMIT_BURST {
            assert!(limiter.allow_now(now).is_ok());
        }
        assert!(limiter.allow_now(now).is_err());
    }

    #[tokio::test]
    async fn agent_health_route_requires_auth() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/agent/health", get(agent_health))
            .with_state(state);

        let req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/health")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let resp = app
            .oneshot(req)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn validate_integrations_requires_api_key_for_datadog() {
        let mut integrations = IntegrationSettings::default();
        integrations.siem.enabled = true;
        integrations.siem.provider = "datadog".to_string();
        integrations.siem.endpoint = "https://us5.datadoghq.com".to_string();
        integrations.siem.api_key = String::new();

        let result = validate_integration_settings(&integrations);
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn integrations_update_roundtrip_without_restart() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .route("/api/v1/agent/integrations/test", post(test_integration_delivery))
            .with_state(state);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{
                    "siem": {
                        "provider": "datadog",
                        "endpoint": "https://us5.datadoghq.com",
                        "api_key": "dd-key",
                        "enabled": true
                    },
                    "apply": false
                }"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));

        let response = app
            .clone()
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let get_req = axum::http::Request::builder()
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));
        let response = app
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("siem")
                .and_then(|v| v.get("provider"))
                .and_then(|v| v.as_str()),
            Some("datadog")
        );
        assert_eq!(
            json.get("siem")
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool()),
            Some(true)
        );
    }

    #[tokio::test]
    async fn integrations_invalid_update_does_not_mutate_state() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .with_state(state.clone());

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{
                    "siem": {
                        "provider": "not-supported",
                        "endpoint": "https://example.invalid",
                        "api_key": "abc123",
                        "enabled": true
                    },
                    "apply": false
                }"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));

        let response = app
            .clone()
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let get_req = axum::http::Request::builder()
            .uri("/api/v1/agent/integrations")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));
        let response = app
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("siem")
                .and_then(|v| v.get("provider"))
                .and_then(|v| v.as_str()),
            Some("datadog"),
            "Rejected update should not mutate in-memory integrations provider"
        );
    }

    #[tokio::test]
    async fn daemon_proxy_route_requires_auth() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route("/api/v1/audit", get(proxy_daemon_get))
            .with_state(state);

        let request = axum::http::Request::builder()
            .uri("/api/v1/audit")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn gateway_request_is_denied_when_policy_blocks() {
        let state = Arc::new(test_state());
        {
            let mut settings = state.settings.write().await;
            settings.daemon_port = 1;
        }
        let app = Router::new()
            .route("/api/v1/openclaw/request", post(gateway_request))
            .with_state(state);

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/openclaw/request")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"gateway_id":"gw-1","method":"node.list","timeout_ms":1000}"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read body: {e}"));
        let body_text =
            String::from_utf8(body.to_vec()).unwrap_or_else(|e| panic!("invalid utf8 body: {e}"));
        assert!(
            body_text.contains("Policy daemon unreachable"),
            "expected policy deny reason, got: {body_text}"
        );
    }

    #[tokio::test]
    async fn gateway_request_reaches_relay_when_policy_allows() {
        let state = Arc::new(test_state());
        {
            let mut settings = state.settings.write().await;
            settings.enabled = false;
        }

        let app = Router::new()
            .route("/api/v1/openclaw/request", post(gateway_request))
            .with_state(state);

        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/openclaw/request")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"gateway_id":"gw-1","method":"node.list","timeout_ms":1000}"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build request: {e}"));
        let response = app
            .oneshot(request)
            .await
            .unwrap_or_else(|e| panic!("request failed: {e}"));

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read body: {e}"));
        let body_text =
            String::from_utf8(body.to_vec()).unwrap_or_else(|e| panic!("invalid utf8 body: {e}"));
        assert!(
            body_text.contains("not connected"),
            "expected relay error from OpenClaw manager, got: {body_text}"
        );
    }

    #[tokio::test]
    async fn integrations_routes_require_auth() {
        let state = Arc::new(test_state());
        let app = Router::new()
            .route(
                "/api/v1/agent/integrations",
                get(get_integrations_settings).put(update_integrations_settings),
            )
            .route("/api/v1/agent/integrations/test", post(test_integration_delivery))
            .with_state(state);

        let get_req = axum::http::Request::builder()
            .method("GET")
            .uri("/api/v1/agent/integrations")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));
        let get_response = app
            .clone()
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));
        assert_eq!(get_response.status(), StatusCode::UNAUTHORIZED);

        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/integrations")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"apply":false}"#))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));
        let put_response = app
            .clone()
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));
        assert_eq!(put_response.status(), StatusCode::UNAUTHORIZED);

        let post_req = axum::http::Request::builder()
            .method("POST")
            .uri("/api/v1/agent/integrations/test")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"target":"siem"}"#))
            .unwrap_or_else(|e| panic!("failed to build POST request: {e}"));
        let post_response = app
            .oneshot(post_req)
            .await
            .unwrap_or_else(|e| panic!("POST request failed: {e}"));
        assert_eq!(post_response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn daemon_proxy_target_preserves_path_and_query() {
        let uri: Uri = "/api/v1/audit?limit=25&decision=block"
            .parse()
            .unwrap_or_else(|err| panic!("failed to parse uri: {err}"));
        let target = build_daemon_proxy_target("http://127.0.0.1:9876", &uri)
            .unwrap_or_else(|err| panic!("failed to build target: {err:?}"));
        assert_eq!(
            target,
            "http://127.0.0.1:9876/api/v1/audit?limit=25&decision=block"
        );
    }

    #[test]
    fn merged_authorization_header_prefers_explicit_hushd_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            HUSHD_AUTHORIZATION_HEADER,
            "Bearer daemon-from-request"
                .parse()
                .unwrap_or_else(|err| panic!("failed to parse daemon auth header: {err}")),
        );
        headers.insert(
            AUTHORIZATION,
            "Bearer local-agent-token"
                .parse()
                .unwrap_or_else(|err| panic!("failed to parse auth header: {err}")),
        );

        let merged = merged_authorization_header(&headers, Some("from-settings"));
        assert_eq!(merged.as_deref(), Some("Bearer daemon-from-request"));
    }

    #[test]
    fn merged_authorization_header_uses_request_authorization_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer from-request"
                .parse()
                .unwrap_or_else(|err| panic!("failed to parse auth header: {err}")),
        );

        let merged = merged_authorization_header(&headers, Some("from-settings"));
        assert_eq!(merged.as_deref(), Some("Bearer from-request"));
    }

    #[test]
    fn merged_authorization_header_falls_back_to_settings_key() {
        let headers = HeaderMap::new();
        let merged = merged_authorization_header(&headers, Some("daemon-key"));
        assert_eq!(merged.as_deref(), Some("Bearer daemon-key"));
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

    #[tokio::test]
    async fn settings_roundtrip_includes_dashboard_url() {
        let state = Arc::new(test_state());

        let app = Router::new()
            .route(
                "/api/v1/agent/settings",
                get(get_settings).put(update_settings),
            )
            .with_state(state);

        // GET should return default dashboard_url.
        let get_req = axum::http::Request::builder()
            .uri("/api/v1/agent/settings")
            .header("authorization", "Bearer test-token")
            .body(axum::body::Body::empty())
            .unwrap_or_else(|e| panic!("failed to build GET request: {e}"));

        let response = app
            .clone()
            .oneshot(get_req)
            .await
            .unwrap_or_else(|e| panic!("GET request failed: {e}"));

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("dashboard_url").and_then(|v| v.as_str()),
            Some("http://127.0.0.1:9878/ui"),
            "GET should return default dashboard_url"
        );
        assert_eq!(
            json.get("ota_enabled").and_then(|v| v.as_bool()),
            Some(true),
            "GET should return default ota_enabled"
        );

        // PUT should persist a custom dashboard_url.
        let put_req = axum::http::Request::builder()
            .method("PUT")
            .uri("/api/v1/agent/settings")
            .header("authorization", "Bearer test-token")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"dashboard_url":"http://localhost:4200"}"#,
            ))
            .unwrap_or_else(|e| panic!("failed to build PUT request: {e}"));

        let response = app
            .oneshot(put_req)
            .await
            .unwrap_or_else(|e| panic!("PUT request failed: {e}"));

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 1024 * 64)
            .await
            .unwrap_or_else(|e| panic!("failed to read PUT response body: {e}"));
        let json: serde_json::Value =
            serde_json::from_slice(&body).unwrap_or_else(|e| panic!("invalid JSON: {e}"));
        assert_eq!(
            json.get("dashboard_url").and_then(|v| v.as_str()),
            Some("http://localhost:4200"),
            "PUT should return updated dashboard_url"
        );
    }
}
