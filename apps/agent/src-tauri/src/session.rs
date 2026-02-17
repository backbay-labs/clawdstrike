//! Session lifecycle management for hushd integration.
//!
//! Manages a session with hushd that enables posture tracking and budget enforcement.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::{broadcast, RwLock};

/// Session state exposed to the tray and other components.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionState {
    pub session_id: Option<String>,
    pub posture: String,
    pub budget_used: u64,
    pub budget_limit: u64,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            session_id: None,
            posture: "unknown".to_string(),
            budget_used: 0,
            budget_limit: 0,
        }
    }
}

impl SessionState {
    pub fn summary(&self) -> String {
        match &self.session_id {
            Some(_) => {
                if self.budget_limit > 0 {
                    format!(
                        "Session: active | Posture: {} | Budget: {}/{}",
                        self.posture, self.budget_used, self.budget_limit
                    )
                } else {
                    format!("Session: active | Posture: {}", self.posture)
                }
            }
            None => "Session: inactive".to_string(),
        }
    }
}

/// Inner session object matching hushd's `SessionContext` (snake_case).
/// We only deserialize the fields the agent cares about; serde ignores the rest.
#[derive(Debug, Deserialize)]
struct HushdSessionInfo {
    session_id: String,
    /// Posture may live in the `state` map; extracted after deserialization.
    #[serde(default)]
    state: Option<std::collections::HashMap<String, serde_json::Value>>,
}

impl HushdSessionInfo {
    /// Extract the posture state name from the nested `PostureRuntimeState` object.
    /// hushd stores `state["posture"]` as `{ "current_state": "...", "budgets": {...}, ... }`.
    fn posture(&self) -> Option<String> {
        self.state
            .as_ref()
            .and_then(|s| s.get("posture"))
            .and_then(|v| v.get("current_state"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }

    /// Sum the budget limits across all posture budget counters.
    /// hushd stores budgets at `state["posture"]["budgets"]` as `{ "<name>": { "used": N, "limit": M } }`.
    fn budget_limit(&self) -> Option<u64> {
        let budgets = self
            .state
            .as_ref()
            .and_then(|s| s.get("posture"))
            .and_then(|v| v.get("budgets"))
            .and_then(|v| v.as_object())?;
        let total: u64 = budgets
            .values()
            .filter_map(|b| b.get("limit").and_then(|v| v.as_u64()))
            .sum();
        Some(total)
    }

    /// Sum the budget usage across all posture budget counters.
    fn budget_used(&self) -> Option<u64> {
        let budgets = self
            .state
            .as_ref()
            .and_then(|s| s.get("posture"))
            .and_then(|v| v.get("budgets"))
            .and_then(|v| v.as_object())?;
        let total: u64 = budgets
            .values()
            .filter_map(|b| b.get("used").and_then(|v| v.as_u64()))
            .sum();
        Some(total)
    }
}

/// hushd session creation response — wraps session in an envelope.
#[derive(Debug, Deserialize)]
struct CreateSessionResponse {
    session: HushdSessionInfo,
}

/// hushd session status/heartbeat response — same envelope.
#[derive(Debug, Deserialize)]
struct GetSessionResponse {
    session: HushdSessionInfo,
}

/// Manages the lifecycle of a hushd session.
pub struct SessionManager {
    state: Arc<RwLock<SessionState>>,
    http_client: reqwest::Client,
    lifecycle_lock: Mutex<()>,
    ensure_loop_running: AtomicBool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeartbeatOutcome {
    /// No-op: session is not currently established.
    NoSession,
    /// Session heartbeat succeeded (and may have updated posture/budget state).
    Updated,
    /// Session heartbeat returned an invalidation response and local session state was cleared.
    Invalidated,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(SessionState::default())),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            lifecycle_lock: Mutex::new(()),
            ensure_loop_running: AtomicBool::new(false),
        }
    }

    /// Get the current session state.
    pub async fn state(&self) -> SessionState {
        self.state.read().await.clone()
    }

    /// Apply a posture transition event from hushd (SSE), keeping the exposed session state
    /// consistent with what the tray/notifications display.
    ///
    /// Returns true if the update applied to the currently tracked session.
    pub async fn update_posture_from_daemon_event(
        &self,
        session_id: Option<&str>,
        new_posture: String,
    ) -> bool {
        if let Some(session_id) = session_id {
            return self
                .with_state_if_current_session_id(session_id, move |state| {
                    state.posture = new_posture;
                })
                .await
                .is_some();
        }

        // Best-effort fallback for legacy events without session_id.
        let mut state = self.state.write().await;
        if state.session_id.is_none() {
            return false;
        }
        state.posture = new_posture;
        true
    }

    /// Get the current session ID, if any.
    pub async fn session_id(&self) -> Option<String> {
        self.state.read().await.session_id.clone()
    }

    async fn delete_session_best_effort(
        &self,
        daemon_url: &str,
        api_key: Option<&str>,
        session_id: &str,
    ) {
        let url = format!("{}/api/v1/session/{}", daemon_url, session_id);
        let mut request = self.http_client.delete(&url);
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        match request.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(session_id = %session_id, "Session terminated before replacement");
            }
            Ok(resp) => {
                tracing::warn!(
                    session_id = %session_id,
                    status = %resp.status(),
                    "Session termination returned non-success status"
                );
            }
            Err(err) => {
                tracing::warn!(
                    session_id = %session_id,
                    error = %err,
                    "Failed to terminate session (daemon may be unreachable)"
                );
            }
        }
    }

    /// Create a new session with hushd.
    pub async fn create_session(&self, daemon_url: &str, api_key: Option<&str>) -> Result<String> {
        // Ensure session create/replace is serialized with termination/shutdown.
        let _lock = self.lifecycle_lock.lock().await;

        if let Some(existing) = self.session_id().await {
            // Best-effort: avoid leaking server-side sessions on reconnect/replacement.
            self.delete_session_best_effort(daemon_url, api_key, &existing)
                .await;
        }

        let url = format!("{}/api/v1/session", daemon_url);

        let hostname = hostname::get()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        let mut request = self.http_client.post(&url).json(&serde_json::json!({
            "client": "clawdstrike-agent",
            "version": env!("CARGO_PKG_VERSION"),
            "hostname": hostname,
        }));
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to create session at {}", url))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Session creation returned {}: {}", status, body);
        }

        let resp: CreateSessionResponse = response
            .json()
            .await
            .with_context(|| "Failed to parse session creation response")?;

        let session_id = resp.session.session_id.clone();
        let posture = resp
            .session
            .posture()
            .unwrap_or_else(|| "standard".to_string());
        let budget_limit = resp.session.budget_limit().unwrap_or(0);
        {
            let mut state = self.state.write().await;
            state.session_id = Some(resp.session.session_id);
            state.posture = posture;
            state.budget_limit = budget_limit;
            state.budget_used = 0;
        }

        tracing::info!(session_id = %session_id, "Session created with hushd");
        Ok(session_id)
    }

    /// Terminate the current session.
    pub async fn terminate_session(&self, daemon_url: &str, api_key: Option<&str>) -> Result<()> {
        // Ensure terminate does not race with create/replace.
        let _lock = self.lifecycle_lock.lock().await;

        let session_id = {
            let state = self.state.read().await;
            state.session_id.clone()
        };

        let Some(session_id) = session_id else {
            return Ok(());
        };

        let url = format!("{}/api/v1/session/{}", daemon_url, session_id);
        let mut request = self.http_client.delete(&url);
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        // Best-effort termination; don't fail the shutdown if this errors.
        match request.send().await {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!(session_id = %session_id, "Session terminated");
            }
            Ok(resp) => {
                tracing::warn!(
                    session_id = %session_id,
                    status = %resp.status(),
                    "Session termination returned non-success status"
                );
            }
            Err(err) => {
                tracing::warn!(
                    session_id = %session_id,
                    error = %err,
                    "Failed to terminate session (daemon may be unreachable)"
                );
            }
        }

        {
            let mut state = self.state.write().await;
            *state = SessionState::default();
        }

        Ok(())
    }

    /// Start an "ensure session" loop with exponential backoff.
    ///
    /// This is used when posture-enabled policies require a session_id and session creation fails
    /// (for example on startup or after reconnect).
    pub fn start_ensure_session(
        self: &Arc<Self>,
        daemon_url: String,
        api_key: Option<String>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        // Avoid spinning up ensure-session loops when a session already exists.
        // This is best-effort since `try_read()` may fail under contention.
        if let Ok(state) = self.state.try_read() {
            if state.session_id.is_some() {
                return;
            }
        }

        if self
            .ensure_loop_running
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return;
        }

        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(250);
            let max_backoff = Duration::from_secs(10);

            loop {
                // Best-effort non-blocking shutdown check before attempting work.
                // `tokio::select!` does not support a `default` branch.
                match shutdown_rx.try_recv() {
                    Ok(_) | Err(broadcast::error::TryRecvError::Closed) => {
                        tracing::debug!("Ensure-session loop shutting down");
                        break;
                    }
                    Err(broadcast::error::TryRecvError::Lagged(_)) => {
                        tracing::debug!("Ensure-session loop lagged; treating as shutdown");
                        break;
                    }
                    Err(broadcast::error::TryRecvError::Empty) => {}
                }

                if manager.session_id().await.is_some() {
                    break;
                }

                match manager
                    .create_session(&daemon_url, api_key.as_deref())
                    .await
                {
                    Ok(session_id) => {
                        tracing::info!(session_id = %session_id, "Session established after retry");
                        break;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, "Failed to establish session with hushd (will retry)");
                    }
                }

                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Ensure-session loop shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(backoff) => {}
                }
                backoff = std::cmp::min(backoff * 2, max_backoff);
            }

            manager.ensure_loop_running.store(false, Ordering::SeqCst);
        });
    }

    async fn with_state_if_current_session_id<T>(
        &self,
        expected_session_id: &str,
        f: impl FnOnce(&mut SessionState) -> T,
    ) -> Option<T> {
        let mut state = self.state.write().await;
        if state.session_id.as_deref() != Some(expected_session_id) {
            return None;
        }
        Some(f(&mut state))
    }

    /// Send a heartbeat to keep the session alive and update state.
    async fn heartbeat(&self, daemon_url: &str, api_key: Option<&str>) -> Result<HeartbeatOutcome> {
        let session_id = {
            let state = self.state.read().await;
            state.session_id.clone()
        };

        let Some(session_id) = session_id else {
            return Ok(HeartbeatOutcome::NoSession);
        };

        let url = format!("{}/api/v1/session/{}", daemon_url, session_id);
        let mut request = self.http_client.get(&url);
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let response = request
            .send()
            .await
            .with_context(|| "Session heartbeat failed")?;

        let status_code = response.status();
        if status_code.is_success() {
            if let Ok(resp) = response.json::<GetSessionResponse>().await {
                // Heartbeat runs concurrently with daemon reconnect handling. Only apply updates
                // if we're still tracking the same session ID we heartbeated.
                let _ = self
                    .with_state_if_current_session_id(&session_id, |state| {
                        if let Some(posture) = resp.session.posture() {
                            state.posture = posture;
                        }
                        if let Some(budget_used) = resp.session.budget_used() {
                            state.budget_used = budget_used;
                        }
                        if let Some(budget_limit) = resp.session.budget_limit() {
                            state.budget_limit = budget_limit;
                        }
                    })
                    .await;
            }
            Ok(HeartbeatOutcome::Updated)
        } else if matches!(
            status_code,
            reqwest::StatusCode::NOT_FOUND
                | reqwest::StatusCode::UNAUTHORIZED
                | reqwest::StatusCode::FORBIDDEN
        ) {
            // Session invalid/expired (or no longer accessible). Clear local state so we don't
            // keep operating against a stale session_id.
            tracing::warn!(
                session_id = %session_id,
                status = %status_code,
                "Session invalid during heartbeat; clearing local session state"
            );
            let _ = self
                .with_state_if_current_session_id(&session_id, |state| {
                    *state = SessionState::default();
                })
                .await;
            Ok(HeartbeatOutcome::Invalidated)
        } else {
            anyhow::bail!("Session heartbeat returned {}", status_code);
        }
    }

    /// Start the heartbeat loop. Runs until shutdown signal.
    pub fn start_heartbeat(
        self: &Arc<Self>,
        daemon_url: String,
        api_key: Option<String>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let manager = Arc::clone(self);
        tokio::spawn(async move {
            let heartbeat_interval = Duration::from_secs(30);
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Session heartbeat loop shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(heartbeat_interval) => {
                        match manager.heartbeat(&daemon_url, api_key.as_deref()).await {
                            Ok(HeartbeatOutcome::Updated) => {}
                            Ok(HeartbeatOutcome::NoSession) => {
                                // Heartbeat loop is started once at agent startup. Until a session
                                // is established (typically by the daemon start/reconnect path),
                                // there's nothing to do here.
                            }
                            Ok(HeartbeatOutcome::Invalidated) => {
                                manager.start_ensure_session(
                                    daemon_url.clone(),
                                    api_key.clone(),
                                    shutdown_rx.resubscribe(),
                                );
                            }
                            Err(err) => {
                                tracing::debug!(error = %err, "Session heartbeat failed");
                            }
                        }
                    }
                }
            }
        });
    }
}

/// Get the system hostname (best-effort).
mod hostname {
    use std::ffi::OsString;

    pub fn get() -> Result<OsString, std::io::Error> {
        #[cfg(unix)]
        {
            let mut buf = vec![0u8; 256];
            let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut _, buf.len()) };
            if ret == 0 {
                let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                buf.truncate(end);
                Ok(OsString::from(String::from_utf8_lossy(&buf).into_owned()))
            } else {
                Err(std::io::Error::last_os_error())
            }
        }

        #[cfg(not(unix))]
        {
            Ok(OsString::from("unknown"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::{
        extract::Path,
        http::StatusCode,
        routing::{delete, post},
        Json, Router,
    };
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;

    #[test]
    fn session_state_default_summary() {
        let state = SessionState::default();
        assert_eq!(state.summary(), "Session: inactive");
    }

    #[test]
    fn session_state_active_summary() {
        let state = SessionState {
            session_id: Some("sess-123".to_string()),
            posture: "restricted".to_string(),
            budget_used: 45,
            budget_limit: 100,
        };
        assert_eq!(
            state.summary(),
            "Session: active | Posture: restricted | Budget: 45/100"
        );
    }

    #[test]
    fn session_state_active_without_budget() {
        let state = SessionState {
            session_id: Some("sess-123".to_string()),
            posture: "standard".to_string(),
            budget_used: 0,
            budget_limit: 0,
        };
        assert_eq!(state.summary(), "Session: active | Posture: standard");
    }

    #[tokio::test]
    async fn session_manager_initial_state() {
        let manager = SessionManager::new();
        let state = manager.state().await;
        assert!(state.session_id.is_none());
        assert_eq!(state.posture, "unknown");
    }

    #[tokio::test]
    async fn update_posture_from_daemon_event_updates_current_session() {
        let manager = SessionManager::new();

        {
            let mut state = manager.state.write().await;
            state.session_id = Some("sess-123".to_string());
            state.posture = "restricted".to_string();
        }

        let applied = manager
            .update_posture_from_daemon_event(Some("sess-123"), "standard".to_string())
            .await;
        assert!(applied);

        let state = manager.state().await;
        assert_eq!(state.posture, "standard");

        let applied = manager
            .update_posture_from_daemon_event(Some("sess-other"), "restricted".to_string())
            .await;
        assert!(!applied);

        let state = manager.state().await;
        assert_eq!(state.posture, "standard");

        let applied = manager
            .update_posture_from_daemon_event(None, "restricted".to_string())
            .await;
        assert!(applied);

        let state = manager.state().await;
        assert_eq!(state.posture, "restricted");
    }

    #[tokio::test]
    async fn heartbeat_does_not_clear_new_session_state() {
        let manager = SessionManager::new();

        {
            let mut state = manager.state.write().await;
            state.session_id = Some("old".to_string());
            state.posture = "restricted".to_string();
        }

        // If the session has been replaced since the heartbeat started, the CAS should fail.
        {
            let mut state = manager.state.write().await;
            state.session_id = Some("new".to_string());
            state.posture = "standard".to_string();
        }

        let cleared = manager
            .with_state_if_current_session_id("old", |state| {
                *state = SessionState::default();
            })
            .await;
        assert!(cleared.is_none());

        let state = manager.state().await;
        assert_eq!(state.session_id.as_deref(), Some("new"));
        assert_eq!(state.posture, "standard");
    }

    async fn start_test_server(
        post_behavior: impl Fn() -> Result<String, StatusCode> + Send + Sync + 'static,
        events: Arc<StdMutex<Vec<String>>>,
    ) -> String {
        let post_behavior = Arc::new(post_behavior);
        let events_post = events.clone();
        let events_delete = events.clone();
        let app = Router::new()
            .route(
                "/api/v1/session",
                post({
                    let post_behavior = post_behavior.clone();
                    move || async move {
                        match post_behavior() {
                            Ok(session_id) => {
                                events_post
                                    .lock()
                                    .unwrap()
                                    .push(format!("post:{}", session_id));
                                (StatusCode::OK, Json(serde_json::json!({ "session": { "session_id": session_id } })))
                            }
                            Err(code) => (code, Json(serde_json::json!({ "error": "fail" }))),
                        }
                    }
                }),
            )
            .route(
                "/api/v1/session/{id}",
                delete({
                    move |Path(id): Path<String>| async move {
                        events_delete
                            .lock()
                            .unwrap()
                            .push(format!("delete:{}", id));
                        StatusCode::NO_CONTENT
                    }
                }),
            );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn create_session_terminates_existing_before_replacement() {
        let events: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let daemon_url = start_test_server(
            {
                let counter = counter.clone();
                move || {
                    let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    Ok(format!("sess-{}", n))
                }
            },
            events.clone(),
        )
        .await;

        let manager = SessionManager::new();
        let s1 = manager.create_session(&daemon_url, None).await.unwrap();
        assert_eq!(s1, "sess-1");

        let s2 = manager.create_session(&daemon_url, None).await.unwrap();
        assert_eq!(s2, "sess-2");

        let got = events.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![
                "post:sess-1".to_string(),
                "delete:sess-1".to_string(),
                "post:sess-2".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn ensure_session_retries_until_success() {
        let events: Arc<StdMutex<Vec<String>>> = Arc::new(StdMutex::new(Vec::new()));
        let attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let daemon_url = start_test_server(
            {
                let attempts = attempts.clone();
                move || {
                    let n = attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                    if n <= 2 {
                        return Err(StatusCode::INTERNAL_SERVER_ERROR);
                    }
                    Ok("sess-ok".to_string())
                }
            },
            events.clone(),
        )
        .await;

        let manager = Arc::new(SessionManager::new());
        let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
        manager.start_ensure_session(daemon_url, None, shutdown_rx);

        let sid = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Some(sid) = manager.session_id().await {
                    return sid;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("timed out waiting for session");
        assert_eq!(sid, "sess-ok");

        let _ = shutdown_tx.send(());
    }
}
