//! `SessionManager` — lifecycle, heartbeats, posture transitions, and ensure-session retries.

use super::hushd_info::{CreateSessionResponse, GetSessionResponse};
use super::state::SessionState;
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::{broadcast, RwLock};

/// Manages the lifecycle of a hushd session.
pub struct SessionManager {
    pub(super) state: Arc<RwLock<SessionState>>,
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

        let hostname = crate::settings::hostname_best_effort();

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

    pub(super) async fn with_state_if_current_session_id<T>(
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

    /// Transition the currently tracked session posture via hushd.
    ///
    /// Returns:
    /// - `Ok(true)` when a session existed and transition succeeded.
    /// - `Ok(false)` when there is no active session (or session became invalid).
    pub async fn transition_current_session_posture(
        &self,
        daemon_url: &str,
        api_key: Option<&str>,
        to_state: &str,
        trigger: &str,
    ) -> Result<bool> {
        let session_id = {
            let state = self.state.read().await;
            state.session_id.clone()
        };

        let Some(session_id) = session_id else {
            return Ok(false);
        };

        let url = format!("{}/api/v1/session/{}/transition", daemon_url, session_id);
        let mut request = self.http_client.post(&url).json(&serde_json::json!({
            "to_state": to_state,
            "trigger": trigger,
        }));
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Session posture transition failed at {}", url))?;

        let status_code = response.status();
        if status_code.is_success() {
            let to_state = to_state.to_string();
            let _ = self
                .with_state_if_current_session_id(&session_id, |state| {
                    state.posture = to_state;
                })
                .await;
            return Ok(true);
        }

        if matches!(
            status_code,
            reqwest::StatusCode::NOT_FOUND
                | reqwest::StatusCode::UNAUTHORIZED
                | reqwest::StatusCode::FORBIDDEN
        ) {
            let _ = self
                .with_state_if_current_session_id(&session_id, |state| {
                    *state = SessionState::default();
                })
                .await;
            return Ok(false);
        }

        let body = response.text().await.unwrap_or_default();
        anyhow::bail!(
            "Session posture transition returned {}: {}",
            status_code,
            body
        );
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

// Hostname retrieval is consolidated in `crate::settings::hostname_best_effort()`.
