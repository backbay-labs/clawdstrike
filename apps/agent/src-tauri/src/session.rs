//! Session lifecycle management for hushd integration.
//!
//! Manages a session with hushd that enables posture tracking and budget enforcement.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
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

/// hushd session creation response.
#[derive(Debug, Deserialize)]
struct CreateSessionResponse {
    session_id: String,
    #[serde(default)]
    posture: Option<String>,
    #[serde(default)]
    budget_limit: Option<u64>,
}

/// hushd session heartbeat/status response.
#[derive(Debug, Deserialize)]
struct SessionStatusResponse {
    #[serde(default)]
    posture: Option<String>,
    #[serde(default)]
    budget_used: Option<u64>,
    #[serde(default)]
    budget_limit: Option<u64>,
}

/// Manages the lifecycle of a hushd session.
pub struct SessionManager {
    state: Arc<RwLock<SessionState>>,
    http_client: reqwest::Client,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(SessionState::default())),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Get the current session state.
    pub async fn state(&self) -> SessionState {
        self.state.read().await.clone()
    }

    /// Get the current session ID, if any.
    #[allow(dead_code)]
    pub async fn session_id(&self) -> Option<String> {
        self.state.read().await.session_id.clone()
    }

    /// Create a new session with hushd.
    pub async fn create_session(
        &self,
        daemon_url: &str,
        api_key: Option<&str>,
    ) -> Result<String> {
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

        let session: CreateSessionResponse = response
            .json()
            .await
            .with_context(|| "Failed to parse session creation response")?;

        let session_id = session.session_id.clone();
        {
            let mut state = self.state.write().await;
            state.session_id = Some(session.session_id);
            state.posture = session.posture.unwrap_or_else(|| "standard".to_string());
            state.budget_limit = session.budget_limit.unwrap_or(0);
            state.budget_used = 0;
        }

        tracing::info!(session_id = %session_id, "Session created with hushd");
        Ok(session_id)
    }

    /// Terminate the current session.
    pub async fn terminate_session(
        &self,
        daemon_url: &str,
        api_key: Option<&str>,
    ) -> Result<()> {
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

    /// Send a heartbeat to keep the session alive and update state.
    async fn heartbeat(&self, daemon_url: &str, api_key: Option<&str>) -> Result<()> {
        let session_id = {
            let state = self.state.read().await;
            state.session_id.clone()
        };

        let Some(session_id) = session_id else {
            return Ok(());
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

        if response.status().is_success() {
            if let Ok(status) = response.json::<SessionStatusResponse>().await {
                let mut state = self.state.write().await;
                if let Some(posture) = status.posture {
                    state.posture = posture;
                }
                if let Some(budget_used) = status.budget_used {
                    state.budget_used = budget_used;
                }
                if let Some(budget_limit) = status.budget_limit {
                    state.budget_limit = budget_limit;
                }
            }
        } else if response.status() == reqwest::StatusCode::NOT_FOUND {
            // Session expired server-side; clear local state.
            tracing::warn!(session_id = %session_id, "Session expired server-side");
            let mut state = self.state.write().await;
            *state = SessionState::default();
        }

        Ok(())
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
                        if let Err(err) = manager.heartbeat(&daemon_url, api_key.as_deref()).await {
                            tracing::debug!(error = %err, "Session heartbeat failed");
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
mod tests {
    use super::*;

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
        assert_eq!(
            state.summary(),
            "Session: active | Posture: standard"
        );
    }

    #[tokio::test]
    async fn session_manager_initial_state() {
        let manager = SessionManager::new();
        let state = manager.state().await;
        assert!(state.session_id.is_none());
        assert_eq!(state.posture, "unknown");
    }
}
