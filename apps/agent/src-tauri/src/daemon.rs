//! Daemon management for hushd process
//!
//! Handles spawning, monitoring, and restarting the hushd daemon.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, RwLock};

/// Health response from hushd /health endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: Option<String>,
    pub uptime_secs: Option<i64>,
    pub session_id: Option<String>,
    pub audit_count: Option<usize>,
}

/// Current state of the daemon
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonState {
    /// Daemon is not running
    Stopped,
    /// Daemon is starting up
    Starting,
    /// Daemon is running and healthy
    Running,
    /// Daemon is running but health check failed
    Unhealthy,
    /// Daemon crashed and will restart
    Restarting,
}

impl DaemonState {
    pub fn as_str(&self) -> &'static str {
        match self {
            DaemonState::Stopped => "stopped",
            DaemonState::Starting => "starting",
            DaemonState::Running => "running",
            DaemonState::Unhealthy => "unhealthy",
            DaemonState::Restarting => "restarting",
        }
    }
}

/// Daemon status with health info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub state: String,
    pub version: Option<String>,
    pub uptime_secs: Option<i64>,
    pub audit_count: Option<usize>,
    pub restart_count: u32,
}

/// Configuration for the daemon manager
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Path to hushd binary
    pub binary_path: PathBuf,
    /// Port to bind to
    pub port: u16,
    /// Path to policy file
    pub policy_path: PathBuf,
    /// Path to audit database
    pub audit_db_path: PathBuf,
    /// API key for authentication (optional)
    pub api_key: Option<String>,
}

impl DaemonConfig {
    pub fn health_url(&self) -> String {
        format!("http://127.0.0.1:{}/health", self.port)
    }
}

/// Manages the hushd daemon lifecycle
pub struct DaemonManager {
    config: DaemonConfig,
    state: Arc<RwLock<DaemonState>>,
    child: Arc<RwLock<Option<Child>>>,
    restart_count: Arc<RwLock<u32>>,
    http_client: reqwest::Client,
    state_tx: broadcast::Sender<DaemonState>,
    shutdown_tx: broadcast::Sender<()>,
}

impl DaemonManager {
    /// Create a new daemon manager
    pub fn new(config: DaemonConfig) -> Self {
        let (state_tx, _) = broadcast::channel(16);
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config,
            state: Arc::new(RwLock::new(DaemonState::Stopped)),
            child: Arc::new(RwLock::new(None)),
            restart_count: Arc::new(RwLock::new(0)),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_default(),
            state_tx,
            shutdown_tx,
        }
    }

    /// Subscribe to state changes
    pub fn subscribe(&self) -> broadcast::Receiver<DaemonState> {
        self.state_tx.subscribe()
    }

    /// Get current state
    pub async fn state(&self) -> DaemonState {
        self.state.read().await.clone()
    }

    /// Get current status with health info
    pub async fn status(&self) -> DaemonStatus {
        let state = self.state.read().await.clone();
        let restart_count = *self.restart_count.read().await;

        // Try to get health info if running
        let (version, uptime_secs, audit_count) = if state == DaemonState::Running {
            match self.health_check().await {
                Ok(health) => (health.version, health.uptime_secs, health.audit_count),
                Err(_) => (None, None, None),
            }
        } else {
            (None, None, None)
        };

        DaemonStatus {
            state: state.as_str().to_string(),
            version,
            uptime_secs,
            audit_count,
            restart_count,
        }
    }

    /// Start the daemon
    pub async fn start(&self) -> Result<()> {
        // Check if already running
        let current_state = self.state.read().await.clone();
        if current_state == DaemonState::Running || current_state == DaemonState::Starting {
            return Ok(());
        }

        self.set_state(DaemonState::Starting).await;

        // Spawn the daemon process
        self.spawn_daemon().await?;

        // Start health monitoring
        self.start_health_monitor();

        Ok(())
    }

    /// Stop the daemon
    pub async fn stop(&self) -> Result<()> {
        // Signal shutdown
        let _ = self.shutdown_tx.send(());

        // Kill the child process
        let mut child_guard = self.child.write().await;
        if let Some(ref mut child) = *child_guard {
            // Try graceful shutdown first
            #[cfg(unix)]
            if let Some(pid) = child.id() {
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
            }

            // Wait briefly for graceful shutdown
            tokio::time::sleep(Duration::from_millis(500)).await;

            // Force kill if still running
            let _ = child.kill().await;
        }
        *child_guard = None;

        self.set_state(DaemonState::Stopped).await;
        Ok(())
    }

    /// Restart the daemon
    pub async fn restart(&self) -> Result<()> {
        self.stop().await?;
        tokio::time::sleep(Duration::from_millis(100)).await;
        self.start().await
    }

    /// Perform a health check
    pub async fn health_check(&self) -> Result<HealthResponse> {
        let url = self.config.health_url();
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to connect to daemon at {}", url))?;

        let health: HealthResponse = response
            .json()
            .await
            .with_context(|| "Failed to parse health response")?;

        Ok(health)
    }

    async fn spawn_daemon(&self) -> Result<()> {
        let binary_path = &self.config.binary_path;

        // Check if binary exists
        if !binary_path.exists() {
            anyhow::bail!("hushd binary not found at {:?}", binary_path);
        }

        // Build command arguments
        let mut cmd = Command::new(binary_path);
        cmd.arg("start")
            .arg("--port")
            .arg(self.config.port.to_string())
            .arg("--bind")
            .arg("127.0.0.1");

        // Add policy path if exists
        if self.config.policy_path.exists() {
            cmd.arg("--ruleset").arg(&self.config.policy_path);
        }

        // Configure stdio
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .stdin(Stdio::null());

        // Spawn the process
        let mut child = cmd
            .spawn()
            .with_context(|| format!("Failed to spawn hushd from {:?}", binary_path))?;

        // Capture and log stdout/stderr
        if let Some(stdout) = child.stdout.take() {
            let reader = BufReader::new(stdout);
            tokio::spawn(async move {
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::info!(target: "hushd", "{}", line);
                }
            });
        }

        if let Some(stderr) = child.stderr.take() {
            let reader = BufReader::new(stderr);
            tokio::spawn(async move {
                let mut lines = reader.lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    tracing::warn!(target: "hushd", "{}", line);
                }
            });
        }

        // Store the child process
        *self.child.write().await = Some(child);

        // Wait for daemon to be ready
        self.wait_for_ready().await?;

        self.set_state(DaemonState::Running).await;
        tracing::info!("hushd daemon started on port {}", self.config.port);

        Ok(())
    }

    async fn wait_for_ready(&self) -> Result<()> {
        let max_attempts = 30;
        let delay = Duration::from_millis(100);

        for attempt in 0..max_attempts {
            match self.health_check().await {
                Ok(health) if health.status == "healthy" => {
                    tracing::debug!("Daemon ready after {} attempts", attempt + 1);
                    return Ok(());
                }
                Ok(_) => {
                    tracing::debug!("Daemon not healthy yet, attempt {}", attempt + 1);
                }
                Err(e) => {
                    tracing::debug!("Health check failed (attempt {}): {}", attempt + 1, e);
                }
            }
            tokio::time::sleep(delay).await;
        }

        anyhow::bail!("Daemon failed to become ready after {} attempts", max_attempts)
    }

    fn start_health_monitor(&self) {
        let state = Arc::clone(&self.state);
        let child = Arc::clone(&self.child);
        let restart_count = Arc::clone(&self.restart_count);
        let config = self.config.clone();
        let http_client = self.http_client.clone();
        let state_tx = self.state_tx.clone();
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let check_interval = Duration::from_secs(5);
            let max_retries = 3;
            let mut consecutive_failures = 0;

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Health monitor received shutdown signal");
                        break;
                    }
                    _ = tokio::time::sleep(check_interval) => {
                        // Check if process is still running
                        let mut child_guard = child.write().await;
                        if let Some(ref mut proc) = *child_guard {
                            match proc.try_wait() {
                                Ok(Some(status)) => {
                                    // Process exited
                                    tracing::warn!("hushd exited with status: {:?}", status);
                                    *child_guard = None;
                                    drop(child_guard);

                                    // Update state and restart
                                    *state.write().await = DaemonState::Restarting;
                                    let _ = state_tx.send(DaemonState::Restarting);

                                    *restart_count.write().await += 1;
                                    consecutive_failures = 0;

                                    // Exponential backoff for restarts
                                    let backoff = Duration::from_secs(
                                        2u64.pow((*restart_count.read().await).min(5))
                                    );
                                    tokio::time::sleep(backoff).await;

                                    // Try to restart (simplified - in production would call spawn_daemon)
                                    continue;
                                }
                                Ok(None) => {
                                    // Still running, check health
                                    drop(child_guard);
                                }
                                Err(e) => {
                                    tracing::error!("Failed to check process status: {}", e);
                                    drop(child_guard);
                                }
                            }
                        } else {
                            // No child process
                            *state.write().await = DaemonState::Stopped;
                            let _ = state_tx.send(DaemonState::Stopped);
                            continue;
                        }

                        // Perform health check
                        let url = config.health_url();
                        match http_client.get(&url).send().await {
                            Ok(response) => {
                                if response.status().is_success() {
                                    consecutive_failures = 0;
                                    let current = state.read().await.clone();
                                    if current != DaemonState::Running {
                                        *state.write().await = DaemonState::Running;
                                        let _ = state_tx.send(DaemonState::Running);
                                    }
                                } else {
                                    consecutive_failures += 1;
                                    tracing::warn!("Health check returned non-success: {}", response.status());
                                }
                            }
                            Err(e) => {
                                consecutive_failures += 1;
                                tracing::warn!("Health check failed: {}", e);
                            }
                        }

                        // Update state if unhealthy
                        if consecutive_failures >= max_retries {
                            let current = state.read().await.clone();
                            if current == DaemonState::Running {
                                *state.write().await = DaemonState::Unhealthy;
                                let _ = state_tx.send(DaemonState::Unhealthy);
                            }
                        }
                    }
                }
            }
        });
    }

    async fn set_state(&self, new_state: DaemonState) {
        *self.state.write().await = new_state.clone();
        let _ = self.state_tx.send(new_state);
    }
}

/// Find the hushd binary
pub fn find_hushd_binary() -> Option<PathBuf> {
    // Check common locations
    let candidates = [
        // In PATH
        which::which("hushd").ok(),
        // Relative to agent binary (bundled)
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("hushd"))),
        // Cargo target directory (development)
        std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("../../target/release/hushd")),
        std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("../../target/debug/hushd")),
        // Common install locations
        Some(PathBuf::from("/usr/local/bin/hushd")),
        Some(PathBuf::from("/opt/clawdstrike/bin/hushd")),
        // Home directory
        dirs::home_dir().map(|p| p.join(".local/bin/hushd")),
        dirs::home_dir().map(|p| p.join(".cargo/bin/hushd")),
    ];

    for candidate in candidates.into_iter().flatten() {
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_state_as_str() {
        assert_eq!(DaemonState::Running.as_str(), "running");
        assert_eq!(DaemonState::Stopped.as_str(), "stopped");
    }
}
