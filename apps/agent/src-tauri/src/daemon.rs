//! Daemon management for hushd process.
//!
//! Handles spawning, monitoring, and restarting the hushd daemon.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, RwLock};

const READY_MAX_ATTEMPTS: usize = 40;
const READY_POLL_DELAY: Duration = Duration::from_millis(150);

/// Health response from hushd `/health` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: Option<String>,
    pub uptime_secs: Option<i64>,
    pub session_id: Option<String>,
    pub audit_count: Option<usize>,
}

/// Current state of the daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DaemonState {
    /// Daemon is not running.
    Stopped,
    /// Daemon is starting up.
    Starting,
    /// Daemon is running and healthy.
    Running,
    /// Daemon is running but health check failed.
    Unhealthy,
    /// Daemon crashed and will restart.
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

/// Daemon status with health info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub state: String,
    pub version: Option<String>,
    pub uptime_secs: Option<i64>,
    pub audit_count: Option<usize>,
    pub restart_count: u32,
}

/// Configuration for the daemon manager.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Path to hushd binary.
    pub binary_path: PathBuf,
    /// Port to bind to.
    pub port: u16,
    /// Path to policy file.
    pub policy_path: PathBuf,
}

impl DaemonConfig {
    pub fn health_url(&self) -> String {
        format!("http://127.0.0.1:{}/health", self.port)
    }
}

/// Manages the hushd daemon lifecycle.
pub struct DaemonManager {
    config: DaemonConfig,
    state: Arc<RwLock<DaemonState>>,
    child: Arc<RwLock<Option<Child>>>,
    restart_count: Arc<RwLock<u32>>,
    http_client: reqwest::Client,
    state_tx: broadcast::Sender<DaemonState>,
    shutdown_tx: broadcast::Sender<()>,
    monitor_started: Arc<AtomicBool>,
}

impl DaemonManager {
    /// Create a new daemon manager.
    pub fn new(config: DaemonConfig) -> Self {
        let (state_tx, _) = broadcast::channel(16);
        let (shutdown_tx, _) = broadcast::channel(4);

        Self {
            config,
            state: Arc::new(RwLock::new(DaemonState::Stopped)),
            child: Arc::new(RwLock::new(None)),
            restart_count: Arc::new(RwLock::new(0)),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            state_tx,
            shutdown_tx,
            monitor_started: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Subscribe to state changes.
    pub fn subscribe(&self) -> broadcast::Receiver<DaemonState> {
        self.state_tx.subscribe()
    }

    /// Get current status with health info.
    pub async fn status(&self) -> DaemonStatus {
        let state = self.state.read().await.clone();
        let restart_count = *self.restart_count.read().await;

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

    /// Start the daemon.
    pub async fn start(&self) -> Result<()> {
        let current = self.state.read().await.clone();
        if current == DaemonState::Running || current == DaemonState::Starting {
            return Ok(());
        }

        self.set_state(DaemonState::Starting).await;
        self.spawn_and_wait_ready().await?;
        self.set_state(DaemonState::Running).await;
        self.start_health_monitor();
        tracing::info!("hushd daemon started on port {}", self.config.port);
        Ok(())
    }

    /// Stop the daemon.
    pub async fn stop(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        self.terminate_child("stop requested").await;
        self.set_state(DaemonState::Stopped).await;
        self.monitor_started.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Restart the daemon.
    pub async fn restart(&self) -> Result<()> {
        self.stop().await?;
        tokio::time::sleep(Duration::from_millis(150)).await;
        self.start().await
    }

    /// Perform a health check.
    pub async fn health_check(&self) -> Result<HealthResponse> {
        health_check_with_client(&self.config, &self.http_client).await
    }

    async fn spawn_and_wait_ready(&self) -> Result<()> {
        spawn_child_into_slot(&self.config, &self.child).await?;

        if let Err(err) = wait_for_ready_with_client(&self.config, &self.http_client).await {
            self.terminate_child("startup readiness check failed").await;
            return Err(err);
        }

        Ok(())
    }

    async fn terminate_child(&self, reason: &str) {
        if terminate_child_slot(&self.child).await {
            tracing::info!(reason, "Terminated hushd process");
        }
    }

    fn start_health_monitor(&self) {
        if self.monitor_started.swap(true, Ordering::SeqCst) {
            return;
        }

        let state = Arc::clone(&self.state);
        let child = Arc::clone(&self.child);
        let restart_count = Arc::clone(&self.restart_count);
        let config = self.config.clone();
        let http_client = self.http_client.clone();
        let state_tx = self.state_tx.clone();
        let monitor_started = Arc::clone(&self.monitor_started);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        tokio::spawn(async move {
            let check_interval = Duration::from_secs(5);
            let max_health_failures = 3u32;
            let stable_window = Duration::from_secs(90);
            let mut consecutive_health_failures = 0u32;
            let mut restart_streak = 0u32;
            let mut last_ready_at = Some(Instant::now());

            'monitor: loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Health monitor received shutdown signal");
                        monitor_started.store(false, Ordering::SeqCst);
                        break;
                    }
                    _ = tokio::time::sleep(check_interval) => {
                        let current_state = state.read().await.clone();
                        if current_state == DaemonState::Stopped {
                            continue;
                        }

                        if let Some(reason) = check_process_exit(&child).await {
                            tracing::warn!(%reason, "hushd exited unexpectedly");
                            let next_restart_count = {
                                let mut value = restart_count.write().await;
                                *value = value.saturating_add(1);
                                *value
                            };

                            if last_ready_at.is_some_and(|ready_at| ready_at.elapsed() >= stable_window) {
                                restart_streak = 0;
                            }
                            last_ready_at = None;
                            restart_streak = restart_streak.saturating_add(1);

                            set_shared_state(&state, &state_tx, DaemonState::Restarting).await;

                            let backoff = compute_backoff(restart_streak, next_restart_count);
                            tracing::info!(backoff_ms = backoff.as_millis() as u64, "Scheduling hushd restart");
                            if sleep_or_shutdown(&mut shutdown_rx, backoff).await {
                                tracing::debug!("Shutdown requested while waiting to restart hushd");
                                monitor_started.store(false, Ordering::SeqCst);
                                break 'monitor;
                            }

                            match spawn_child_into_slot(&config, &child).await {
                                Ok(()) => {
                                    match wait_for_ready_with_client_or_shutdown(
                                        &config,
                                        &http_client,
                                        &mut shutdown_rx,
                                    )
                                    .await
                                    {
                                        Ok(ReadyWaitOutcome::Ready) => {
                                            consecutive_health_failures = 0;
                                            restart_streak = 0;
                                            last_ready_at = Some(Instant::now());
                                            set_shared_state(&state, &state_tx, DaemonState::Running).await;
                                            tracing::info!("hushd restart complete");
                                        }
                                        Ok(ReadyWaitOutcome::Shutdown) => {
                                            tracing::debug!("Shutdown requested during hushd readiness wait");
                                            terminate_child_slot(&child).await;
                                            monitor_started.store(false, Ordering::SeqCst);
                                            break 'monitor;
                                        }
                                        Err(err) => {
                                            tracing::error!(error = %err, "hushd restart failed readiness check");
                                            terminate_child_slot(&child).await;
                                            set_shared_state(&state, &state_tx, DaemonState::Unhealthy).await;
                                        }
                                    }
                                }
                                Err(err) => {
                                    tracing::error!(error = %err, "Failed to respawn hushd");
                                    set_shared_state(&state, &state_tx, DaemonState::Unhealthy).await;
                                }
                            }

                            continue;
                        }

                        match health_check_with_client(&config, &http_client).await {
                            Ok(health) if health.status == "healthy" => {
                                consecutive_health_failures = 0;
                                if last_ready_at.is_none() {
                                    last_ready_at = Some(Instant::now());
                                }
                                let current = state.read().await.clone();
                                if current != DaemonState::Running {
                                    set_shared_state(&state, &state_tx, DaemonState::Running).await;
                                }
                            }
                            Ok(health) => {
                                consecutive_health_failures = consecutive_health_failures.saturating_add(1);
                                tracing::warn!(status = %health.status, "hushd health status is not healthy");
                            }
                            Err(err) => {
                                consecutive_health_failures = consecutive_health_failures.saturating_add(1);
                                tracing::warn!(error = %err, "hushd health check failed");
                            }
                        }

                        if consecutive_health_failures >= max_health_failures {
                            let current = state.read().await.clone();
                            if current == DaemonState::Running {
                                set_shared_state(&state, &state_tx, DaemonState::Unhealthy).await;
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

async fn spawn_child_into_slot(
    config: &DaemonConfig,
    child_slot: &Arc<RwLock<Option<Child>>>,
) -> Result<()> {
    let mut child = spawn_daemon_process(config).await?;
    attach_child_logs(&mut child);
    *child_slot.write().await = Some(child);
    Ok(())
}

async fn terminate_child_slot(child_slot: &Arc<RwLock<Option<Child>>>) -> bool {
    let mut guard = child_slot.write().await;
    let mut maybe_child = guard.take();
    drop(guard);
    let Some(ref mut child) = maybe_child else {
        return false;
    };

    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // Best-effort graceful shutdown before force kill.
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    tokio::time::sleep(Duration::from_millis(400)).await;
    let _ = child.kill().await;
    let _ = child.wait().await;
    true
}

async fn spawn_daemon_process(config: &DaemonConfig) -> Result<Child> {
    if !config.binary_path.exists() {
        anyhow::bail!("hushd binary not found at {:?}", config.binary_path);
    }

    let mut cmd = Command::new(&config.binary_path);
    cmd.arg("start")
        .arg("--port")
        .arg(config.port.to_string())
        .arg("--bind")
        .arg("127.0.0.1");

    if config.policy_path.exists() {
        cmd.arg("--ruleset").arg(&config.policy_path);
    }

    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    let child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn hushd from {:?}", config.binary_path))?;

    Ok(child)
}

fn attach_child_logs(child: &mut Child) {
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
}

async fn wait_for_ready_with_client(
    config: &DaemonConfig,
    http_client: &reqwest::Client,
) -> Result<()> {
    for attempt in 0..READY_MAX_ATTEMPTS {
        if evaluate_ready_probe(attempt, health_check_with_client(config, http_client).await) {
            return Ok(());
        }
        tokio::time::sleep(READY_POLL_DELAY).await;
    }

    anyhow::bail!(
        "Daemon failed to become ready after {} attempts",
        READY_MAX_ATTEMPTS
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadyWaitOutcome {
    Ready,
    Shutdown,
}

async fn sleep_or_shutdown(shutdown_rx: &mut broadcast::Receiver<()>, duration: Duration) -> bool {
    tokio::select! {
        recv = shutdown_rx.recv() => {
            match recv {
                Ok(_) | Err(broadcast::error::RecvError::Closed) | Err(broadcast::error::RecvError::Lagged(_)) => true,
            }
        }
        _ = tokio::time::sleep(duration) => false,
    }
}

async fn wait_for_ready_with_client_or_shutdown(
    config: &DaemonConfig,
    http_client: &reqwest::Client,
    shutdown_rx: &mut broadcast::Receiver<()>,
) -> Result<ReadyWaitOutcome> {
    for attempt in 0..READY_MAX_ATTEMPTS {
        let health_result = tokio::select! {
            recv = shutdown_rx.recv() => {
                match recv {
                    Ok(_) | Err(broadcast::error::RecvError::Closed) | Err(broadcast::error::RecvError::Lagged(_)) => {
                        return Ok(ReadyWaitOutcome::Shutdown);
                    }
                }
            }
            result = health_check_with_client(config, http_client) => result,
        };

        if evaluate_ready_probe(attempt, health_result) {
            return Ok(ReadyWaitOutcome::Ready);
        }

        if sleep_or_shutdown(shutdown_rx, READY_POLL_DELAY).await {
            return Ok(ReadyWaitOutcome::Shutdown);
        }
    }

    anyhow::bail!(
        "Daemon failed to become ready after {} attempts",
        READY_MAX_ATTEMPTS
    )
}

fn evaluate_ready_probe(attempt: usize, result: Result<HealthResponse>) -> bool {
    match result {
        Ok(health) if health.status == "healthy" => {
            tracing::debug!("Daemon ready after {} attempts", attempt + 1);
            true
        }
        Ok(_) => {
            tracing::debug!("Daemon not healthy yet, attempt {}", attempt + 1);
            false
        }
        Err(err) => {
            tracing::debug!("Health check failed (attempt {}): {}", attempt + 1, err);
            false
        }
    }
}

async fn health_check_with_client(
    config: &DaemonConfig,
    http_client: &reqwest::Client,
) -> Result<HealthResponse> {
    let url = config.health_url();
    let response = http_client
        .get(&url)
        .send()
        .await
        .with_context(|| format!("Failed to connect to daemon at {}", url))?;

    if !response.status().is_success() {
        anyhow::bail!("health endpoint returned {}", response.status());
    }

    let health: HealthResponse = response
        .json()
        .await
        .with_context(|| "Failed to parse health response")?;
    Ok(health)
}

async fn check_process_exit(child_slot: &Arc<RwLock<Option<Child>>>) -> Option<String> {
    let mut guard = child_slot.write().await;
    if let Some(ref mut proc) = *guard {
        match proc.try_wait() {
            Ok(Some(status)) => {
                *guard = None;
                Some(format!("process exited with status {}", status))
            }
            Ok(None) => None,
            Err(err) => {
                *guard = None;
                Some(format!("failed to check process status: {}", err))
            }
        }
    } else {
        Some("process handle missing".to_string())
    }
}

async fn set_shared_state(
    state: &Arc<RwLock<DaemonState>>,
    state_tx: &broadcast::Sender<DaemonState>,
    new_state: DaemonState,
) {
    *state.write().await = new_state.clone();
    let _ = state_tx.send(new_state);
}

fn compute_backoff(restart_streak: u32, restart_count: u32) -> Duration {
    let exponent = restart_streak.saturating_sub(1).min(6);
    let base_ms = 500u64.saturating_mul(2u64.saturating_pow(exponent));
    let capped_ms = base_ms.min(20_000);
    let jitter_ms = (restart_count as u64).saturating_mul(113) % 250;
    Duration::from_millis(capped_ms.saturating_add(jitter_ms))
}

/// Find the hushd binary.
pub fn find_hushd_binary() -> Option<PathBuf> {
    let candidates = [
        which::which("hushd").ok(),
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("hushd"))),
        std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("../../target/release/hushd")),
        std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("../../target/debug/hushd")),
        Some(PathBuf::from("/usr/local/bin/hushd")),
        Some(PathBuf::from("/opt/clawdstrike/bin/hushd")),
        dirs::home_dir().map(|p| p.join(".local/bin/hushd")),
        dirs::home_dir().map(|p| p.join(".cargo/bin/hushd")),
    ];

    candidates
        .into_iter()
        .flatten()
        .find(|candidate| candidate.exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_state_as_str() {
        assert_eq!(DaemonState::Running.as_str(), "running");
        assert_eq!(DaemonState::Stopped.as_str(), "stopped");
    }

    #[test]
    fn backoff_is_bounded() {
        let backoff = compute_backoff(10, 10);
        assert!(backoff <= Duration::from_millis(20_500));
    }
}
