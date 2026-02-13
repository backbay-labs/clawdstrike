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

#[derive(Debug, Serialize)]
struct HushdRuntimeConfig {
    listen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_path: Option<PathBuf>,
    ruleset: String,
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
    external_mode: Arc<AtomicBool>,
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
            external_mode: Arc::new(AtomicBool::new(false)),
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

        // If another hushd is already healthy on this port, attach instead of spawning.
        if let Ok(health) = health_check_with_client(&self.config, &self.http_client).await {
            if health.status == "healthy" {
                self.external_mode.store(true, Ordering::SeqCst);
                *self.child.write().await = None;
                self.set_state(DaemonState::Running).await;
                self.start_health_monitor();
                tracing::info!(
                    "Attached to externally managed hushd on port {}",
                    self.config.port
                );
                return Ok(());
            }
        }

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
        self.external_mode.store(false, Ordering::SeqCst);
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
        let url = self.config.health_url();
        let response = self
            .http_client
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

    async fn spawn_and_wait_ready(&self) -> Result<()> {
        spawn_child_into_slot(&self.config, &self.child).await?;

        if let Err(err) = wait_for_ready_with_client(&self.config, &self.http_client).await {
            self.terminate_child("startup readiness check failed").await;
            return Err(err);
        }

        // If the spawned child already exited but health is still good, another daemon owns the port.
        if let Some(reason) = check_process_exit(&self.child).await {
            if let Ok(health) = health_check_with_client(&self.config, &self.http_client).await {
                if health.status == "healthy" {
                    self.external_mode.store(true, Ordering::SeqCst);
                    tracing::warn!(
                        reason = %reason,
                        "Managed hushd exited during startup; using external hushd instance"
                    );
                    return Ok(());
                }
            }
            anyhow::bail!("hushd exited during startup: {}", reason);
        }

        self.external_mode.store(false, Ordering::SeqCst);

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
        let external_mode = Arc::clone(&self.external_mode);
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

                        if !external_mode.load(Ordering::SeqCst) {
                            if let Some(reason) = check_process_exit(&child).await {
                                if let Ok(health) =
                                    health_check_with_client(&config, &http_client).await
                                {
                                    if health.status == "healthy" {
                                        external_mode.store(true, Ordering::SeqCst);
                                        consecutive_health_failures = 0;
                                        restart_streak = 0;
                                        last_ready_at = Some(Instant::now());
                                        set_shared_state(&state, &state_tx, DaemonState::Running)
                                            .await;
                                        tracing::warn!(
                                            reason = %reason,
                                            "Managed hushd exited but external hushd is healthy; switching to attach mode"
                                        );
                                        continue;
                                    }
                                }

                                tracing::warn!(%reason, "hushd exited unexpectedly");
                                let next_restart_count = {
                                    let mut value = restart_count.write().await;
                                    *value = value.saturating_add(1);
                                    *value
                                };

                                if last_ready_at
                                    .is_some_and(|ready_at| ready_at.elapsed() >= stable_window)
                                {
                                    restart_streak = 0;
                                }
                                last_ready_at = None;
                                restart_streak = restart_streak.saturating_add(1);

                                set_shared_state(&state, &state_tx, DaemonState::Restarting).await;

                                let backoff = compute_backoff(restart_streak, next_restart_count);
                                tracing::info!(
                                    backoff_ms = backoff.as_millis() as u64,
                                    "Scheduling hushd restart"
                                );
                                if sleep_or_shutdown(&mut shutdown_rx, backoff).await {
                                    tracing::debug!(
                                        "Shutdown requested while waiting to restart hushd"
                                    );
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
                                                if let Some(reason) = check_process_exit(&child).await
                                                {
                                                    if let Ok(health) = health_check_with_client(
                                                        &config,
                                                        &http_client,
                                                    )
                                                    .await
                                                    {
                                                        if health.status == "healthy" {
                                                            external_mode
                                                                .store(true, Ordering::SeqCst);
                                                            consecutive_health_failures = 0;
                                                            restart_streak = 0;
                                                            last_ready_at = Some(Instant::now());
                                                            set_shared_state(
                                                                &state,
                                                                &state_tx,
                                                                DaemonState::Running,
                                                            )
                                                            .await;
                                                            tracing::warn!(
                                                                reason = %reason,
                                                                "Restarted hushd exited immediately; attached to external hushd"
                                                            );
                                                            continue;
                                                        }
                                                    }
                                                    tracing::error!(
                                                        reason = %reason,
                                                        "hushd exited before restart readiness stabilized"
                                                    );
                                                    terminate_child_slot(&child).await;
                                                    set_shared_state(
                                                        &state,
                                                        &state_tx,
                                                        DaemonState::Unhealthy,
                                                    )
                                                    .await;
                                                    continue;
                                                }

                                                external_mode.store(false, Ordering::SeqCst);
                                                consecutive_health_failures = 0;
                                                restart_streak = 0;
                                                last_ready_at = Some(Instant::now());
                                                set_shared_state(
                                                    &state,
                                                    &state_tx,
                                                    DaemonState::Running,
                                                )
                                                .await;
                                                tracing::info!("hushd restart complete");
                                            }
                                            Ok(ReadyWaitOutcome::Shutdown) => {
                                                tracing::debug!(
                                                    "Shutdown requested during hushd readiness wait"
                                                );
                                                terminate_child_slot(&child).await;
                                                monitor_started.store(false, Ordering::SeqCst);
                                                break 'monitor;
                                            }
                                            Err(err) => {
                                                tracing::error!(
                                                    error = %err,
                                                    "hushd restart failed readiness check"
                                                );
                                                terminate_child_slot(&child).await;
                                                set_shared_state(
                                                    &state,
                                                    &state_tx,
                                                    DaemonState::Unhealthy,
                                                )
                                                .await;
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        tracing::error!(error = %err, "Failed to respawn hushd");
                                        set_shared_state(
                                            &state,
                                            &state_tx,
                                            DaemonState::Unhealthy,
                                        )
                                        .await;
                                    }
                                }

                                continue;
                            }
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

    let runtime_config_path = write_runtime_config_file(config)?;

    let mut cmd = Command::new(&config.binary_path);
    cmd.arg("start")
        .arg("--config")
        .arg(&runtime_config_path)
        .arg("--port")
        .arg(config.port.to_string())
        .arg("--bind")
        .arg("127.0.0.1");

    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    let child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn hushd from {:?}", config.binary_path))?;

    Ok(child)
}

fn write_runtime_config_file(config: &DaemonConfig) -> Result<PathBuf> {
    let parent = config
        .policy_path
        .parent()
        .map(|path| path.to_path_buf())
        .unwrap_or_else(|| {
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("clawdstrike")
        });
    std::fs::create_dir_all(&parent)
        .with_context(|| format!("Failed to create runtime config dir {:?}", parent))?;

    let runtime_config_path = parent.join("hushd.runtime.toml");
    let policy_path = resolve_supported_policy_path(&config.policy_path);
    let runtime = HushdRuntimeConfig {
        listen: format!("127.0.0.1:{}", config.port),
        policy_path,
        // Fallback when policy_path is unavailable.
        ruleset: "default".to_string(),
    };
    let serialized =
        toml::to_string(&runtime).with_context(|| "Failed to serialize hushd runtime config")?;
    std::fs::write(&runtime_config_path, serialized).with_context(|| {
        format!(
            "Failed to write hushd runtime config to {:?}",
            runtime_config_path
        )
    })?;
    Ok(runtime_config_path)
}

fn resolve_supported_policy_path(policy_path: &PathBuf) -> Option<PathBuf> {
    if !policy_path.exists() {
        return None;
    }
    let Ok(raw) = std::fs::read_to_string(policy_path) else {
        return None;
    };

    // Hushd no longer accepts legacy guard keys like `fs_blocklist`.
    // When an incompatible policy is detected, fall back to built-in ruleset
    // so the daemon stays available instead of restart-looping.
    if raw.contains("fs_blocklist:") {
        tracing::warn!(
            path = %policy_path.display(),
            "Policy file contains legacy fs_blocklist guard; falling back to default ruleset"
        );
        return None;
    }

    Some(policy_path.clone())
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
    let max_attempts = 40;
    let delay = Duration::from_millis(150);
    for attempt in 0..max_attempts {
        match health_check_with_client(config, http_client).await {
            Ok(health) if health.status == "healthy" => {
                tracing::debug!("Daemon ready after {} attempts", attempt + 1);
                return Ok(());
            }
            Ok(_) => {
                tracing::debug!("Daemon not healthy yet, attempt {}", attempt + 1);
            }
            Err(err) => {
                tracing::debug!("Health check failed (attempt {}): {}", attempt + 1, err);
            }
        }
        tokio::time::sleep(delay).await;
    }

    anyhow::bail!(
        "Daemon failed to become ready after {} attempts",
        max_attempts
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
    let max_attempts = 40;
    let delay = Duration::from_millis(150);
    for attempt in 0..max_attempts {
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

        match health_result {
            Ok(health) if health.status == "healthy" => {
                tracing::debug!("Daemon ready after {} attempts", attempt + 1);
                return Ok(ReadyWaitOutcome::Ready);
            }
            Ok(_) => {
                tracing::debug!("Daemon not healthy yet, attempt {}", attempt + 1);
            }
            Err(err) => {
                tracing::debug!("Health check failed (attempt {}): {}", attempt + 1, err);
            }
        }

        if sleep_or_shutdown(shutdown_rx, delay).await {
            return Ok(ReadyWaitOutcome::Shutdown);
        }
    }

    anyhow::bail!(
        "Daemon failed to become ready after {} attempts",
        max_attempts
    )
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
    let mut candidates: Vec<PathBuf> = Vec::new();
    let mut seen = std::collections::HashSet::<PathBuf>::new();

    let mut push_candidate = |candidate: Option<PathBuf>| {
        if let Some(path) = candidate {
            if seen.insert(path.clone()) {
                candidates.push(path);
            }
        }
    };

    // Explicit path override for local troubleshooting.
    push_candidate(
        std::env::var("CLAWDSTRIKE_HUSHD_PATH")
            .ok()
            .map(PathBuf::from),
    );

    push_candidate(which::which("hushd").ok());
    push_candidate(
        std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|p| p.join("hushd"))),
    );
    push_candidate(
        std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("../../target/release/hushd")),
    );
    push_candidate(
        std::env::var("CARGO_MANIFEST_DIR")
            .ok()
            .map(|p| PathBuf::from(p).join("../../target/debug/hushd")),
    );

    // Compile-time workspace-relative fallback for local `cargo run`.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    push_candidate(Some(manifest_dir.join("../../../target/debug/hushd")));
    push_candidate(Some(manifest_dir.join("../../../target/release/hushd")));

    // Runtime workspace fallback: walk ancestors and probe `target/{debug,release}`.
    if let Ok(current_dir) = std::env::current_dir() {
        for ancestor in current_dir.ancestors().take(8) {
            push_candidate(Some(ancestor.join("target/debug/hushd")));
            push_candidate(Some(ancestor.join("target/release/hushd")));
        }
    }

    if let Ok(current_exe) = std::env::current_exe() {
        for ancestor in current_exe.ancestors().take(8) {
            push_candidate(Some(ancestor.join("target/debug/hushd")));
            push_candidate(Some(ancestor.join("target/release/hushd")));
        }
    }

    push_candidate(Some(PathBuf::from("/usr/local/bin/hushd")));
    push_candidate(Some(PathBuf::from("/opt/clawdstrike/bin/hushd")));
    push_candidate(dirs::home_dir().map(|p| p.join(".local/bin/hushd")));
    push_candidate(dirs::home_dir().map(|p| p.join(".cargo/bin/hushd")));

    candidates.into_iter().find(|candidate| candidate.exists())
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
