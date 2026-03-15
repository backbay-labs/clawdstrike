//! Daemon management for hushd process.
//!
//! Handles spawning, monitoring, and restarting the hushd daemon.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, Mutex, RwLock};

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
    /// Canonical in-memory agent settings (preferred over on-disk reads).
    pub settings: Option<Arc<RwLock<crate::settings::Settings>>>,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeConfig {
    listen: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_path: Option<PathBuf>,
    ruleset: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signing_key: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    siem: Option<HushdRuntimeSiemConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    spine: Option<HushdRuntimeSpineConfig>,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeSiemConfig {
    enabled: bool,
    exporters: HushdRuntimeExportersConfig,
}

#[derive(Debug, Default, Serialize)]
struct HushdRuntimeExportersConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    splunk: Option<HushdRuntimeExporterSettings<HushdRuntimeSplunkConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    elastic: Option<HushdRuntimeExporterSettings<HushdRuntimeElasticConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    datadog: Option<HushdRuntimeExporterSettings<HushdRuntimeDatadogConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sumo_logic: Option<HushdRuntimeExporterSettings<HushdRuntimeSumoLogicConfig>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    webhooks: Option<HushdRuntimeExporterSettings<HushdRuntimeWebhookExporterConfig>>,
}

impl HushdRuntimeExportersConfig {
    fn has_any(&self) -> bool {
        self.splunk.is_some()
            || self.elastic.is_some()
            || self.datadog.is_some()
            || self.sumo_logic.is_some()
            || self.webhooks.is_some()
    }
}

#[derive(Debug, Serialize)]
struct HushdRuntimeExporterSettings<T> {
    enabled: bool,
    #[serde(flatten)]
    config: T,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeSplunkConfig {
    hec_url: String,
    hec_token: String,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeElasticConfig {
    base_url: String,
    index: String,
    auth: HushdRuntimeElasticAuthConfig,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeElasticAuthConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    api_key: Option<String>,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeDatadogConfig {
    api_key: String,
    site: String,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeSumoLogicConfig {
    http_source_url: String,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeWebhookExporterConfig {
    webhooks: Vec<HushdRuntimeGenericWebhookConfig>,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeGenericWebhookConfig {
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    headers: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<HushdRuntimeWebhookAuthConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    content_type: Option<String>,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeWebhookAuthConfig {
    #[serde(rename = "type")]
    auth_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
}

#[derive(Debug, Serialize)]
struct HushdRuntimeSpineConfig {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    nats_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    creds_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nkey_seed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    keypair_path: Option<PathBuf>,
    subject_prefix: String,
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
    lifecycle_lock: Arc<Mutex<()>>,
    restart_count: Arc<RwLock<u32>>,
    external_mode: Arc<AtomicBool>,
    http_client: reqwest::Client,
    state_tx: broadcast::Sender<DaemonState>,
    shutdown_tx: broadcast::Sender<()>,
    monitor_started: Arc<AtomicBool>,
    monitor_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
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
            lifecycle_lock: Arc::new(Mutex::new(())),
            restart_count: Arc::new(RwLock::new(0)),
            external_mode: Arc::new(AtomicBool::new(false)),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            state_tx,
            shutdown_tx,
            monitor_started: Arc::new(AtomicBool::new(false)),
            monitor_task: Arc::new(Mutex::new(None)),
        }
    }

    /// Subscribe to state changes.
    pub fn subscribe(&self) -> broadcast::Receiver<DaemonState> {
        self.state_tx.subscribe()
    }

    /// Return the configured hushd binary path.
    pub fn binary_path(&self) -> PathBuf {
        self.config.binary_path.clone()
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
                let _guard = Arc::clone(&self.lifecycle_lock).lock_owned().await;
                self.external_mode.store(true, Ordering::SeqCst);
                // Ensure we do not leak a managed child when transitioning into attach mode.
                let _ = terminate_child_slot(&self.child).await;
                self.set_state(DaemonState::Running).await;
                self.start_health_monitor().await;
                tracing::info!(
                    "Attached to externally managed hushd on port {}",
                    self.config.port
                );
                return Ok(());
            }
        }

        if let Err(err) = self.spawn_and_wait_ready().await {
            self.set_state(DaemonState::Stopped).await;
            return Err(err);
        }
        self.set_state(DaemonState::Running).await;
        self.start_health_monitor().await;
        tracing::info!("hushd daemon started on port {}", self.config.port);
        Ok(())
    }

    /// Stop the daemon.
    pub async fn stop(&self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        {
            let _guard = Arc::clone(&self.lifecycle_lock).lock_owned().await;
            self.terminate_child("stop requested").await;
            self.external_mode.store(false, Ordering::SeqCst);
            self.set_state(DaemonState::Stopped).await;
        }

        let monitor_handle = self.monitor_task.lock().await.take();
        if let Some(handle) = monitor_handle {
            // Ensure the background health monitor has fully observed shutdown before we return.
            // This prevents overlapping monitor tasks during restart cycles.
            if self.monitor_started.load(Ordering::SeqCst) {
                let deadline = Instant::now() + Duration::from_secs(8);
                while self.monitor_started.load(Ordering::SeqCst) && Instant::now() < deadline {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                if self.monitor_started.load(Ordering::SeqCst) {
                    tracing::warn!("Health monitor did not shut down in time; aborting task");
                    handle.abort();
                }
            }

            // Await the monitor so the flag guard can run; don't block shutdown indefinitely.
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        } else if self.monitor_started.load(Ordering::SeqCst) {
            tracing::warn!("Health monitor flag set but no join handle present; resetting flag");
            self.monitor_started.store(false, Ordering::SeqCst);
        }
        if let Err(err) = cleanup_runtime_enrollment_keypair(self.config.port) {
            tracing::warn!(error = %err, "Failed to clean up runtime enrollment keypair");
        }
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
        let _guard = Arc::clone(&self.lifecycle_lock).lock_owned().await;
        spawn_child_into_slot(&self.config, &self.child).await?;

        if let Err(err) = wait_for_ready_with_client(&self.config, &self.http_client).await {
            self.terminate_child("startup readiness check failed").await;
            return Err(err);
        }

        // If the spawned child already exited but health is still good, another daemon owns the
        // port. Attach to that external instance instead of restart-looping.
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

    async fn start_health_monitor(&self) {
        if self.monitor_started.swap(true, Ordering::SeqCst) {
            return;
        }

        let state = Arc::clone(&self.state);
        let child = Arc::clone(&self.child);
        let lifecycle_lock = Arc::clone(&self.lifecycle_lock);
        let restart_count = Arc::clone(&self.restart_count);
        let external_mode = Arc::clone(&self.external_mode);
        let config = self.config.clone();
        let http_client = self.http_client.clone();
        let state_tx = self.state_tx.clone();
        let monitor_started = Arc::clone(&self.monitor_started);
        let mut shutdown_rx = self.shutdown_tx.subscribe();

        let handle = tokio::spawn(async move {
            struct MonitorFlagGuard(Arc<AtomicBool>);

            impl Drop for MonitorFlagGuard {
                fn drop(&mut self) {
                    self.0.store(false, Ordering::SeqCst);
                }
            }

            let _monitor_flag_guard = MonitorFlagGuard(Arc::clone(&monitor_started));

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
                        break;
                    }
                    _ = tokio::time::sleep(check_interval) => {
                        if shutdown_rx.try_recv().is_ok() {
                            tracing::debug!("Shutdown requested while health monitor tick was running");
                            break 'monitor;
                        }

                        let current_state = state.read().await.clone();
                        if current_state == DaemonState::Stopped {
                            continue;
                        }

                        if !external_mode.load(Ordering::SeqCst) {
                            if let Some(reason) = check_process_exit(&child).await {
                                // If our managed child died but the port is now owned by a healthy
                                // external hushd, attach instead of restart-looping.
                                if let Ok(health) = health_check_with_client(&config, &http_client).await {
                                    if health.status == "healthy" {
                                        let _guard = Arc::clone(&lifecycle_lock).lock_owned().await;
                                        external_mode.store(true, Ordering::SeqCst);
                                        let _ = terminate_child_slot(&child).await;
                                        consecutive_health_failures = 0;
                                        restart_streak = 0;
                                        last_ready_at = Some(Instant::now());
                                        set_shared_state(&state, &state_tx, DaemonState::Running).await;
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

                                if last_ready_at.is_some_and(|ready_at| ready_at.elapsed() >= stable_window) {
                                    restart_streak = 0;
                                }
                                last_ready_at = None;
                                restart_streak = restart_streak.saturating_add(1);

                                {
                                    // Coordinate state transitions with stop()/start() so we don't
                                    // advertise a restart (or respawn) during shutdown.
                                    let _guard = Arc::clone(&lifecycle_lock).lock_owned().await;
                                    if shutdown_rx.try_recv().is_ok() {
                                        tracing::debug!(
                                            "Shutdown requested while scheduling restart; skipping"
                                        );
                                        break 'monitor;
                                    }
                                    if state.read().await.clone() == DaemonState::Stopped {
                                        break 'monitor;
                                    }
                                    set_shared_state(&state, &state_tx, DaemonState::Restarting)
                                        .await;
                                }

                                let backoff = compute_backoff(restart_streak, next_restart_count);
                                tracing::info!(backoff_ms = backoff.as_millis() as u64, "Scheduling hushd restart");
                                if sleep_or_shutdown(&mut shutdown_rx, backoff).await {
                                    tracing::debug!("Shutdown requested while waiting to restart hushd");
                                    break 'monitor;
                                }

                                let _guard = Arc::clone(&lifecycle_lock).lock_owned().await;
                                if shutdown_rx.try_recv().is_ok()
                                    || state.read().await.clone() == DaemonState::Stopped
                                {
                                    tracing::debug!(
                                        "Shutdown requested while acquiring lifecycle lock; skipping restart"
                                    );
                                    break 'monitor;
                                }
                                if external_mode.load(Ordering::SeqCst) {
                                    tracing::info!(
                                        "External mode enabled during restart backoff; skipping managed respawn"
                                    );
                                    continue;
                                }
                                // If another hushd has claimed the port since we scheduled the
                                // restart, attach instead of respawning.
                                if let Ok(health) =
                                    health_check_with_client(&config, &http_client).await
                                {
                                    if health.status == "healthy" {
                                        external_mode.store(true, Ordering::SeqCst);
                                        let _ = terminate_child_slot(&child).await;
                                        consecutive_health_failures = 0;
                                        restart_streak = 0;
                                        last_ready_at = Some(Instant::now());
                                        set_shared_state(&state, &state_tx, DaemonState::Running)
                                            .await;
                                        tracing::warn!(
                                            "External hushd became healthy during restart; switching to attach mode"
                                        );
                                        continue;
                                    }
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
                                                // If the restarted child exited but health is good, attach.
                                                if let Some(reason) = check_process_exit(&child).await {
                                                    if let Ok(health) = health_check_with_client(&config, &http_client).await {
                                                        if health.status == "healthy" {
                                                            external_mode.store(true, Ordering::SeqCst);
                                                            consecutive_health_failures = 0;
                                                            restart_streak = 0;
                                                            last_ready_at = Some(Instant::now());
                                                            set_shared_state(&state, &state_tx, DaemonState::Running).await;
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
                                                    set_shared_state(&state, &state_tx, DaemonState::Unhealthy).await;
                                                    continue;
                                                }

                                                external_mode.store(false, Ordering::SeqCst);
                                                consecutive_health_failures = 0;
                                                restart_streak = 0;
                                                last_ready_at = Some(Instant::now());
                                                set_shared_state(&state, &state_tx, DaemonState::Running).await;
                                                tracing::info!("hushd restart complete");
                                            }
                                            Ok(ReadyWaitOutcome::Shutdown) => {
                                                tracing::debug!("Shutdown requested during hushd readiness wait");
                                                terminate_child_slot(&child).await;
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

                            // In external mode there is no child to restart, but the external daemon
                            // may have disappeared. Fall back to spawning a managed child so the
                            // agent can self-heal instead of staying offline indefinitely.
                            if external_mode.load(Ordering::SeqCst) {
                                tracing::warn!(
                                    consecutive_failures = consecutive_health_failures,
                                    "External hushd unhealthy; falling back to managed daemon"
                                );
                                let _guard = Arc::clone(&lifecycle_lock).lock_owned().await;
                                if shutdown_rx.try_recv().is_ok()
                                    || state.read().await.clone() == DaemonState::Stopped
                                {
                                    tracing::debug!(
                                        "Shutdown requested while preparing external fallback; skipping respawn"
                                    );
                                    break 'monitor;
                                }
                                set_shared_state(&state, &state_tx, DaemonState::Restarting).await;
                                external_mode.store(false, Ordering::SeqCst);
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
                                                let count = {
                                                    let mut value = restart_count.write().await;
                                                    *value = value.saturating_add(1);
                                                    *value
                                                };
                                                set_shared_state(&state, &state_tx, DaemonState::Running).await;
                                                tracing::info!(
                                                    restart_count = count,
                                                    "Recovered from external hushd loss; managed daemon running"
                                                );
                                            }
                                            Ok(ReadyWaitOutcome::Shutdown) => {
                                                tracing::debug!("Shutdown requested during hushd readiness wait");
                                                terminate_child_slot(&child).await;
                                                break 'monitor;
                                            }
                                            Err(err) => {
                                                tracing::error!(
                                                    error = %err,
                                                    "Managed daemon failed readiness after external fallback"
                                                );
                                                terminate_child_slot(&child).await;
                                                set_shared_state(&state, &state_tx, DaemonState::Unhealthy).await;
                                            }
                                        }
                                    }
                                    Err(err) => {
                                        tracing::error!(
                                            error = %err,
                                            "Failed to spawn managed daemon after external hushd loss"
                                        );
                                        set_shared_state(&state, &state_tx, DaemonState::Unhealthy).await;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // Store handle for shutdown coordination (stop() may abort on timeout).
        *self.monitor_task.lock().await = Some(handle);
    }

    async fn set_state(&self, new_state: DaemonState) {
        *self.state.write().await = new_state.clone();
        let _ = self.state_tx.send(new_state);
    }
}

// ---- Policy cache for warm-start recovery ----

/// Path for the cached policy bundle.
fn policy_cache_path() -> PathBuf {
    crate::settings::get_config_dir().join("policy-cache.yaml")
}

/// Persistent policy cache that stores the last-known-good policy bundle
/// fetched from hushd. Used for quick warm-start on agent restart so that
/// hushd can re-load policies faster. This is NOT used for inline evaluation
/// fallback — when hushd is unreachable, policy checks return deny with
/// guard "hushd_unreachable" (fail-closed).
pub struct PolicyCache {
    http_client: reqwest::Client,
    cached_policy: Mutex<Option<String>>,
}

impl PolicyCache {
    pub fn new() -> Self {
        let cached = std::fs::read_to_string(policy_cache_path()).ok();
        Self {
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            cached_policy: Mutex::new(cached),
        }
    }

    /// Fetch the policy bundle from hushd and persist it to disk.
    pub async fn sync_from_daemon(&self, daemon_url: &str, api_key: Option<&str>) -> Result<()> {
        let url = format!("{}/api/v1/policy/bundle", daemon_url);
        let mut request = self.http_client.get(&url);
        if let Some(key) = api_key {
            request = request.header("Authorization", format!("Bearer {}", key));
        }

        let response = request
            .send()
            .await
            .with_context(|| format!("Failed to fetch policy bundle from {}", url))?;

        if !response.status().is_success() {
            anyhow::bail!("Policy bundle endpoint returned {}", response.status());
        }

        let body = response
            .text()
            .await
            .with_context(|| "Failed to read policy bundle response body")?;

        // Persist to disk via spawn_blocking to avoid blocking the tokio runtime.
        let path = policy_cache_path();
        let path_for_log = path.clone();
        let body_clone = body.clone();
        tokio::task::spawn_blocking(move || {
            crate::security::fs::write_private_atomic(
                &path,
                body_clone.as_bytes(),
                "policy cache file",
            )?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .with_context(|| "Policy cache write task panicked")??;

        *self.cached_policy.lock().await = Some(body);
        tracing::info!(path = ?path_for_log, "Policy cache updated");
        Ok(())
    }

    /// Return the last-known-good cached policy YAML, if any.
    #[allow(dead_code)]
    pub async fn cached_policy(&self) -> Option<String> {
        self.cached_policy.lock().await.clone()
    }

    /// Return the cached policy version (best effort) for telemetry/health payloads.
    pub async fn cached_policy_version(&self) -> Option<String> {
        let raw = self.cached_policy.lock().await.clone()?;
        parse_cached_policy_version(&raw)
    }

    /// Start a periodic sync loop that refreshes the policy cache from hushd.
    pub fn start_periodic_sync(
        self: &Arc<Self>,
        daemon_url: String,
        api_key: Option<String>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            let sync_interval = Duration::from_secs(300); // 5 minutes
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        tracing::debug!("Policy cache sync loop shutting down");
                        break;
                    }
                    _ = tokio::time::sleep(sync_interval) => {
                        if let Err(err) = cache.sync_from_daemon(&daemon_url, api_key.as_deref()).await {
                            tracing::debug!(error = %err, "Periodic policy cache sync failed (daemon may be offline)");
                        }
                    }
                }
            }
        });
    }
}

fn parse_cached_policy_version(policy_yaml: &str) -> Option<String> {
    let root: serde_yaml::Value = serde_yaml::from_str(policy_yaml).ok()?;
    let version = root.get("version")?;
    match version {
        serde_yaml::Value::String(value) => Some(value.clone()),
        serde_yaml::Value::Number(value) => Some(value.to_string()),
        serde_yaml::Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

/// Queued audit events for offline mode.
/// Stores events that were generated while hushd was unreachable so they
/// can be uploaded when connectivity is restored.
pub struct AuditQueue {
    path: PathBuf,
    queue: Mutex<VecDeque<serde_json::Value>>,
    flush_lock: Mutex<()>,
    http_client: reqwest::Client,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct PersistedAuditQueue {
    entries: VecDeque<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct FlushAuditBatchResponse {
    accepted: usize,
    duplicates: usize,
    rejected: usize,
    #[serde(default)]
    accepted_ids: Vec<String>,
    #[serde(default)]
    duplicate_ids: Vec<String>,
    #[serde(default)]
    rejected_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AuditFlushOutcome {
    pub accepted: usize,
    pub duplicates: usize,
    pub rejected: usize,
    pub partial_rejection: bool,
}

#[derive(Debug, Clone)]
pub struct AuditFlushProgressError {
    pub outcome: AuditFlushOutcome,
    pub message: String,
}

impl fmt::Display for AuditFlushProgressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} (accepted={}, duplicates={}, rejected={})",
            self.message, self.outcome.accepted, self.outcome.duplicates, self.outcome.rejected
        )
    }
}

impl std::error::Error for AuditFlushProgressError {}

const MAX_AUDIT_QUEUE_LEN: usize = 10_000;
const MAX_AUDIT_BATCH_LEN: usize = 5_000;

fn audit_flush_has_prior_progress(outcome: AuditFlushOutcome) -> bool {
    outcome.accepted > 0 || outcome.duplicates > 0 || outcome.rejected > 0
}

fn audit_flush_progress_error(
    outcome: AuditFlushOutcome,
    message: impl Into<String>,
) -> anyhow::Error {
    AuditFlushProgressError {
        outcome,
        message: message.into(),
    }
    .into()
}

fn audit_queue_path() -> PathBuf {
    crate::settings::get_config_dir().join("audit-outbox.json")
}

fn load_persisted_audit_queue(path: &Path) -> (VecDeque<serde_json::Value>, bool) {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return (VecDeque::new(), false),
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "Failed to read audit outbox file; starting with empty queue"
            );
            return (VecDeque::new(), false);
        }
    };

    match serde_json::from_str::<PersistedAuditQueue>(&raw) {
        Ok(parsed) => sanitize_persisted_audit_queue(path, parsed.entries),
        Err(err) => {
            tracing::warn!(
                error = %err,
                path = %path.display(),
                "Failed to parse audit outbox file; starting with empty queue"
            );
            (VecDeque::new(), false)
        }
    }
}

fn persist_audit_queue(path: &Path, queue: &VecDeque<serde_json::Value>) -> Result<()> {
    let serialized = serde_json::to_string_pretty(&PersistedAuditQueue {
        entries: queue.clone(),
    })
    .with_context(|| "Failed to serialize audit outbox")?;
    crate::security::fs::write_private_atomic(path, serialized.as_bytes(), "audit outbox")?;
    Ok(())
}

fn non_empty_audit_string(value: Option<&serde_json::Value>) -> bool {
    value
        .and_then(|value| value.as_str())
        .map(str::trim)
        .is_some_and(|value| !value.is_empty())
}

fn normalize_audit_event_id(value: &serde_json::Value) -> Option<String> {
    match value {
        serde_json::Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        }
        serde_json::Value::Number(raw) => Some(raw.to_string()),
        _ => None,
    }
}

fn normalize_and_validate_audit_event(event: &mut serde_json::Value) -> Option<String> {
    let obj = event.as_object_mut()?;

    let id = obj
        .get("id")
        .and_then(normalize_audit_event_id)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    obj.insert("id".to_string(), serde_json::Value::String(id.clone()));

    if !non_empty_audit_string(obj.get("timestamp"))
        || !non_empty_audit_string(obj.get("event_type"))
        || !non_empty_audit_string(obj.get("action_type"))
        || !non_empty_audit_string(obj.get("decision"))
    {
        return None;
    }

    Some(id)
}

fn sanitize_persisted_audit_queue(
    path: &Path,
    entries: VecDeque<serde_json::Value>,
) -> (VecDeque<serde_json::Value>, bool) {
    let mut sanitized = VecDeque::new();
    let mut dropped_invalid = 0usize;
    let mut dropped_overflow = 0usize;
    let mut changed = false;

    for mut event in entries {
        let original = event.clone();
        if normalize_and_validate_audit_event(&mut event).is_none() {
            dropped_invalid += 1;
            changed = true;
            continue;
        }
        if event != original {
            changed = true;
        }
        if sanitized.len() >= MAX_AUDIT_QUEUE_LEN {
            sanitized.pop_front();
            dropped_overflow += 1;
            changed = true;
        }
        sanitized.push_back(event);
    }

    if dropped_invalid > 0 || dropped_overflow > 0 {
        tracing::warn!(
            path = %path.display(),
            dropped_invalid,
            dropped_overflow,
            retained = sanitized.len(),
            "Sanitized persisted audit outbox"
        );
    }

    (sanitized, changed)
}

fn drain_flush_batch(
    queue: &mut VecDeque<serde_json::Value>,
) -> (VecDeque<serde_json::Value>, usize) {
    let mut batch = VecDeque::new();
    let mut dropped_invalid = 0usize;

    while batch.len() < MAX_AUDIT_BATCH_LEN {
        let Some(mut event) = queue.pop_front() else {
            break;
        };
        if normalize_and_validate_audit_event(&mut event).is_some() {
            batch.push_back(event);
        } else {
            dropped_invalid += 1;
        }
    }

    (batch, dropped_invalid)
}

impl AuditQueue {
    fn with_path(path: PathBuf) -> Self {
        let (queue, sanitized) = load_persisted_audit_queue(&path);
        if sanitized {
            if let Err(err) = persist_audit_queue(&path, &queue) {
                tracing::warn!(error = %err, "Failed to persist sanitized audit outbox");
            }
        }
        Self {
            path,
            queue: Mutex::new(queue),
            flush_lock: Mutex::new(()),
            http_client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub fn new() -> Self {
        Self::with_path(audit_queue_path())
    }

    #[cfg(test)]
    pub fn new_test_isolated() -> Self {
        let path = std::env::temp_dir().join(format!(
            "clawdstrike-audit-outbox-test-{}.json",
            uuid::Uuid::new_v4()
        ));
        Self::with_path(path)
    }

    /// Enqueue an audit event to be uploaded later.
    pub async fn enqueue(&self, event: serde_json::Value) {
        let mut event = event;
        let Some(event_id) = normalize_and_validate_audit_event(&mut event) else {
            tracing::warn!("Dropping invalid audit event from offline outbox enqueue");
            return;
        };
        let mut queue = self.queue.lock().await;
        if queue.iter().any(|existing| {
            existing
                .get("id")
                .and_then(normalize_audit_event_id)
                .is_some_and(|id| id == event_id)
        }) {
            return;
        }
        if queue.len() >= MAX_AUDIT_QUEUE_LEN {
            queue.pop_front();
        }
        queue.push_back(event);
        if let Err(err) = persist_audit_queue(&self.path, &queue) {
            tracing::warn!(error = %err, "Failed to persist audit outbox after enqueue");
        }
    }

    async fn persist_current_queue(&self, context: &str) {
        let queue = self.queue.lock().await;
        if let Err(err) = persist_audit_queue(&self.path, &queue) {
            tracing::warn!(error = %err, context, "Failed to persist audit outbox");
        }
    }

    async fn requeue_failed_flush(&self, events: VecDeque<serde_json::Value>) {
        // Preserve chronological ordering: front=oldest, back=newest.
        // If over capacity, drop oldest entries to match `enqueue()` semantics.
        let mut queue = self.queue.lock().await;
        let new_events = std::mem::take(&mut *queue);
        let mut restored = events;
        restored.extend(new_events);
        while restored.len() > MAX_AUDIT_QUEUE_LEN {
            restored.pop_front();
        }
        *queue = restored;
        if let Err(err) = persist_audit_queue(&self.path, &queue) {
            tracing::warn!(error = %err, "Failed to persist audit outbox after requeue");
        }
    }

    async fn requeue_selected_flush(
        &self,
        events: VecDeque<serde_json::Value>,
        failed_ids: &HashSet<String>,
    ) {
        let selected = events
            .into_iter()
            .filter(|event| {
                event
                    .get("id")
                    .and_then(normalize_audit_event_id)
                    .is_some_and(|id| failed_ids.contains(&id))
            })
            .collect();
        self.requeue_failed_flush(selected).await;
    }

    /// Drain all queued events and upload them to hushd.
    pub async fn flush(
        &self,
        daemon_url: &str,
        api_key: Option<&str>,
    ) -> Result<AuditFlushOutcome> {
        // Serialize flushes so we never interleave drain/requeue in ways that can reorder or
        // duplicate audit uploads during rapid reconnects.
        let _flush_guard = self.flush_lock.lock().await;
        let url = format!("{}/api/v1/audit/batch", daemon_url);
        let mut outcome = AuditFlushOutcome::default();
        let mut dropped_invalid_total = 0usize;

        loop {
            let events = {
                let mut queue = self.queue.lock().await;
                let (events, dropped_invalid) = drain_flush_batch(&mut queue);
                dropped_invalid_total += dropped_invalid;
                events
            };

            if events.is_empty() {
                self.persist_current_queue("after draining audit outbox")
                    .await;
                if dropped_invalid_total > 0 {
                    tracing::warn!(
                        dropped_invalid = dropped_invalid_total,
                        "Dropped invalid audit events from offline outbox"
                    );
                }
                if outcome.accepted > 0 {
                    tracing::info!(
                        count = outcome.accepted,
                        "Flushed queued audit events to daemon"
                    );
                }
                return Ok(outcome);
            }

            let attempted = events.len();
            let events_vec: Vec<_> = events.iter().collect();
            let mut request = self.http_client.post(&url).json(&serde_json::json!({
                "events": events_vec,
            }));
            if let Some(key) = api_key {
                request = request.header("Authorization", format!("Bearer {}", key));
            }

            let response = match request.send().await {
                Ok(resp) => resp,
                Err(err) => {
                    self.requeue_failed_flush(events).await;
                    if audit_flush_has_prior_progress(outcome) {
                        return Err(audit_flush_progress_error(
                            outcome,
                            format!("Failed to flush audit queue to daemon: {}", err),
                        ));
                    }
                    return Err(err).with_context(|| "Failed to flush audit queue to daemon");
                }
            };

            let status = response.status();
            if !status.is_success() {
                let body = response.text().await.unwrap_or_default();
                self.requeue_failed_flush(events).await;
                if audit_flush_has_prior_progress(outcome) {
                    if body.trim().is_empty() {
                        return Err(audit_flush_progress_error(
                            outcome,
                            format!("Audit batch upload returned {}", status),
                        ));
                    }
                    return Err(audit_flush_progress_error(
                        outcome,
                        format!("Audit batch upload returned {}: {}", status, body.trim()),
                    ));
                }
                if body.trim().is_empty() {
                    anyhow::bail!("Audit batch upload returned {}", status);
                }
                anyhow::bail!("Audit batch upload returned {}: {}", status, body.trim());
            }

            let body = response.text().await.unwrap_or_default();
            match serde_json::from_str::<FlushAuditBatchResponse>(&body) {
                Ok(summary) => {
                    if summary.duplicates > 0 {
                        tracing::info!(
                            duplicates = summary.duplicates,
                            "Daemon reported duplicate audit outbox events already ingested"
                        );
                    }
                    if summary.rejected > 0 {
                        let rejected_ids: HashSet<_> = summary.rejected_ids.into_iter().collect();
                        let has_complete_rejected_ids = rejected_ids.len() == summary.rejected;
                        if has_complete_rejected_ids {
                            outcome.accepted += summary.accepted;
                            outcome.duplicates += summary.duplicates;
                            outcome.rejected += summary.rejected;
                            outcome.partial_rejection = true;
                            self.requeue_selected_flush(events, &rejected_ids).await;
                            tracing::warn!(
                                accepted = outcome.accepted,
                                duplicates = outcome.duplicates,
                                rejected = outcome.rejected,
                                "Daemon rejected some audit outbox events; rejected entries remain queued"
                            );
                            return Ok(outcome);
                        } else {
                            self.requeue_failed_flush(events).await;
                            tracing::warn!(
                                prior_accepted = outcome.accepted,
                                prior_duplicates = outcome.duplicates,
                                accepted = summary.accepted,
                                duplicates = summary.duplicates,
                                rejected = summary.rejected,
                                rejected_ids = rejected_ids.len(),
                                "Daemon response lacked complete rejected event IDs; requeueing entire batch"
                            );
                            let message = format!(
                                "Audit batch upload partially rejected after previously flushing {} accepted events; current batch status: accepted={}, duplicates={}, rejected={}",
                                outcome.accepted,
                                summary.accepted,
                                summary.duplicates,
                                summary.rejected
                            );
                            if audit_flush_has_prior_progress(outcome) {
                                return Err(audit_flush_progress_error(outcome, message));
                            }
                            anyhow::bail!("{}", message);
                        }
                    }
                    if !summary.accepted_ids.is_empty() || !summary.duplicate_ids.is_empty() {
                        tracing::debug!(
                            accepted_ids = summary.accepted_ids.len(),
                            duplicate_ids = summary.duplicate_ids.len(),
                            "Daemon returned audit batch event ID summaries"
                        );
                    }
                    outcome.accepted += summary.accepted;
                    outcome.duplicates += summary.duplicates;
                    // Persist after each acknowledged batch so a crash before the next loop
                    // iteration does not resurrect events the daemon already accepted.
                    self.persist_current_queue("after accepted audit batch confirmation")
                        .await;
                }
                Err(err) => {
                    self.requeue_failed_flush(events).await;
                    tracing::warn!(
                        error = %err,
                        attempted,
                        body = %body,
                        "Failed to parse audit batch response; requeued audit outbox batch"
                    );
                    if audit_flush_has_prior_progress(outcome) {
                        return Err(audit_flush_progress_error(
                            outcome,
                            format!("Failed to parse audit batch response: {}", err),
                        ));
                    }
                    anyhow::bail!("Failed to parse audit batch response: {}", err);
                }
            }
        }
    }

    /// Number of events currently queued.
    pub async fn len(&self) -> usize {
        self.queue.lock().await.len()
    }
}

async fn spawn_child_into_slot(
    config: &DaemonConfig,
    child_slot: &Arc<RwLock<Option<Child>>>,
) -> Result<()> {
    // Defensive: if any managed child is already tracked, terminate it before overwriting
    // the slot to avoid leaking processes.
    let _ = terminate_child_slot(child_slot).await;
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

    let runtime_settings = load_runtime_settings_for_config(config).await;
    let runtime_config_path = write_runtime_config_file(config, runtime_settings).await?;

    let mut cmd = Command::new(&config.binary_path);
    cmd.arg("start").arg("--config").arg(&runtime_config_path);

    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    let child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn hushd from {:?}", config.binary_path))?;

    Ok(child)
}

async fn write_runtime_config_file(
    config: &DaemonConfig,
    settings: Option<crate::settings::Settings>,
) -> Result<PathBuf> {
    // Keep runtime config files in the agent config directory rather than alongside the
    // policy file. Users may point policy_path at a repo directory or read-only location.
    let parent = crate::settings::get_config_dir().join("runtime");
    let runtime_config_filename = format!("hushd.runtime.{}.yaml", config.port);
    let runtime_config_path = parent.join(&runtime_config_filename);
    let listen = format!("127.0.0.1:{}", config.port);
    let policy_path = config.policy_path.clone();
    let daemon_port = config.port;

    let path = tokio::task::spawn_blocking(move || {
        std::fs::create_dir_all(&parent)
            .with_context(|| format!("Failed to create runtime config dir {:?}", parent))?;

        let runtime_signing_key_path = materialize_runtime_signing_keypair(&parent, daemon_port)?;
        let runtime_keypair_path = if settings
            .as_ref()
            .and_then(|s| build_runtime_spine_config(s, None))
            .is_some()
        {
            materialize_runtime_enrollment_keypair(&parent, daemon_port)?
        } else {
            None
        };
        let policy_path = resolve_supported_policy_path(&policy_path);
        let runtime = HushdRuntimeConfig {
            listen,
            policy_path,
            ruleset: "default".to_string(),
            signing_key: Some(runtime_signing_key_path),
            siem: settings.as_ref().and_then(build_runtime_siem_config),
            spine: settings
                .as_ref()
                .and_then(|s| build_runtime_spine_config(s, runtime_keypair_path.clone())),
        };
        let serialized = serde_yaml::to_string(&runtime)
            .with_context(|| "Failed to serialize hushd runtime config")?;
        crate::security::fs::write_private_atomic(
            &runtime_config_path,
            serialized.as_bytes(),
            "hushd runtime config",
        )?;

        Ok::<_, anyhow::Error>(runtime_config_path)
    })
    .await
    .with_context(|| "Runtime config write task panicked")??;

    Ok(path)
}

async fn load_runtime_settings_for_config(
    config: &DaemonConfig,
) -> Option<crate::settings::Settings> {
    if let Some(settings) = config.settings.as_ref() {
        return Some(settings.read().await.clone());
    }

    let settings = match crate::settings::Settings::load() {
        Ok(settings) => settings,
        Err(err) => {
            tracing::warn!(
                error = %err,
                "Failed to load agent settings while generating hushd runtime config"
            );
            return None;
        }
    };

    Some(settings)
}

fn runtime_enrollment_keypair_path(runtime_parent: &Path, daemon_port: u16) -> PathBuf {
    runtime_parent.join(format!("agent.runtime.{}.key", daemon_port))
}

fn runtime_signing_keypair_path(runtime_parent: &Path, daemon_port: u16) -> PathBuf {
    runtime_parent.join(format!("hushd.signing.{}.key", daemon_port))
}

fn materialize_runtime_signing_keypair(runtime_parent: &Path, daemon_port: u16) -> Result<PathBuf> {
    let key_path = runtime_signing_keypair_path(runtime_parent, daemon_port);
    if key_path.exists() {
        return Ok(key_path);
    }

    let keypair = hush_core::Keypair::generate();
    let normalized = format!("{}\n", keypair.to_hex());
    crate::security::fs::write_private_atomic(
        &key_path,
        normalized.as_bytes(),
        "runtime hushd signing keypair",
    )?;
    Ok(key_path)
}

fn materialize_runtime_enrollment_keypair(
    runtime_parent: &Path,
    daemon_port: u16,
) -> Result<Option<PathBuf>> {
    let key_hex = match crate::enrollment::load_enrollment_key_hex()
        .with_context(|| "Failed to load enrollment key for runtime config")?
    {
        Some(value) => value,
        None => return Ok(None),
    };

    let key_path = runtime_enrollment_keypair_path(runtime_parent, daemon_port);
    let normalized = format!("{}\n", key_hex.trim());
    crate::security::fs::write_private_atomic(
        &key_path,
        normalized.as_bytes(),
        "runtime enrollment keypair",
    )?;
    Ok(Some(key_path))
}

fn cleanup_runtime_enrollment_keypair(daemon_port: u16) -> Result<()> {
    let runtime_parent = crate::settings::get_config_dir().join("runtime");
    let key_path = runtime_enrollment_keypair_path(&runtime_parent, daemon_port);
    if key_path.exists() {
        std::fs::remove_file(&key_path)
            .with_context(|| format!("Failed to remove runtime enrollment key {:?}", key_path))?;
    }
    Ok(())
}

fn build_runtime_siem_config(
    settings: &crate::settings::Settings,
) -> Option<HushdRuntimeSiemConfig> {
    let mut exporters = HushdRuntimeExportersConfig::default();

    let siem = &settings.integrations.siem;
    let provider = siem.provider.trim().to_ascii_lowercase();
    let endpoint = siem.endpoint.trim();
    let api_key = siem.api_key.trim();
    let siem_requested = siem.enabled || !endpoint.is_empty() || !api_key.is_empty();

    if siem_requested {
        match provider.as_str() {
            "datadog" => {
                if !endpoint.is_empty() && !api_key.is_empty() {
                    exporters.datadog = Some(HushdRuntimeExporterSettings {
                        enabled: true,
                        config: HushdRuntimeDatadogConfig {
                            api_key: api_key.to_string(),
                            site: normalize_datadog_site(endpoint),
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider datadog requires both endpoint and API key; exporter not enabled"
                    );
                }
            }
            "splunk" => {
                if !endpoint.is_empty() && !api_key.is_empty() {
                    exporters.splunk = Some(HushdRuntimeExporterSettings {
                        enabled: true,
                        config: HushdRuntimeSplunkConfig {
                            hec_url: endpoint.to_string(),
                            hec_token: api_key.to_string(),
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider splunk requires both endpoint and API key; exporter not enabled"
                    );
                }
            }
            "elastic" => {
                if !endpoint.is_empty() && !api_key.is_empty() {
                    exporters.elastic = Some(HushdRuntimeExporterSettings {
                        enabled: true,
                        config: HushdRuntimeElasticConfig {
                            base_url: endpoint.to_string(),
                            index: "clawdstrike-security".to_string(),
                            auth: HushdRuntimeElasticAuthConfig {
                                api_key: Some(api_key.to_string()),
                            },
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider elastic requires both endpoint and API key; exporter not enabled"
                    );
                }
            }
            "sumo_logic" => {
                if !endpoint.is_empty() {
                    exporters.sumo_logic = Some(HushdRuntimeExporterSettings {
                        enabled: true,
                        config: HushdRuntimeSumoLogicConfig {
                            http_source_url: endpoint.to_string(),
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider sumo_logic requires an endpoint; exporter not enabled"
                    );
                }
            }
            "custom" => {
                if !endpoint.is_empty() {
                    let webhook = build_generic_webhook_exporter(endpoint, Some(api_key));
                    exporters.webhooks = Some(HushdRuntimeExporterSettings {
                        enabled: true,
                        config: HushdRuntimeWebhookExporterConfig {
                            webhooks: vec![webhook],
                        },
                    });
                } else {
                    tracing::warn!(
                        "SIEM provider custom requires an endpoint; exporter not enabled"
                    );
                }
            }
            other => {
                tracing::warn!(
                    provider = %other,
                    "Unknown SIEM provider in settings; exporter not enabled"
                );
            }
        }
    }

    let webhooks = &settings.integrations.webhooks;
    let webhook_url = webhooks.url.trim();
    let webhook_secret = webhooks.secret.trim();
    let webhooks_requested = webhooks.enabled || !webhook_url.is_empty();
    if webhooks_requested && !webhook_url.is_empty() {
        let exporter = exporters
            .webhooks
            .get_or_insert(HushdRuntimeExporterSettings {
                enabled: true,
                config: HushdRuntimeWebhookExporterConfig { webhooks: vec![] },
            });

        exporter
            .config
            .webhooks
            .push(build_generic_webhook_exporter(
                webhook_url,
                Some(webhook_secret),
            ));
    }

    if !exporters.has_any() {
        return None;
    }

    Some(HushdRuntimeSiemConfig {
        enabled: true,
        exporters,
    })
}

fn build_runtime_spine_config(
    settings: &crate::settings::Settings,
    keypair_path: Option<PathBuf>,
) -> Option<HushdRuntimeSpineConfig> {
    if !settings.nats.enabled {
        return None;
    }

    let subject_prefix = settings.nats.subject_prefix.as_ref()?.trim();
    if subject_prefix.is_empty() {
        return None;
    }

    Some(HushdRuntimeSpineConfig {
        enabled: true,
        nats_url: settings.nats.nats_url.clone(),
        creds_file: settings.nats.creds_file.clone(),
        token: settings.nats.token.clone(),
        nkey_seed: settings.nats.nkey_seed.clone(),
        keypair_path,
        subject_prefix: subject_prefix.to_string(),
    })
}

fn build_generic_webhook_exporter(
    url: &str,
    token: Option<&str>,
) -> HushdRuntimeGenericWebhookConfig {
    let token = token.map(str::trim).unwrap_or_default();
    let auth = if token.is_empty() {
        None
    } else {
        Some(HushdRuntimeWebhookAuthConfig {
            auth_type: "bearer".to_string(),
            token: Some(token.to_string()),
        })
    };

    HushdRuntimeGenericWebhookConfig {
        url: url.to_string(),
        method: Some("POST".to_string()),
        headers: HashMap::new(),
        auth,
        content_type: Some("application/json".to_string()),
    }
}

fn normalize_datadog_site(endpoint: &str) -> String {
    let trimmed = endpoint.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return "datadoghq.com".to_string();
    }

    if let Ok(parsed) = reqwest::Url::parse(trimmed) {
        if let Some(host) = parsed.host_str() {
            return host.trim_start_matches("http-intake.logs.").to_string();
        }
    }

    let host_port = trimmed
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("datadoghq.com");
    host_port
        .split(':')
        .next()
        .unwrap_or("datadoghq.com")
        .trim_start_matches("http-intake.logs.")
        .to_string()
}

fn yaml_contains_mapping_key(value: &serde_yaml::Value, needle: &str) -> bool {
    match value {
        serde_yaml::Value::Mapping(map) => map.iter().any(|(k, v)| {
            matches!(k, serde_yaml::Value::String(s) if s == needle)
                || yaml_contains_mapping_key(v, needle)
        }),
        serde_yaml::Value::Sequence(seq) => {
            seq.iter().any(|v| yaml_contains_mapping_key(v, needle))
        }
        _ => false,
    }
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
    let doc: serde_yaml::Value = match serde_yaml::from_str(&raw) {
        Ok(v) => v,
        Err(err) => {
            tracing::warn!(
                path = %policy_path.display(),
                error = %err,
                "Failed to parse policy file; falling back to default ruleset"
            );
            return None;
        }
    };

    let legacy_guard_keys = ["fs_blocklist", "exec_blocklist", "egress_allowlist"];
    if let Some(legacy_key) = legacy_guard_keys
        .into_iter()
        .find(|key| yaml_contains_mapping_key(&doc, key))
    {
        tracing::warn!(
            path = %policy_path.display(),
            legacy_key,
            "Policy file contains legacy guard key; falling back to default ruleset"
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
    let Some(ref mut proc) = *guard else {
        // Treat missing child as an exit event so the health monitor can attempt recovery.
        return Some("process handle missing".to_string());
    };
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

fn hushd_binary_name() -> &'static str {
    if cfg!(windows) {
        "hushd.exe"
    } else {
        "hushd"
    }
}

pub fn managed_hushd_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("bin")
        .join(hushd_binary_name())
}

fn bundled_hushd_candidates() -> Vec<PathBuf> {
    let binary = hushd_binary_name();
    let mut candidates = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            // Local dev/build target dir.
            candidates.push(exe_dir.join(binary));

            // macOS app bundle locations.
            if let Some(contents_dir) = exe_dir.parent() {
                candidates.push(contents_dir.join("Resources").join(binary));
                candidates.push(contents_dir.join("Resources").join("bin").join(binary));
                candidates.push(
                    contents_dir
                        .join("Resources")
                        .join("resources")
                        .join(binary),
                );
                candidates.push(
                    contents_dir
                        .join("Resources")
                        .join("resources")
                        .join("bin")
                        .join(binary),
                );
            }
        }
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let root = PathBuf::from(manifest_dir);
        candidates.push(root.join("resources").join(binary));
        candidates.push(root.join("resources").join("bin").join(binary));
        candidates.push(root.join("../../target/release").join(binary));
        candidates.push(root.join("../../target/debug").join(binary));
    }

    candidates
}

/// Ensure a writable managed hushd binary is available under user config.
///
/// Returns `Ok(Some(path))` when a bundled hushd was found and prepared,
/// `Ok(None)` when no bundled hushd candidate is present.
pub fn prepare_managed_hushd_binary() -> Result<Option<PathBuf>> {
    let Some(source_path) = bundled_hushd_candidates()
        .into_iter()
        .find(|candidate| candidate.is_file())
    else {
        return Ok(None);
    };

    let managed_path = managed_hushd_path();
    // Seed the managed binary once. Do not overwrite an existing managed binary
    // on startup, so OTA-applied updates remain persistent across app relaunches.
    let copy_needed = !managed_path.is_file();

    if copy_needed {
        if let Some(parent) = managed_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create managed hushd directory {:?}", parent)
            })?;
        }

        std::fs::copy(&source_path, &managed_path).with_context(|| {
            format!(
                "Failed to copy bundled hushd from {:?} to {:?}",
                source_path, managed_path
            )
        })?;
    } else {
        tracing::debug!(
            managed_path = %managed_path.display(),
            "Managed hushd already exists; preserving current binary"
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&managed_path)
            .with_context(|| format!("Failed to stat managed hushd at {:?}", managed_path))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&managed_path, perms).with_context(|| {
            format!(
                "Failed to set executable permissions on managed hushd at {:?}",
                managed_path
            )
        })?;
    }

    #[cfg(target_os = "macos")]
    if copy_needed {
        let status = std::process::Command::new("codesign")
            .args([
                "--force",
                "--sign",
                "-",
                managed_path.to_string_lossy().as_ref(),
            ])
            .status()
            .with_context(|| format!("Failed to invoke codesign for {:?}", managed_path))?;
        if !status.success() {
            anyhow::bail!(
                "codesign failed for managed hushd at {:?} with status {}",
                managed_path,
                status
            );
        }
    }

    Ok(Some(managed_path))
}

/// Find the hushd binary.
pub fn find_hushd_binary() -> Option<PathBuf> {
    let binary = hushd_binary_name();
    let mut candidates = vec![managed_hushd_path()];
    candidates.extend(bundled_hushd_candidates());
    candidates.extend(
        [
            which::which("hushd").ok(),
            Some(PathBuf::from("/usr/local/bin").join(binary)),
            Some(PathBuf::from("/opt/homebrew/bin").join(binary)),
            Some(PathBuf::from("/opt/clawdstrike/bin").join(binary)),
            dirs::home_dir().map(|p| p.join(".local/bin").join(binary)),
            dirs::home_dir().map(|p| p.join(".cargo/bin").join(binary)),
        ]
        .into_iter()
        .flatten(),
    );

    candidates.into_iter().find(|candidate| candidate.exists())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_audit_event(id: impl Into<String>) -> serde_json::Value {
        serde_json::json!({
            "id": id.into(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "event_type": "violation",
            "action_type": "shell",
            "target": "echo test",
            "decision": "blocked",
            "guard": "policy_guard",
            "severity": "high",
            "message": "blocked by policy",
            "session_id": "session-1",
            "agent_id": "agent-1"
        })
    }

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

    #[test]
    fn normalize_datadog_site_accepts_host_or_intake_url() {
        assert_eq!(
            normalize_datadog_site("https://us5.datadoghq.com"),
            "us5.datadoghq.com"
        );
        assert_eq!(
            normalize_datadog_site("https://http-intake.logs.datadoghq.eu/api/v2/logs"),
            "datadoghq.eu"
        );
    }

    #[test]
    fn runtime_siem_config_is_generated_for_datadog_and_webhooks() {
        let mut settings = crate::settings::Settings::default();
        settings.integrations.siem.provider = "datadog".to_string();
        settings.integrations.siem.endpoint = "https://us5.datadoghq.com".to_string();
        settings.integrations.siem.api_key = "dd-key".to_string();
        settings.integrations.siem.enabled = true;
        settings.integrations.webhooks.url = "https://hooks.example.com/security".to_string();
        settings.integrations.webhooks.secret = "hook-secret".to_string();
        settings.integrations.webhooks.enabled = true;

        let config = build_runtime_siem_config(&settings)
            .unwrap_or_else(|| panic!("expected runtime SIEM config"));

        assert!(config.exporters.datadog.is_some());
        let datadog = config
            .exporters
            .datadog
            .as_ref()
            .unwrap_or_else(|| panic!("missing datadog exporter"));
        assert_eq!(datadog.config.site, "us5.datadoghq.com");
        assert_eq!(datadog.config.api_key, "dd-key");

        let webhooks = config
            .exporters
            .webhooks
            .as_ref()
            .unwrap_or_else(|| panic!("missing webhooks exporter"));
        assert_eq!(webhooks.config.webhooks.len(), 1);
        assert_eq!(
            webhooks.config.webhooks[0]
                .auth
                .as_ref()
                .and_then(|auth| auth.token.as_deref()),
            Some("hook-secret")
        );
    }

    #[test]
    fn runtime_spine_config_is_generated_from_nats_settings() {
        let mut settings = crate::settings::Settings::default();
        settings.nats.enabled = true;
        settings.nats.nats_url = Some("nats://example:4222".to_string());
        settings.nats.token = Some("nats-token".to_string());
        settings.nats.subject_prefix = Some("tenant-acme.clawdstrike".to_string());

        let config = build_runtime_spine_config(&settings, None)
            .unwrap_or_else(|| panic!("expected runtime spine config"));

        assert!(config.enabled);
        assert_eq!(config.nats_url.as_deref(), Some("nats://example:4222"));
        assert_eq!(config.token.as_deref(), Some("nats-token"));
        assert_eq!(config.subject_prefix, "tenant-acme.clawdstrike");
    }

    #[test]
    fn runtime_spine_config_is_none_when_nats_disabled_or_prefix_missing() {
        let settings = crate::settings::Settings::default();
        assert!(build_runtime_spine_config(&settings, None).is_none());

        let mut enabled = crate::settings::Settings::default();
        enabled.nats.enabled = true;
        enabled.nats.nats_url = Some("nats://example:4222".to_string());
        assert!(build_runtime_spine_config(&enabled, None).is_none());
    }

    #[test]
    fn parse_cached_policy_version_accepts_string_or_number() {
        assert_eq!(
            parse_cached_policy_version("version: \"42\"\nrules: []\n"),
            Some("42".to_string())
        );
        assert_eq!(
            parse_cached_policy_version("version: 7\nrules: []\n"),
            Some("7".to_string())
        );
    }

    #[test]
    fn parse_cached_policy_version_returns_none_for_missing_or_complex_values() {
        assert_eq!(parse_cached_policy_version("rules: []\n"), None);
        assert_eq!(parse_cached_policy_version("version:\n  major: 1\n"), None);
        assert_eq!(parse_cached_policy_version("not: [valid"), None);
    }

    #[tokio::test]
    async fn audit_queue_enqueue_and_len() {
        let queue = AuditQueue::new_test_isolated();
        assert_eq!(queue.len().await, 0);
        queue.enqueue(sample_audit_event("1")).await;
        queue.enqueue(sample_audit_event("2")).await;
        assert_eq!(queue.len().await, 2);
    }

    #[tokio::test]
    async fn audit_queue_assigns_id_when_missing() {
        let queue = AuditQueue::new_test_isolated();
        queue
            .enqueue(serde_json::json!({
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "event_type": "violation",
                "action_type": "shell",
                "target": "echo test",
                "decision": "blocked"
            }))
            .await;
        let guard = queue.queue.lock().await;
        assert_eq!(guard.len(), 1);
        let id = guard[0].get("id").and_then(|value| value.as_str());
        assert!(id.is_some());
        assert!(!id.unwrap_or_default().is_empty());
    }

    #[tokio::test]
    async fn audit_queue_dedupes_duplicate_ids() {
        let queue = AuditQueue::new_test_isolated();
        queue.enqueue(sample_audit_event("dup-1")).await;
        let mut duplicate = sample_audit_event("dup-1");
        duplicate["target"] = serde_json::Value::String("/tmp/file".to_string());
        queue.enqueue(duplicate).await;
        assert_eq!(queue.len().await, 1);
    }

    #[tokio::test]
    async fn audit_queue_caps_at_limit() {
        let queue = AuditQueue::new_test_isolated();
        {
            let mut guard = queue.queue.lock().await;
            for i in 0..MAX_AUDIT_QUEUE_LEN {
                guard.push_back(sample_audit_event(i.to_string()));
            }
        }
        queue.enqueue(sample_audit_event("overflow")).await;
        assert_eq!(queue.len().await, MAX_AUDIT_QUEUE_LEN);
        let guard = queue.queue.lock().await;
        assert_eq!(
            guard
                .front()
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str()),
            Some("1")
        );
        assert_eq!(
            guard
                .back()
                .and_then(|v| v.get("id"))
                .and_then(|v| v.as_str()),
            Some("overflow")
        );
    }

    #[tokio::test]
    async fn failed_start_resets_state_to_stopped() {
        let manager = DaemonManager::new(DaemonConfig {
            binary_path: PathBuf::from("/tmp/does-not-exist/hushd"),
            port: 0,
            policy_path: PathBuf::from("/tmp/policy.yaml"),
            settings: None,
        });

        let result = manager.start().await;
        assert!(result.is_err());

        let status = manager.status().await;
        assert_eq!(status.state, "stopped");
    }

    #[tokio::test]
    async fn audit_queue_flush_failure_preserves_order_and_requeues_new_events() {
        use axum::{http::StatusCode, routing::post, Json, Router};
        use std::sync::{Arc, Mutex as StdMutex};
        use tokio::net::TcpListener;
        use tokio::sync::{oneshot, Notify};

        let queue = Arc::new(AuditQueue::new_test_isolated());
        let initial_events = 512usize;

        for i in 0..initial_events {
            queue.enqueue(sample_audit_event(i.to_string())).await;
        }
        assert_eq!(queue.len().await, initial_events);

        let notify = Arc::new(Notify::new());
        let notify_for_handler = notify.clone();

        let (started_tx, started_rx) = oneshot::channel::<()>();
        let started_tx = Arc::new(StdMutex::new(Some(started_tx)));
        let started_tx_for_handler = started_tx.clone();

        let app = Router::new().route(
            "/api/v1/audit/batch",
            post(move || {
                let notify_for_handler = notify_for_handler.clone();
                let started_tx_for_handler = started_tx_for_handler.clone();
                async move {
                    if let Some(tx) = started_tx_for_handler.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    // Hold the response so the caller can enqueue new events mid-flush.
                    notify_for_handler.notified().await;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "fail"})),
                    )
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let daemon_url = format!("http://{}", addr);

        let queue_for_flush = queue.clone();
        let daemon_url_for_flush = daemon_url.clone();
        let flush_task =
            tokio::spawn(async move { queue_for_flush.flush(&daemon_url_for_flush, None).await });

        // Wait until the server has received the batch request.
        let _ = started_rx.await;

        // Enqueue new events while flush is in-flight.
        for i in initial_events..(initial_events + 5) {
            queue.enqueue(sample_audit_event(i.to_string())).await;
        }

        // Now let the server respond with failure.
        notify.notify_one();

        let res = flush_task.await.unwrap();
        assert!(res.is_err());

        let guard = queue.queue.lock().await;
        assert_eq!(guard.len(), initial_events + 5);

        let ids: Vec<usize> = guard
            .iter()
            .map(|v| {
                v.get("id")
                    .and_then(|x| x.as_str())
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap()
            })
            .collect();

        assert_eq!(ids.first().copied(), Some(0usize));
        // Newest should be preserved.
        assert_eq!(ids.last().copied(), Some(initial_events + 4));

        // Queue must preserve chronological order (strictly increasing IDs).
        for w in ids.windows(2) {
            assert!(w[0] < w[1]);
        }
    }

    #[tokio::test]
    async fn audit_queue_flush_chunks_large_batches() {
        use axum::{extract::State, routing::post, Json, Router};
        use std::sync::{Arc, Mutex as StdMutex};
        use tokio::net::TcpListener;

        #[derive(Clone)]
        struct BatchState {
            sizes: Arc<StdMutex<Vec<usize>>>,
        }

        let queue = AuditQueue::new_test_isolated();
        let total_events = MAX_AUDIT_BATCH_LEN + 37;
        {
            let mut guard = queue.queue.lock().await;
            for i in 0..total_events {
                guard.push_back(sample_audit_event(format!("evt-{i}")));
            }
            persist_audit_queue(&queue.path, &guard).unwrap();
        }

        let state = BatchState {
            sizes: Arc::new(StdMutex::new(Vec::new())),
        };
        let sizes = state.sizes.clone();
        let app =
            Router::new()
                .route(
                    "/api/v1/audit/batch",
                    post(
                        |State(state): State<BatchState>,
                         Json(payload): Json<serde_json::Value>| async move {
                            let len = payload
                                .get("events")
                                .and_then(|events| events.as_array())
                                .map(|events| events.len())
                                .unwrap_or(0);
                            state.sizes.lock().unwrap().push(len);
                            Json(serde_json::json!({
                                "accepted": len,
                                "duplicates": 0,
                                "rejected": 0
                            }))
                        },
                    ),
                )
                .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let flushed = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .unwrap();
        assert_eq!(flushed.accepted, total_events);
        assert_eq!(flushed.rejected, 0);
        assert_eq!(queue.len().await, 0);
        assert_eq!(&*sizes.lock().unwrap(), &[MAX_AUDIT_BATCH_LEN, 37]);
    }

    #[tokio::test]
    async fn audit_queue_flush_does_not_count_duplicates_as_new_uploads() {
        use axum::{routing::post, Json, Router};
        use tokio::net::TcpListener;

        let queue = AuditQueue::new_test_isolated();
        queue.enqueue(sample_audit_event("dup-1")).await;
        queue.enqueue(sample_audit_event("dup-2")).await;

        let app = Router::new().route(
            "/api/v1/audit/batch",
            post(|| async {
                Json(serde_json::json!({
                    "accepted": 0,
                    "duplicates": 2,
                    "rejected": 0
                }))
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let flushed = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .unwrap();
        assert_eq!(flushed.accepted, 0);
        assert_eq!(flushed.duplicates, 2);
        assert_eq!(queue.len().await, 0);
    }

    #[tokio::test]
    async fn audit_queue_flush_persists_empty_outbox_after_acceptance() {
        use axum::{routing::post, Json, Router};
        use tokio::net::TcpListener;

        let queue = AuditQueue::new_test_isolated();
        queue.enqueue(sample_audit_event("evt-1")).await;
        queue.enqueue(sample_audit_event("evt-2")).await;

        let app = Router::new().route(
            "/api/v1/audit/batch",
            post(|| async {
                Json(serde_json::json!({
                    "accepted": 2,
                    "duplicates": 0,
                    "rejected": 0,
                    "accepted_ids": ["evt-1", "evt-2"]
                }))
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let flushed = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .unwrap();
        assert_eq!(flushed.accepted, 2);
        assert_eq!(queue.len().await, 0);

        let persisted: PersistedAuditQueue =
            serde_json::from_slice(&std::fs::read(&queue.path).unwrap()).unwrap();
        assert!(persisted.entries.is_empty());

        let _ = std::fs::remove_file(&queue.path);
    }

    #[tokio::test]
    async fn audit_queue_flush_keeps_batch_persisted_until_daemon_acknowledges() {
        use axum::{extract::State, routing::post, Json, Router};
        use std::sync::Arc;
        use tokio::{net::TcpListener, sync::Notify};

        #[derive(Clone)]
        struct FlushGate {
            started: Arc<Notify>,
            release: Arc<Notify>,
        }

        let queue = Arc::new(AuditQueue::new_test_isolated());
        queue.enqueue(sample_audit_event("evt-1")).await;
        queue.enqueue(sample_audit_event("evt-2")).await;

        let gate = FlushGate {
            started: Arc::new(Notify::new()),
            release: Arc::new(Notify::new()),
        };

        let app = Router::new()
            .route(
                "/api/v1/audit/batch",
                post(|State(gate): State<FlushGate>| async move {
                    gate.started.notify_one();
                    gate.release.notified().await;
                    Json(serde_json::json!({
                        "accepted": 2,
                        "duplicates": 0,
                        "rejected": 0,
                        "accepted_ids": ["evt-1", "evt-2"]
                    }))
                }),
            )
            .with_state(gate.clone());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let queue_for_flush = Arc::clone(&queue);
        let flush_task = tokio::spawn(async move {
            queue_for_flush
                .flush(&format!("http://{}", addr), None)
                .await
        });

        gate.started.notified().await;

        let persisted: PersistedAuditQueue =
            serde_json::from_slice(&std::fs::read(&queue.path).unwrap()).unwrap();
        let ids: Vec<_> = persisted
            .entries
            .iter()
            .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
            .collect();
        assert_eq!(ids, vec!["evt-1", "evt-2"]);

        gate.release.notify_one();

        let flushed = flush_task.await.unwrap().unwrap();
        assert_eq!(flushed.accepted, 2);

        let persisted: PersistedAuditQueue =
            serde_json::from_slice(&std::fs::read(&queue.path).unwrap()).unwrap();
        assert!(persisted.entries.is_empty());

        let _ = std::fs::remove_file(&queue.path);
    }

    #[tokio::test]
    async fn audit_queue_flush_requeues_batch_when_response_body_is_invalid() {
        use axum::{routing::post, Router};
        use tokio::net::TcpListener;

        let queue = AuditQueue::new_test_isolated();
        queue.enqueue(sample_audit_event("evt-1")).await;
        queue.enqueue(sample_audit_event("evt-2")).await;

        let app = Router::new().route("/api/v1/audit/batch", post(|| async { "not-json" }));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let err = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .expect_err("invalid response bodies must requeue the batch");
        assert!(err
            .to_string()
            .contains("Failed to parse audit batch response"));

        let guard = queue.queue.lock().await;
        let ids: Vec<_> = guard
            .iter()
            .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
            .collect();
        assert_eq!(ids, vec!["evt-1", "evt-2"]);
    }

    #[tokio::test]
    async fn audit_queue_flush_requeues_partially_rejected_batches() {
        use axum::{routing::post, Json, Router};
        use tokio::net::TcpListener;

        let queue = AuditQueue::new_test_isolated();
        queue.enqueue(sample_audit_event("evt-1")).await;
        queue.enqueue(sample_audit_event("evt-2")).await;
        queue.enqueue(sample_audit_event("evt-3")).await;

        let app = Router::new().route(
            "/api/v1/audit/batch",
            post(|| async {
                Json(serde_json::json!({
                    "accepted": 2,
                    "duplicates": 0,
                    "rejected": 1,
                    "accepted_ids": ["evt-1", "evt-2"],
                    "rejected_ids": ["evt-3"]
                }))
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let outcome = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .expect("complete rejected_ids should return a partial flush outcome");
        assert_eq!(outcome.accepted, 2);
        assert_eq!(outcome.rejected, 1);
        assert!(outcome.partial_rejection);

        let guard = queue.queue.lock().await;
        let ids: Vec<_> = guard
            .iter()
            .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
            .collect();
        assert_eq!(ids, vec!["evt-3"]);
    }

    #[tokio::test]
    async fn audit_queue_flush_requeues_full_batch_when_rejected_ids_are_missing() {
        use axum::{routing::post, Json, Router};
        use tokio::net::TcpListener;

        let queue = AuditQueue::new_test_isolated();
        queue.enqueue(sample_audit_event("evt-1")).await;
        queue.enqueue(sample_audit_event("evt-2")).await;
        queue.enqueue(sample_audit_event("evt-3")).await;

        let app = Router::new().route(
            "/api/v1/audit/batch",
            post(|| async {
                Json(serde_json::json!({
                    "accepted": 2,
                    "duplicates": 0,
                    "rejected": 1
                }))
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let err = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .expect_err("partial rejection should fail the flush");
        assert!(err
            .to_string()
            .contains("Audit batch upload partially rejected"));
        assert!(err
            .to_string()
            .contains("after previously flushing 0 accepted events"));

        let guard = queue.queue.lock().await;
        let ids: Vec<_> = guard
            .iter()
            .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
            .collect();
        assert_eq!(ids, vec!["evt-1", "evt-2", "evt-3"]);
    }

    #[tokio::test]
    async fn audit_queue_flush_reports_prior_accepted_count_on_later_batch_rejection() {
        use axum::{extract::State, routing::post, Json, Router};
        use std::sync::{Arc, Mutex as StdMutex};
        use tokio::net::TcpListener;

        #[derive(Clone)]
        struct BatchState {
            calls: Arc<StdMutex<usize>>,
        }

        let queue = AuditQueue::new_test_isolated();
        let total_events = MAX_AUDIT_BATCH_LEN + 2;
        {
            let mut guard = queue.queue.lock().await;
            for i in 0..total_events {
                guard.push_back(sample_audit_event(format!("evt-{i}")));
            }
            persist_audit_queue(&queue.path, &guard).unwrap();
        }

        let state = BatchState {
            calls: Arc::new(StdMutex::new(0)),
        };
        let app =
            Router::new()
                .route(
                    "/api/v1/audit/batch",
                    post(
                        |State(state): State<BatchState>,
                         Json(payload): Json<serde_json::Value>| async move {
                            let len = payload
                                .get("events")
                                .and_then(|events| events.as_array())
                                .map(|events| events.len())
                                .unwrap_or(0);
                            let mut calls = state.calls.lock().unwrap();
                            *calls += 1;
                            if *calls == 1 {
                                Json(serde_json::json!({
                                    "accepted": len,
                                    "duplicates": 0,
                                    "rejected": 0
                                }))
                            } else {
                                Json(serde_json::json!({
                                    "accepted": 1,
                                    "duplicates": 0,
                                    "rejected": 1,
                                    "accepted_ids": [format!("evt-{}", MAX_AUDIT_BATCH_LEN)],
                                    "rejected_ids": [format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)]
                                }))
                            }
                        },
                    ),
                )
                .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let outcome = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .expect("later partial rejection should still report prior accepted batches");
        assert_eq!(outcome.accepted, MAX_AUDIT_BATCH_LEN + 1);
        assert_eq!(outcome.rejected, 1);
        assert!(outcome.partial_rejection);

        let guard = queue.queue.lock().await;
        let ids: Vec<String> = guard
            .iter()
            .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
            .map(ToString::to_string)
            .collect();
        assert_eq!(ids, vec![format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)]);
    }

    #[tokio::test]
    async fn audit_queue_flush_reports_prior_progress_when_rejected_ids_are_incomplete() {
        use axum::{extract::State, routing::post, Json, Router};
        use std::sync::{Arc, Mutex as StdMutex};
        use tokio::net::TcpListener;

        #[derive(Clone)]
        struct BatchState {
            calls: Arc<StdMutex<usize>>,
        }

        let queue = AuditQueue::new_test_isolated();
        let total_events = MAX_AUDIT_BATCH_LEN + 2;
        {
            let mut guard = queue.queue.lock().await;
            for i in 0..total_events {
                guard.push_back(sample_audit_event(format!("evt-{i}")));
            }
            persist_audit_queue(&queue.path, &guard).unwrap();
        }

        let state = BatchState {
            calls: Arc::new(StdMutex::new(0)),
        };
        let app =
            Router::new()
                .route(
                    "/api/v1/audit/batch",
                    post(
                        |State(state): State<BatchState>,
                         Json(payload): Json<serde_json::Value>| async move {
                            let len = payload
                                .get("events")
                                .and_then(|events| events.as_array())
                                .map(|events| events.len())
                                .unwrap_or(0);
                            let mut calls = state.calls.lock().unwrap();
                            *calls += 1;
                            if *calls == 1 {
                                Json(serde_json::json!({
                                    "accepted": len,
                                    "duplicates": 0,
                                    "rejected": 0
                                }))
                            } else {
                                Json(serde_json::json!({
                                    "accepted": 1,
                                    "duplicates": 0,
                                    "rejected": 1
                                }))
                            }
                        },
                    ),
                )
                .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let err = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .expect_err("incomplete rejected_ids should preserve prior flush progress");
        let progress = err
            .downcast_ref::<AuditFlushProgressError>()
            .expect("incomplete rejected_ids should return a structured progress error");
        assert_eq!(progress.outcome.accepted, MAX_AUDIT_BATCH_LEN);
        assert_eq!(progress.outcome.duplicates, 0);
        assert_eq!(progress.outcome.rejected, 0);
        assert!(progress
            .message
            .contains("Audit batch upload partially rejected"));

        let guard = queue.queue.lock().await;
        let ids: Vec<String> = guard
            .iter()
            .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            ids,
            vec![
                format!("evt-{}", MAX_AUDIT_BATCH_LEN),
                format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)
            ]
        );
    }

    #[tokio::test]
    async fn audit_queue_flush_reports_prior_accepted_count_on_later_http_failure() {
        use axum::{extract::State, http::StatusCode, routing::post, Json, Router};
        use std::sync::{Arc, Mutex as StdMutex};
        use tokio::net::TcpListener;

        #[derive(Clone)]
        struct BatchState {
            calls: Arc<StdMutex<usize>>,
        }

        let queue = AuditQueue::new_test_isolated();
        let total_events = MAX_AUDIT_BATCH_LEN + 2;
        {
            let mut guard = queue.queue.lock().await;
            for i in 0..total_events {
                guard.push_back(sample_audit_event(format!("evt-{i}")));
            }
            persist_audit_queue(&queue.path, &guard).unwrap();
        }

        let state = BatchState {
            calls: Arc::new(StdMutex::new(0)),
        };
        let app =
            Router::new()
                .route(
                    "/api/v1/audit/batch",
                    post(
                        |State(state): State<BatchState>,
                         Json(payload): Json<serde_json::Value>| async move {
                            let len = payload
                                .get("events")
                                .and_then(|events| events.as_array())
                                .map(|events| events.len())
                                .unwrap_or(0);
                            let mut calls = state.calls.lock().unwrap();
                            *calls += 1;
                            if *calls == 1 {
                                Ok::<_, StatusCode>(Json(serde_json::json!({
                                    "accepted": len,
                                    "duplicates": 0,
                                    "rejected": 0
                                })))
                            } else {
                                Err(StatusCode::INTERNAL_SERVER_ERROR)
                            }
                        },
                    ),
                )
                .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let err = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .expect_err("later HTTP failure should preserve prior accepted counts");
        let progress = err
            .downcast_ref::<AuditFlushProgressError>()
            .expect("later HTTP failure should preserve flush progress");
        assert_eq!(progress.outcome.accepted, MAX_AUDIT_BATCH_LEN);
        assert_eq!(progress.outcome.duplicates, 0);
        assert_eq!(progress.outcome.rejected, 0);
        assert!(progress
            .message
            .contains("Audit batch upload returned 500 Internal Server Error"));

        let guard = queue.queue.lock().await;
        let ids: Vec<String> = guard
            .iter()
            .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            ids,
            vec![
                format!("evt-{}", MAX_AUDIT_BATCH_LEN),
                format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)
            ]
        );
    }

    #[tokio::test]
    async fn audit_queue_flush_reports_prior_accepted_count_on_later_parse_failure() {
        use axum::{extract::State, response::IntoResponse, routing::post, Json, Router};
        use std::sync::{Arc, Mutex as StdMutex};
        use tokio::net::TcpListener;

        #[derive(Clone)]
        struct BatchState {
            calls: Arc<StdMutex<usize>>,
        }

        let queue = AuditQueue::new_test_isolated();
        let total_events = MAX_AUDIT_BATCH_LEN + 2;
        {
            let mut guard = queue.queue.lock().await;
            for i in 0..total_events {
                guard.push_back(sample_audit_event(format!("evt-{i}")));
            }
            persist_audit_queue(&queue.path, &guard).unwrap();
        }

        let state = BatchState {
            calls: Arc::new(StdMutex::new(0)),
        };
        let app =
            Router::new()
                .route(
                    "/api/v1/audit/batch",
                    post(
                        |State(state): State<BatchState>,
                         Json(payload): Json<serde_json::Value>| async move {
                            let len = payload
                                .get("events")
                                .and_then(|events| events.as_array())
                                .map(|events| events.len())
                                .unwrap_or(0);
                            let mut calls = state.calls.lock().unwrap();
                            *calls += 1;
                            if *calls == 1 {
                                Json(serde_json::json!({
                                    "accepted": len,
                                    "duplicates": 0,
                                    "rejected": 0
                                }))
                                .into_response()
                            } else {
                                "not-json".into_response()
                            }
                        },
                    ),
                )
                .with_state(state);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let err = queue
            .flush(&format!("http://{}", addr), None)
            .await
            .expect_err("later parse failure should preserve prior accepted counts");
        let progress = err
            .downcast_ref::<AuditFlushProgressError>()
            .expect("later parse failure should preserve flush progress");
        assert_eq!(progress.outcome.accepted, MAX_AUDIT_BATCH_LEN);
        assert_eq!(progress.outcome.duplicates, 0);
        assert_eq!(progress.outcome.rejected, 0);
        assert!(progress
            .message
            .contains("Failed to parse audit batch response"));

        let guard = queue.queue.lock().await;
        let ids: Vec<String> = guard
            .iter()
            .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            ids,
            vec![
                format!("evt-{}", MAX_AUDIT_BATCH_LEN),
                format!("evt-{}", MAX_AUDIT_BATCH_LEN + 1)
            ]
        );
    }

    #[tokio::test]
    async fn audit_queue_load_drops_invalid_persisted_entries() {
        let dir = std::env::temp_dir().join(format!(
            "clawdstrike-audit-outbox-load-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit-outbox.json");
        let persisted = PersistedAuditQueue {
            entries: VecDeque::from([
                serde_json::json!({"id": 1}),
                sample_audit_event("valid-1"),
                serde_json::json!({"id": "missing-fields"}),
                sample_audit_event("valid-2"),
            ]),
        };
        std::fs::write(&path, serde_json::to_vec(&persisted).unwrap()).unwrap();

        let queue = AuditQueue::with_path(path.clone());
        let guard = queue.queue.lock().await;
        assert_eq!(guard.len(), 2);
        assert_eq!(
            guard
                .iter()
                .filter_map(|event| event.get("id").and_then(|id| id.as_str()))
                .collect::<Vec<_>>(),
            vec!["valid-1", "valid-2"]
        );
        drop(guard);

        let persisted_after: PersistedAuditQueue =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(persisted_after.entries.len(), 2);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[tokio::test]
    async fn policy_cache_returns_none_initially() {
        let cache = PolicyCache::new();
        // May or may not have a cached file on disk; just verify the method works.
        let _ = cache.cached_policy().await;
    }
}
