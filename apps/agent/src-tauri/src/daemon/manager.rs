//! Daemon lifecycle manager.
//!
//! `DaemonManager` owns the hushd process: it starts/stops/restarts the
//! child, attaches to an externally-managed hushd when one is already
//! healthy on the configured port, and runs a background health monitor
//! that re-spawns the daemon on crash with exponential backoff.

use anyhow::Result;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::Child;
use tokio::sync::{broadcast, Mutex, RwLock};

use super::ready_probe::{
    health_check_with_client, sleep_or_shutdown, wait_for_ready_with_client,
    wait_for_ready_with_client_or_shutdown, ReadyWaitOutcome,
};
use super::runtime_keypair::cleanup_runtime_enrollment_keypair;
use super::spawn::{
    check_process_exit, compute_backoff, set_shared_state, spawn_child_into_slot,
    terminate_child_slot,
};
use super::state::{DaemonConfig, DaemonState, DaemonStatus, HealthResponse};

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
    pub fn binary_path(&self) -> std::path::PathBuf {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
}
