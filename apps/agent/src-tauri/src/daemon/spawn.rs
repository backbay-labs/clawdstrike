//! Hushd child-process lifecycle primitives.
//!
//! These helpers are used by `DaemonManager` (start/restart loop) and the
//! health monitor to spawn, track, terminate, and observe the managed hushd
//! process. They are intentionally low-level: they have no notion of the
//! `DaemonState` machine and never publish state updates of their own.

use anyhow::{Context, Result};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{broadcast, RwLock};

use super::runtime_config::{load_runtime_settings_for_config, write_runtime_config_file};
use super::state::{DaemonConfig, DaemonState};

pub(super) async fn spawn_child_into_slot(
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

pub(super) async fn terminate_child_slot(child_slot: &Arc<RwLock<Option<Child>>>) -> bool {
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

pub(super) async fn check_process_exit(child_slot: &Arc<RwLock<Option<Child>>>) -> Option<String> {
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

pub(super) async fn set_shared_state(
    state: &Arc<RwLock<DaemonState>>,
    state_tx: &broadcast::Sender<DaemonState>,
    new_state: DaemonState,
) {
    *state.write().await = new_state.clone();
    let _ = state_tx.send(new_state);
}

pub(super) fn compute_backoff(restart_streak: u32, restart_count: u32) -> Duration {
    let exponent = restart_streak.saturating_sub(1).min(6);
    let base_ms = 500u64.saturating_mul(2u64.saturating_pow(exponent));
    let capped_ms = base_ms.min(20_000);
    let jitter_ms = (restart_count as u64).saturating_mul(113) % 250;
    Duration::from_millis(capped_ms.saturating_add(jitter_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_is_bounded() {
        let backoff = compute_backoff(10, 10);
        assert!(backoff <= Duration::from_millis(20_500));
    }
}
