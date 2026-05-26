//! Ready/health probing for the hushd process.
//!
//! This module owns:
//!   * `health_check_with_client` — single HTTP probe of `/health`.
//!   * `wait_for_ready_with_client[_or_shutdown]` — polls until the daemon
//!     reports `healthy` or the attempts/shutdown signal exhaust.
//!   * `sleep_or_shutdown` — race a sleep against a shutdown broadcast.

use anyhow::{Context, Result};
use std::time::Duration;
use tokio::sync::broadcast;

use super::state::{DaemonConfig, HealthResponse};

const READY_MAX_ATTEMPTS: usize = 40;
const READY_POLL_DELAY: Duration = Duration::from_millis(150);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ReadyWaitOutcome {
    Ready,
    Shutdown,
}

pub(super) async fn wait_for_ready_with_client(
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

pub(super) async fn sleep_or_shutdown(
    shutdown_rx: &mut broadcast::Receiver<()>,
    duration: Duration,
) -> bool {
    tokio::select! {
        recv = shutdown_rx.recv() => {
            match recv {
                Ok(_) | Err(broadcast::error::RecvError::Closed) | Err(broadcast::error::RecvError::Lagged(_)) => true,
            }
        }
        _ = tokio::time::sleep(duration) => false,
    }
}

pub(super) async fn wait_for_ready_with_client_or_shutdown(
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

pub(super) async fn health_check_with_client(
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
