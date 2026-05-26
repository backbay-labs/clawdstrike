//! Core daemon state, config, and status types.
//!
//! These small data types are shared by the daemon manager, health monitor,
//! and ready probe modules.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

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

impl DaemonConfig {
    pub fn health_url(&self) -> String {
        format!("http://127.0.0.1:{}/health", self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_state_as_str() {
        assert_eq!(DaemonState::Running.as_str(), "running");
        assert_eq!(DaemonState::Stopped.as_str(), "stopped");
    }
}
