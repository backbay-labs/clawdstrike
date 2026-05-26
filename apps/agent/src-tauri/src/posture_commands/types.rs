//! Posture command request/response types.

use serde::{Deserialize, Serialize};

/// Known posture values accepted by the agent.
pub(super) const VALID_POSTURES: &[&str] = &["standard", "restricted", "audit", "locked"];

/// Commands that can be sent to the agent via NATS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum PostureCommand {
    /// Change the agent's security posture.
    SetPosture { posture: String },
    /// Emergency kill switch: immediately deny-all and terminate session.
    KillSwitch {
        #[serde(default)]
        reason: Option<String>,
    },
    /// Request the agent to reload its policy file.
    RequestPolicyReload,
}

/// Response sent back for a command request.
#[derive(Debug, Serialize)]
pub(super) struct CommandResponse {
    pub(super) status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) message: Option<String>,
}
