//! NATS request-based posture command handler.
//!
//! Subscribes to a tenant/agent-scoped command subject and processes
//! remote management commands (set_posture, kill_switch, request_policy_reload).

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::broadcast;

use crate::daemon::DaemonManager;
use crate::nats_client::NatsClient;
use crate::session::SessionManager;

/// Known posture values accepted by the agent.
const VALID_POSTURES: &[&str] = &["standard", "restricted", "audit", "locked"];

/// Commands that can be sent to the agent via NATS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum PostureCommand {
    /// Change the agent's security posture.
    SetPosture {
        posture: String,
    },
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
struct CommandResponse {
    status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<String>,
}

/// Manages the command subscription lifecycle.
pub struct PostureCommandHandler {
    nats: Arc<NatsClient>,
    session_manager: Arc<SessionManager>,
    daemon_manager: Arc<DaemonManager>,
}

impl PostureCommandHandler {
    pub fn new(
        nats: Arc<NatsClient>,
        session_manager: Arc<SessionManager>,
        daemon_manager: Arc<DaemonManager>,
    ) -> Self {
        Self {
            nats,
            session_manager,
            daemon_manager,
        }
    }

    /// Build the command subject for this agent.
    pub fn command_subject(tenant_id: &str, agent_id: &str) -> String {
        format!("commands.{}.{}", tenant_id, agent_id)
    }

    /// Start listening for posture commands. Runs until shutdown.
    pub async fn start(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        let subject = Self::command_subject(self.nats.tenant_id(), self.nats.agent_id());
        tracing::info!(subject = %subject, "Starting posture command subscriber");

        let mut subscriber = match self.nats.client().subscribe(subject.clone()).await {
            Ok(sub) => sub,
            Err(err) => {
                tracing::error!(error = %err, "Failed to subscribe to command subject");
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Posture command handler shutting down");
                    break;
                }
                msg = subscriber.next() => {
                    let Some(msg) = msg else {
                        tracing::warn!("Command subscription ended unexpectedly");
                        break;
                    };

                    let reply = msg.reply.clone();

                    match serde_json::from_slice::<PostureCommand>(&msg.payload) {
                        Ok(cmd) => {
                            let response = self.handle_command(cmd).await;
                            if let Some(reply_subject) = reply {
                                let response_json = serde_json::to_vec(&response)
                                    .unwrap_or_else(|_| b"{}".to_vec());
                                if let Err(err) = self.nats.client()
                                    .publish(reply_subject, response_json.into())
                                    .await
                                {
                                    tracing::warn!(error = %err, "Failed to send command response");
                                }
                            }
                        }
                        Err(err) => {
                            tracing::warn!(error = %err, "Failed to parse posture command");
                            if let Some(reply_subject) = reply {
                                let error_response = CommandResponse {
                                    status: "error".to_string(),
                                    message: Some(format!("Invalid command: {}", err)),
                                };
                                let response_json = serde_json::to_vec(&error_response)
                                    .unwrap_or_else(|_| b"{}".to_vec());
                                let _ = self.nats.client()
                                    .publish(reply_subject, response_json.into())
                                    .await;
                            }
                        }
                    }
                }
            }
        }
    }

    async fn handle_command(&self, cmd: PostureCommand) -> CommandResponse {
        match cmd {
            PostureCommand::SetPosture { posture } => {
                // Validate posture against known values.
                if !VALID_POSTURES.contains(&posture.as_str()) {
                    tracing::warn!(
                        posture = %posture,
                        "Rejected set_posture command with unknown posture value"
                    );
                    return CommandResponse {
                        status: "error".to_string(),
                        message: Some(format!(
                            "Unknown posture '{}'. Valid values: {}",
                            posture,
                            VALID_POSTURES.join(", ")
                        )),
                    };
                }

                tracing::info!(posture = %posture, "Received set_posture command");
                // Update the session's posture via the session manager.
                let applied = self
                    .session_manager
                    .update_posture_from_daemon_event(None, posture.clone())
                    .await;

                if applied {
                    CommandResponse {
                        status: "ok".to_string(),
                        message: Some(format!("Posture set to {}", posture)),
                    }
                } else {
                    CommandResponse {
                        status: "ok".to_string(),
                        message: Some("No active session to update posture".to_string()),
                    }
                }
            }
            PostureCommand::KillSwitch { reason } => {
                let reason_str = reason.as_deref().unwrap_or("remote kill switch activated");
                tracing::warn!(reason = %reason_str, "KILL SWITCH activated via remote command");

                // Set posture to "locked" which deny-all's all policy evaluations.
                self.session_manager
                    .update_posture_from_daemon_event(None, "locked".to_string())
                    .await;

                // Restart the daemon so it reloads with locked posture enforced.
                if let Err(err) = self.daemon_manager.restart().await {
                    tracing::error!(error = %err, "Failed to restart daemon for kill switch");
                }

                CommandResponse {
                    status: "ok".to_string(),
                    message: Some(format!("Kill switch activated: {}", reason_str)),
                }
            }
            PostureCommand::RequestPolicyReload => {
                tracing::info!("Received request_policy_reload command");

                match self.daemon_manager.restart().await {
                    Ok(()) => CommandResponse {
                        status: "ok".to_string(),
                        message: Some("Policy reload triggered".to_string()),
                    },
                    Err(err) => CommandResponse {
                        status: "error".to_string(),
                        message: Some(format!("Policy reload failed: {}", err)),
                    },
                }
            }
        }
    }
}

/// Helper to poll the next message from a NATS subscriber.
/// `subscriber.next()` requires `use futures::StreamExt` which is handled at the call site.
trait SubscriberNext {
    fn next(
        &mut self,
    ) -> impl std::future::Future<Output = Option<async_nats::Message>> + Send;
}

impl SubscriberNext for async_nats::Subscriber {
    fn next(
        &mut self,
    ) -> impl std::future::Future<Output = Option<async_nats::Message>> + Send {
        use futures::StreamExt;
        StreamExt::next(self)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn command_subject_format() {
        assert_eq!(
            PostureCommandHandler::command_subject("tenant-abc", "agent-xyz"),
            "commands.tenant-abc.agent-xyz"
        );
    }

    #[test]
    fn set_posture_command_deserializes() {
        let json = r#"{"command":"set_posture","posture":"restricted"}"#;
        let cmd: PostureCommand = serde_json::from_str(json).unwrap();
        match cmd {
            PostureCommand::SetPosture { posture } => {
                assert_eq!(posture, "restricted");
            }
            other => panic!("expected SetPosture, got {:?}", other),
        }
    }

    #[test]
    fn kill_switch_command_deserializes() {
        let json = r#"{"command":"kill_switch","reason":"security breach"}"#;
        let cmd: PostureCommand = serde_json::from_str(json).unwrap();
        match cmd {
            PostureCommand::KillSwitch { reason } => {
                assert_eq!(reason.as_deref(), Some("security breach"));
            }
            other => panic!("expected KillSwitch, got {:?}", other),
        }
    }

    #[test]
    fn kill_switch_without_reason_deserializes() {
        let json = r#"{"command":"kill_switch"}"#;
        let cmd: PostureCommand = serde_json::from_str(json).unwrap();
        match cmd {
            PostureCommand::KillSwitch { reason } => {
                assert!(reason.is_none());
            }
            other => panic!("expected KillSwitch, got {:?}", other),
        }
    }

    #[test]
    fn request_policy_reload_deserializes() {
        let json = r#"{"command":"request_policy_reload"}"#;
        let cmd: PostureCommand = serde_json::from_str(json).unwrap();
        assert!(matches!(cmd, PostureCommand::RequestPolicyReload));
    }

    #[test]
    fn valid_postures_are_accepted() {
        for posture in VALID_POSTURES {
            assert!(
                VALID_POSTURES.contains(posture),
                "posture '{}' should be valid",
                posture
            );
        }
    }

    #[test]
    fn unknown_posture_is_rejected() {
        assert!(!VALID_POSTURES.contains(&"bogus"));
        assert!(!VALID_POSTURES.contains(&""));
        assert!(!VALID_POSTURES.contains(&"STANDARD")); // case-sensitive
    }
}
