//! NATS subscription lifecycle and per-command dispatch for the agent's posture commands.

use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::RwLock;

use crate::daemon::DaemonManager;
use crate::nats_client::NatsClient;
use crate::nats_subjects;
use crate::session::SessionManager;
use crate::settings::Settings;

use super::signing::{parse_signed_posture_command_payload, transition_posture_command};
use super::types::{CommandResponse, PostureCommand, VALID_POSTURES};

/// Manages the command subscription lifecycle.
pub struct PostureCommandHandler {
    nats: Arc<NatsClient>,
    session_manager: Arc<SessionManager>,
    daemon_manager: Arc<DaemonManager>,
    settings: Arc<RwLock<Settings>>,
}

impl PostureCommandHandler {
    pub fn new(
        nats: Arc<NatsClient>,
        session_manager: Arc<SessionManager>,
        daemon_manager: Arc<DaemonManager>,
        settings: Arc<RwLock<Settings>>,
    ) -> Self {
        Self {
            nats,
            session_manager,
            daemon_manager,
            settings,
        }
    }

    /// Build the command subject for this agent.
    pub fn command_subject(subject_prefix: &str, agent_id: &str) -> String {
        nats_subjects::posture_command_subject(subject_prefix, agent_id)
    }

    /// Start listening for posture commands. Runs until shutdown.
    pub async fn start(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        let subject = Self::command_subject(self.nats.subject_prefix(), self.nats.agent_id());
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
                msg = crate::nats_client::subscriber_next(&mut subscriber) => {
                    let Some(msg) = msg else {
                        tracing::warn!("Command subscription ended unexpectedly");
                        break;
                    };

                    let reply = msg.reply.clone();
                    let trusted_issuer = {
                        let settings = self.settings.read().await;
                        settings.nats.approval_response_trusted_issuer.clone()
                    };

                    match parse_signed_posture_command_payload(
                        &msg.payload,
                        trusted_issuer.as_deref(),
                    ) {
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
                            tracing::warn!(error = %err, "Failed to verify signed posture command");
                            if let Some(reply_subject) = reply {
                                let error_response = CommandResponse {
                                    status: "error".to_string(),
                                    message: Some(format!("Invalid signed command: {}", err)),
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
                transition_posture_command(
                    self.session_manager.as_ref(),
                    self.settings.as_ref(),
                    &posture,
                    "remote_command",
                    format!("Posture set to {}", posture),
                    "No active session to transition posture".to_string(),
                    "Failed to transition posture via hushd API".to_string(),
                )
                .await
            }
            PostureCommand::KillSwitch { reason } => {
                let reason_str = reason.as_deref().unwrap_or("remote kill switch activated");
                tracing::warn!(reason = %reason_str, "KILL SWITCH activated via remote command");

                let transition = transition_posture_command(
                    self.session_manager.as_ref(),
                    self.settings.as_ref(),
                    "locked",
                    "user_denial",
                    format!(
                        "Kill switch activated: transitioned active session to locked ({})",
                        reason_str
                    ),
                    format!(
                        "Kill switch rejected: no active session to transition ({})",
                        reason_str
                    ),
                    "Kill switch failed to transition posture via hushd".to_string(),
                )
                .await;

                // Always restart daemon for kill switch, even if there is no
                // active session to transition.
                let restart = self.daemon_manager.restart().await;
                let transition_message = transition.message.unwrap_or_else(|| {
                    "Kill switch transition result did not include details".to_string()
                });
                let no_active_session = transition_message
                    .to_ascii_lowercase()
                    .contains("no active session");

                match (transition.status.as_str(), restart) {
                    ("ok", Ok(())) => CommandResponse {
                        status: "ok".to_string(),
                        message: Some(format!(
                            "Kill switch activated: transitioned active session to locked ({}) and restarted daemon",
                            reason_str
                        )),
                    },
                    ("ok", Err(err)) => CommandResponse {
                        status: "error".to_string(),
                        message: Some(format!(
                            "Kill switch transitioned posture to locked but daemon restart failed: {}",
                            err
                        )),
                    },
                    ("error", Ok(())) if no_active_session => CommandResponse {
                        status: "ok".to_string(),
                        message: Some(format!(
                            "Kill switch activated: restarted daemon ({}); {}",
                            reason_str, transition_message
                        )),
                    },
                    ("error", Ok(())) => CommandResponse {
                        status: "error".to_string(),
                        message: Some(format!(
                            "Kill switch restarted daemon but posture transition reported an error: {}",
                            transition_message
                        )),
                    },
                    ("error", Err(err)) => CommandResponse {
                        status: "error".to_string(),
                        message: Some(format!(
                            "Kill switch failed: transition error ({}) and daemon restart failed ({})",
                            transition_message, err
                        )),
                    },
                    (_, Err(err)) => CommandResponse {
                        status: "error".to_string(),
                        message: Some(format!("Kill switch daemon restart failed: {}", err)),
                    },
                    _ => CommandResponse {
                        status: "error".to_string(),
                        message: Some("Kill switch failed due to unexpected transition state".to_string()),
                    },
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
