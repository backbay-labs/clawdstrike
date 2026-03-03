//! NATS request-based posture command handler.
//!
//! Subscribes to a tenant/agent-scoped command subject and processes
//! remote management commands (set_posture, kill_switch, request_policy_reload).

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::broadcast;
use tokio::sync::RwLock;

use crate::daemon::DaemonManager;
use crate::nats_client::NatsClient;
use crate::nats_subjects;
use crate::session::SessionManager;
use crate::settings::Settings;

/// Known posture values accepted by the agent.
const VALID_POSTURES: &[&str] = &["standard", "restricted", "audit", "locked"];

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

fn parse_signed_posture_command_payload(
    payload: &[u8],
    trusted_issuer: Option<&str>,
) -> Result<PostureCommand> {
    let raw: Value = serde_json::from_slice(payload)?;
    let envelope = if raw.get("replayed").and_then(|v| v.as_bool()) == Some(true) {
        raw.get("envelope")
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("replayed command missing envelope"))?
    } else {
        raw
    };

    if envelope.get("fact").is_none() {
        anyhow::bail!("posture command payload must be a signed envelope");
    }

    if !spine::verify_envelope(&envelope)? {
        anyhow::bail!("posture command signature verification failed");
    }

    let issuer = envelope
        .get("issuer")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("signed posture command missing issuer"))?;
    let expected = trusted_issuer
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing trusted posture command issuer"))?;
    if issuer != expected {
        anyhow::bail!("posture command issuer mismatch: expected {expected}, got {issuer}");
    }

    let fact = envelope
        .get("fact")
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("signed posture command missing fact"))?;
    let cmd: PostureCommand = serde_json::from_value(fact)?;
    Ok(cmd)
}

async fn transition_posture_command(
    session_manager: &SessionManager,
    settings: &RwLock<Settings>,
    to_state: &str,
    trigger: &str,
    success_message: String,
    no_session_message: String,
    failure_prefix: String,
) -> CommandResponse {
    let (daemon_url, api_key) = {
        let guard = settings.read().await;
        (guard.daemon_url(), guard.api_key.clone())
    };

    match session_manager
        .transition_current_session_posture(&daemon_url, api_key.as_deref(), to_state, trigger)
        .await
    {
        Ok(true) => CommandResponse {
            status: "ok".to_string(),
            message: Some(success_message),
        },
        Ok(false) => CommandResponse {
            status: "error".to_string(),
            message: Some(no_session_message),
        },
        Err(err) => CommandResponse {
            status: "error".to_string(),
            message: Some(format!("{failure_prefix}: {err}")),
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use axum::{extract::Path, http::StatusCode, routing::post, Json, Router};
    use hush_core::Keypair;
    use spine::envelope::{build_signed_envelope, now_rfc3339};
    use std::sync::Mutex as StdMutex;
    use tokio::net::TcpListener;

    #[test]
    fn command_subject_format() {
        assert_eq!(
            PostureCommandHandler::command_subject("tenant-acme.clawdstrike", "agent-xyz"),
            "tenant-acme.clawdstrike.posture.command.agent-xyz"
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
    fn signed_posture_command_requires_trusted_issuer() {
        let kp = Keypair::generate();
        let envelope = build_signed_envelope(
            &kp,
            1,
            None,
            serde_json::json!({
                "command": "request_policy_reload"
            }),
            now_rfc3339(),
        )
        .unwrap();
        let err =
            parse_signed_posture_command_payload(&serde_json::to_vec(&envelope).unwrap(), None)
                .unwrap_err();
        assert!(err
            .to_string()
            .contains("missing trusted posture command issuer"));
    }

    #[test]
    fn signed_posture_command_accepts_matching_issuer() {
        let kp = Keypair::generate();
        let envelope = build_signed_envelope(
            &kp,
            1,
            None,
            serde_json::json!({
                "command": "request_policy_reload"
            }),
            now_rfc3339(),
        )
        .unwrap();
        let issuer = envelope
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        let parsed = parse_signed_posture_command_payload(
            &serde_json::to_vec(&envelope).unwrap(),
            Some(&issuer),
        )
        .unwrap();
        assert!(matches!(parsed, PostureCommand::RequestPolicyReload));
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

    async fn start_transition_test_server(events: std::sync::Arc<StdMutex<Vec<String>>>) -> String {
        let events_for_create = events.clone();
        let events_for_transition = events.clone();
        let app = Router::new()
            .route(
                "/api/v1/session",
                post(move || {
                    let events_for_create = events_for_create.clone();
                    async move {
                        events_for_create
                            .lock()
                            .unwrap()
                            .push("create:sess-1".to_string());
                        (
                            StatusCode::OK,
                            Json(serde_json::json!({
                                "session": { "session_id": "sess-1" }
                            })),
                        )
                    }
                }),
            )
            .route(
                "/api/v1/session/{id}/transition",
                post(
                    move |Path(id): Path<String>, Json(body): Json<serde_json::Value>| {
                        let events_for_transition = events_for_transition.clone();
                        async move {
                            let to_state = body
                                .get("to_state")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            let trigger = body
                                .get("trigger")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unknown");
                            events_for_transition
                                .lock()
                                .unwrap()
                                .push(format!("transition:{id}:{to_state}:{trigger}"));
                            StatusCode::OK
                        }
                    },
                ),
            );

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap_or_else(|err| panic!("failed to bind transition test server: {err}"));
        let addr = listener
            .local_addr()
            .unwrap_or_else(|err| panic!("failed to read transition test server address: {err}"));
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap_or_else(|err| panic!("transition test server failed: {err}"));
        });
        format!("http://{}", addr)
    }

    #[tokio::test]
    async fn set_posture_transition_uses_hushd_api_path() {
        let events = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let daemon_url = start_transition_test_server(events.clone()).await;

        let session_manager = SessionManager::new();
        session_manager
            .create_session(&daemon_url, None)
            .await
            .unwrap_or_else(|err| panic!("create_session failed: {err}"));

        let daemon_port = daemon_url
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("failed to parse daemon test port from {daemon_url}"));
        let settings = RwLock::new(Settings {
            daemon_port,
            ..Settings::default()
        });

        let response = transition_posture_command(
            &session_manager,
            &settings,
            "restricted",
            "remote_command",
            "Posture set to restricted".to_string(),
            "No active session".to_string(),
            "transition failed".to_string(),
        )
        .await;
        assert_eq!(response.status, "ok");

        let got = events.lock().unwrap().clone();
        assert!(got.contains(&"create:sess-1".to_string()));
        assert!(got.contains(&"transition:sess-1:restricted:remote_command".to_string()));
    }

    #[tokio::test]
    async fn kill_switch_transition_uses_hushd_api_path() {
        let events = std::sync::Arc::new(StdMutex::new(Vec::new()));
        let daemon_url = start_transition_test_server(events.clone()).await;

        let session_manager = SessionManager::new();
        session_manager
            .create_session(&daemon_url, None)
            .await
            .unwrap_or_else(|err| panic!("create_session failed: {err}"));

        let daemon_port = daemon_url
            .rsplit(':')
            .next()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("failed to parse daemon test port from {daemon_url}"));
        let settings = RwLock::new(Settings {
            daemon_port,
            ..Settings::default()
        });

        let response = transition_posture_command(
            &session_manager,
            &settings,
            "locked",
            "user_denial",
            "Kill switch activated".to_string(),
            "No active session".to_string(),
            "kill switch failed".to_string(),
        )
        .await;
        assert_eq!(response.status, "ok");

        let got = events.lock().unwrap().clone();
        assert!(got.contains(&"transition:sess-1:locked:user_denial".to_string()));
    }
}
