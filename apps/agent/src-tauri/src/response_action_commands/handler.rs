//! NATS subscriber lifecycle for response-action commands.
//!
//! `ResponseActionCommandHandler` owns the long-running subscription on the
//! tenant-scoped command subject. Each incoming message is verified, parsed,
//! dispatched to the policy rule-diff validator, and acknowledged back to
//! Control API. Failures fall through to the durable ack retry sink.

use std::sync::Arc;
use tokio::sync::{broadcast, RwLock};

use crate::api_server::ControlAckPostbackRetrySink;
use crate::nats_client::NatsClient;
use crate::nats_subjects;
use crate::settings::Settings;

use super::control_ack::{
    current_local_api_token, enqueue_control_ack_retry, post_control_acknowledgement,
};
use super::dto::{ControlAckContext, ResponseActionTransportCommand, ResponseCommandReply};
use super::policy_rule_diff::{
    execute_policy_rule_diff_validation, policy_rule_diff_failure_payload,
    sign_policy_rule_diff_failure_payload,
};
use super::validate::truncate_message;
use super::validate::{parse_signed_response_action_payload, policy_rule_diff_validation_command};

/// Manages the response-action command subscription lifecycle.
pub struct ResponseActionCommandHandler {
    nats: Arc<NatsClient>,
    settings: Arc<RwLock<Settings>>,
    local_api_token: String,
    control_ack_retry_sink: Option<ControlAckPostbackRetrySink>,
    http_client: reqwest::Client,
}

impl ResponseActionCommandHandler {
    pub fn new(
        nats: Arc<NatsClient>,
        settings: Arc<RwLock<Settings>>,
        local_api_token: String,
        control_ack_retry_sink: Option<ControlAckPostbackRetrySink>,
    ) -> Self {
        Self {
            nats,
            settings,
            local_api_token,
            control_ack_retry_sink,
            http_client: reqwest::Client::new(),
        }
    }

    /// Build the canonical response-action command subject for this endpoint.
    pub fn command_subject(subject_prefix: &str, agent_id: &str) -> String {
        nats_subjects::response_command_subject(subject_prefix, "endpoint", agent_id)
    }

    /// Start listening for response-action commands. Runs until shutdown.
    pub async fn start(&self, mut shutdown_rx: broadcast::Receiver<()>) {
        let subject = Self::command_subject(self.nats.subject_prefix(), self.nats.agent_id());
        tracing::info!(subject = %subject, "Starting response-action command subscriber");

        let mut subscriber = match self.nats.client().subscribe(subject.clone()).await {
            Ok(subscriber) => subscriber,
            Err(err) => {
                tracing::error!(
                    error = %err,
                    subject = %subject,
                    "Failed to subscribe to response-action command subject"
                );
                return;
            }
        };

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("Response-action command handler shutting down");
                    break;
                }
                msg = crate::nats_client::subscriber_next(&mut subscriber) => {
                    let Some(msg) = msg else {
                        tracing::warn!("Response-action command subscription ended unexpectedly");
                        break;
                    };

                    let reply = msg.reply.clone();
                    let trusted_issuer = {
                        let settings = self.settings.read().await;
                        settings.nats.approval_response_trusted_issuer.clone()
                    };

                    let response = match parse_signed_response_action_payload(
                        &msg.payload,
                        trusted_issuer.as_deref(),
                    ) {
                        Ok(command) => self.handle_command(command).await,
                        Err(err) => {
                            tracing::warn!(
                                error = %err,
                                "Failed to verify signed response-action command"
                            );
                            ResponseCommandReply {
                                status: "error".to_string(),
                                response_action_id: None,
                                message: Some(format!("Invalid signed response action: {err}")),
                            }
                        }
                    };

                    if let Some(reply_subject) = reply {
                        let response_json = serde_json::to_vec(&response)
                            .unwrap_or_else(|_| b"{}".to_vec());
                        if let Err(err) = self.nats.client()
                            .publish(reply_subject, response_json.into())
                            .await
                        {
                            tracing::warn!(
                                error = %err,
                                "Failed to send response-action command reply"
                            );
                        }
                    }
                }
            }
        }
    }

    async fn handle_command(
        &self,
        command: ResponseActionTransportCommand,
    ) -> ResponseCommandReply {
        let response_action_id = command.action_id.clone();
        let validation = match policy_rule_diff_validation_command(
            &command,
            self.nats.tenant_id(),
            self.nats.agent_id(),
            chrono::Utc::now(),
        ) {
            Ok(validation) => validation,
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    response_action_id = %response_action_id,
                    "Rejected response-action command"
                );
                return ResponseCommandReply {
                    status: "error".to_string(),
                    response_action_id: Some(response_action_id),
                    message: Some(err.to_string()),
                };
            }
        };

        let local_api_token = current_local_api_token(&self.local_api_token);
        match execute_policy_rule_diff_validation(
            &self.http_client,
            self.settings.as_ref(),
            &local_api_token,
            &validation,
        )
        .await
        {
            Ok(raw_payload) => {
                let retry_raw_payload = raw_payload.clone();
                let observed_at = chrono::Utc::now();
                let ack_context = ControlAckContext {
                    status: "acknowledged",
                    observed_at,
                    message: Some("policy rule-diff validation completed"),
                    resulting_state: Some("policy_rule_diff_validation:succeeded"),
                    failure_message: "",
                };
                let postback = post_control_acknowledgement(
                    &self.http_client,
                    self.settings.as_ref(),
                    &validation,
                    &ack_context,
                    raw_payload,
                )
                .await;
                match postback {
                    Ok(()) => ResponseCommandReply {
                        status: "ok".to_string(),
                        response_action_id: Some(response_action_id),
                        message: Some("policy rule-diff validation acknowledged".to_string()),
                    },
                    Err(err) => {
                        let failure_message = err.to_string();
                        if let Err(queue_err) = enqueue_control_ack_retry(
                            self.control_ack_retry_sink.as_ref(),
                            self.settings.as_ref(),
                            &validation,
                            ControlAckContext {
                                failure_message: &failure_message,
                                ..ack_context
                            },
                            retry_raw_payload,
                        )
                        .await
                        {
                            tracing::warn!(
                                error = %queue_err,
                                response_action_id = %response_action_id,
                                "Failed to queue policy rule-diff acknowledgement postback retry"
                            );
                        }
                        tracing::warn!(
                            error = %err,
                            response_action_id = %response_action_id,
                            "Policy rule-diff validation completed but ack postback failed"
                        );
                        ResponseCommandReply {
                            status: "error".to_string(),
                            response_action_id: Some(response_action_id),
                            message: Some(format!(
                                "policy rule-diff validation completed but ack postback failed: {err}"
                            )),
                        }
                    }
                }
            }
            Err(err) => {
                let message = truncate_message(&err.to_string(), 512);
                let raw_payload = policy_rule_diff_failure_payload(&validation, &message);
                let observed_at = chrono::Utc::now();
                let ack_context = ControlAckContext {
                    status: "failed",
                    observed_at,
                    message: Some(&message),
                    resulting_state: Some("policy_rule_diff_validation:failed"),
                    failure_message: "",
                };
                let raw_payload = match sign_policy_rule_diff_failure_payload(
                    self.control_ack_retry_sink.as_ref(),
                    &validation,
                    &ack_context,
                    raw_payload,
                )
                .await
                {
                    Ok(raw_payload) => raw_payload,
                    Err(sign_err) => {
                        tracing::error!(
                            error = %sign_err,
                            response_action_id = %response_action_id,
                            "Policy rule-diff validation failed but acknowledgement receipt signing failed"
                        );
                        return ResponseCommandReply {
                            status: "error".to_string(),
                            response_action_id: Some(response_action_id),
                            message: Some(format!(
                                "policy rule-diff validation failed and signed acknowledgement could not be produced: {sign_err}"
                            )),
                        };
                    }
                };
                let retry_raw_payload = raw_payload.clone();
                let postback = post_control_acknowledgement(
                    &self.http_client,
                    self.settings.as_ref(),
                    &validation,
                    &ack_context,
                    raw_payload,
                )
                .await;
                if let Err(postback_err) = postback {
                    let failure_message = postback_err.to_string();
                    if let Err(queue_err) = enqueue_control_ack_retry(
                        self.control_ack_retry_sink.as_ref(),
                        self.settings.as_ref(),
                        &validation,
                        ControlAckContext {
                            failure_message: &failure_message,
                            ..ack_context
                        },
                        retry_raw_payload,
                    )
                    .await
                    {
                        tracing::warn!(
                            error = %queue_err,
                            response_action_id = %response_action_id,
                            "Failed to queue failed policy rule-diff acknowledgement postback retry"
                        );
                    }
                    tracing::warn!(
                        error = %postback_err,
                        response_action_id = %response_action_id,
                        "Policy rule-diff validation failed and failed to post failure ack"
                    );
                }
                ResponseCommandReply {
                    status: "error".to_string(),
                    response_action_id: Some(response_action_id),
                    message: Some(format!("policy rule-diff validation failed: {message}")),
                }
            }
        }
    }
}
