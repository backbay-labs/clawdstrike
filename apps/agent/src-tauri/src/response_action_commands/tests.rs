#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::control_ack::{
    control_ack_postback_config, control_ack_postback_payload, post_control_acknowledgement,
};
use super::dto::{
    ControlAckContext, ResponseActionTransportCommand, POLICY_RULE_DIFF_IMPACT_PATH,
    POLICY_RULE_DIFF_VALIDATION_ACTION,
};
use super::handler::ResponseActionCommandHandler;
use super::policy_rule_diff::{
    execute_policy_rule_diff_validation, policy_rule_diff_failure_acknowledgement,
    policy_rule_diff_failure_payload, policy_rule_diff_success_payload,
};
use super::validate::{parse_signed_response_action_payload, policy_rule_diff_validation_command};

use crate::api_server::canonical_json_hash;
use crate::nats_client::NatsClient;
use crate::settings::Settings;
use axum::extract::{Path as AxumPath, State};
use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use clawdstrike_policy_event::edr::EndpointResponseExecutionStatus;
use hush_core::{sha256, Keypair};
use serde_json::{json, Value};
use spine::envelope::{build_signed_envelope, now_rfc3339};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{broadcast, mpsc, RwLock};

const EXPECTED_PROPOSED_POLICY_HASH: &str =
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const EXPECTED_PROPOSED_POLICY_EPOCH: u64 = 2;

#[derive(Debug)]
struct LocalImpactRequest {
    authorization: Option<String>,
    body: Value,
}

#[derive(Debug)]
struct ControlAckRequest {
    response_action_id: String,
    api_key: Option<String>,
    body: Value,
}

fn transport_command() -> ResponseActionTransportCommand {
    serde_json::from_value(json!({
        "actionId": "11111111-1111-4111-8111-111111111111",
        "tenantId": "33333333-3333-4333-8333-333333333333",
        "actionType": POLICY_RULE_DIFF_VALIDATION_ACTION,
        "expiresAt": "2999-01-01T00:00:00Z",
        "requireAcknowledgement": true,
        "target": {
            "kind": "endpoint",
            "id": "agent-1"
        },
        "payload": {
            "operation": POLICY_RULE_DIFF_VALIDATION_ACTION,
            "proposalId": "22222222-2222-4222-8222-222222222222",
            "validationPlanSha256": "sha256:plan",
            "endpointAgentId": "agent-1",
            "request": {
                "method": "POST",
                "path": POLICY_RULE_DIFF_IMPACT_PATH,
                "body": {
                    "limit": 25,
                    "proposedPolicyYaml": "version: 1\n"
                }
            },
            "expectedReceipt": {
                "receiptFamily": "policy_event_impact",
                "ruleId": "endpoint.policy_event.impact",
                "graphProcessNodeId": "fleet-rule-diff",
                "proposedPolicyHash": EXPECTED_PROPOSED_POLICY_HASH,
                "proposedPolicyEpoch": EXPECTED_PROPOSED_POLICY_EPOCH,
                "requiredEvidenceKeys": [
                    "impactId",
                    "proposedPolicyHash",
                    "proposedPolicyEpoch"
                ]
            }
        },
        "delivery": {
            "targetKind": "endpoint",
            "targetId": "agent-1",
            "ackToken": "ack-token"
        }
    }))
    .unwrap()
}

fn live_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("set {name} to run the live NATS dogfood test"))
}

async fn spawn_mock_local_policy_impact() -> (
    u16,
    mpsc::Receiver<LocalImpactRequest>,
    tokio::task::JoinHandle<()>,
) {
    async fn handler(
        State(tx): State<mpsc::Sender<LocalImpactRequest>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let authorization = headers
            .get(AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let _ = tx
            .send(LocalImpactRequest {
                authorization,
                body,
            })
            .await;
        Json(local_policy_rule_diff_response())
    }

    let (tx, rx) = mpsc::channel(1);
    let app = Router::new()
        .route(POLICY_RULE_DIFF_IMPACT_PATH, post(handler))
        .with_state(tx);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (port, rx, task)
}

fn local_policy_rule_diff_response() -> Value {
    let proposed_policy_hash = format!("0x{EXPECTED_PROPOSED_POLICY_HASH}");
    let proposed_policy_epoch = EXPECTED_PROPOSED_POLICY_EPOCH;
    json!({
        "impact": {
            "impactId": "impact-loopback-1",
            "eventStreamHash": "sha256:event-stream",
            "currentResultHash": "sha256:current-result",
            "proposedResultHash": "sha256:proposed-result",
            "impactHash": "sha256:impact",
            "eventCount": 3,
            "changedCount": 1,
            "allowToBlockCount": 0,
            "trackPosture": true,
            "changedEventCount": 3,
            "proposedPolicy": {
                "policyHash": proposed_policy_hash,
                "policyEpoch": proposed_policy_epoch,
            }
        },
        "receipt": {
            "receipt_id": "receipt-loopback-1",
            "finding_id": "impact-loopback-1",
            "signature": "signed",
            "receipt": {
                "metadata": {
                    "endpointDecision": {
                        "evidence": [
                            {
                                "key": "proposedPolicyHash",
                                "valueHash": sha256(proposed_policy_hash.as_bytes()).to_hex_prefixed(),
                                "redactionClass": "hash_only"
                            },
                            {
                                "key": "proposedPolicyEpoch",
                                "valueHash": sha256(proposed_policy_epoch.to_string().as_bytes()).to_hex_prefixed(),
                                "redactionClass": "hash_only"
                            }
                        ]
                    }
                }
            }
        }
    })
}

async fn spawn_mock_control_api_agent_ack() -> (
    String,
    mpsc::Receiver<ControlAckRequest>,
    tokio::task::JoinHandle<()>,
) {
    async fn handler(
        AxumPath(response_action_id): AxumPath<String>,
        State(tx): State<mpsc::Sender<ControlAckRequest>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        let api_key = headers
            .get("x-api-key")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let _ = tx
            .send(ControlAckRequest {
                response_action_id,
                api_key,
                body,
            })
            .await;
        Json(json!({"accepted": true}))
    }

    let (tx, rx) = mpsc::channel(1);
    let app = Router::new()
        .route("/api/v1/response-actions/{id}/agent-acks", post(handler))
        .with_state(tx);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base_url, rx, task)
}

async fn recv_with_timeout<T>(rx: &mut mpsc::Receiver<T>) -> T {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

#[test]
fn command_subject_format() {
    assert_eq!(
        ResponseActionCommandHandler::command_subject("tenant-acme.clawdstrike", "agent-1"),
        "tenant-acme.clawdstrike.response.command.endpoint.agent-1"
    );
}

#[test]
fn signed_response_action_accepts_matching_issuer() {
    let kp = Keypair::generate();
    let fact = serde_json::to_value(transport_command()).unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact, now_rfc3339()).unwrap();
    let issuer = envelope
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let parsed = parse_signed_response_action_payload(
        &serde_json::to_vec(&envelope).unwrap(),
        Some(&issuer),
    )
    .unwrap();
    assert_eq!(parsed.action_type, POLICY_RULE_DIFF_VALIDATION_ACTION);
    assert_eq!(parsed.target.id, "agent-1");
}

#[test]
fn policy_rule_diff_validation_rejects_wrong_local_path() {
    let mut command = transport_command();
    command.payload["request"]["path"] = json!("/api/v1/agent/edr/findings");
    let err = policy_rule_diff_validation_command(
        &command,
        "33333333-3333-4333-8333-333333333333",
        "agent-1",
        chrono::Utc::now(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("payload.request.path"));
}

#[test]
fn policy_rule_diff_validation_rejects_wrong_tenant() {
    let command = transport_command();
    let err = policy_rule_diff_validation_command(
        &command,
        "44444444-4444-4444-8444-444444444444",
        "agent-1",
        chrono::Utc::now(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("tenantId"));
}

#[test]
fn policy_rule_diff_validation_rejects_expired_command() {
    let mut command = transport_command();
    command.expires_at = Some(
        chrono::DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
    );
    let now = chrono::DateTime::parse_from_rfc3339("2026-01-02T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let err = policy_rule_diff_validation_command(
        &command,
        "33333333-3333-4333-8333-333333333333",
        "agent-1",
        now,
    )
    .unwrap_err();
    assert!(err.to_string().contains("expired"));
}

#[test]
fn policy_rule_diff_validation_requires_expiry_to_prevent_unbounded_replay() {
    let mut command = transport_command();
    command.expires_at = None;

    let err = policy_rule_diff_validation_command(
        &command,
        "33333333-3333-4333-8333-333333333333",
        "agent-1",
        chrono::Utc::now(),
    )
    .unwrap_err();

    assert!(err.to_string().contains("expiresAt"));
}

#[test]
fn policy_rule_diff_validation_extracts_ack_contract() {
    let command = policy_rule_diff_validation_command(
        &transport_command(),
        "33333333-3333-4333-8333-333333333333",
        "agent-1",
        chrono::Utc::now(),
    )
    .unwrap();
    assert_eq!(
        command.response_action_id,
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(command.target_id, "agent-1");
    assert_eq!(command.ack_token, "ack-token");
    assert_eq!(command.proposal_id, "22222222-2222-4222-8222-222222222222");
    assert_eq!(command.validation_plan_sha256, "sha256:plan");
    assert_eq!(
        command.expected_proposed_policy_hash,
        EXPECTED_PROPOSED_POLICY_HASH
    );
    assert_eq!(
        command.expected_proposed_policy_epoch,
        EXPECTED_PROPOSED_POLICY_EPOCH
    );
    assert_eq!(command.request_body["limit"], 25);
}

#[test]
fn policy_rule_diff_validation_builds_control_ack_payload() {
    let settings = Settings {
        control_api: crate::settings::ControlApiSettings {
            enabled: true,
            url: Some("http://127.0.0.1:3000".to_string()),
            api_key: None,
        },
        ..Settings::default()
    };
    let command = policy_rule_diff_validation_command(
        &transport_command(),
        "33333333-3333-4333-8333-333333333333",
        "agent-1",
        chrono::Utc::now(),
    )
    .unwrap();
    let raw_payload =
        policy_rule_diff_success_payload(&command, &local_policy_rule_diff_response()).unwrap();
    let observed_at = chrono::DateTime::parse_from_rfc3339("2026-05-18T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let ack = control_ack_postback_payload(
        &command,
        "acknowledged",
        Some("policy rule-diff validation completed"),
        Some("policy_rule_diff_validation:succeeded"),
        observed_at,
        raw_payload,
    );

    assert_eq!(ack["targetKind"], "endpoint");
    assert_eq!(ack["targetId"], "agent-1");
    assert_eq!(ack["ackToken"], "ack-token");
    assert_eq!(ack["status"], "acknowledged");
    assert_eq!(
        ack["rawPayload"]["policyRuleDiffValidation"]["proposalId"],
        "22222222-2222-4222-8222-222222222222"
    );
    assert_eq!(
        ack["rawPayload"]["policyRuleDiffValidation"]["impact"]["impactId"],
        "impact-loopback-1"
    );
    assert_eq!(
        ack["rawPayload"]["policyRuleDiffValidation"]["expectedReceipt"]["proposedPolicyHash"],
        EXPECTED_PROPOSED_POLICY_HASH
    );
    let config = control_ack_postback_config(&settings, &command.response_action_id)
        .unwrap()
        .unwrap();
    assert_eq!(config.base_url, "http://127.0.0.1:3000");
    assert_eq!(
        config.url,
        "http://127.0.0.1:3000/api/v1/response-actions/11111111-1111-4111-8111-111111111111/agent-acks"
    );
    assert!(config.api_key.is_none());
}

#[test]
fn policy_rule_diff_validation_failure_payload_binds_request_context() {
    let command = policy_rule_diff_validation_command(
        &transport_command(),
        "33333333-3333-4333-8333-333333333333",
        "agent-1",
        chrono::Utc::now(),
    )
    .unwrap();
    let raw_payload = policy_rule_diff_failure_payload(&command, "local validation failed");

    assert_eq!(
        raw_payload["policyRuleDiffValidationError"]["proposalId"],
        "22222222-2222-4222-8222-222222222222"
    );
    assert_eq!(
        raw_payload["policyRuleDiffValidationError"]["request"]["path"],
        POLICY_RULE_DIFF_IMPACT_PATH
    );
    assert_eq!(
        raw_payload["policyRuleDiffValidationError"]["request"]["body"]["limit"],
        25
    );
    assert!(raw_payload.get("signedReceipt").is_none());

    let observed_at = chrono::Utc::now();
    let ack_context = ControlAckContext {
        status: "failed",
        observed_at,
        message: Some("local validation failed"),
        resulting_state: Some("policy_rule_diff_validation:failed"),
        failure_message: "",
    };
    let acknowledgement =
        policy_rule_diff_failure_acknowledgement(&command, &ack_context, &raw_payload).unwrap();
    assert_eq!(acknowledgement.action_id, command.response_action_id);
    assert_eq!(
        acknowledgement.status,
        EndpointResponseExecutionStatus::Failed
    );
    assert_eq!(acknowledgement.acknowledged_at, observed_at);
    let control = acknowledgement.control_correlation.as_ref().unwrap();
    assert_eq!(control.response_action_id, command.response_action_id);
    assert_eq!(control.target_id, command.target_id);
    assert_eq!(control.ack_status, "failed");
    assert_eq!(
        control.resulting_state.as_deref(),
        Some("policy_rule_diff_validation:failed")
    );
    assert_eq!(
        control.ack_token_hash,
        sha256(command.ack_token.as_bytes()).to_hex_prefixed()
    );
    let request_hash = canonical_json_hash(
        &json!({
            "method": "POST",
            "path": POLICY_RULE_DIFF_IMPACT_PATH,
            "body": command.request_body.clone(),
        }),
        "test policy rule-diff failure request",
    )
    .unwrap();
    assert!(acknowledgement.effects.iter().any(|effect| {
        effect.effect_type == "policy_rule_diff_validation_request"
            && effect.content_hash.as_deref() == Some(request_hash.as_str())
    }));
    assert!(acknowledgement.effects.iter().any(|effect| {
        effect.effect_type == "policy_rule_diff_validation_error_message"
            && effect.content_hash.as_deref()
                == Some(
                    sha256(b"local validation failed")
                        .to_hex_prefixed()
                        .as_str(),
                )
    }));
}

#[test]
fn policy_rule_diff_validation_rejects_mismatched_local_policy_identity() {
    let command = policy_rule_diff_validation_command(
        &transport_command(),
        "33333333-3333-4333-8333-333333333333",
        "agent-1",
        chrono::Utc::now(),
    )
    .unwrap();
    let mut response = local_policy_rule_diff_response();
    response["impact"]["proposedPolicy"]["policyHash"] =
        json!("0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    let err = policy_rule_diff_success_payload(&command, &response)
        .unwrap_err()
        .to_string();

    assert!(err.contains("proposedPolicy.policyHash does not match"));
}

#[test]
fn policy_rule_diff_validation_rejects_mismatched_receipt_policy_evidence() {
    let command = policy_rule_diff_validation_command(
        &transport_command(),
        "33333333-3333-4333-8333-333333333333",
        "agent-1",
        chrono::Utc::now(),
    )
    .unwrap();
    let mut response = local_policy_rule_diff_response();
    response["receipt"]["receipt"]["metadata"]["endpointDecision"]["evidence"][0]["valueHash"] =
        json!(sha256(b"wrong-policy").to_hex_prefixed());

    let err = policy_rule_diff_success_payload(&command, &response)
        .unwrap_err()
        .to_string();

    assert!(err.contains("receipt evidence proposedPolicyHash"));
}

#[tokio::test]
async fn policy_rule_diff_validation_executes_local_api_and_posts_agent_ack() {
    let (agent_api_port, mut local_rx, local_task) = spawn_mock_local_policy_impact().await;
    let (control_api_url, mut control_rx, control_task) = spawn_mock_control_api_agent_ack().await;
    let settings = RwLock::new(Settings {
        agent_api_port,
        control_api: crate::settings::ControlApiSettings {
            enabled: true,
            url: Some(control_api_url),
            api_key: None,
        },
        ..Settings::default()
    });
    let command = policy_rule_diff_validation_command(
        &transport_command(),
        "33333333-3333-4333-8333-333333333333",
        "agent-1",
        chrono::Utc::now(),
    )
    .unwrap();
    let http_client = reqwest::Client::new();

    let raw_payload =
        execute_policy_rule_diff_validation(&http_client, &settings, "local-token", &command)
            .await
            .unwrap();
    let local_request = recv_with_timeout(&mut local_rx).await;
    assert_eq!(
        local_request.authorization.as_deref(),
        Some("Bearer local-token")
    );
    assert_eq!(local_request.body["limit"], 25);
    assert_eq!(
        raw_payload["policyRuleDiffValidation"]["impact"]["impactId"],
        "impact-loopback-1"
    );
    assert_eq!(
        raw_payload["policyRuleDiffValidation"]["receipt"]["receipt_id"],
        "receipt-loopback-1"
    );

    let observed_at = chrono::DateTime::parse_from_rfc3339("2026-05-18T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    post_control_acknowledgement(
        &http_client,
        &settings,
        &command,
        &ControlAckContext {
            status: "acknowledged",
            observed_at,
            message: Some("policy rule-diff validation completed"),
            resulting_state: Some("policy_rule_diff_validation:succeeded"),
            failure_message: "",
        },
        raw_payload,
    )
    .await
    .unwrap();

    let control_request = recv_with_timeout(&mut control_rx).await;
    assert_eq!(
        control_request.response_action_id,
        "11111111-1111-4111-8111-111111111111"
    );
    assert!(control_request.api_key.is_none());
    assert_eq!(control_request.body["ackToken"], "ack-token");
    assert_eq!(control_request.body["targetKind"], "endpoint");
    assert_eq!(control_request.body["targetId"], "agent-1");
    assert_eq!(control_request.body["status"], "acknowledged");
    assert_eq!(
        control_request.body["rawPayload"]["policyRuleDiffValidation"]["proposalId"],
        "22222222-2222-4222-8222-222222222222"
    );
    assert_eq!(
        control_request.body["rawPayload"]["policyRuleDiffValidation"]["impact"]["impactId"],
        "impact-loopback-1"
    );

    local_task.abort();
    control_task.abort();
}

#[tokio::test]
#[ignore = "requires live NATS credentials; set CLAWDSTRIKE_LIVE_NATS_* env vars"]
async fn live_nats_response_action_command_executes_and_acknowledges() {
    let nats_url = live_env("CLAWDSTRIKE_LIVE_NATS_URL");
    let tenant_id = live_env("CLAWDSTRIKE_LIVE_NATS_TENANT_ID");
    let agent_id = live_env("CLAWDSTRIKE_LIVE_NATS_AGENT_ID");
    let subject_prefix = live_env("CLAWDSTRIKE_LIVE_NATS_SUBJECT_PREFIX");
    let nats_settings = crate::settings::NatsSettings {
        enabled: true,
        nats_url: Some(nats_url),
        token: std::env::var("CLAWDSTRIKE_LIVE_NATS_TOKEN").ok(),
        creds_file: std::env::var("CLAWDSTRIKE_LIVE_NATS_CREDS_FILE").ok(),
        nkey_seed: std::env::var("CLAWDSTRIKE_LIVE_NATS_NKEY_SEED").ok(),
        tenant_id: Some(tenant_id.clone()),
        agent_id: Some(agent_id.clone()),
        subject_prefix: Some(subject_prefix),
        ..crate::settings::NatsSettings::default()
    };

    let (agent_api_port, mut local_rx, local_task) = spawn_mock_local_policy_impact().await;
    let (control_api_url, mut control_rx, control_task) = spawn_mock_control_api_agent_ack().await;
    let nats = Arc::new(NatsClient::connect(&nats_settings).await.unwrap());
    let mut command = transport_command();
    command.tenant_id = tenant_id;
    command.target.id = agent_id.clone();
    command.delivery.target_id = agent_id.clone();
    command.payload["endpointAgentId"] = json!(agent_id);

    let kp = Keypair::generate();
    let fact = serde_json::to_value(command).unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact, now_rfc3339()).unwrap();
    let issuer = envelope
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap()
        .to_string();
    let settings = Arc::new(RwLock::new(Settings {
        agent_api_port,
        control_api: crate::settings::ControlApiSettings {
            enabled: true,
            url: Some(control_api_url),
            api_key: None,
        },
        nats: crate::settings::NatsSettings {
            approval_response_trusted_issuer: Some(issuer),
            ..nats_settings
        },
        ..Settings::default()
    }));
    let handler =
        ResponseActionCommandHandler::new(nats.clone(), settings, "local-token".to_string(), None);
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
    let handler_task = tokio::spawn(async move {
        handler.start(shutdown_rx).await;
    });
    tokio::time::sleep(Duration::from_millis(250)).await;

    let subject =
        ResponseActionCommandHandler::command_subject(nats.subject_prefix(), nats.agent_id());
    let envelope_json = serde_json::to_vec(&envelope).unwrap();
    let mut reply = None;
    let mut last_error = None;
    for _ in 0..20 {
        match tokio::time::timeout(
            Duration::from_secs(2),
            nats.client()
                .request(subject.clone(), envelope_json.clone().into()),
        )
        .await
        {
            Ok(Ok(message)) => {
                reply = Some(message);
                break;
            }
            Ok(Err(err)) => {
                last_error = Some(err.to_string());
            }
            Err(_) => {
                last_error = Some("timed out waiting for response-command reply".to_string());
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let reply = reply.unwrap_or_else(|| {
        panic!(
            "live NATS response-action command request failed: {}",
            last_error.unwrap_or_else(|| "unknown error".to_string())
        )
    });
    let reply: Value = serde_json::from_slice(&reply.payload).unwrap();
    assert_eq!(reply["status"], "ok");
    assert_eq!(
        reply["responseActionId"],
        "11111111-1111-4111-8111-111111111111"
    );

    let local_request = recv_with_timeout(&mut local_rx).await;
    assert_eq!(local_request.body["limit"], 25);
    let control_request = recv_with_timeout(&mut control_rx).await;
    assert_eq!(
        control_request.response_action_id,
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(control_request.body["ackToken"], "ack-token");
    assert_eq!(control_request.body["status"], "acknowledged");
    assert_eq!(
        control_request.body["rawPayload"]["policyRuleDiffValidation"]["impact"]["impactId"],
        "impact-loopback-1"
    );

    let _ = shutdown_tx.send(());
    handler_task.abort();
    local_task.abort();
    control_task.abort();
}
