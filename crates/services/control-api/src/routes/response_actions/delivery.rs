//! Delivery-plan construction, NATS subject derivation, and transport payloads.

use super::*;

pub(crate) fn delivery_plan(action: &ResponseActionRecord, tenant_slug: &str) -> DeliveryPlan {
    let subject_prefix = tenant_subject_prefix(tenant_slug);
    let ack_deadline = action
        .require_acknowledgement
        .then(|| Utc::now() + Duration::minutes(ACK_DEADLINE_MINUTES));
    let ack_token = action
        .require_acknowledgement
        .then(|| Uuid::new_v4().to_string());

    match action.target.kind {
        ResponseTargetKind::Endpoint
        | ResponseTargetKind::Runtime
        | ResponseTargetKind::Session => {
            let canonical_subject = canonical_response_subject(action, &subject_prefix);
            let legacy_subject = legacy_posture_subject(action, &subject_prefix);

            DeliveryPlan {
                target_kind: action.target.kind.as_str().to_string(),
                target_id: action.target.id.clone(),
                executor_kind: match action.target.kind {
                    ResponseTargetKind::Endpoint => "endpoint_agent".to_string(),
                    ResponseTargetKind::Runtime => "runtime_agent".to_string(),
                    ResponseTargetKind::Session => "session_api".to_string(),
                    _ => "endpoint_agent".to_string(),
                },
                delivery_subject: Some(canonical_subject.clone()),
                acknowledgement_deadline: ack_deadline,
                metadata: json!({
                    "ack_token": ack_token,
                    "canonical_subject": canonical_subject,
                    "compat_mirror_subject": legacy_subject,
                    "protocol": "response_action_v1",
                }),
            }
        }
        _ => DeliveryPlan {
            target_kind: action.target.kind.as_str().to_string(),
            target_id: action.target.id.clone(),
            executor_kind: "cloud_only".to_string(),
            delivery_subject: None,
            acknowledgement_deadline: ack_deadline,
            metadata: json!({
                "ack_token": ack_token,
                "cloud_only": true,
                "protocol": "cloud_only",
            }),
        },
    }
}

fn canonical_response_subject(action: &ResponseActionRecord, subject_prefix: &str) -> String {
    format!(
        "{subject_prefix}.response.command.{}.{}",
        action.target.kind.as_str(),
        action.target.id
    )
}

fn legacy_posture_subject(action: &ResponseActionRecord, subject_prefix: &str) -> Option<String> {
    if matches!(
        action.action_type.as_str(),
        "transition_posture" | "request_policy_reload" | "kill_switch"
    ) && matches!(action.target.kind, ResponseTargetKind::Endpoint)
    {
        Some(format!(
            "{subject_prefix}.posture.command.{}",
            action.target.id
        ))
    } else {
        None
    }
}

pub(crate) fn build_delivery_payload_bytes(
    action: &ResponseActionRecord,
    delivery: &ResponseActionDelivery,
    signing_enabled: bool,
    signing_keypair: Option<&hush_core::Keypair>,
) -> Result<Vec<u8>, ApiError> {
    let payload = action_transport_payload(action, delivery);
    build_signed_payload_bytes(payload, signing_enabled, signing_keypair)
}

fn action_transport_payload(
    action: &ResponseActionRecord,
    delivery: &ResponseActionDelivery,
) -> Value {
    let ack_token = delivery.metadata.get("ack_token").and_then(Value::as_str);

    let mut payload = action.to_transport_payload();
    payload["delivery"] = json!({
        "subject": delivery.delivery_subject,
        "targetKind": delivery.target_kind,
        "targetId": delivery.target_id,
        "ackToken": ack_token,
    });
    payload
}

pub(crate) fn legacy_posture_command_payload(
    action: &ResponseActionRecord,
) -> Result<Value, ApiError> {
    match action.action_type.as_str() {
        "transition_posture" => {
            let posture = transition_posture_value(&action.payload).ok_or_else(|| {
                ApiError::BadRequest(
                    "transition_posture actions require payload.toState or payload.posture"
                        .to_string(),
                )
            })?;
            Ok(json!({
                "command": "set_posture",
                "posture": posture,
            }))
        }
        "request_policy_reload" => Ok(json!({
            "command": "request_policy_reload",
        })),
        "kill_switch" => Ok(json!({
            "command": "kill_switch",
            "reason": action.reason,
        })),
        other => Err(ApiError::BadRequest(format!(
            "action '{other}' does not support legacy posture transport"
        ))),
    }
}

pub(crate) fn build_signed_payload_bytes(
    payload: Value,
    signing_enabled: bool,
    signing_keypair: Option<&hush_core::Keypair>,
) -> Result<Vec<u8>, ApiError> {
    if signing_enabled {
        let keypair = signing_keypair.ok_or_else(|| {
            ApiError::Internal("response signing is enabled but keypair is not loaded".to_string())
        })?;
        let envelope =
            spine::build_signed_envelope(keypair, 0, None, payload, spine::now_rfc3339()).map_err(
                |err| ApiError::Internal(format!("failed to sign response action: {err}")),
            )?;
        return serde_json::to_vec(&envelope).map_err(|err| {
            ApiError::Internal(format!(
                "failed to serialize signed response action envelope: {err}"
            ))
        });
    }

    Ok(serde_json::to_vec(&payload).unwrap_or_default())
}

pub(crate) fn transition_posture_value(payload: &Value) -> Option<String> {
    payload
        .get("toState")
        .and_then(Value::as_str)
        .or_else(|| payload.get("to_state").and_then(Value::as_str))
        .or_else(|| payload.get("posture").and_then(Value::as_str))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

pub(crate) fn scrub_delivery_metadata(mut metadata: Value) -> Value {
    if let Some(object) = metadata.as_object_mut() {
        object.remove("ack_token");
    }
    metadata
}
