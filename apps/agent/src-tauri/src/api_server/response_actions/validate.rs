//! Request validation for live response actions.
//!
//! Validates actor identity, TTL bounds, and reason fields, and provides
//! default reason strings keyed by action kind.

use super::*;

pub(crate) fn validate_response_action_actor(
    actor: Option<&EdrResponseActionActorInput>,
) -> Result<(), (StatusCode, String)> {
    let Some(actor) = actor else {
        return Err((
            StatusCode::BAD_REQUEST,
            "live response execution requires actor identity".to_string(),
        ));
    };
    if !response_action_actor_identity_present(actor) {
        return Err((
            StatusCode::BAD_REQUEST,
            "live response execution actor must include userId, sessionId, agentId, workloadId, or approvalId".to_string(),
        ));
    }
    if non_empty(actor.approval_id.as_deref()).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "live response execution requires actor approvalId".to_string(),
        ));
    }
    Ok(())
}

fn response_action_actor_identity_present(actor: &EdrResponseActionActorInput) -> bool {
    [
        actor.user_id.as_deref(),
        actor.session_id.as_deref(),
        actor.agent_id.as_deref(),
        actor.workload_id.as_deref(),
        actor.approval_id.as_deref(),
    ]
    .into_iter()
    .any(|value| non_empty(value).is_some())
}

pub(crate) fn validate_response_action_actor_fields(
    actor: Option<&EdrResponseActionActorInput>,
) -> Result<(), (StatusCode, String)> {
    let Some(actor) = actor else {
        return Ok(());
    };
    for (field, value) in [
        (
            "actor.endpointId",
            non_empty(Some(actor.endpoint_id.as_str())),
        ),
        ("actor.hostId", non_empty(actor.host_id.as_deref())),
        ("actor.userId", non_empty(actor.user_id.as_deref())),
        ("actor.sessionId", non_empty(actor.session_id.as_deref())),
        ("actor.posture", non_empty(actor.posture.as_deref())),
        ("actor.agentId", non_empty(actor.agent_id.as_deref())),
        ("actor.workloadId", non_empty(actor.workload_id.as_deref())),
        ("actor.approvalId", non_empty(actor.approval_id.as_deref())),
    ] {
        if value.is_some_and(|value| value.len() > EDR_MAX_RESPONSE_ACTOR_FIELD_BYTES) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("{field} must be at most {EDR_MAX_RESPONSE_ACTOR_FIELD_BYTES} bytes"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_response_action_ttl_seconds(
    ttl_seconds: Option<u64>,
) -> Result<u64, (StatusCode, String)> {
    let ttl_seconds = ttl_seconds.unwrap_or(EDR_DEFAULT_RESPONSE_TTL_SECONDS);
    if (1..=EDR_MAX_RESPONSE_TTL_SECONDS).contains(&ttl_seconds) {
        return Ok(ttl_seconds);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("ttlSeconds must be between 1 and {EDR_MAX_RESPONSE_TTL_SECONDS} seconds"),
    ))
}

pub(crate) fn validate_response_reason(
    field: &str,
    reason: Option<&str>,
    default_reason: &'static str,
) -> Result<String, (StatusCode, String)> {
    let reason = reason
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_reason);
    if reason.len() <= EDR_MAX_RESPONSE_REASON_BYTES {
        return Ok(reason.to_string());
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} reason must be at most {EDR_MAX_RESPONSE_REASON_BYTES} bytes"),
    ))
}
