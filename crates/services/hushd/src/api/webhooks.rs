//! Provider webhook endpoints (Okta/Auth0).

use axum::{extract::State, http::StatusCode, Json};
use serde::Deserialize;

use crate::config::expand_env_refs;
use crate::state::AppState;

fn timing_safe_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn extract_bearer_token(headers: &axum::http::HeaderMap) -> Option<String> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let auth_header = auth_header.trim();
    let (scheme, token) = auth_header.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let token = token.trim();
    if token.is_empty() {
        return None;
    }
    Some(token.to_string())
}

#[derive(Clone, Debug, Deserialize)]
struct OktaVerificationChallenge {
    #[serde(default)]
    verification: Option<String>,
}

/// POST /api/v1/webhooks/okta
pub async fn okta_webhook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(okta) = state.config.identity.okta.as_ref() else {
        return Err((StatusCode::NOT_FOUND, "okta_not_configured".to_string()));
    };

    // Support Okta verification challenge (initial setup).
    if let Ok(challenge) = serde_json::from_str::<OktaVerificationChallenge>(&body) {
        if let Some(v) = challenge.verification {
            return Ok(Json(serde_json::json!({ "verification": v })));
        }
    }

    let Some(webhooks) = okta.webhooks.as_ref() else {
        return Err((
            StatusCode::NOT_FOUND,
            "okta_webhooks_not_configured".to_string(),
        ));
    };

    let expected = expand_env_refs(&webhooks.verification_key)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(token) = extract_bearer_token(&headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "missing_authorization".to_string(),
        ));
    };
    if !timing_safe_eq(&token, &expected) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid_authorization".to_string(),
        ));
    }

    let payload: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Okta Event Hooks include an array under data.events.
    let mut terminated = 0u64;
    if let Some(events) = payload
        .get("data")
        .and_then(|d| d.get("events"))
        .and_then(|e| e.as_array())
    {
        for ev in events {
            let event_type = ev.get("eventType").and_then(|v| v.as_str()).unwrap_or("");
            let should_terminate = matches!(
                event_type,
                "user.lifecycle.deactivate"
                    | "user.lifecycle.suspend"
                    | "user.lifecycle.delete.initiated"
                    | "user.session.end"
            );
            if !should_terminate {
                continue;
            }

            let user_ids = extract_okta_user_ids(ev);
            for user_id in user_ids {
                terminated = terminated.saturating_add(
                    state
                        .sessions
                        .terminate_sessions_for_user(&user_id, Some("okta_webhook"))
                        .unwrap_or(0),
                );
            }
        }
    }

    // Audit + broadcast.
    let mut audit = crate::audit::AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "webhook_okta".to_string();
    audit.action_type = "webhook".to_string();
    audit.target = Some("okta".to_string());
    audit.message = Some("Okta webhook processed".to_string());
    audit.metadata = Some(serde_json::json!({ "terminated_sessions": terminated }));
    let _ = state.ledger.record(&audit);

    state.broadcast(crate::state::DaemonEvent {
        event_type: "webhook_okta".to_string(),
        data: serde_json::json!({ "terminated_sessions": terminated }),
    });

    Ok(Json(
        serde_json::json!({ "ok": true, "terminated_sessions": terminated }),
    ))
}

fn extract_okta_user_ids(event: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(targets) = event.get("target").and_then(|v| v.as_array()) else {
        return out;
    };
    for t in targets {
        let Some(obj) = t.as_object() else {
            continue;
        };
        let typ = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        if typ != "User" && typ != "AppUser" {
            continue;
        }
        if let Some(id) = obj.get("id").and_then(|v| v.as_str()) {
            out.push(id.to_string());
        }
    }
    out
}

/// POST /api/v1/webhooks/auth0
pub async fn auth0_webhook(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    body: String,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let Some(auth0) = state.config.identity.auth0.as_ref() else {
        return Err((StatusCode::NOT_FOUND, "auth0_not_configured".to_string()));
    };
    let Some(log_stream) = auth0.log_stream.as_ref() else {
        return Err((
            StatusCode::NOT_FOUND,
            "auth0_log_stream_not_configured".to_string(),
        ));
    };

    let expected = expand_env_refs(&log_stream.authorization)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let Some(token) = extract_bearer_token(&headers) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "missing_authorization".to_string(),
        ));
    };
    if !timing_safe_eq(&token, &expected) {
        return Err((
            StatusCode::UNAUTHORIZED,
            "invalid_authorization".to_string(),
        ));
    }

    let payload: serde_json::Value =
        serde_json::from_str(&body).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    let mut terminated = 0u64;
    for (event_type, user_id) in extract_auth0_events(&payload) {
        if matches!(event_type.as_str(), "du" | "slo") {
            terminated = terminated.saturating_add(
                state
                    .sessions
                    .terminate_sessions_for_user(&user_id, Some("auth0_webhook"))
                    .unwrap_or(0),
            );
        }
    }

    let mut audit = crate::audit::AuditEvent::session_start(&state.session_id, None);
    audit.event_type = "webhook_auth0".to_string();
    audit.action_type = "webhook".to_string();
    audit.target = Some("auth0".to_string());
    audit.message = Some("Auth0 webhook processed".to_string());
    audit.metadata = Some(serde_json::json!({ "terminated_sessions": terminated }));
    let _ = state.ledger.record(&audit);

    state.broadcast(crate::state::DaemonEvent {
        event_type: "webhook_auth0".to_string(),
        data: serde_json::json!({ "terminated_sessions": terminated }),
    });

    Ok(Json(
        serde_json::json!({ "ok": true, "terminated_sessions": terminated }),
    ))
}

fn extract_auth0_events(payload: &serde_json::Value) -> Vec<(String, String)> {
    // Auth0 log streams may send a single event object or an array of events.
    if let Some(arr) = payload.as_array() {
        return arr.iter().flat_map(extract_auth0_events).collect();
    }

    let Some(obj) = payload.as_object() else {
        return Vec::new();
    };

    let event_type = obj
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let user_id = find_string_field(payload, &["user_id", "userId"]);
    match user_id {
        Some(user_id) if !event_type.is_empty() => vec![(event_type, user_id)],
        _ => Vec::new(),
    }
}

fn find_string_field(value: &serde_json::Value, keys: &[&str]) -> Option<String> {
    match value {
        serde_json::Value::Object(obj) => {
            for k in keys {
                if let Some(v) = obj.get(*k).and_then(|v| v.as_str()) {
                    return Some(v.to_string());
                }
            }
            for v in obj.values() {
                if let Some(found) = find_string_field(v, keys) {
                    return Some(found);
                }
            }
            None
        }
        serde_json::Value::Array(arr) => arr.iter().find_map(|v| find_string_field(v, keys)),
        _ => None,
    }
}
