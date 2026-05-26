//! UI bootstrap handlers (one-time code, verify form, fallback page).
//!
//! These three handlers implement the one-time-code login flow used to attach a
//! local browser session to the agent's auth-cookie scope. The static HTML for
//! the pages lives in `ui_bootstrap_html.rs`.

use super::*;
use crate::security::auth::constant_time_eq_token;
use axum::extract::{Form, State};
use axum::http::header::LOCATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Deserialize)]
pub(crate) struct UiBootstrapStartInput {
    #[serde(default)]
    next_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct UiBootstrapStartResponse {
    pub(crate) session_id: String,
    pub(crate) user_code: String,
    pub(crate) expires_in_seconds: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct UiBootstrapVerifyInput {
    session_id: String,
    user_code: String,
}

pub(crate) fn control_console_dist_candidates() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    if let Ok(override_path) = std::env::var("CLAWDSTRIKE_CONTROL_CONSOLE_DIST") {
        candidates.push(PathBuf::from(override_path));
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            candidates.push(exe_dir.join("control-console"));
            candidates.push(exe_dir.join("resources").join("control-console"));

            if let Some(contents_dir) = exe_dir.parent() {
                candidates.push(contents_dir.join("Resources").join("control-console"));
                candidates.push(
                    contents_dir
                        .join("Resources")
                        .join("resources")
                        .join("control-console"),
                );
            }
        }
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let root = PathBuf::from(manifest_dir);
        candidates.push(root.join("resources").join("control-console"));
        candidates.push(root.join("../../control-console/dist"));
    }

    candidates
}

pub(crate) fn resolve_control_console_dist() -> Option<PathBuf> {
    control_console_dist_candidates()
        .into_iter()
        .find(|candidate| candidate.join("index.html").is_file())
}

pub(crate) fn prune_ui_bootstrap_sessions(
    sessions: &mut HashMap<String, UiBootstrapSession>,
    now: Instant,
) {
    sessions.retain(|_, session| {
        session.expires_at > now && session.attempts < UI_BOOTSTRAP_MAX_ATTEMPTS
    });
    while sessions.len() > UI_BOOTSTRAP_MAX_SESSIONS {
        let Some((oldest_key, _)) = sessions
            .iter()
            .min_by_key(|(_, session)| session.created_at)
            .map(|(id, session)| (id.clone(), session.created_at))
        else {
            break;
        };
        let _ = sessions.remove(&oldest_key);
    }
}

pub(crate) async fn agent_web_ui_fallback() -> Html<&'static str> {
    super::ui_bootstrap_html::agent_web_ui_fallback_html()
}

pub(crate) async fn start_ui_bootstrap(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<UiBootstrapStartInput>,
) -> Result<Json<UiBootstrapStartResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let now = Instant::now();
    let session_id = uuid::Uuid::new_v4().to_string();
    let (code_normalized, user_code) = generate_ui_bootstrap_code();
    let next_path = sanitize_ui_next_path(input.next_path.as_deref());

    {
        let mut sessions = state.ui_bootstrap_sessions.lock().await;
        prune_ui_bootstrap_sessions(&mut sessions, now);
        sessions.insert(
            session_id.clone(),
            UiBootstrapSession {
                code_normalized,
                next_path,
                created_at: now,
                expires_at: now + UI_BOOTSTRAP_TTL,
                attempts: 0,
            },
        );
    }

    Ok(Json(UiBootstrapStartResponse {
        session_id,
        user_code,
        expires_in_seconds: UI_BOOTSTRAP_TTL.as_secs(),
    }))
}

pub(crate) async fn ui_bootstrap_page(uri: Uri) -> impl IntoResponse {
    let session_id = query_param(&uri, "session_id");
    let valid_session = session_id
        .as_deref()
        .map(is_valid_bootstrap_session_id)
        .unwrap_or(false);
    if !valid_session {
        return (
            StatusCode::BAD_REQUEST,
            "Missing or invalid bootstrap session id",
        )
            .into_response();
    }

    super::ui_bootstrap_html::ui_bootstrap_page_html().into_response()
}

pub(crate) async fn ui_bootstrap_verify(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    uri: Uri,
    Form(input): Form<UiBootstrapVerifyInput>,
) -> Response {
    let secure_cookie = request_is_secure_uri(&headers, &uri);
    if !secure_cookie && !is_local_host_header(&headers) {
        return (
            StatusCode::FORBIDDEN,
            "Non-localhost dashboard access requires HTTPS",
        )
            .into_response();
    }

    if !is_valid_bootstrap_session_id(input.session_id.trim()) {
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired bootstrap code",
        )
            .into_response();
    }
    let Some(code_normalized) = normalize_bootstrap_code(&input.user_code) else {
        return (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired bootstrap code",
        )
            .into_response();
    };

    let now = Instant::now();
    let session_id = input.session_id.trim().to_string();

    let next_path = {
        let mut sessions = state.ui_bootstrap_sessions.lock().await;
        prune_ui_bootstrap_sessions(&mut sessions, now);

        let Some(session) = sessions.get_mut(&session_id) else {
            return (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired bootstrap code",
            )
                .into_response();
        };
        if !constant_time_eq_token(&code_normalized, &session.code_normalized) {
            session.attempts = session.attempts.saturating_add(1);
            if session.attempts >= UI_BOOTSTRAP_MAX_ATTEMPTS {
                let _ = sessions.remove(&session_id);
            }
            return (
                StatusCode::UNAUTHORIZED,
                "Invalid or expired bootstrap code",
            )
                .into_response();
        }
        let next = session.next_path.clone();
        let _ = sessions.remove(&session_id);
        next
    };

    let mut response = StatusCode::SEE_OTHER.into_response();
    match HeaderValue::from_str(&next_path) {
        Ok(value) => {
            response.headers_mut().insert(LOCATION, value);
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                location = %next_path,
                "Failed to build bootstrap redirect location"
            );
            response
                .headers_mut()
                .insert(LOCATION, HeaderValue::from_static("/ui"));
        }
    }
    let token = current_auth_token(&state);
    set_ui_auth_cookie(&mut response, &token, secure_cookie);
    response
}
