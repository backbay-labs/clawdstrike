//! Authentication helpers and UI cookie middleware.
//!
//! `require_auth` is the central token-and-cookie check; `attach_ui_auth_cookie`
//! is an axum middleware that gates `/ui/*` access and refreshes the auth cookie.

use super::super::*;
use crate::agent_auth::rotate_local_api_token;
use crate::security::auth::constant_time_eq_token;
use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, SET_COOKIE};
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) fn current_auth_token(state: &AgentApiState) -> String {
    let guard = state
        .auth_token
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
}

pub(crate) fn current_token_grace_minutes(state: &AgentApiState) -> u32 {
    let guard = state
        .token_grace_minutes
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    (*guard).max(1)
}

pub(crate) fn set_token_grace_minutes(state: &AgentApiState, value: u32) {
    let mut guard = state
        .token_grace_minutes
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = value.max(1);
}

pub(crate) fn rotate_local_api_token_with_grace(
    state: &AgentApiState,
) -> Result<u64, (StatusCode, String)> {
    let old_token = current_auth_token(state);
    let new_token = rotate_local_api_token().map_err(internal_error)?;
    {
        let mut guard = state
            .auth_token
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = new_token;
    }

    let grace_secs = u64::from(current_token_grace_minutes(state)) * 60;
    {
        let mut previous = state
            .previous_auth_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *previous = Some(PreviousAuthToken {
            token: old_token,
            expires_at: Instant::now() + Duration::from_secs(grace_secs),
        });
    }

    Ok(grace_secs)
}

pub(crate) fn auth_token_matches(candidate: &str, state: &AgentApiState) -> bool {
    let current = state
        .auth_token
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if constant_time_eq_token(candidate, current.as_str()) {
        return true;
    }
    drop(current);

    let mut previous = state
        .previous_auth_token
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(prev) = previous.as_ref() {
        if Instant::now() > prev.expires_at {
            *previous = None;
            return false;
        }
        return constant_time_eq_token(candidate, &prev.token);
    }

    false
}

pub(crate) fn require_auth(
    headers: &HeaderMap,
    state: &AgentApiState,
) -> Result<(), (StatusCode, String)> {
    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim);

    if let Some(auth) = auth_header {
        if let Some(token) = auth.strip_prefix("Bearer ") {
            if auth_token_matches(token.trim(), state) {
                return Ok(());
            }
        }
    }

    if let Some(cookie_token) = auth_token_from_cookie(headers) {
        if auth_token_matches(cookie_token.trim(), state) {
            return Ok(());
        }
    }

    let err = match auth_header {
        None => "missing authorization header".to_string(),
        Some(auth) if !auth.starts_with("Bearer ") => "invalid authorization scheme".to_string(),
        Some(_) => "invalid authorization token".to_string(),
    };
    Err((StatusCode::UNAUTHORIZED, err))
}

pub(crate) fn auth_cookie_header_value(auth_token: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict{}",
        AGENT_AUTH_COOKIE_NAME, auth_token, secure_flag
    )
}

pub(crate) fn set_ui_auth_cookie(response: &mut Response, auth_token: &str, secure: bool) {
    match HeaderValue::from_str(&auth_cookie_header_value(auth_token, secure)) {
        Ok(value) => {
            response.headers_mut().append(SET_COOKIE, value);
        }
        Err(err) => {
            tracing::warn!(error = %err, "Failed to build UI auth cookie header");
        }
    }
}

pub(crate) fn request_is_secure_uri(headers: &HeaderMap, uri: &Uri) -> bool {
    if uri.scheme_str() == Some("https") {
        return true;
    }
    if !is_local_host_header(headers) {
        return false;
    }
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
}

pub(crate) fn request_is_secure(headers: &HeaderMap, request: &Request) -> bool {
    request_is_secure_uri(headers, request.uri())
}

pub(crate) async fn attach_ui_auth_cookie(
    State(state): State<Arc<AgentApiState>>,
    request: Request,
    next: Next,
) -> Response {
    let secure_cookie = request_is_secure(request.headers(), &request);
    if !secure_cookie && !is_local_host_header(request.headers()) {
        return (
            StatusCode::FORBIDDEN,
            "Non-localhost dashboard access requires HTTPS",
        )
            .into_response();
    }

    if has_query_param(request.uri(), "agent_token") {
        tracing::warn!(
            path = %request.uri().path(),
            "Rejected deprecated query-based UI bootstrap token"
        );
        return (
            StatusCode::BAD_REQUEST,
            "Query-based UI bootstrap is disabled",
        )
            .into_response();
    }

    if require_auth(request.headers(), &state).is_err() {
        return (
            StatusCode::UNAUTHORIZED,
            "Missing authorization token for /ui",
        )
            .into_response();
    }

    let mut response = next.run(request).await;
    let token = current_auth_token(&state);
    set_ui_auth_cookie(&mut response, &token, secure_cookie);
    response
}
