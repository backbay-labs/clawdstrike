//! Local API auth, cookie attachment, and rotating-token plumbing.
//!
//! Every authenticated handler funnels through `require_auth`. The token
//! lives in `AgentApiState::auth_token`; rotation can publish a previous
//! token with a grace window so in-flight requests keep working.

use super::{
    internal_error, AgentApiState, PreviousAuthToken, RotateLocalApiTokenResponse,
    AGENT_AUTH_COOKIE_NAME, HUSHD_AUTHORIZATION_HEADER,
};

use crate::agent_auth::rotate_local_api_token;
use crate::security::auth::constant_time_eq_token;

use axum::extract::{Request, State};
use axum::http::header::{AUTHORIZATION, COOKIE, SET_COOKIE};
use axum::http::{uri::Authority, HeaderMap, HeaderValue, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use hush_core::sha256;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

pub(super) fn merged_authorization_header(
    request_headers: &HeaderMap,
    daemon_api_key: Option<&str>,
) -> Option<String> {
    if let Some(value) = request_headers
        .get(HUSHD_AUTHORIZATION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_string());
    }

    if let Some(value) = request_headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Some(value.to_string());
    }

    daemon_api_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|key| format!("Bearer {}", key))
}

fn auth_cookie_header_value(auth_token: &str, secure: bool) -> String {
    let secure_flag = if secure { "; Secure" } else { "" };
    format!(
        "{}={}; Path=/; HttpOnly; SameSite=Strict{}",
        AGENT_AUTH_COOKIE_NAME, auth_token, secure_flag
    )
}

pub(super) fn set_ui_auth_cookie(response: &mut Response, auth_token: &str, secure: bool) {
    match HeaderValue::from_str(&auth_cookie_header_value(auth_token, secure)) {
        Ok(value) => {
            response.headers_mut().append(SET_COOKIE, value);
        }
        Err(err) => {
            tracing::warn!(error = %err, "Failed to build UI auth cookie header");
        }
    }
}

pub(super) fn request_is_secure_uri(headers: &HeaderMap, uri: &Uri) -> bool {
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

fn request_is_secure(headers: &HeaderMap, request: &Request) -> bool {
    request_is_secure_uri(headers, request.uri())
}

pub(super) fn is_local_host_header(headers: &HeaderMap) -> bool {
    let Some(host) = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return false;
    };

    let host_only = host
        .parse::<Authority>()
        .map(|authority| authority.host().to_ascii_lowercase())
        .unwrap_or_else(|_| host.to_ascii_lowercase());
    let host_only = host_only
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    host_only == "localhost" || host_only == "127.0.0.1" || host_only == "::1"
}

fn has_query_param(uri: &Uri, param_name: &str) -> bool {
    let Some(query) = uri.query() else {
        return false;
    };

    query.split('&').any(|pair| {
        if pair.is_empty() {
            return false;
        }
        let (name, _) = pair.split_once('=').unwrap_or((pair, ""));
        name == param_name
    })
}

pub(super) async fn attach_ui_auth_cookie(
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

pub(super) fn current_auth_token(state: &AgentApiState) -> String {
    let guard = state
        .auth_token
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    guard.clone()
}

pub(super) fn current_token_grace_minutes(state: &AgentApiState) -> u32 {
    let guard = state
        .token_grace_minutes
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    (*guard).max(1)
}

pub(super) fn set_token_grace_minutes(state: &AgentApiState, value: u32) {
    let mut guard = state
        .token_grace_minutes
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = value.max(1);
}

pub(super) fn rotate_local_api_token_with_grace(
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

pub(super) fn rotate_local_api_token_without_grace(
    state: &AgentApiState,
) -> Result<String, (StatusCode, String)> {
    let old_token = current_auth_token(state);
    let old_token_hash = sha256(old_token.as_bytes()).to_hex_prefixed();
    let new_token = rotate_local_api_token_for_response().map_err(internal_error)?;
    {
        let mut guard = state
            .auth_token
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = new_token;
    }
    {
        let mut previous = state
            .previous_auth_token
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *previous = None;
    }
    Ok(old_token_hash)
}

fn rotate_local_api_token_for_response() -> anyhow::Result<String> {
    #[cfg(test)]
    {
        Ok(format!("clawdstrike-test-{}", uuid::Uuid::new_v4()))
    }
    #[cfg(not(test))]
    {
        rotate_local_api_token()
    }
}

pub(super) fn auth_token_matches(candidate: &str, state: &AgentApiState) -> bool {
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

pub(super) fn auth_token_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let Some((name, value)) = cookie.trim().split_once('=') else {
            continue;
        };
        if name.trim() == AGENT_AUTH_COOKIE_NAME {
            let token = value.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
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

pub(super) async fn rotate_local_api_token_route(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<RotateLocalApiTokenResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let grace_secs = rotate_local_api_token_with_grace(&state)?;

    Ok(Json(RotateLocalApiTokenResponse {
        rotated: true,
        previous_token_valid_for_seconds: grace_secs,
    }))
}

pub(super) async fn token_rotation_loop(
    state: Arc<AgentApiState>,
    shutdown_rx: &mut broadcast::Receiver<()>,
) {
    loop {
        let interval_hours = {
            let settings = state.settings.read().await;
            settings
                .local_api_security
                .token_rotation_interval_hours
                .max(1)
        };
        let sleep_for = Duration::from_secs(u64::from(interval_hours) * 60 * 60);
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::debug!("Local API token rotation loop shutting down");
                break;
            }
            _ = tokio::time::sleep(sleep_for) => {}
        }

        match rotate_local_api_token_with_grace(&state) {
            Ok(grace_secs) => {
                tracing::info!(grace_secs, "Rotated local API auth token on schedule");
            }
            Err((status, err)) => {
                tracing::warn!(
                    status = %status,
                    error = %err,
                    "Scheduled local API token rotation failed"
                );
            }
        }
    }
}

