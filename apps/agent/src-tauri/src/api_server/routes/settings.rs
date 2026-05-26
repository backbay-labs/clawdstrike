//! Agent settings core handlers: get/update, runtime registration, and shared validators.
//!
//! Integration- and OTA-specific handlers live in sibling files
//! (`integrations.rs`, `ota.rs`); the `agent_policy_check` route lives in
//! `policy_check.rs`. DTOs are in `settings_dto.rs`.

use super::super::*;
use crate::runtime_registry::{
    register_runtime_agent, resolve_effective_endpoint_agent_id, RuntimeRegistrationInput,
};
use crate::settings::RuntimeAgentRegistration;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use std::path::PathBuf;
use std::sync::Arc;

pub(crate) fn bounded_u32_setting(
    field: &str,
    value: u32,
    min: u32,
    max: u32,
) -> Result<u32, (StatusCode, String)> {
    if (min..=max).contains(&value) {
        return Ok(value);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be between {min} and {max}"),
    ))
}

pub(crate) fn bounded_u16_setting(
    field: &str,
    value: u16,
    min: u16,
    max: u16,
) -> Result<u16, (StatusCode, String)> {
    if (min..=max).contains(&value) {
        return Ok(value);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be between {min} and {max}"),
    ))
}

pub(crate) fn normalize_settings_url(
    field: &str,
    value: &str,
    allow_non_loopback_http: bool,
) -> Result<String, (StatusCode, String)> {
    let trimmed = value.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must not be empty"),
        ));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("{field} must be a valid URL: {err}"),
        )
    })?;
    if parsed.host_str().is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must include a host"),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{field} must not contain userinfo"),
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if allow_non_loopback_http || control_api_url_is_loopback(&parsed) => {}
        "http" => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("{field} may use http only for loopback hosts"),
            ));
        }
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("{field} must use http or https, got {other}"),
            ));
        }
    }
    Ok(trimmed.to_string())
}

pub(crate) fn normalize_notification_severity_setting(
    value: &str,
) -> Result<String, (StatusCode, String)> {
    match value.trim().to_ascii_lowercase().as_str() {
        "info" | "allow" | "allowed" => Ok("info".to_string()),
        "warn" | "warning" | "medium" => Ok("warn".to_string()),
        "block" | "blocked" | "high" | "critical" => Ok("block".to_string()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "notification_severity must be one of info, warn, or block".to_string(),
        )),
    }
}

pub(crate) fn normalize_ota_mode_setting(value: &str) -> Result<String, (StatusCode, String)> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok("auto".to_string()),
        "manual" => Ok("manual".to_string()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "ota_mode must be one of auto or manual".to_string(),
        )),
    }
}

pub(crate) fn normalize_ota_channel_setting(value: &str) -> Result<String, (StatusCode, String)> {
    match value.trim().to_ascii_lowercase().as_str() {
        "stable" => Ok("stable".to_string()),
        "beta" => Ok("beta".to_string()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "ota_channel must be one of stable or beta".to_string(),
        )),
    }
}

pub(crate) async fn get_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<AgentSettingsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings = state.settings.read().await;

    Ok(Json(AgentSettingsResponse {
        daemon_port: settings.daemon_port,
        mcp_port: settings.mcp_port,
        agent_api_port: settings.agent_api_port,
        enabled: settings.enabled,
        auto_start: settings.auto_start,
        notifications_enabled: settings.notifications_enabled,
        notification_severity: settings.notification_severity.clone(),
        dashboard_url: settings.dashboard_url.clone(),
        debug_include_daemon_error_body: settings.debug_include_daemon_error_body,
        openclaw_active_gateway_id: settings.openclaw.active_gateway_id.clone(),
        ota_enabled: settings.ota_enabled,
        ota_mode: settings.ota_mode.clone(),
        ota_channel: settings.ota_channel.clone(),
        ota_manifest_url: settings.ota_manifest_url.clone(),
        ota_allow_fallback_to_default: settings.ota_allow_fallback_to_default,
        ota_check_interval_minutes: settings.ota_check_interval_minutes,
        ota_pinned_public_keys: settings.ota_pinned_public_keys.clone(),
        ota_last_check_at: settings.ota_last_check_at.clone(),
        ota_last_result: settings.ota_last_result.clone(),
        ota_current_hushd_version: settings.ota_current_hushd_version.clone(),
        control_api: ControlApiSettingsResponse {
            enabled: settings.control_api.enabled,
            url: settings.control_api.url.clone(),
            api_key_configured: settings
                .control_api
                .api_key
                .as_deref()
                .map(str::trim)
                .is_some_and(|value| !value.is_empty()),
        },
        local_api_security: LocalApiSecurityResponse {
            token_rotation_interval_hours: settings
                .local_api_security
                .token_rotation_interval_hours,
            token_grace_minutes: settings.local_api_security.token_grace_minutes,
            mtls_enabled: settings.local_api_security.mtls_enabled,
            mtls_port: settings.local_api_security.mtls_port,
            mtls_server_cert_path: settings
                .local_api_security
                .mtls_server_cert_path
                .as_ref()
                .map(|path| path.display().to_string()),
            mtls_server_key_path: settings
                .local_api_security
                .mtls_server_key_path
                .as_ref()
                .map(|path| path.display().to_string()),
            mtls_client_ca_path: settings
                .local_api_security
                .mtls_client_ca_path
                .as_ref()
                .map(|path| path.display().to_string()),
        },
    }))
}

pub(crate) async fn list_runtime_agents(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<Vec<RuntimeAgentRegistration>>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let mut runtimes = {
        let settings = state.settings.read().await;
        settings.runtime_registry.runtimes.clone()
    };
    runtimes.sort_by(|a, b| b.last_seen_at.cmp(&a.last_seen_at));
    Ok(Json(runtimes))
}

pub(crate) async fn register_runtime_agent_route(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<RuntimeRegisterInput>,
) -> Result<Json<RuntimeRegisterResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    if input.runtime_agent_kind.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "runtime_agent_kind must be a non-empty string".to_string(),
        ));
    }

    let registration = {
        let mut settings = state.settings.write().await;
        let endpoint_agent_id =
            resolve_effective_endpoint_agent_id(&mut settings, input.endpoint_agent_id.as_deref());
        let registration = register_runtime_agent(
            &mut settings,
            RuntimeRegistrationInput {
                endpoint_agent_id,
                runtime_agent_kind: input.runtime_agent_kind.clone(),
                external_runtime_id: input.runtime_agent_id.clone(),
                display_name: input.display_name,
                metadata: input.metadata,
            },
        );
        settings
            .save()
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        registration
    };

    Ok(Json(RuntimeRegisterResponse {
        endpoint_agent_id: registration.endpoint_agent_id,
        runtime_agent_id: registration.runtime_agent_id,
        runtime_agent_kind: registration.runtime_agent_kind,
        external_runtime_id: registration.external_runtime_id,
        first_seen_at: registration.first_seen_at,
        last_seen_at: registration.last_seen_at,
    }))
}

pub(crate) async fn update_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<AgentSettingsUpdate>,
) -> Result<Json<AgentSettingsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    {
        let mut settings = state.settings.write().await;
        let mut next_settings = settings.clone();

        if let Some(value) = input.enabled {
            next_settings.enabled = value;
        }
        if let Some(value) = input.auto_start {
            next_settings.auto_start = value;
        }
        if let Some(value) = input.notifications_enabled {
            next_settings.notifications_enabled = value;
        }
        if let Some(value) = input.notification_severity {
            next_settings.notification_severity = normalize_notification_severity_setting(&value)?;
        }
        if let Some(value) = input.dashboard_url {
            next_settings.dashboard_url = normalize_settings_url("dashboard_url", &value, true)?;
        }
        if let Some(value) = input.debug_include_daemon_error_body {
            next_settings.debug_include_daemon_error_body = value;
        }
        if let Some(value) = input.ota_enabled {
            next_settings.ota_enabled = value;
        }
        if let Some(value) = input.ota_mode {
            next_settings.ota_mode = normalize_ota_mode_setting(&value)?;
        }
        if let Some(value) = input.ota_channel {
            next_settings.ota_channel = normalize_ota_channel_setting(&value)?;
        }
        if let Some(value) = input.ota_manifest_url {
            next_settings.ota_manifest_url = value
                .as_deref()
                .map(|url| normalize_settings_url("ota_manifest_url", url, false))
                .transpose()?;
        }
        if let Some(value) = input.ota_allow_fallback_to_default {
            next_settings.ota_allow_fallback_to_default = value;
        }
        if let Some(value) = input.ota_check_interval_minutes {
            next_settings.ota_check_interval_minutes = bounded_u32_setting(
                "ota_check_interval_minutes",
                value,
                OTA_CHECK_INTERVAL_MIN_MINUTES,
                OTA_CHECK_INTERVAL_MAX_MINUTES,
            )?;
        }
        if let Some(value) = input.ota_pinned_public_keys {
            next_settings.ota_pinned_public_keys = value;
        }
        if let Some(value) = input.ota_last_check_at {
            next_settings.ota_last_check_at = value;
        }
        if let Some(value) = input.ota_last_result {
            next_settings.ota_last_result = value;
        }
        if let Some(value) = input.ota_current_hushd_version {
            next_settings.ota_current_hushd_version = value;
        }
        if let Some(control_api) = input.control_api {
            if let Some(value) = control_api.enabled {
                next_settings.control_api.enabled = value;
            }
            if let Some(value) = control_api.url {
                next_settings.control_api.url = value
                    .as_deref()
                    .map(|url| normalize_settings_url("control_api.url", url, false))
                    .transpose()?;
            }
            if let Some(value) = control_api.api_key {
                next_settings.control_api.api_key = value
                    .map(|api_key| api_key.trim().to_string())
                    .filter(|api_key| !api_key.is_empty());
            }
        }
        if let Some(value) = input.openclaw_active_gateway_id {
            next_settings.openclaw.active_gateway_id = value;
        }
        if let Some(local_api_security) = input.local_api_security {
            if let Some(value) = local_api_security.token_rotation_interval_hours {
                next_settings
                    .local_api_security
                    .token_rotation_interval_hours = bounded_u32_setting(
                    "local_api_security.token_rotation_interval_hours",
                    value,
                    LOCAL_API_TOKEN_ROTATION_MIN_HOURS,
                    LOCAL_API_TOKEN_ROTATION_MAX_HOURS,
                )?;
            }
            if let Some(value) = local_api_security.token_grace_minutes {
                next_settings.local_api_security.token_grace_minutes = bounded_u32_setting(
                    "local_api_security.token_grace_minutes",
                    value,
                    LOCAL_API_TOKEN_GRACE_MIN_MINUTES,
                    LOCAL_API_TOKEN_GRACE_MAX_MINUTES,
                )?;
            }
            if let Some(value) = local_api_security.mtls_enabled {
                next_settings.local_api_security.mtls_enabled = value;
            }
            if let Some(value) = local_api_security.mtls_port {
                next_settings.local_api_security.mtls_port = bounded_u16_setting(
                    "local_api_security.mtls_port",
                    value,
                    LOCAL_API_MTLS_MIN_PORT,
                    u16::MAX,
                )?;
            }
            if let Some(value) = local_api_security.mtls_server_cert_path {
                next_settings.local_api_security.mtls_server_cert_path = value
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty())
                    .map(PathBuf::from);
            }
            if let Some(value) = local_api_security.mtls_server_key_path {
                next_settings.local_api_security.mtls_server_key_path = value
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty())
                    .map(PathBuf::from);
            }
            if let Some(value) = local_api_security.mtls_client_ca_path {
                next_settings.local_api_security.mtls_client_ca_path = value
                    .as_deref()
                    .map(str::trim)
                    .filter(|raw| !raw.is_empty())
                    .map(PathBuf::from);
            }

            if next_settings.local_api_security.mtls_enabled {
                let cert = next_settings
                    .local_api_security
                    .mtls_server_cert_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                let key = next_settings
                    .local_api_security
                    .mtls_server_key_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                let ca = next_settings
                    .local_api_security
                    .mtls_client_ca_path
                    .as_ref()
                    .is_some_and(|path| path.is_file());
                if !(cert && key && ca) {
                    return Err((
                        StatusCode::BAD_REQUEST,
                        "mTLS enabled requires valid cert/key/CA file paths".to_string(),
                    ));
                }
            }
        }

        require_enrolled_edr_receipt_signer_for_settings(
            &state,
            &next_settings,
            "settings update enabling cloud/control EDR mode",
        )
        .await?;

        next_settings
            .save()
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

        let token_grace_minutes = next_settings.local_api_security.token_grace_minutes.max(1);
        *settings = next_settings;
        set_token_grace_minutes(&state, token_grace_minutes);
    }

    get_settings(State(state), headers).await
}
