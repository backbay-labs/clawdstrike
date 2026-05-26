//! Integrations (SIEM + webhook) settings handlers + test-delivery endpoint.

use super::super::*;
use crate::settings::IntegrationSettings;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub(crate) fn normalize_integration_settings(settings: &mut IntegrationSettings) {
    settings.siem.provider = settings.siem.provider.trim().to_ascii_lowercase();
    if settings.siem.provider.is_empty() {
        settings.siem.provider = "datadog".to_string();
    }
    settings.siem.endpoint = settings.siem.endpoint.trim().to_string();
    settings.siem.api_key = settings.siem.api_key.trim().to_string();
    settings.webhooks.url = settings.webhooks.url.trim().to_string();
    settings.webhooks.secret = settings.webhooks.secret.trim().to_string();

    if settings.siem.endpoint.is_empty() && settings.siem.api_key.is_empty() {
        settings.siem.enabled = false;
    }
    if settings.webhooks.url.is_empty() {
        settings.webhooks.enabled = false;
    }
}

pub(crate) fn validate_integration_settings(
    settings: &IntegrationSettings,
) -> std::result::Result<(), String> {
    let provider = settings.siem.provider.as_str();
    let provider_supported = matches!(
        provider,
        "datadog" | "splunk" | "elastic" | "sumo_logic" | "custom"
    );
    if !provider_supported {
        return Err(format!(
            "Unsupported SIEM provider '{}'",
            settings.siem.provider
        ));
    }

    if settings.siem.enabled {
        if settings.siem.endpoint.is_empty() {
            return Err("SIEM endpoint is required when SIEM is enabled".to_string());
        }
        let key_required = matches!(provider, "datadog" | "splunk" | "elastic");
        if key_required && settings.siem.api_key.is_empty() {
            return Err(format!(
                "SIEM API key is required for provider '{}'",
                settings.siem.provider
            ));
        }
    }

    if settings.webhooks.enabled && settings.webhooks.url.is_empty() {
        return Err("Webhook URL is required when webhook forwarding is enabled".to_string());
    }

    Ok(())
}

pub(crate) async fn fetch_daemon_exporter_status(state: &AgentApiState) -> Option<Value> {
    let (daemon_url, daemon_api_key) = {
        let settings = state.settings.read().await;
        (settings.daemon_url(), settings.api_key.clone())
    };

    let url = format!("{}/api/v1/siem/exporters", daemon_url.trim_end_matches('/'));
    let mut request = state.http_client.get(url);

    if let Some(key) = daemon_api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", key));
    }

    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    response.json::<Value>().await.ok()
}

pub(crate) async fn get_integrations_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<IntegrationSettings>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings = state.settings.read().await;
    Ok(Json(settings.integrations.clone()))
}

pub(crate) async fn update_integrations_settings(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<IntegrationsSettingsUpdateInput>,
) -> Result<Json<IntegrationsApplyResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    {
        let mut settings = state.settings.write().await;
        let mut next_integrations = settings.integrations.clone();

        if let Some(siem) = input.siem {
            if let Some(value) = siem.provider {
                next_integrations.siem.provider = value;
            }
            if let Some(value) = siem.endpoint {
                next_integrations.siem.endpoint = value;
            }
            if let Some(value) = siem.api_key {
                next_integrations.siem.api_key = value;
            }
            if let Some(value) = siem.enabled {
                next_integrations.siem.enabled = value;
            }
        }

        if let Some(webhooks) = input.webhooks {
            if let Some(value) = webhooks.url {
                next_integrations.webhooks.url = value;
            }
            if let Some(value) = webhooks.secret {
                next_integrations.webhooks.secret = value;
            }
            if let Some(value) = webhooks.enabled {
                next_integrations.webhooks.enabled = value;
            }
        }

        normalize_integration_settings(&mut next_integrations);
        validate_integration_settings(&next_integrations)
            .map_err(|err| (StatusCode::BAD_REQUEST, err))?;
        settings.integrations = next_integrations;

        settings
            .save()
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    }

    let mut restarted = false;
    let mut warning = None;

    if input.apply {
        state
            .daemon_manager
            .restart()
            .await
            .map_err(internal_error)?;
        restarted = true;
    }

    let daemon = state.daemon_manager.status().await;
    let exporter_status = fetch_daemon_exporter_status(&state).await;
    let integrations = {
        let settings = state.settings.read().await;
        settings.integrations.clone()
    };
    if input.apply {
        if exporter_status.is_none() {
            warning = Some("hushd restarted but exporter status could not be fetched".to_string());
        } else {
            let export_enabled = exporter_status
                .as_ref()
                .and_then(|v| v.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let exporter_count = exporter_status
                .as_ref()
                .and_then(|v| v.get("exporters"))
                .and_then(|v| v.as_array())
                .map(|v| v.len())
                .unwrap_or(0);

            let expected_exporters = integrations.siem.enabled || integrations.webhooks.enabled;
            if expected_exporters && (!export_enabled || exporter_count == 0) {
                warning = Some(
                    "Integration settings were saved, but hushd reports no active exporters after restart."
                        .to_string(),
                );
            }
        }
    }

    Ok(Json(IntegrationsApplyResponse {
        integrations,
        restarted,
        daemon,
        exporter_status,
        warning,
    }))
}

pub(crate) async fn test_integration_delivery(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<IntegrationTestInput>,
) -> Result<Json<IntegrationTestResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;

    let target = input.target.trim().to_ascii_lowercase();
    let max_retries = input.max_retries.unwrap_or(2).min(5);

    let (endpoint, enabled, provider, siem_api_key, webhook_secret, agent_id) = {
        let settings = state.settings.read().await;
        let integrations = &settings.integrations;
        let endpoint_agent_id = settings
            .local_agent_id
            .clone()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "unknown-agent".to_string());

        match target.as_str() {
            "siem" => (
                integrations.siem.endpoint.clone(),
                integrations.siem.enabled,
                integrations.siem.provider.clone(),
                integrations.siem.api_key.clone(),
                String::new(),
                endpoint_agent_id,
            ),
            "webhook" | "webhooks" => (
                integrations.webhooks.url.clone(),
                integrations.webhooks.enabled,
                "webhook".to_string(),
                String::new(),
                integrations.webhooks.secret.clone(),
                endpoint_agent_id,
            ),
            other => {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("unsupported test target '{}'", other),
                ))
            }
        }
    };

    if !enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{} delivery is disabled", target),
        ));
    }

    if endpoint.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("{} endpoint is empty", target),
        ));
    }

    let normalized_endpoint = endpoint.trim().to_string();
    let payload = serde_json::json!({
        "event_type": "integration_test_delivery",
        "target": target,
        "provider": provider,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "endpoint_agent_id": agent_id,
        "message": "ClawdStrike integration delivery test event"
    });
    let payload_bytes = serde_json::to_vec(&payload).map_err(|err| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("failed to serialize test payload: {err}"),
        )
    })?;

    let started_at = Instant::now();
    let tested_at = chrono::Utc::now().to_rfc3339();
    let mut attempts: u8 = 0;
    let mut status_code: Option<u16> = None;
    let mut last_error: Option<String> = None;
    let mut delivered = false;

    for attempt in 0..=max_retries {
        attempts = attempt + 1;

        let mut request = state
            .http_client
            .post(normalized_endpoint.clone())
            .header(CONTENT_TYPE, "application/json")
            .header("x-clawdstrike-test-delivery", "1")
            .body(payload_bytes.clone());

        if target == "siem" && !siem_api_key.is_empty() {
            let auth_header = if provider.trim().eq_ignore_ascii_case("splunk") {
                format!("Splunk {}", siem_api_key)
            } else {
                format!("Bearer {}", siem_api_key)
            };
            request = request
                .header(AUTHORIZATION, auth_header)
                .header("dd-api-key", siem_api_key.clone());
        }

        if target.starts_with("webhook") && !webhook_secret.is_empty() {
            request = request
                .header("x-clawdstrike-secret-configured", "true")
                .header("x-clawdstrike-signature-scheme", "hmac-sha256");
        }

        match request.send().await {
            Ok(response) => {
                let status = response.status();
                status_code = Some(status.as_u16());
                if status.is_success() {
                    delivered = true;
                    last_error = None;
                    break;
                }
                let body = response.text().await.unwrap_or_default();
                let reason = if body.trim().is_empty() {
                    format!("HTTP {}", status.as_u16())
                } else {
                    format!("HTTP {}: {}", status.as_u16(), body.trim())
                };
                last_error = Some(truncate_delivery_error(&reason));
            }
            Err(err) => {
                last_error = Some(truncate_delivery_error(&err.to_string()));
            }
        }

        if attempt < max_retries {
            let backoff_ms = 250u64.saturating_mul((attempt + 1) as u64);
            tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        }
    }

    let elapsed_ms_u128 = started_at.elapsed().as_millis();
    let latency_ms = elapsed_ms_u128.min(u128::from(u64::MAX)) as u64;

    Ok(Json(IntegrationTestResponse {
        target: if target == "webhooks" {
            "webhook".to_string()
        } else {
            target
        },
        endpoint: normalized_endpoint,
        delivered,
        status_code,
        attempts,
        retry_count: attempts.saturating_sub(1),
        latency_ms,
        last_error,
        tested_at,
    }))
}
