//! Diagnostics bundle endpoint.
//!
//! Writes a redacted diagnostics zip-equivalent (file tree) to the agent config dir
//! and returns the resulting path so an operator can copy it off-host.

use super::super::*;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use std::sync::Arc;

pub(crate) async fn write_diagnostics_bundle(
    state: Arc<AgentApiState>,
    input: DiagnosticsBundleInput,
) -> Result<DiagnosticsBundleResponse, (StatusCode, String)> {
    let include_logs = input.include_logs.unwrap_or(true);
    let log_lines = input.log_lines.unwrap_or(500).clamp(10, 5000);
    let settings_snapshot = state.settings.read().await.clone();
    let daemon_status = state.daemon_manager.status().await;
    let session_state = state.session_manager.state().await;
    let audit_queue_depth = state.audit_queue.len().await;
    let pending_approvals = state.approval_queue.pending_count().await;
    let last_policy_version = cached_policy_version_for_health(&state).await;
    let runtime_agents = settings_snapshot.runtime_registry.runtimes.clone();

    let mut settings_json = serde_json::to_value(&settings_snapshot)
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    redact_settings_json(&mut settings_json);

    let daemon_url = settings_snapshot.daemon_url();
    let mut health_request = state.http_client.get(format!("{}/health", daemon_url));
    if let Some(api_key) = settings_snapshot
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        health_request =
            health_request.header(AUTHORIZATION.as_str(), format!("Bearer {}", api_key));
    }
    let daemon_health = match health_request.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response.text().await.unwrap_or_default();
            serde_json::json!({
                "reachable": status < 500,
                "status_code": status,
                "body_preview": trim_tail_lines(&body, 20),
            })
        }
        Err(err) => serde_json::json!({
            "reachable": false,
            "error": err.to_string(),
        }),
    };

    let diagnostics_root = crate::settings::get_config_dir().join("diagnostics");
    let generated_at = chrono::Utc::now();
    let bundle_dir =
        diagnostics_root.join(format!("bundle-{}", generated_at.format("%Y%m%dT%H%M%SZ")));
    let bundle_dir_for_write = bundle_dir.clone();
    let manifest = serde_json::json!({
        "generated_at": generated_at.to_rfc3339(),
        "agent_version": env!("CARGO_PKG_VERSION"),
        "bundle_dir": bundle_dir.display().to_string(),
    });
    let connectivity = serde_json::json!({
        "daemon_health": daemon_health,
        "session": {
            "session_id": session_state.session_id,
            "posture": session_state.posture,
        },
    });
    let version_matrix = serde_json::json!({
        "agent_version": env!("CARGO_PKG_VERSION"),
        "daemon_version": daemon_status.version,
        "last_policy_version": last_policy_version,
        "runtime_registry_count": runtime_agents.len(),
    });
    let queue_state = serde_json::json!({
        "audit_outbox_depth": audit_queue_depth,
        "pending_approvals": pending_approvals,
    });

    let agent_log_path = crate::settings::get_config_dir()
        .join("logs")
        .join("agent.log");
    let hushd_log_path = crate::settings::get_config_dir()
        .join("logs")
        .join("hushd.log");
    let agent_log = if include_logs {
        std::fs::read_to_string(&agent_log_path)
            .map(|content| trim_tail_lines(&content, log_lines))
            .unwrap_or_else(|_| "agent.log unavailable".to_string())
    } else {
        "logs omitted by request".to_string()
    };
    let hushd_log = if include_logs {
        std::fs::read_to_string(&hushd_log_path)
            .map(|content| trim_tail_lines(&content, log_lines))
            .unwrap_or_else(|_| "hushd.log unavailable".to_string())
    } else {
        "logs omitted by request".to_string()
    };

    tokio::task::spawn_blocking(move || -> Result<(), (StatusCode, String)> {
        std::fs::create_dir_all(bundle_dir_for_write.join("logs"))
            .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("manifest.json"),
            serde_json::to_vec_pretty(&manifest)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("settings.redacted.json"),
            serde_json::to_vec_pretty(&settings_json)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("runtime_registry.json"),
            serde_json::to_vec_pretty(&runtime_agents)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("connectivity_checks.json"),
            serde_json::to_vec_pretty(&connectivity)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("version_matrix.json"),
            serde_json::to_vec_pretty(&version_matrix)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("queue_state.json"),
            serde_json::to_vec_pretty(&queue_state)
                .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("logs").join("agent.tail.log"),
            agent_log,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        std::fs::write(
            bundle_dir_for_write.join("logs").join("hushd.tail.log"),
            hushd_log,
        )
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
        Ok(())
    })
    .await
    .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))??;

    Ok(DiagnosticsBundleResponse {
        bundle_path: bundle_dir.display().to_string(),
        generated_at: generated_at.to_rfc3339(),
    })
}

pub(crate) async fn create_diagnostics_bundle(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    payload: Option<Json<DiagnosticsBundleInput>>,
) -> Result<Json<DiagnosticsBundleResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let input = payload.map(|value| value.0).unwrap_or_default();
    let response = write_diagnostics_bundle(state, input).await?;
    Ok(Json(response))
}
