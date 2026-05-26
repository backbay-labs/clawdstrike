//! Agent health and drift endpoints.

use super::super::*;
use crate::macos::status::{
    CombinedSystemExtensionStatus, ProviderRuntimeState, SystemExtensionApproval,
    SystemExtensionInstallState,
};
use crate::settings::Settings;
use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use std::sync::Arc;

pub(crate) async fn fetch_daemon_policy_version(state: &AgentApiState) -> Option<String> {
    let (daemon_url, daemon_api_key) = {
        let settings = state.settings.read().await;
        (settings.daemon_url(), settings.api_key.clone())
    };

    let url = format!("{}/api/v1/policy", daemon_url.trim_end_matches('/'));
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

    let json = response.json::<serde_json::Value>().await.ok()?;
    json.get("version")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
}

pub(crate) async fn cached_policy_version_for_health(state: &Arc<AgentApiState>) -> Option<String> {
    let (cached_value, should_refresh) = {
        let mut cache = state.policy_version_cache.write().await;
        let should_refresh = cache.mark_refresh_started_if_due(std::time::Instant::now());
        (cache.value.clone(), should_refresh)
    };

    if should_refresh {
        let state = state.clone();
        tokio::spawn(async move {
            let fetched = tokio::time::timeout(
                POLICY_VERSION_FETCH_TIMEOUT,
                fetch_daemon_policy_version(state.as_ref()),
            )
            .await
            .ok()
            .flatten();

            let mut cache = state.policy_version_cache.write().await;
            cache.finish_refresh(fetched, std::time::Instant::now());
        });
    }

    cached_value
}

pub(crate) fn macos_host_health_status(status: &CombinedSystemExtensionStatus) -> &'static str {
    let endpoint_active = matches!(
        status.endpoint_security.runtime,
        ProviderRuntimeState::Active
    );
    let network_active = matches!(
        status.network_extension.runtime,
        ProviderRuntimeState::Active
    );
    let endpoint_unknown = matches!(
        status.endpoint_security.runtime,
        ProviderRuntimeState::Unknown
    );
    let network_unknown = matches!(
        status.network_extension.runtime,
        ProviderRuntimeState::Unknown
    );
    let endpoint_inactive = matches!(
        status.endpoint_security.runtime,
        ProviderRuntimeState::Inactive
    );
    let network_inactive = matches!(
        status.network_extension.runtime,
        ProviderRuntimeState::Inactive
    );
    let endpoint_degraded = matches!(
        status.endpoint_security.runtime,
        ProviderRuntimeState::Degraded { .. }
    );
    let network_degraded = matches!(
        status.network_extension.runtime,
        ProviderRuntimeState::Degraded { .. }
    );

    if status.install_state == SystemExtensionInstallState::NotInstalled
        || status.approval == SystemExtensionApproval::ApprovalBlocked
        || endpoint_degraded
        || network_degraded
    {
        "degraded"
    } else if status.install_state == SystemExtensionInstallState::Unknown
        || status.approval == SystemExtensionApproval::Unknown
        || endpoint_unknown
        || network_unknown
        || endpoint_inactive
        || network_inactive
    {
        "pending"
    } else if status.install_state == SystemExtensionInstallState::Installed
        && status.approval == SystemExtensionApproval::Approved
        && endpoint_active
        && network_active
    {
        "ok"
    } else {
        "degraded"
    }
}

pub(crate) fn agent_health_status(status: &CombinedSystemExtensionStatus) -> &'static str {
    if cfg!(target_os = "macos") {
        macos_host_health_status(status)
    } else {
        let _ = status;
        "ok"
    }
}

pub(crate) async fn edr_health_summary(state: &Arc<AgentApiState>) -> EdrHealthSummary {
    let recorder = state.edr_flight_recorder.lock().await;
    let graph = recorder.graph().clone();
    let recent_finding_count = state.edr_recent_findings.lock().await.len();
    EdrHealthSummary {
        observation_count: recorder.observation_count(),
        graph_node_count: graph.nodes.len(),
        graph_edge_count: graph.edges.len(),
        recent_finding_count,
    }
}

pub(crate) fn resolve_endpoint_agent_id_for_health(settings: &Settings) -> String {
    settings
        .nats
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            settings
                .enrollment
                .agent_uuid
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
        })
        .or_else(|| {
            settings
                .local_agent_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| format!("endpoint-{}", crate::settings::hostname_best_effort()))
}

pub(crate) async fn fetch_daemon_endpoint_status_for_health(
    state: &Arc<AgentApiState>,
    settings: &Settings,
    endpoint_agent_id: &str,
    expected_policy_version: Option<&str>,
    expected_daemon_version: Option<&str>,
) -> Option<DaemonEndpointStatus> {
    let mut url =
        reqwest::Url::parse(&format!("{}/api/v1/agents/status", settings.daemon_url())).ok()?;
    {
        let mut query = url.query_pairs_mut();
        query.append_pair("endpoint_agent_id", endpoint_agent_id);
        query.append_pair("limit", "1");
        query.append_pair("include_stale", "true");
        if let Some(policy_version) = expected_policy_version {
            query.append_pair("expected_policy_version", policy_version);
        }
        if let Some(daemon_version) = expected_daemon_version {
            query.append_pair("expected_daemon_version", daemon_version);
        }
    }

    let mut request = state.http_client.get(url);
    if let Some(api_key) = settings
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {}", api_key));
    }

    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    let payload = response.json::<DaemonAgentStatusResponse>().await.ok()?;
    payload.endpoints.into_iter().next()
}

pub(crate) async fn agent_health(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<AgentHealthResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let settings_snapshot = state.settings.read().await.clone();
    let endpoint_agent_id = resolve_endpoint_agent_id_for_health(&settings_snapshot);
    let daemon = state.daemon_manager.status().await;
    let session = state.session_manager.state().await;
    let openclaw = state.openclaw.list_gateways().await;
    let runtime_agents = settings_snapshot.runtime_registry.runtimes.len();
    let last_policy_version = cached_policy_version_for_health(&state).await;
    let macos_host = state.macos_host.snapshot().await;
    let edr = edr_health_summary(&state).await;
    let daemon_status = fetch_daemon_endpoint_status_for_health(
        &state,
        &settings_snapshot,
        &endpoint_agent_id,
        last_policy_version.as_deref(),
        daemon.version.as_deref(),
    )
    .await;
    let (last_heartbeat_at, heartbeat_age_secs, endpoint_online, policy_drift, daemon_drift, stale) =
        if let Some(status) = daemon_status {
            (
                status.last_heartbeat_at,
                status.seconds_since_heartbeat,
                status.online,
                status.drift.as_ref().and_then(|value| value.policy_drift),
                status.drift.as_ref().and_then(|value| value.daemon_drift),
                status.drift.as_ref().and_then(|value| value.stale),
            )
        } else {
            (None, None, None, None, None, None)
        };

    Ok(Json(AgentHealthResponse {
        status: agent_health_status(&macos_host),
        daemon,
        session,
        macos_host,
        edr,
        openclaw: serde_json::to_value(openclaw)
            .unwrap_or_else(|_| serde_json::json!({"error":"serialize_failed"})),
        runtime_agents,
        last_policy_version,
        endpoint_agent_id,
        last_heartbeat_at,
        heartbeat_age_secs,
        endpoint_online,
        policy_drift,
        daemon_drift,
        stale,
        version: env!("CARGO_PKG_VERSION"),
    }))
}
