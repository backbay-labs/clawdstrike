//! Host-level event handlers: macOS EndpointSecurity, NetworkExtension,
//! generic policy events, and agent secret-touch queries.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::State;
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_endpoint_security_events(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrEndpointSecurityEventsInput>,
) -> Result<Json<EdrEndpointSecurityEventsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(input.events.len(), input.honey_artifacts.len())?;
    let mut observations = Vec::with_capacity(input.events.len());
    for (index, event) in input.events.iter().enumerate() {
        observations.push(endpoint_security_event_observation(event, index)?);
        if let Some(credential_observation) =
            endpoint_security_auth_open_credential_observation(event, index)?
        {
            observations.push(credential_observation);
        }
    }
    let recorded_observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &recorded_observations,
        input.honey_artifacts,
    )
    .await?;
    let observation_receipts = emit_edr_provider_observation_receipts(
        &state,
        &recorded_observations,
        "endpoint_security_observation",
    )
    .await
    .map_err(internal_error)?;
    let policy_decision_receipts = emit_edr_provider_policy_decision_receipts(
        &state,
        &recorded_observations,
        "endpoint_security_policy_decision",
    )
    .await
    .map_err(internal_error)?;
    let degraded_provider_receipts = if let Some(sensor_state) =
        endpoint_security_event_loss_sensor_state(&input.events)
    {
        let settings = state.settings.read().await.clone();
        let policy = endpoint_policy_snapshot_from_settings(&settings).map_err(internal_error)?;
        emit_edr_provider_degradation_receipts(state.as_ref(), policy, sensor_state)
            .await
            .map_err(internal_error)?
    } else {
        Vec::new()
    };
    let receipt_count = evaluated.receipts.len()
        + observation_receipts.len()
        + policy_decision_receipts.len()
        + degraded_provider_receipts.len();

    Ok(Json(EdrEndpointSecurityEventsResponse {
        event_count: input.events.len(),
        observation_count: recorded_observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations: recorded_observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
        policy_decision_receipts,
        degraded_provider_receipts,
    }))
}

pub(crate) async fn agent_edr_network_extension_events(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrNetworkExtensionEventsInput>,
) -> Result<Json<EdrNetworkExtensionEventsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(
        input.events.len().saturating_mul(2),
        input.honey_artifacts.len(),
    )?;
    let observations = input
        .events
        .iter()
        .enumerate()
        .map(|(index, event)| network_extension_event_observations(event, index))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let recorded_observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &recorded_observations,
        input.honey_artifacts,
    )
    .await?;
    let observation_receipts = emit_edr_provider_observation_receipts(
        &state,
        &recorded_observations,
        "network_extension_observation",
    )
    .await
    .map_err(internal_error)?;
    let policy_decision_receipts = emit_edr_provider_policy_decision_receipts(
        &state,
        &recorded_observations,
        "network_extension_policy_decision",
    )
    .await
    .map_err(internal_error)?;
    let receipt_count =
        evaluated.receipts.len() + observation_receipts.len() + policy_decision_receipts.len();

    Ok(Json(EdrNetworkExtensionEventsResponse {
        event_count: input.events.len(),
        observation_count: recorded_observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations: recorded_observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
        policy_decision_receipts,
    }))
}

pub(crate) async fn agent_edr_policy_events(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrPolicyEventsInput>,
) -> Result<Json<EdrPolicyEventsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(input.events.len(), input.honey_artifacts.len())?;
    for event in &input.events {
        validate_policy_event_submission(event, None)?;
    }

    let observations = input
        .events
        .iter()
        .map(EndpointObservation::from_policy_event)
        .collect::<Vec<_>>();
    let observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &observations,
        input.honey_artifacts,
    )
    .await?;
    let observation_receipts =
        emit_edr_provider_observation_receipts(&state, &observations, "policy_event_observation")
            .await
            .map_err(internal_error)?;
    let receipt_count = evaluated.receipts.len() + observation_receipts.len();

    Ok(Json(EdrPolicyEventsResponse {
        policy_event_count: input.events.len(),
        observation_count: observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
    }))
}

pub(crate) async fn agent_edr_policy_events_jsonl(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    body: String,
) -> Result<Json<EdrPolicyEventsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let events = parse_policy_event_jsonl(&body)?;
    validate_edr_request_sizes(events.len(), 0)?;

    let observations = events
        .iter()
        .map(EndpointObservation::from_policy_event)
        .collect::<Vec<_>>();
    let observations = redact_endpoint_observations(&observations);
    let evaluated = evaluate_record_and_receipt_edr_observations(
        &state,
        &observations,
        &observations,
        Vec::new(),
    )
    .await?;
    let observation_receipts =
        emit_edr_provider_observation_receipts(&state, &observations, "policy_event_observation")
            .await
            .map_err(internal_error)?;
    let receipt_count = evaluated.receipts.len() + observation_receipts.len();

    Ok(Json(EdrPolicyEventsResponse {
        policy_event_count: events.len(),
        observation_count: observations.len(),
        finding_count: evaluated.findings.len(),
        receipt_count,
        observations,
        findings: evaluated.findings,
        receipts: evaluated.receipts,
        observation_receipts,
    }))
}

pub(crate) async fn agent_edr_agent_secret_touches(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrAgentSecretTouchesInput>,
) -> Result<Json<EdrAgentSecretTouchesResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    collect_agent_secret_touches(state.as_ref(), input)
        .await
        .map(Json)
}

pub(crate) async fn agent_edr_agent_secret_touches_fleet_publish(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrAgentSecretTouchesInput>,
) -> Result<Json<EdrAgentSecretTouchesFleetPublishResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let publish_context = fleet_hunt_publish_context(state.as_ref()).await?;
    let response = collect_agent_secret_touches(state.as_ref(), input).await?;
    let events = publish_agent_secret_touches_to_fleet(&publish_context, &response.touches).await?;

    Ok(Json(EdrAgentSecretTouchesFleetPublishResponse {
        touch_count: response.touch_count,
        published_count: events.len(),
        events,
    }))
}
