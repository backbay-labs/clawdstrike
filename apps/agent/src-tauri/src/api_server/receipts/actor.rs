//! Endpoint identity and response actor helpers — derive an
//! `EndpointDecisionActor` from session state, observations, or a
//! request-supplied actor input.

use super::super::*;

pub(crate) fn endpoint_id_for_observation(
    settings: &Settings,
    observation: &EndpointObservation,
) -> String {
    settings
        .enrollment
        .agent_uuid
        .clone()
        .or_else(|| settings.local_agent_id.clone())
        .or_else(|| observation.host_id.clone())
        .unwrap_or_else(crate::settings::hostname_best_effort)
}

pub(crate) fn endpoint_id_for_settings(settings: &Settings) -> String {
    settings
        .enrollment
        .agent_uuid
        .clone()
        .or_else(|| settings.local_agent_id.clone())
        .unwrap_or_else(crate::settings::hostname_best_effort)
}

pub(crate) fn endpoint_response_actor_from_session(
    settings: &Settings,
    session_state: &SessionState,
    agent_id: &str,
) -> EndpointDecisionActor {
    EndpointDecisionActor {
        endpoint_id: endpoint_id_for_settings(settings),
        session_id: session_state.session_id.clone(),
        posture: Some(session_state.posture.clone()),
        agent_id: Some(agent_id.to_string()),
        workload_id: Some("endpoint-response-engine".to_string()),
        ..EndpointDecisionActor::default()
    }
}

pub(crate) fn endpoint_response_actor_from_action_input(
    settings: &Settings,
    session_state: &SessionState,
    agent_id: &str,
    input: Option<&EdrResponseActionActorInput>,
) -> EndpointDecisionActor {
    let mut actor = endpoint_response_actor_from_session(settings, session_state, agent_id);
    let Some(input) = input else {
        return actor;
    };

    if let Some(endpoint_id) = trimmed_owned(Some(input.endpoint_id.as_str())) {
        actor.endpoint_id = endpoint_id;
    }
    if let Some(host_id) = trimmed_owned(input.host_id.as_deref()) {
        actor.host_id = Some(host_id);
    }
    if let Some(user_id) = trimmed_owned(input.user_id.as_deref()) {
        actor.user_id = Some(user_id);
    }
    if let Some(session_id) = trimmed_owned(input.session_id.as_deref()) {
        actor.session_id = Some(session_id);
    }
    if let Some(posture) = trimmed_owned(input.posture.as_deref()) {
        actor.posture = Some(posture);
    }
    if let Some(agent_id) = trimmed_owned(input.agent_id.as_deref()) {
        actor.agent_id = Some(agent_id);
    }
    if let Some(workload_id) = trimmed_owned(input.workload_id.as_deref()) {
        actor.workload_id = Some(workload_id);
    }
    if let Some(approval_id) = trimmed_owned(input.approval_id.as_deref()) {
        actor.approval_id = Some(approval_id);
    }
    actor
}
