use super::*;

pub(crate) async fn replay_policy_events_under_current_policy(
    state: &AgentApiState,
    events: Vec<PolicyEvent>,
    source: &str,
    track_posture: bool,
) -> Result<EdrPolicyEventReplayResponse, (StatusCode, String)> {
    validate_policy_event_replay_events(&events)?;
    let settings = state.settings.read().await.clone();
    let policy_bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for policy event replay {}",
            settings.policy_path.display()
        )
    });
    let policy_bytes = policy_bytes.map_err(internal_error)?;
    let policy = endpoint_policy_snapshot_from_policy_bytes(&policy_bytes, &settings.policy_path)
        .map_err(internal_error)?;
    let replay_policy_yaml = policy_yaml_for_replay(&policy_bytes).map_err(internal_error)?;
    let event_stream_hash =
        canonical_json_hash(&events, "policy event replay event stream").map_err(internal_error)?;
    let result = replay_events(&replay_policy_yaml, &events, track_posture)
        .await
        .map_err(internal_error)?;
    let result_hash =
        canonical_json_hash(&result, "policy event replay result").map_err(internal_error)?;
    let replay = build_policy_event_replay_report(
        policy,
        source,
        events.len(),
        track_posture,
        event_stream_hash,
        result_hash,
        &result,
    );
    let receipt = emit_edr_policy_event_replay_receipt(state, &settings, &replay)
        .await
        .map_err(internal_error)?;

    Ok(EdrPolicyEventReplayResponse {
        replay,
        result,
        receipt,
    })
}

pub(crate) fn validate_policy_event_replay_events(
    events: &[PolicyEvent],
) -> Result<(), (StatusCode, String)> {
    if events.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "at least one PolicyEvent must be provided for replay".to_string(),
        ));
    }
    validate_edr_request_sizes(events.len(), 0)?;
    for event in events {
        validate_policy_event_submission(event, None)?;
    }
    Ok(())
}

pub(crate) fn policy_yaml_for_replay(policy_bytes: &[u8]) -> Result<String> {
    let mut value = serde_yaml::from_slice::<serde_yaml::Value>(policy_bytes)
        .context("parse local policy YAML for policy event replay")?;
    remove_yaml_policy_epoch_metadata(&mut value);
    serde_yaml::to_string(&value).context("serialize replay policy YAML")
}

fn remove_yaml_policy_epoch_metadata(value: &mut serde_yaml::Value) {
    let serde_yaml::Value::Mapping(map) = value else {
        return;
    };
    for key in ["policy_epoch", "policyEpoch", "epoch"] {
        map.remove(serde_yaml::Value::String(key.to_string()));
    }
    for container in ["policy", "metadata", "bundle"] {
        let key = serde_yaml::Value::String(container.to_string());
        let mut empty_after_strip = false;
        if let Some(serde_yaml::Value::Mapping(child)) = map.get_mut(&key) {
            for epoch_key in ["policy_epoch", "policyEpoch", "epoch"] {
                child.remove(serde_yaml::Value::String(epoch_key.to_string()));
            }
            empty_after_strip = child.is_empty();
        }
        if empty_after_strip {
            map.remove(&key);
        }
    }
}

pub(crate) fn canonical_json_hash(value: &impl Serialize, label: &str) -> Result<String> {
    let value = serde_json::to_value(value).with_context(|| format!("serialize {label}"))?;
    let canonical = canonicalize_json(&value).with_context(|| format!("canonicalize {label}"))?;
    Ok(sha256(canonical.as_bytes()).to_hex_prefixed())
}

// build_policy_event_replay_report, build_policy_event_impact_changes,
// build_policy_event_impact_drivers, build_policy_event_impact_report
// moved to crate::edr::policy_events

pub(crate) async fn analyze_policy_event_impact_under_proposed_policy(
    state: &AgentApiState,
    events: Vec<PolicyEvent>,
    source: &str,
    proposed_policy_yaml: String,
    track_posture: bool,
) -> Result<EdrPolicyEventImpactResponse, (StatusCode, String)> {
    validate_policy_event_replay_events(&events)?;
    if proposed_policy_yaml.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "proposedPolicyYaml must be provided".to_string(),
        ));
    }

    let settings = state.settings.read().await.clone();
    let current_policy_bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for policy event impact {}",
            settings.policy_path.display()
        )
    });
    let current_policy_bytes = current_policy_bytes.map_err(internal_error)?;
    let current_policy =
        endpoint_policy_snapshot_from_policy_bytes(&current_policy_bytes, &settings.policy_path)
            .map_err(internal_error)?;
    let proposed_policy =
        endpoint_policy_snapshot_from_memory_policy_bytes(proposed_policy_yaml.as_bytes())
            .map_err(internal_error)?;
    let current_replay_yaml =
        policy_yaml_for_replay(&current_policy_bytes).map_err(internal_error)?;
    let proposed_replay_yaml =
        policy_yaml_for_replay(proposed_policy_yaml.as_bytes()).map_err(internal_error)?;
    let event_stream_hash =
        canonical_json_hash(&events, "policy event impact event stream").map_err(internal_error)?;
    let current_result = replay_events(&current_replay_yaml, &events, track_posture)
        .await
        .map_err(internal_error)?;
    let proposed_result = replay_events(&proposed_replay_yaml, &events, track_posture)
        .await
        .map_err(internal_error)?;
    let current_result_hash = canonical_json_hash(&current_result, "current policy impact result")
        .map_err(internal_error)?;
    let proposed_result_hash =
        canonical_json_hash(&proposed_result, "proposed policy impact result")
            .map_err(internal_error)?;
    let (summary, changes, drivers) =
        build_policy_event_impact_changes(&current_result, &proposed_result);
    let impact_hash = canonical_json_hash(
        &(serde_json::json!({
            "summary": &summary,
            "changes": &changes,
        })),
        "policy event impact report",
    )
    .map_err(internal_error)?;
    let impact = build_policy_event_impact_report(
        current_policy,
        proposed_policy,
        source,
        track_posture,
        event_stream_hash,
        current_result_hash,
        proposed_result_hash,
        impact_hash,
        &summary,
    );
    let receipt = emit_edr_policy_event_impact_receipt(state, &settings, &impact)
        .await
        .map_err(internal_error)?;

    Ok(EdrPolicyEventImpactResponse {
        impact,
        summary,
        drivers,
        changes,
        current_result,
        proposed_result,
        receipt,
    })
}

pub(crate) fn validate_policy_event_submission(
    event: &PolicyEvent,
    jsonl_line: Option<usize>,
) -> Result<(), (StatusCode, String)> {
    event.validate().map_err(|err| {
        let message = match jsonl_line {
            Some(line_number) => {
                format!("invalid PolicyEvent JSONL at line {line_number}: {err}")
            }
            None => err.to_string(),
        };
        (StatusCode::BAD_REQUEST, message)
    })
}

pub(crate) async fn record_edr_observations(
    state: &AgentApiState,
    observations: &[EndpointObservation],
) -> Result<(), (StatusCode, String)> {
    let mut recorder = state.edr_flight_recorder.lock().await;
    recorder
        .append_observations(observations)
        .map_err(internal_error)?;
    Ok(())
}
