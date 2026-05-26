use super::*;

pub(crate) fn parse_policy_event_jsonl(
    body: &str,
) -> Result<Vec<PolicyEvent>, (StatusCode, String)> {
    let mut events = Vec::new();
    for (line_index, line) in body.lines().enumerate() {
        let line_number = line_index + 1;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event = serde_json::from_str::<PolicyEvent>(trimmed).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("invalid PolicyEvent JSONL at line {line_number}: {err}"),
            )
        })?;
        validate_policy_event_submission(&event, Some(line_number))?;
        events.push(event);
        validate_edr_request_sizes(events.len(), 0)?;
    }
    Ok(events)
}

pub(crate) async fn select_policy_event_history_from_flight_recorder(
    state: &AgentApiState,
    input: EdrPolicyEventHistoryReplayInput,
) -> Result<EdrPolicyEventHistorySelection, (StatusCode, String)> {
    let limit = input.limit.unwrap_or(EDR_MAX_OBSERVATIONS_PER_REQUEST);
    if limit == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "history replay limit must be greater than zero".to_string(),
        ));
    }
    if limit > EDR_MAX_OBSERVATIONS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "history replay limit exceeds max {}",
                EDR_MAX_OBSERVATIONS_PER_REQUEST
            ),
        ));
    }
    if let (Some(since), Some(until)) = (input.since, input.until) {
        if since > until {
            return Err((
                StatusCode::BAD_REQUEST,
                "history replay since must be earlier than until".to_string(),
            ));
        }
    }
    let event_kinds = normalize_history_event_kinds(&input.event_kinds)?;
    let identity_filters = normalize_history_identity_filters(input.identity_filters())?;
    let process_filters = normalize_history_process_filters(input.process_filters())?;
    let target_filters = normalize_history_target_filters(input.target_filters())?;

    let now = chrono::Utc::now();
    let (path, history_window) = {
        let recorder = state.edr_flight_recorder.lock().await;
        let path = recorder.path().map(|path| path.display().to_string());
        if path.is_none() {
            return Err((
                StatusCode::CONFLICT,
                "policy-event history replay requires a durable flight recorder path".to_string(),
            ));
        }
        let history_window = recorder
            .read_indexed_observation_window(limit, |entry| {
                let time_matches = match input.since {
                    Some(since) => entry.timestamp >= since,
                    None => true,
                } && match input.until {
                    Some(until) => entry.timestamp <= until,
                    None => true,
                } && match input.max_age_seconds {
                    Some(max_age_seconds) => {
                        let age_seconds = now
                            .signed_duration_since(entry.timestamp)
                            .num_seconds()
                            .max(0) as u64;
                        age_seconds <= max_age_seconds
                    }
                    None => true,
                };
                let event_kind_matches =
                    event_kinds.is_empty() || event_kinds.contains(entry.event_kind.as_str());
                let identity_matches =
                    crate::edr::dto::edr_policy_event_history_identity_filters_matches_index_entry(
                        &identity_filters,
                        entry,
                    );
                let process_matches =
                    crate::edr::dto::edr_policy_event_history_process_filters_matches_index_entry(
                        &process_filters,
                        entry,
                    );
                let target_matches =
                    crate::edr::dto::edr_policy_event_history_target_filters_matches_index_entry(
                        &target_filters,
                        entry,
                    );
                time_matches
                    && event_kind_matches
                    && identity_matches
                    && process_matches
                    && target_matches
            })
            .map_err(internal_error)?;
        (path, history_window)
    };
    let total_observation_count = history_window.total_observation_count;
    let matched_observation_count = history_window.matched_observation_count;
    let matched = history_window.selected_observations;
    if matched.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "flight recorder history selection produced no observations".to_string(),
        ));
    }
    validate_edr_request_sizes(matched.len(), 0)?;

    let oldest_timestamp = matched
        .iter()
        .map(|observation| observation.timestamp)
        .min();
    let newest_timestamp = matched
        .iter()
        .map(|observation| observation.timestamp)
        .max();
    let events = matched
        .iter()
        .map(EndpointObservation::to_policy_event_projection)
        .collect::<Vec<_>>();
    validate_policy_event_replay_events(&events)?;
    let event_stream_hash =
        canonical_json_hash(&events, "policy event history replay event stream")
            .map_err(internal_error)?;
    let summary = format!(
        "Projected {} selected flight-recorder observations into {} PolicyEvent candidates from {} matched observations.",
        matched.len(),
        events.len(),
        matched_observation_count
    );
    let report = EdrPolicyEventHistoryReport {
        source: "endpoint_flight_recorder".to_string(),
        projection_mode: "endpoint_observation_policy_event_projection".to_string(),
        selection_mode: history_window.selection_mode,
        path,
        index_path: history_window
            .index_path
            .map(|path| path.display().to_string()),
        total_observation_count,
        matched_observation_count,
        selected_observation_count: matched.len(),
        policy_event_count: events.len(),
        limit,
        since: input.since,
        until: input.until,
        max_age_seconds: input.max_age_seconds,
        event_kinds: event_kinds.iter().cloned().collect(),
        identity_filters,
        process_filters,
        target_filters,
        oldest_timestamp,
        newest_timestamp,
        event_stream_hash,
        summary,
    };

    Ok(EdrPolicyEventHistorySelection {
        report,
        events,
        observations: matched,
    })
}

fn normalize_history_event_kinds(
    event_kinds: &[String],
) -> Result<BTreeSet<String>, (StatusCode, String)> {
    if event_kinds.len() > 64 {
        return Err((
            StatusCode::BAD_REQUEST,
            "history replay eventKinds must contain at most 64 entries".to_string(),
        ));
    }
    let mut normalized = BTreeSet::new();
    for event_kind in event_kinds {
        let event_kind = event_kind.trim().replace('-', "_").to_ascii_lowercase();
        if event_kind.is_empty() {
            continue;
        }
        if !event_kind
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_')
        {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid history replay event kind: {event_kind}"),
            ));
        }
        normalized.insert(event_kind);
    }
    Ok(normalized)
}

fn normalize_history_identity_filters(
    filters: EdrPolicyEventHistoryIdentityFilters,
) -> Result<EdrPolicyEventHistoryIdentityFilters, (StatusCode, String)> {
    Ok(EdrPolicyEventHistoryIdentityFilters {
        host_id: normalize_history_identity_filter("hostId", filters.host_id)?,
        user_id: normalize_history_identity_filter("userId", filters.user_id)?,
        session_id: normalize_history_identity_filter("sessionId", filters.session_id)?,
        process_guid: normalize_history_identity_filter("processGuid", filters.process_guid)?,
        parent_process_guid: normalize_history_identity_filter(
            "parentProcessGuid",
            filters.parent_process_guid,
        )?,
        agent_id: normalize_history_identity_filter("agentId", filters.agent_id)?,
        workload_id: normalize_history_identity_filter("workloadId", filters.workload_id)?,
        approval_id: normalize_history_identity_filter("approvalId", filters.approval_id)?,
        tool_name: normalize_history_identity_filter("toolName", filters.tool_name)?,
        tool_call_id: normalize_history_identity_filter("toolCallId", filters.tool_call_id)?,
        credential_kind: normalize_history_identity_filter(
            "credentialKind",
            filters.credential_kind,
        )?,
    })
}

fn normalize_history_target_filters(
    filters: EdrPolicyEventHistoryTargetFilters,
) -> Result<EdrPolicyEventHistoryTargetFilters, (StatusCode, String)> {
    Ok(EdrPolicyEventHistoryTargetFilters {
        event_target: normalize_history_target_filter("eventTarget", filters.event_target)?,
        event_target_hash: normalize_history_hash_filter(
            "eventTargetHash",
            filters.event_target_hash,
        )?,
    })
}

fn normalize_history_process_filters(
    filters: EdrPolicyEventHistoryProcessFilters,
) -> Result<EdrPolicyEventHistoryProcessFilters, (StatusCode, String)> {
    Ok(EdrPolicyEventHistoryProcessFilters {
        process_image_hash: normalize_history_hash_filter(
            "processImageHash",
            filters.process_image_hash,
        )?,
        process_command_line_hash: normalize_history_hash_filter(
            "processCommandLineHash",
            filters.process_command_line_hash,
        )?,
    })
}

pub(crate) fn normalize_policy_event_history_validation_window_seconds(
    value: Option<u64>,
) -> Result<Option<u64>, (StatusCode, String)> {
    let Some(window_seconds) = value else {
        return Ok(None);
    };
    if window_seconds == 0 {
        return Err((
            StatusCode::BAD_REQUEST,
            "history impact validationWindowSeconds must be greater than zero".to_string(),
        ));
    }
    if window_seconds > EDR_MAX_POLICY_EVENT_IMPACT_VALIDATION_WINDOW_SECONDS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "history impact validationWindowSeconds exceeds max {}",
                EDR_MAX_POLICY_EVENT_IMPACT_VALIDATION_WINDOW_SECONDS
            ),
        ));
    }
    Ok(Some(window_seconds))
}

fn normalize_history_target_filter(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 2048 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} exceeds 2048 bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} cannot contain control characters"),
        ));
    }
    Ok(Some(value.to_string()))
}

fn normalize_history_hash_filter(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 128 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} exceeds 128 bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} cannot contain control characters"),
        ));
    }
    let normalized = value.to_ascii_lowercase();
    let Some(hex) = normalized
        .strip_prefix("0x")
        .or_else(|| normalized.strip_prefix("sha256:"))
    else {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} must be a sha256 hash"),
        ));
    };
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} must be a sha256 hash"),
        ));
    }
    Ok(Some(format!("0x{hex}")))
}

fn normalize_history_identity_filter(
    field: &str,
    value: Option<String>,
) -> Result<Option<String>, (StatusCode, String)> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 512 {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} exceeds 512 bytes"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("history replay {field} cannot contain control characters"),
        ));
    }
    Ok(Some(value.to_string()))
}
