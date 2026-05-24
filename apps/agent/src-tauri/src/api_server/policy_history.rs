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
                let identity_matches = identity_filters.matches_index_entry(entry);
                let process_matches = process_filters.matches_index_entry(entry);
                let target_matches = target_filters.matches_index_entry(entry);
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

pub(crate) fn build_policy_event_history_cross_window_impact(
    selection: &EdrPolicyEventHistorySelection,
    policy_impact: &EdrPolicyEventImpactReport,
    changes: &[EdrPolicyEventImpactEntry],
    window_seconds: u64,
) -> EdrPolicyEventHistoryCrossWindowImpact {
    let timestamps = selection
        .observations
        .iter()
        .map(|observation| (observation.observation_id.as_str(), observation.timestamp))
        .collect::<BTreeMap<_, _>>();
    let window_seconds = window_seconds.max(1);
    let window_seconds_i64 = i64::try_from(window_seconds).unwrap_or(i64::MAX);
    let mut windows = BTreeMap::<i64, EdrPolicyEventHistoryImpactWindowAccumulator>::new();

    for change in changes {
        let Some(timestamp) = timestamps.get(change.event_id.as_str()).copied() else {
            continue;
        };
        let window_index = timestamp.timestamp().div_euclid(window_seconds_i64);
        let window = windows.entry(window_index).or_default();
        window.window_start = Some(
            window
                .window_start
                .map_or(timestamp, |current| current.min(timestamp)),
        );
        window.window_end = Some(
            window
                .window_end
                .map_or(timestamp, |current| current.max(timestamp)),
        );
        window.event_count = window.event_count.saturating_add(1);
        if change.changed {
            window.changed_count = window.changed_count.saturating_add(1);
            if change.proposed_outcome == "blocked" {
                window.blocking_change_count = window.blocking_change_count.saturating_add(1);
            }
            if window.sample_event_ids.len() < EDR_MAX_POLICY_EVENT_IMPACT_CHAIN_DRIVER_SAMPLES {
                window.sample_event_ids.push(change.event_id.clone());
            }
        }
    }

    let windows = windows
        .into_iter()
        .filter_map(|(window_index, window)| {
            let window_start = window.window_start?;
            let window_end = window.window_end?;
            Some(EdrPolicyEventHistoryImpactWindow {
                window_index,
                window_start,
                window_end,
                event_count: window.event_count,
                changed_count: window.changed_count,
                blocking_change_count: window.blocking_change_count,
                sample_event_ids: window.sample_event_ids,
            })
        })
        .collect::<Vec<_>>();
    let total_event_count = windows.iter().map(|window| window.event_count).sum::<u64>();
    let total_changed_count = windows
        .iter()
        .map(|window| window.changed_count)
        .sum::<u64>();
    let total_blocking_change_count = windows
        .iter()
        .map(|window| window.blocking_change_count)
        .sum::<u64>();
    let changed_window_count = windows
        .iter()
        .filter(|window| window.changed_count > 0)
        .count();
    let blocking_window_count = windows
        .iter()
        .filter(|window| window.blocking_change_count > 0)
        .count();
    let (repeatability, recommended_stage, promotion_ready, recommendation_reason) =
        cross_window_impact_recommendation(
            windows.len(),
            changed_window_count,
            blocking_window_count,
            total_blocking_change_count,
        );
    let history_selector_hash = policy_event_history_selector_hash(&selection.report);
    let impact_hash = cross_window_impact_hash(CrossWindowImpactHashInput {
        window_seconds,
        total_event_count,
        total_changed_count,
        total_blocking_change_count,
        windows: &windows,
        event_stream_hash: selection.report.event_stream_hash.as_str(),
        current_policy_hash: policy_impact.current_policy.policy_hash.as_str(),
        current_policy_epoch: policy_impact.current_policy.policy_epoch,
        proposed_policy_hash: policy_impact.proposed_policy.policy_hash.as_str(),
        proposed_policy_epoch: policy_impact.proposed_policy.policy_epoch,
        current_result_hash: policy_impact.current_result_hash.as_str(),
        proposed_result_hash: policy_impact.proposed_result_hash.as_str(),
        history_selector_hash: history_selector_hash.as_str(),
    });
    let recommendation_hash = cross_window_recommendation_hash(
        impact_hash.as_str(),
        repeatability.as_str(),
        recommended_stage.as_str(),
        promotion_ready,
        recommendation_reason.as_str(),
    );

    EdrPolicyEventHistoryCrossWindowImpact {
        window_seconds,
        window_count: windows.len(),
        changed_window_count,
        blocking_window_count,
        total_event_count,
        total_changed_count,
        total_blocking_change_count,
        impact_hash,
        event_stream_hash: selection.report.event_stream_hash.clone(),
        current_policy_hash: policy_impact.current_policy.policy_hash.clone(),
        current_policy_epoch: policy_impact.current_policy.policy_epoch,
        proposed_policy_hash: policy_impact.proposed_policy.policy_hash.clone(),
        proposed_policy_epoch: policy_impact.proposed_policy.policy_epoch,
        current_result_hash: policy_impact.current_result_hash.clone(),
        proposed_result_hash: policy_impact.proposed_result_hash.clone(),
        history_selector_hash,
        repeatability,
        recommended_stage,
        promotion_ready,
        recommendation_hash,
        recommendation_reason,
        windows,
    }
}

pub(crate) struct CrossWindowImpactHashInput<'a> {
    pub(crate) window_seconds: u64,
    pub(crate) total_event_count: u64,
    pub(crate) total_changed_count: u64,
    pub(crate) total_blocking_change_count: u64,
    pub(crate) windows: &'a [EdrPolicyEventHistoryImpactWindow],
    pub(crate) event_stream_hash: &'a str,
    pub(crate) current_policy_hash: &'a str,
    pub(crate) current_policy_epoch: u64,
    pub(crate) proposed_policy_hash: &'a str,
    pub(crate) proposed_policy_epoch: u64,
    pub(crate) current_result_hash: &'a str,
    pub(crate) proposed_result_hash: &'a str,
    pub(crate) history_selector_hash: &'a str,
}

pub(crate) fn cross_window_impact_hash(input: CrossWindowImpactHashInput<'_>) -> String {
    let mut material = format!(
        "window_seconds={}\ntotal_event_count={}\ntotal_changed_count={}\ntotal_blocking_change_count={}\nevent_stream_hash={}\ncurrent_policy_hash={}\ncurrent_policy_epoch={}\nproposed_policy_hash={}\nproposed_policy_epoch={}\ncurrent_result_hash={}\nproposed_result_hash={}\nhistory_selector_hash={}\n",
        input.window_seconds,
        input.total_event_count,
        input.total_changed_count,
        input.total_blocking_change_count,
        input.event_stream_hash,
        input.current_policy_hash,
        input.current_policy_epoch,
        input.proposed_policy_hash,
        input.proposed_policy_epoch,
        input.current_result_hash,
        input.proposed_result_hash,
        input.history_selector_hash,
    );
    for window in input.windows {
        material.push_str(&format!(
            "window_index={};start={};end={};events={};changed={};blocking={};samples={}\n",
            window.window_index,
            window.window_start.to_rfc3339(),
            window.window_end.to_rfc3339(),
            window.event_count,
            window.changed_count,
            window.blocking_change_count,
            window.sample_event_ids.join(",")
        ));
    }
    sha256(material.as_bytes()).to_hex_prefixed()
}

pub(crate) fn cross_window_recommendation_hash(
    impact_hash: &str,
    repeatability: &str,
    recommended_stage: &str,
    promotion_ready: bool,
    recommendation_reason: &str,
) -> String {
    let material = format!(
        "impact_hash={impact_hash}\nrepeatability={repeatability}\nrecommended_stage={recommended_stage}\npromotion_ready={promotion_ready}\nrecommendation_reason={recommendation_reason}\n"
    );
    sha256(material.as_bytes()).to_hex_prefixed()
}

pub(crate) fn policy_event_history_selector_hash(history: &EdrPolicyEventHistoryReport) -> String {
    let selector = serde_json::json!({
        "source": &history.source,
        "projectionMode": &history.projection_mode,
        "selectionMode": &history.selection_mode,
        "limit": history.limit,
        "since": history.since,
        "until": history.until,
        "maxAgeSeconds": history.max_age_seconds,
        "eventKinds": &history.event_kinds,
        "identityFilters": &history.identity_filters,
        "processFilters": &history.process_filters,
        "targetFilters": &history.target_filters,
        "oldestTimestamp": history.oldest_timestamp,
        "newestTimestamp": history.newest_timestamp,
        "eventStreamHash": &history.event_stream_hash,
    });
    canonical_json_hash(&selector, "policy event history selector")
        .unwrap_or_else(|_| sha256(history.event_stream_hash.as_bytes()).to_hex_prefixed())
}

fn cross_window_impact_recommendation(
    window_count: usize,
    changed_window_count: usize,
    blocking_window_count: usize,
    total_blocking_change_count: u64,
) -> (String, String, bool, String) {
    if total_blocking_change_count == 0 {
        return (
            "none".to_string(),
            "observe".to_string(),
            false,
            format!(
                "No blocking rule diff appeared across {window_count} validation windows; keep observing before promotion."
            ),
        );
    }

    if blocking_window_count < 2 {
        return (
            "single_window".to_string(),
            "audit".to_string(),
            false,
            format!(
                "Blocking impact appeared in {blocking_window_count} of {window_count} validation windows; keep the candidate in audit until repeated history supports promotion."
            ),
        );
    }

    let repeatability = if changed_window_count == window_count {
        "all_windows"
    } else {
        "repeated_windows"
    };
    let recommended_stage = if blocking_window_count == window_count {
        "limited_block"
    } else {
        "warn"
    };
    (
        repeatability.to_string(),
        recommended_stage.to_string(),
        true,
        format!(
            "Blocking impact appeared in {blocking_window_count} of {window_count} validation windows; repeated local history supports {recommended_stage} staging with receipts and rollback gates."
        ),
    )
}

pub(crate) fn build_policy_event_history_causal_impact(
    selection: &EdrPolicyEventHistorySelection,
    changes: &[EdrPolicyEventImpactEntry],
    graph: &CausalGraph,
    context_depth: usize,
    promotion_stage: Option<&str>,
    cross_window_hashes: Option<(&str, &str)>,
) -> EdrPolicyEventHistoryCausalImpact {
    let observations = selection
        .observations
        .iter()
        .map(|observation| (observation.observation_id.as_str(), observation))
        .collect::<BTreeMap<_, _>>();
    let changed = changes
        .iter()
        .filter(|change| change.changed)
        .collect::<Vec<_>>();
    let mut contexts = Vec::new();
    let mut union_node_ids = BTreeSet::new();
    let mut missing_graph_context_count = 0usize;

    for change in changed
        .iter()
        .take(EDR_MAX_POLICY_EVENT_IMPACT_CONTEXTS)
        .copied()
    {
        let Some(observation) = observations.get(change.event_id.as_str()) else {
            missing_graph_context_count = missing_graph_context_count.saturating_add(1);
            continue;
        };
        let touched_node_ids = graph_node_ids_for_observation(graph, &observation.observation_id);
        let Some(root_node_id) =
            finding_group_root_node_id(graph, &observation.observation_id, &touched_node_ids)
        else {
            missing_graph_context_count = missing_graph_context_count.saturating_add(1);
            continue;
        };
        let context = graph
            .causal_context_around(&root_node_id, context_depth, context_depth)
            .unwrap_or_else(|| {
                graph_slice_for_node_ids(graph, &BTreeSet::from([root_node_id.clone()]))
            });
        union_node_ids.extend(context.nodes.keys().cloned());
        let root_label = graph
            .nodes
            .get(&root_node_id)
            .map(|node| node.label.clone())
            .unwrap_or_else(|| root_node_id.clone());
        let chains =
            causal_chains_for_changed_observation(&context, &root_node_id, &touched_node_ids);
        contexts.push(EdrPolicyEventHistoryCausalContext {
            event_id: change.event_id.clone(),
            current_outcome: change.current_outcome.clone(),
            proposed_outcome: change.proposed_outcome.clone(),
            current_guard: change.current_decision.guard.clone(),
            proposed_guard: change.proposed_decision.guard.clone(),
            current_reason_code: change.current_decision.reason_code.clone(),
            proposed_reason_code: change.proposed_decision.reason_code.clone(),
            root_node_id,
            root_label,
            node_count: context.nodes.len(),
            edge_count: context.edges.len(),
            chain_count: chains.len(),
            chains,
            node_kinds: causal_node_kind_counts(&context),
            graph: context,
        });
    }

    let union_graph = graph_slice_for_node_ids(graph, &union_node_ids);
    let omitted_context_count = (changed.len())
        .saturating_sub(contexts.len())
        .saturating_sub(missing_graph_context_count);
    let chain_drivers = causal_chain_drivers_for_contexts(&contexts);
    let promotion_suggestions = promotion_suggestions_for_causal_impact(
        &contexts,
        context_depth,
        promotion_stage,
        cross_window_hashes,
    );
    let affected_identities = affected_identities_for_causal_impact(&union_graph);
    let affected_identity_count = affected_identities.count();
    let affected_tools = affected_tools_for_causal_impact(&union_graph);
    let affected_tool_count = affected_tools.len();
    let blocking_change_count = changed
        .iter()
        .filter(|change| change.proposed_outcome == "blocked")
        .count() as u64;
    let mut breakage_drivers = breakage_drivers_for_causal_impact(&union_graph);
    let developer_breakage_score = if blocking_change_count > 0 {
        score_policy_event_history_breakage(&breakage_drivers, &union_graph)
    } else {
        0
    };
    let impact_level = policy_event_history_impact_level_for_score(developer_breakage_score);
    let breakage_driver_count = breakage_drivers.len();
    breakage_drivers.truncate(EDR_MAX_POLICY_EVENT_IMPACT_BREAKAGE_DRIVERS);

    EdrPolicyEventHistoryCausalImpact {
        changed_event_count: changed.len() as u64,
        context_count: contexts.len(),
        chain_count: contexts.iter().map(|context| context.chain_count).sum(),
        chain_driver_count: chain_drivers.len(),
        promotion_suggestion_count: promotion_suggestions.len(),
        affected_identity_count,
        affected_tool_count,
        blocking_change_count,
        developer_breakage_score,
        impact_level,
        breakage_driver_count,
        omitted_context_count,
        missing_graph_context_count,
        context_depth,
        node_count: union_graph.nodes.len(),
        edge_count: union_graph.edges.len(),
        node_kinds: causal_node_kind_counts(&union_graph),
        affected_identities,
        affected_tools,
        top_breakage_drivers: breakage_drivers,
        contexts,
        chain_drivers,
        promotion_suggestions,
        receipt: None,
    }
}

pub(crate) fn affected_tools_for_causal_impact(
    graph: &CausalGraph,
) -> Vec<EdrPolicyEventHistoryAffectedTool> {
    graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Tool)
        .map(|node| EdrPolicyEventHistoryAffectedTool {
            node_id: node.node_id.clone(),
            label: node.label.clone(),
            tool_name: node.label.clone(),
        })
        .collect()
}

fn breakage_drivers_for_causal_impact(
    graph: &CausalGraph,
) -> Vec<EdrPolicyEventHistoryBreakageDriver> {
    let mut drivers = graph
        .nodes
        .values()
        .map(policy_event_history_breakage_driver)
        .collect::<Vec<_>>();
    drivers.sort_by(|left, right| {
        right
            .breakage_score
            .cmp(&left.breakage_score)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    drivers
}

fn policy_event_history_breakage_driver(node: &CausalNode) -> EdrPolicyEventHistoryBreakageDriver {
    let (breakage_score, reason) = match node.kind {
        CausalNodeKind::Host => (
            25,
            "blocking this host affects endpoint-wide local activity",
        ),
        CausalNodeKind::User => (
            48,
            "blocking this user identity can disrupt every local workflow for that principal",
        ),
        CausalNodeKind::Session => (
            36,
            "blocking this session can disrupt the active user or agent workflow",
        ),
        CausalNodeKind::Agent => (
            42,
            "blocking this agent identity can disrupt local automation workflows",
        ),
        CausalNodeKind::Workload => (
            42,
            "blocking this workload identity can disrupt delegated automation or service activity",
        ),
        CausalNodeKind::Approval => (
            18,
            "blocking this approval context affects authorized workflow bookkeeping",
        ),
        CausalNodeKind::Process => (30, "blocking this process affects local execution"),
        CausalNodeKind::File => (18, "blocking this file interaction may affect local files"),
        CausalNodeKind::Network => (24, "blocking this network target may affect egress"),
        CausalNodeKind::DnsName => (
            26,
            "blocking this DNS name may affect name resolution for local or developer workflows",
        ),
        CausalNodeKind::PackageScript => (
            55,
            "blocking this package-manager lifecycle script can break dependency installation",
        ),
        CausalNodeKind::Credential => (
            50,
            "blocking this credential access can break authenticated developer or cloud workflows",
        ),
        CausalNodeKind::Tool => (
            42,
            "blocking this tool call can break local agent or automation workflows",
        ),
        CausalNodeKind::BrowserDownload => (
            22,
            "blocking this browser download may affect a user-sourced artifact",
        ),
        CausalNodeKind::BrowserExtension => (
            28,
            "blocking this browser extension change may affect browser functionality",
        ),
        CausalNodeKind::PolicyDecision => (
            12,
            "blocking this policy decision node affects enforcement bookkeeping",
        ),
        CausalNodeKind::DeceptionArtifact => (
            5,
            "blocking deception material should have minimal legitimate workflow impact",
        ),
        CausalNodeKind::Other => (10, "blocking this node has unknown local workflow impact"),
    };

    EdrPolicyEventHistoryBreakageDriver {
        node_id: node.node_id.clone(),
        kind: node.kind.clone(),
        label: node.label.clone(),
        workflow_category: policy_event_history_workflow_category(node).to_string(),
        breakage_score,
        reason: reason.to_string(),
    }
}

fn policy_event_history_workflow_category(node: &CausalNode) -> &'static str {
    match node.kind {
        CausalNodeKind::Host => "endpoint_identity",
        CausalNodeKind::User => "user_identity",
        CausalNodeKind::Session => "session_identity",
        CausalNodeKind::Agent => "agent_identity",
        CausalNodeKind::Workload => "workload_identity",
        CausalNodeKind::Approval => "approval_context",
        CausalNodeKind::Process => "process_execution",
        CausalNodeKind::File => "file_activity",
        CausalNodeKind::Network => "network_egress",
        CausalNodeKind::DnsName => "dns_resolution",
        CausalNodeKind::PackageScript => "package_manager_script",
        CausalNodeKind::Credential => "credential_access",
        CausalNodeKind::Tool => {
            if node.label.starts_with("mcp__") {
                "mcp_tool_call"
            } else if node.label.contains("browser") {
                "browser_automation_tool"
            } else if node.label.contains("shell") || node.label.contains("terminal") {
                "shell_tool_call"
            } else {
                "agent_tool_call"
            }
        }
        CausalNodeKind::BrowserDownload => "browser_download",
        CausalNodeKind::BrowserExtension => "browser_extension",
        CausalNodeKind::PolicyDecision => "policy_decision",
        CausalNodeKind::DeceptionArtifact => "endpoint_deception",
        CausalNodeKind::Other => "other_endpoint_activity",
    }
}

fn score_policy_event_history_breakage(
    drivers: &[EdrPolicyEventHistoryBreakageDriver],
    graph: &CausalGraph,
) -> u8 {
    let max_node_score = drivers
        .iter()
        .map(|driver| driver.breakage_score)
        .max()
        .unwrap_or(0);
    let breadth = graph
        .nodes
        .len()
        .saturating_sub(1)
        .saturating_mul(4)
        .min(24) as u8;
    let edge_weight = graph.edges.len().saturating_mul(2).min(16) as u8;
    let process_weight = count_causal_nodes_by_kind(graph, CausalNodeKind::Process)
        .saturating_sub(1)
        .saturating_mul(6)
        .min(18) as u8;
    let credential_weight = if count_causal_nodes_by_kind(graph, CausalNodeKind::Credential) > 0 {
        10
    } else {
        0
    };

    max_node_score
        .saturating_add(breadth)
        .saturating_add(edge_weight)
        .saturating_add(process_weight)
        .saturating_add(credential_weight)
        .min(100)
}

fn policy_event_history_impact_level_for_score(score: u8) -> EndpointSimulationImpactLevel {
    match score {
        0 => EndpointSimulationImpactLevel::None,
        1..=24 => EndpointSimulationImpactLevel::Low,
        25..=49 => EndpointSimulationImpactLevel::Medium,
        50..=74 => EndpointSimulationImpactLevel::High,
        _ => EndpointSimulationImpactLevel::Critical,
    }
}

fn count_causal_nodes_by_kind(graph: &CausalGraph, kind: CausalNodeKind) -> usize {
    graph
        .nodes
        .values()
        .filter(|node| node.kind == kind)
        .count()
}

fn causal_chain_drivers_for_contexts(
    contexts: &[EdrPolicyEventHistoryCausalContext],
) -> Vec<EdrPolicyEventHistoryCausalChainDriver> {
    let mut buckets = BTreeMap::<
        EdrPolicyEventHistoryCausalChainDriverKey,
        EdrPolicyEventHistoryCausalChainDriverBucket,
    >::new();

    for context in contexts {
        for chain in &context.chains {
            let Some(target_node) = context.graph.nodes.get(&chain.target_node_id) else {
                continue;
            };
            let action = default_detection_candidate_action(target_node);
            if !supported_edr_simulation_action(&action) {
                continue;
            }
            let key = EdrPolicyEventHistoryCausalChainDriverKey {
                current_outcome: context.current_outcome.clone(),
                proposed_outcome: context.proposed_outcome.clone(),
                current_guard: context.current_guard.clone(),
                proposed_guard: context.proposed_guard.clone(),
                current_reason_code: context.current_reason_code.clone(),
                proposed_reason_code: context.proposed_reason_code.clone(),
                target_kind: chain.target_kind.clone(),
                action: action.as_str().to_string(),
                edge_kinds: chain.edge_kinds.clone(),
            };
            let bucket = buckets.entry(key).or_default();
            bucket.count = bucket.count.saturating_add(1);
            push_limited_unique_chain_driver_sample(
                &mut bucket.sample_event_ids,
                context.event_id.clone(),
            );
            push_limited_unique_chain_driver_sample(
                &mut bucket.sample_target_node_ids,
                chain.target_node_id.clone(),
            );
            push_limited_unique_chain_driver_sample(
                &mut bucket.sample_target_labels,
                chain.target_label.clone(),
            );
        }
    }

    let mut drivers = buckets
        .into_iter()
        .filter_map(|(key, bucket)| {
            let action = endpoint_decision_action_from_str(&key.action)?;
            let edge_kinds_material = key.edge_kinds.join(">");
            let driver_id = local_stable_id(
                "chain_driver",
                [
                    key.current_outcome.as_str(),
                    key.proposed_outcome.as_str(),
                    key.current_guard.as_deref().unwrap_or(""),
                    key.proposed_guard.as_deref().unwrap_or(""),
                    key.current_reason_code.as_str(),
                    key.proposed_reason_code.as_str(),
                    key.target_kind.as_str(),
                    key.action.as_str(),
                    edge_kinds_material.as_str(),
                ],
            );
            Some(EdrPolicyEventHistoryCausalChainDriver {
                driver_id,
                current_outcome: key.current_outcome,
                proposed_outcome: key.proposed_outcome,
                current_guard: key.current_guard,
                proposed_guard: key.proposed_guard,
                current_reason_code: key.current_reason_code,
                proposed_reason_code: key.proposed_reason_code,
                target_kind: key.target_kind,
                action,
                edge_kinds: key.edge_kinds,
                count: bucket.count,
                sample_event_ids: bucket.sample_event_ids,
                sample_target_node_ids: bucket.sample_target_node_ids,
                sample_target_labels: bucket.sample_target_labels,
            })
        })
        .collect::<Vec<_>>();
    drivers.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.target_kind.cmp(&right.target_kind))
            .then_with(|| left.action.as_str().cmp(right.action.as_str()))
            .then_with(|| left.edge_kinds.cmp(&right.edge_kinds))
            .then_with(|| left.driver_id.cmp(&right.driver_id))
    });
    drivers
}

fn push_limited_unique_chain_driver_sample(samples: &mut Vec<String>, sample: String) {
    if samples.len() >= EDR_MAX_POLICY_EVENT_IMPACT_CHAIN_DRIVER_SAMPLES {
        return;
    }
    if samples.iter().any(|existing| existing == &sample) {
        return;
    }
    samples.push(sample);
}

fn endpoint_decision_action_from_str(value: &str) -> Option<EndpointDecisionAction> {
    match value {
        "allow" => Some(EndpointDecisionAction::Allow),
        "observe" => Some(EndpointDecisionAction::Observe),
        "warn" => Some(EndpointDecisionAction::Warn),
        "alert" => Some(EndpointDecisionAction::Alert),
        "block" => Some(EndpointDecisionAction::Block),
        "restrict_egress" => Some(EndpointDecisionAction::RestrictEgress),
        "suspend_process_tree" => Some(EndpointDecisionAction::SuspendProcessTree),
        "terminate_process_tree" => Some(EndpointDecisionAction::TerminateProcessTree),
        "quarantine_file" => Some(EndpointDecisionAction::QuarantineFile),
        "revoke_grant" => Some(EndpointDecisionAction::RevokeGrant),
        "disable_persistence" => Some(EndpointDecisionAction::DisablePersistence),
        "collect_evidence" => Some(EndpointDecisionAction::CollectEvidence),
        _ => None,
    }
}

fn promotion_suggestions_for_causal_impact(
    contexts: &[EdrPolicyEventHistoryCausalContext],
    max_depth: usize,
    selected_stage: Option<&str>,
    cross_window_hashes: Option<(&str, &str)>,
) -> Vec<EdrPolicyEventHistoryPromotionSuggestion> {
    let mut suggestions = Vec::new();
    let mut seen = BTreeSet::new();
    let selected_stage = selected_stage.unwrap_or("audit").to_string();
    let cross_window_impact_hash =
        cross_window_hashes.map(|(impact_hash, _)| impact_hash.to_string());
    let cross_window_recommendation_hash =
        cross_window_hashes.map(|(_, recommendation_hash)| recommendation_hash.to_string());

    for context in contexts {
        for chain in &context.chains {
            if suggestions.len() >= EDR_MAX_POLICY_EVENT_IMPACT_PROMOTION_SUGGESTIONS {
                return suggestions;
            }
            let Some(target_node) = context.graph.nodes.get(&chain.target_node_id) else {
                continue;
            };
            let action = default_detection_candidate_action(target_node);
            if !supported_edr_simulation_action(&action) {
                continue;
            }
            let dedupe_key = format!("{}:{}", chain.target_node_id, action.as_str());
            if !seen.insert(dedupe_key) {
                continue;
            }
            let description = detection_candidate_description(target_node, &action);
            let note = format!(
                "Stage candidate from history impact event {} ({} -> {}) for review before enforcement.",
                context.event_id, context.current_outcome, context.proposed_outcome
            );
            let suggestion_id = local_stable_id(
                "impact_promotion",
                [
                    context.event_id.as_str(),
                    chain.target_node_id.as_str(),
                    action.as_str(),
                    selected_stage.as_str(),
                ],
            );
            suggestions.push(EdrPolicyEventHistoryPromotionSuggestion {
                suggestion_id,
                event_id: context.event_id.clone(),
                target_node_id: chain.target_node_id.clone(),
                target_label: chain.target_label.clone(),
                target_kind: chain.target_kind.clone(),
                action: action.clone(),
                selected_stage: selected_stage.clone(),
                cross_window_impact_hash: cross_window_impact_hash.clone(),
                cross_window_recommendation_hash: cross_window_recommendation_hash.clone(),
                reason: format!(
                    "Changed verdict {} -> {} on {} chain target {}; simulate and stage through the existing detection-candidate workflow.",
                    context.current_outcome,
                    context.proposed_outcome,
                    chain.target_kind,
                    chain.target_label
                ),
                candidate_endpoint: "/api/v1/agent/edr/detection-candidate".to_string(),
                candidate_request: EdrPolicyEventHistoryPromotionCandidateRequest {
                    root_node_id: chain.target_node_id.clone(),
                    action: action.clone(),
                    max_depth,
                    description: description.clone(),
                },
                stage_endpoint: "/api/v1/agent/edr/staged-detections".to_string(),
                stage_request: EdrPolicyEventHistoryPromotionStageRequest {
                    root_node_id: chain.target_node_id.clone(),
                    action,
                    max_depth,
                    selected_stage: selected_stage.clone(),
                    cross_window_impact_hash: cross_window_impact_hash.clone(),
                    cross_window_recommendation_hash: cross_window_recommendation_hash.clone(),
                    staged_by: "operator".to_string(),
                    note,
                },
            });
        }
    }

    suggestions
}

fn causal_chains_for_changed_observation(
    graph: &CausalGraph,
    root_node_id: &str,
    touched_node_ids: &BTreeSet<String>,
) -> Vec<EdrPolicyEventHistoryCausalChain> {
    let mut chains = Vec::new();
    for target_node_id in touched_node_ids
        .iter()
        .filter(|node_id| node_id.as_str() != root_node_id)
        .filter(|node_id| graph.nodes.contains_key(*node_id))
        .take(EDR_MAX_POLICY_EVENT_IMPACT_CHAINS_PER_CONTEXT)
    {
        let Some(path_node_ids) = causal_path_node_ids(graph, root_node_id, target_node_id) else {
            continue;
        };
        let Some(target_node) = graph.nodes.get(target_node_id) else {
            continue;
        };
        let nodes = path_node_ids
            .iter()
            .filter_map(|node_id| {
                graph
                    .nodes
                    .get(node_id)
                    .map(|node| EdrPolicyEventHistoryCausalChainNode {
                        node_id: node_id.clone(),
                        kind: causal_node_kind_name(&node.kind).to_string(),
                        label: node.label.clone(),
                    })
            })
            .collect::<Vec<_>>();
        let edge_kinds = path_node_ids
            .windows(2)
            .filter_map(|window| {
                graph
                    .edges
                    .iter()
                    .find(|edge| edge.from == window[0] && edge.to == window[1])
                    .map(|edge| causal_edge_kind_name(&edge.kind).to_string())
            })
            .collect::<Vec<_>>();

        chains.push(EdrPolicyEventHistoryCausalChain {
            target_node_id: target_node_id.clone(),
            target_label: target_node.label.clone(),
            target_kind: causal_node_kind_name(&target_node.kind).to_string(),
            path_node_count: nodes.len(),
            path_edge_count: edge_kinds.len(),
            nodes,
            edge_kinds,
        });
    }
    chains
}

fn causal_path_node_ids(graph: &CausalGraph, from: &str, to: &str) -> Option<Vec<String>> {
    if !graph.nodes.contains_key(from) || !graph.nodes.contains_key(to) {
        return None;
    }
    if from == to {
        return Some(vec![from.to_string()]);
    }

    let mut queue = VecDeque::from([from.to_string()]);
    let mut seen = BTreeSet::from([from.to_string()]);
    let mut previous: BTreeMap<String, String> = BTreeMap::new();

    while let Some(node_id) = queue.pop_front() {
        for edge in graph.edges.iter().filter(|edge| edge.from == node_id) {
            if !seen.insert(edge.to.clone()) {
                continue;
            }
            previous.insert(edge.to.clone(), node_id.clone());
            if edge.to == to {
                let mut path = vec![to.to_string()];
                let mut current = to;
                while let Some(parent) = previous.get(current) {
                    path.push(parent.clone());
                    if parent == from {
                        break;
                    }
                    current = parent;
                }
                path.reverse();
                return Some(path);
            }
            queue.push_back(edge.to.clone());
        }
    }

    None
}

pub(crate) fn causal_impact_receipt_graph(
    impact: &EdrPolicyEventHistoryCausalImpact,
) -> Option<(String, CausalGraph)> {
    let root_node_id = impact.contexts.first()?.root_node_id.clone();
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeMap::new();

    for context in &impact.contexts {
        for (node_id, node) in &context.graph.nodes {
            nodes.insert(node_id.clone(), node.clone());
        }
        for edge in &context.graph.edges {
            edges.insert(edge.edge_id.clone(), edge.clone());
        }
    }

    Some((
        root_node_id,
        CausalGraph {
            nodes,
            edges: edges.into_values().collect(),
        },
    ))
}

fn causal_node_kind_counts(graph: &CausalGraph) -> BTreeMap<String, u64> {
    let mut counts = BTreeMap::new();
    for node in graph.nodes.values() {
        *counts
            .entry(causal_node_kind_name(&node.kind).to_string())
            .or_insert(0) += 1;
    }
    counts
}

fn causal_edge_kind_name(kind: &CausalEdgeKind) -> &'static str {
    match kind {
        CausalEdgeKind::ObservedOn => "observed_on",
        CausalEdgeKind::RanAs => "ran_as",
        CausalEdgeKind::InSession => "in_session",
        CausalEdgeKind::UsedAgent => "used_agent",
        CausalEdgeKind::UsedWorkload => "used_workload",
        CausalEdgeKind::AuthorizedBy => "authorized_by",
        CausalEdgeKind::Spawned => "spawned",
        CausalEdgeKind::Executed => "executed",
        CausalEdgeKind::Read => "read",
        CausalEdgeKind::Wrote => "wrote",
        CausalEdgeKind::Connected => "connected",
        CausalEdgeKind::ResolvedDns => "resolved_dns",
        CausalEdgeKind::RanScript => "ran_script",
        CausalEdgeKind::LoadedLibrary => "loaded_library",
        CausalEdgeKind::CreatedPersistence => "created_persistence",
        CausalEdgeKind::InstalledExtension => "installed_extension",
        CausalEdgeKind::Downloaded => "downloaded",
        CausalEdgeKind::AccessedCredential => "accessed_credential",
        CausalEdgeKind::MadeDecision => "made_decision",
        CausalEdgeKind::InvokedTool => "invoked_tool",
        CausalEdgeKind::TemporalNext => "temporal_next",
        CausalEdgeKind::TouchedHoney => "touched_honey",
        CausalEdgeKind::Related => "related",
    }
}

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

fn validate_policy_event_replay_events(events: &[PolicyEvent]) -> Result<(), (StatusCode, String)> {
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

fn policy_yaml_for_replay(policy_bytes: &[u8]) -> Result<String> {
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
