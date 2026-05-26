use super::*;

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
