//! Pure helpers for policy event impact analysis (current vs proposed policy comparison).

use crate::edr::dto::{
    EdrPolicyEventImpactDriver, EdrPolicyEventImpactDriverKey, EdrPolicyEventImpactEntry,
    EdrPolicyEventImpactReport, EdrPolicyEventImpactSummary,
};
use clawdstrike_policy_event::edr::{
    endpoint_policy_event_impact_id, EndpointPolicyEventImpactIdInput, EndpointPolicySnapshot,
};
use std::collections::BTreeMap;

pub(crate) fn build_policy_event_impact_changes(
    current_result: &clawdstrike_policy_event::simulate::SimulationResult,
    proposed_result: &clawdstrike_policy_event::simulate::SimulationResult,
) -> (
    EdrPolicyEventImpactSummary,
    Vec<EdrPolicyEventImpactEntry>,
    Vec<EdrPolicyEventImpactDriver>,
) {
    let mut summary = EdrPolicyEventImpactSummary {
        total: 0,
        changed: 0,
        allow_to_warn: 0,
        allow_to_block: 0,
        warn_to_allow: 0,
        warn_to_block: 0,
        block_to_allow: 0,
        block_to_warn: 0,
    };
    let mut changes = Vec::new();

    for (current, proposed) in current_result.results.iter().zip(&proposed_result.results) {
        summary.total = summary.total.saturating_add(1);
        let changed = current.outcome != proposed.outcome;
        if changed {
            summary.changed = summary.changed.saturating_add(1);
            match (current.outcome, proposed.outcome) {
                ("allowed", "warn") => summary.allow_to_warn += 1,
                ("allowed", "blocked") => summary.allow_to_block += 1,
                ("warn", "allowed") => summary.warn_to_allow += 1,
                ("warn", "blocked") => summary.warn_to_block += 1,
                ("blocked", "allowed") => summary.block_to_allow += 1,
                ("blocked", "warn") => summary.block_to_warn += 1,
                _ => {}
            }
        }
        changes.push(EdrPolicyEventImpactEntry {
            event_id: current.event_id.clone(),
            current_outcome: current.outcome.to_string(),
            proposed_outcome: proposed.outcome.to_string(),
            changed,
            current_decision: current.decision.clone(),
            proposed_decision: proposed.decision.clone(),
        });
    }

    let drivers = build_policy_event_impact_drivers(&changes);

    (summary, changes, drivers)
}

pub(crate) fn build_policy_event_impact_drivers(
    changes: &[EdrPolicyEventImpactEntry],
) -> Vec<EdrPolicyEventImpactDriver> {
    let mut buckets: BTreeMap<EdrPolicyEventImpactDriverKey, (u64, Vec<String>)> = BTreeMap::new();
    for change in changes.iter().filter(|change| change.changed) {
        let key = EdrPolicyEventImpactDriverKey {
            current_outcome: change.current_outcome.clone(),
            proposed_outcome: change.proposed_outcome.clone(),
            current_guard: change.current_decision.guard.clone(),
            proposed_guard: change.proposed_decision.guard.clone(),
            current_reason_code: change.current_decision.reason_code.clone(),
            proposed_reason_code: change.proposed_decision.reason_code.clone(),
        };
        let (count, samples) = buckets.entry(key).or_default();
        *count = count.saturating_add(1);
        if samples.len() < 5 {
            samples.push(change.event_id.clone());
        }
    }

    let mut drivers = buckets
        .into_iter()
        .map(
            |(key, (count, sample_event_ids))| EdrPolicyEventImpactDriver {
                current_outcome: key.current_outcome,
                proposed_outcome: key.proposed_outcome,
                current_guard: key.current_guard,
                proposed_guard: key.proposed_guard,
                current_reason_code: key.current_reason_code,
                proposed_reason_code: key.proposed_reason_code,
                count,
                sample_event_ids,
            },
        )
        .collect::<Vec<_>>();
    drivers.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.proposed_outcome.cmp(&right.proposed_outcome))
            .then_with(|| left.proposed_guard.cmp(&right.proposed_guard))
            .then_with(|| left.proposed_reason_code.cmp(&right.proposed_reason_code))
            .then_with(|| left.current_outcome.cmp(&right.current_outcome))
    });
    drivers
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_policy_event_impact_report(
    current_policy: EndpointPolicySnapshot,
    proposed_policy: EndpointPolicySnapshot,
    source: &str,
    track_posture: bool,
    event_stream_hash: String,
    current_result_hash: String,
    proposed_result_hash: String,
    impact_hash: String,
    summary: &EdrPolicyEventImpactSummary,
) -> EdrPolicyEventImpactReport {
    let impact_id = endpoint_policy_event_impact_id(EndpointPolicyEventImpactIdInput {
        current_policy_hash: current_policy.policy_hash.as_str(),
        current_policy_epoch: current_policy.policy_epoch,
        proposed_policy_hash: proposed_policy.policy_hash.as_str(),
        proposed_policy_epoch: proposed_policy.policy_epoch,
        event_source: source,
        event_stream_hash: event_stream_hash.as_str(),
        current_result_hash: current_result_hash.as_str(),
        proposed_result_hash: proposed_result_hash.as_str(),
        impact_hash: impact_hash.as_str(),
        event_count: summary.total,
        changed_count: summary.changed,
        allow_to_block_count: summary.allow_to_block,
        track_posture,
    });
    let summary_text = format!(
        "Compared {} PolicyEvent records between current policy {} epoch {} and proposed policy {} epoch {}; {} changed, {} allow-to-block.",
        summary.total,
        current_policy.policy_version,
        current_policy.policy_epoch,
        proposed_policy.policy_version,
        proposed_policy.policy_epoch,
        summary.changed,
        summary.allow_to_block
    );

    EdrPolicyEventImpactReport {
        impact_id,
        analyzed_at: chrono::Utc::now(),
        mode: "current_vs_proposed_policy_event_impact".to_string(),
        source: source.to_string(),
        current_policy,
        proposed_policy,
        event_count: summary.total,
        changed_count: summary.changed,
        allow_to_block_count: summary.allow_to_block,
        track_posture,
        event_stream_hash,
        current_result_hash,
        proposed_result_hash,
        impact_hash,
        summary: summary_text,
    }
}
