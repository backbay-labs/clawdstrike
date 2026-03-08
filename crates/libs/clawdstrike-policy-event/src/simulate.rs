//! Pure replay/simulation of PolicyEvents against a loaded policy.

use std::collections::HashMap;

use clawdstrike::{
    decision_taxonomy::summarize_decision, GuardReport, HushEngine, OriginRuntimeState,
    PostureRuntimeState, Severity,
};
use serde::Serialize;

use crate::event::{map_policy_event, PolicyEvent};

/// Summary counts for a simulation run.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SimulationSummary {
    pub total: u64,
    pub allowed: u64,
    pub warn: u64,
    pub blocked: u64,
}

/// The result of simulating all events against a policy.
#[derive(Clone, Debug, Serialize)]
pub struct SimulationResult {
    pub summary: SimulationSummary,
    pub results: Vec<SimulationResultEntry>,
}

/// Per-event simulation result.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulationResultEntry {
    pub event_id: String,
    pub outcome: &'static str,
    pub decision: DecisionInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub posture: Option<SimulatedPostureState>,
}

/// Decision details for a single event.
#[derive(Clone, Debug, Serialize)]
pub struct DecisionInfo {
    pub allowed: bool,
    pub denied: bool,
    pub warn: bool,
    pub reason_code: String,
    pub guard: Option<String>,
    pub severity: Option<String>,
    pub message: Option<String>,
    pub reason: Option<String>,
}

/// Posture snapshot after evaluating an event.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SimulatedPostureState {
    pub state: String,
    pub budgets: HashMap<String, SimulatedBudgetCounter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition: Option<SimulatedTransition>,
}

/// Budget counter state.
#[derive(Clone, Debug, Serialize)]
pub struct SimulatedBudgetCounter {
    pub used: u64,
    pub limit: u64,
}

/// Record of a posture state transition.
#[derive(Clone, Debug, Serialize)]
pub struct SimulatedTransition {
    pub from: String,
    pub to: String,
    pub trigger: String,
    pub at: String,
}

/// Replay events against a policy and return results.
///
/// Creates an engine from the given YAML policy, evaluates each event,
/// and returns the aggregate summary plus per-event decision details.
pub async fn replay_events(
    policy_yaml: &str,
    events: &[PolicyEvent],
    track_posture: bool,
) -> anyhow::Result<SimulationResult> {
    let policy: clawdstrike::Policy = serde_yaml::from_str(policy_yaml)?;
    let engine = HushEngine::builder(policy).build()?;

    let mut summary = SimulationSummary::default();
    let mut results = Vec::with_capacity(events.len());
    let mut posture_state: Option<PostureRuntimeState> = None;
    let mut origin_state: Option<OriginRuntimeState> = None;

    for event in events {
        let mapped = map_policy_event(event)?;

        let (report, posture_snapshot) = if track_posture {
            let posture_report = engine
                .check_action_report_with_runtime(
                    &mapped.action.as_guard_action(),
                    &mapped.context,
                    &mut posture_state,
                    &mut origin_state,
                )
                .await?;

            (
                posture_report.guard_report,
                posture_snapshot_from_runtime(
                    posture_state.as_ref(),
                    posture_report.transition.as_ref(),
                ),
            )
        } else {
            let mut ephemeral_posture: Option<PostureRuntimeState> = None;
            let mut ephemeral_origin: Option<OriginRuntimeState> = None;
            let report = engine
                .check_action_report_with_runtime(
                    &mapped.action.as_guard_action(),
                    &mapped.context,
                    &mut ephemeral_posture,
                    &mut ephemeral_origin,
                )
                .await?
                .guard_report;
            engine.reset().await;
            (report, None)
        };

        let decision = decision_from_report(&report, mapped.decision_reason);
        let outcome = outcome_label(&report);

        summary.total += 1;
        match outcome {
            "allowed" => summary.allowed += 1,
            "warn" => summary.warn += 1,
            "blocked" => summary.blocked += 1,
            _ => {}
        }

        results.push(SimulationResultEntry {
            event_id: event.event_id.clone(),
            outcome,
            decision,
            posture: posture_snapshot,
        });
    }

    Ok(SimulationResult { summary, results })
}

fn decision_from_report(report: &GuardReport, reason_override: Option<String>) -> DecisionInfo {
    let overall = &report.overall;
    let taxonomy = summarize_decision(overall, reason_override.as_deref());

    DecisionInfo {
        allowed: overall.allowed,
        denied: taxonomy.denied,
        warn: taxonomy.warn,
        reason_code: taxonomy.reason_code,
        guard: if overall.allowed && overall.severity == Severity::Info {
            None
        } else {
            Some(overall.guard.clone())
        },
        severity: taxonomy.severity,
        message: Some(overall.message.clone()),
        reason: reason_override,
    }
}

fn outcome_label(report: &GuardReport) -> &'static str {
    if !report.overall.allowed {
        return "blocked";
    }
    if report.overall.severity == Severity::Warning {
        return "warn";
    }
    "allowed"
}

fn posture_snapshot_from_runtime(
    runtime: Option<&PostureRuntimeState>,
    transition: Option<&clawdstrike::PostureTransitionRecord>,
) -> Option<SimulatedPostureState> {
    let runtime = runtime?;
    let budgets = runtime
        .budgets
        .iter()
        .map(|(name, counter)| {
            (
                name.clone(),
                SimulatedBudgetCounter {
                    used: counter.used,
                    limit: counter.limit,
                },
            )
        })
        .collect::<HashMap<_, _>>();

    Some(SimulatedPostureState {
        state: runtime.current_state.clone(),
        budgets,
        transition: transition.map(|t| SimulatedTransition {
            from: t.from.clone(),
            to: t.to.clone(),
            trigger: t.trigger.clone(),
            at: t.at.clone(),
        }),
    })
}
