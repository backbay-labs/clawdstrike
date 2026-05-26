//! Policy simulation, replay, delta, and detection-staging handlers.

mod delta;
mod delta_apply;
mod detection;
mod events;
mod simulation;

#[allow(unused_imports)]
pub(crate) use delta::{agent_edr_policy_delta, agent_edr_policy_deltas};
#[allow(unused_imports)]
pub(crate) use delta_apply::agent_edr_policy_delta_apply;
#[allow(unused_imports)]
pub(crate) use detection::{
    agent_edr_detection_candidate, agent_edr_stage_detection, agent_edr_staged_detections,
};
#[allow(unused_imports)]
pub(crate) use events::{
    agent_edr_policy_events_impact, agent_edr_policy_events_impact_history,
    agent_edr_policy_events_replay, agent_edr_policy_events_replay_history,
    agent_edr_policy_events_replay_jsonl,
};
#[allow(unused_imports)]
pub(crate) use simulation::{agent_edr_policy_replay, agent_edr_policy_simulation};
