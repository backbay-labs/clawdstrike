//! Internal guard evaluation pipeline helpers.
//!
//! This module is intentionally not policy-authorable. It exists to provide a stable internal
//! staged execution model and telemetry for receipts/audit.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Internal evaluation stage names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationStage {
    FastPath,
    StdPath,
    DeepPath,
}

impl EvaluationStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FastPath => "fast_path",
            Self::StdPath => "std_path",
            Self::DeepPath => "deep_path",
        }
    }
}

/// Per-check pipeline trace used for explainability and stage timing telemetry.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvaluationPath {
    /// Ordered list of visited stage names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub stages: Vec<String>,
    /// Ordered list of guard names that executed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guard_sequence: Vec<String>,
    /// Per-stage elapsed time in microseconds.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub stage_timings_us: BTreeMap<String, u64>,
}

impl EvaluationPath {
    pub fn is_empty(&self) -> bool {
        self.stages.is_empty() && self.guard_sequence.is_empty()
    }

    pub fn path_string(&self) -> String {
        self.stages.join(" -> ")
    }

    pub fn record_stage(
        &mut self,
        stage: EvaluationStage,
        stage_guards: Vec<String>,
        elapsed: Duration,
    ) {
        if stage_guards.is_empty() {
            return;
        }

        let stage_name = stage.as_str().to_string();
        self.stages.push(stage_name.clone());
        self.guard_sequence.extend(stage_guards);
        self.stage_timings_us
            .insert(stage_name, duration_to_micros(elapsed));
    }
}

/// Internal routing for built-in guards.
///
/// - fast_path: cheap path/network/tool checks
/// - std_path: content/deeper synchronous analysis
pub fn builtin_stage_for_guard_name(guard_name: &str) -> EvaluationStage {
    match guard_name {
        "forbidden_path" | "path_allowlist" | "egress_allowlist" | "mcp_tool" => {
            EvaluationStage::FastPath
        }
        _ => EvaluationStage::StdPath,
    }
}

fn duration_to_micros(duration: Duration) -> u64 {
    let micros = duration.as_micros();
    if micros > u64::MAX as u128 {
        u64::MAX
    } else {
        micros as u64
    }
}
