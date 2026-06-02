//! Public report and statistics types produced by the engine.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::guards::GuardResult;
use crate::origin::OriginContext;
use crate::pipeline::EvaluationPath;
use crate::posture::{PostureBudgetCounter, PostureTransitionRecord};

/// Per-guard evidence + an aggregated verdict.
#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardReport {
    pub overall: GuardResult,
    pub per_guard: Vec<GuardResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_path: Option<EvaluationPath>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<GuardEvaluationMetadata>,
}

#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardEvaluationMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<OriginContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave: Option<GuardResolvedEnclave>,
}

#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardResolvedEnclave {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_path: Vec<String>,
}

/// Guard report plus posture runtime updates.
#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostureAwareReport {
    pub guard_report: GuardReport,
    pub posture_before: String,
    pub posture_after: String,
    pub budgets_before: HashMap<String, PostureBudgetCounter>,
    pub budgets_after: HashMap<String, PostureBudgetCounter>,
    pub budget_deltas: HashMap<String, i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition: Option<PostureTransitionRecord>,
}

/// Session statistics
#[derive(Clone, Debug)]
pub struct EngineStats {
    pub action_count: u64,
    pub violation_count: u64,
}
