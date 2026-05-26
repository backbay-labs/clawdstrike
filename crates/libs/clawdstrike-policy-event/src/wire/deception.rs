//! Deception (honey-artifact) plan lifecycle DTOs.

use serde::{Deserialize, Serialize};

use crate::edr::{
    DeceptionCleanupReport, DeceptionMaterializationReport, DeceptionPlan, DeceptionRotationReport,
};
use hush_core::SignedReceipt;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrDeceptionPlanInput {
    pub root: String,
    pub endpoint_id: String,
}

#[derive(Debug, Serialize)]
pub struct EdrDeceptionPlanResponse {
    pub artifact_count: usize,
    pub plan: DeceptionPlan,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrMaterializeDeceptionPlanInput {
    pub plan: DeceptionPlan,
}

#[derive(Debug, Serialize)]
pub struct EdrMaterializeDeceptionPlanResponse {
    pub report: DeceptionMaterializationReport,
    pub registered_artifact_count: usize,
    pub registry_path: Option<String>,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrCleanupDeceptionPlanInput {
    pub plan: DeceptionPlan,
    #[serde(default)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrCleanupDeceptionPlanResponse {
    pub report: DeceptionCleanupReport,
    pub deregistered_artifact_count: usize,
    pub remaining_registered_artifact_count: usize,
    pub registry_path: Option<String>,
    pub receipt: SignedReceipt,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrRotateDeceptionPlanInput {
    pub old_plan: DeceptionPlan,
    pub new_plan: DeceptionPlan,
    #[serde(default)]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrRotateDeceptionPlanResponse {
    pub report: DeceptionRotationReport,
    pub deregistered_artifact_count: usize,
    pub registered_artifact_count: usize,
    pub remaining_registered_artifact_count: usize,
    pub registry_path: Option<String>,
    pub cleanup_receipt: SignedReceipt,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub materialization_receipt: Option<SignedReceipt>,
    pub rotation_receipt: SignedReceipt,
}
