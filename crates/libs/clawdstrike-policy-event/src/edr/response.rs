use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use hush_core::sha256;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::action::EndpointDecisionAction;
use super::actor::EndpointDecisionActor;
use super::causal::{CausalGraph, CausalNode};
use super::receipt::evidence::{EndpointEvidenceBundleReference, EndpointGraphReference};
use super::receipt::{
    response_acknowledgement_id_from_report_fields,
    response_acknowledgement_id_from_report_fields_with_control,
    response_execution_effect_binding_digest_from_effects, response_rollback_id_from_effects,
};
use super::{
    response_execution_id_from_effects, response_execution_transition_id_from_reason_hash,
    stable_id,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponsePlan {
    pub action_id: String,
    pub action: EndpointDecisionAction,
    pub dry_run: bool,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub ttl_seconds: u64,
    pub rollback_ref: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub node_count: usize,
    pub edge_count: usize,
}

impl Default for EndpointResponsePlan {
    fn default() -> Self {
        let created_at = Utc::now();
        Self {
            action_id: String::new(),
            action: EndpointDecisionAction::CollectEvidence,
            dry_run: true,
            root_node_id: String::new(),
            graph_slice_id: String::new(),
            ttl_seconds: 0,
            rollback_ref: String::new(),
            reason: String::new(),
            created_at,
            expires_at: created_at,
            node_count: 0,
            edge_count: 0,
        }
    }
}

impl EndpointResponsePlan {
    #[must_use]
    pub fn dry_run(
        action: EndpointDecisionAction,
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(action, true, root_node_id, graph, ttl_seconds, reason)
    }

    #[must_use]
    pub fn collect_evidence_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::CollectEvidence,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn restrict_egress_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::RestrictEgress,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn quarantine_file_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::QuarantineFile,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn disable_persistence_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::DisablePersistence,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn revoke_grant_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::RevokeGrant,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    pub fn suspend_process_tree_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::SuspendProcessTree,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    #[must_use]
    #[deprecated(
        note = "terminate_process_tree is dry-run/modeling only; use EndpointResponsePlan::dry_run or suspend_process_tree_execution for live response plans"
    )]
    pub fn terminate_process_tree_execution(
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self::new(
            EndpointDecisionAction::TerminateProcessTree,
            false,
            root_node_id,
            graph,
            ttl_seconds,
            reason,
        )
    }

    fn new(
        action: EndpointDecisionAction,
        dry_run: bool,
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
        ttl_seconds: u64,
        reason: impl Into<String>,
    ) -> Self {
        let root_node_id = root_node_id.into();
        let graph_ref = EndpointGraphReference::for_subgraph(root_node_id.clone(), graph);
        let graph_slice_id = graph_ref.graph_slice_id.unwrap_or_else(|| {
            let node_count = graph.nodes.len().to_string();
            let edge_count = graph.edges.len().to_string();
            stable_id(
                "graph_slice",
                [
                    root_node_id.as_str(),
                    node_count.as_str(),
                    edge_count.as_str(),
                ],
            )
        });
        let created_at = Utc::now();
        let issuance_id = Uuid::now_v7().to_string();
        let action_name = action.as_str();
        let ttl = ttl_seconds.to_string();
        let mode = if dry_run { "dry_run" } else { "execute" };
        let stable_action_id = stable_id(
            "response_action",
            [
                root_node_id.as_str(),
                graph_slice_id.as_str(),
                action_name,
                mode,
                ttl.as_str(),
            ],
        );
        let action_id = format!("{stable_action_id}:{issuance_id}");
        let rollback_ref = if !dry_run && action == EndpointDecisionAction::CollectEvidence {
            format!("rollback:noop:{action_id}")
        } else {
            format!("rollback:{action_id}")
        };
        let expires_at = created_at + chrono::Duration::seconds(ttl_seconds as i64);

        Self {
            action_id,
            action,
            dry_run,
            root_node_id,
            graph_slice_id,
            ttl_seconds,
            rollback_ref,
            reason: reason.into(),
            created_at,
            expires_at,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edr::{CausalGraph, EndpointEvidenceBundleReference};
    use chrono::Utc;

    #[test]
    fn response_plan_action_ids_do_not_collapse_repeated_actions() {
        let graph = CausalGraph::default();

        let first = EndpointResponsePlan::restrict_egress_execution(
            "process:repeat",
            &graph,
            600,
            "repeat restriction",
        );
        let second = EndpointResponsePlan::restrict_egress_execution(
            "process:repeat",
            &graph,
            600,
            "repeat restriction",
        );

        assert_ne!(first.action_id, second.action_id);
        assert_ne!(first.rollback_ref, second.rollback_ref);
    }

    fn rollbackable_execution(
        action: EndpointDecisionAction,
        status: EndpointResponseExecutionStatus,
        effect: EndpointResponseExecutionEffect,
    ) -> EndpointResponseExecutionReport {
        let now = Utc::now();
        EndpointResponseExecutionReport {
            execution_id: "response-execution-partial".to_string(),
            action_id: "response-action-partial".to_string(),
            action,
            status,
            dry_run: false,
            root_node_id: "process-node".to_string(),
            graph_slice_id: "graph-slice".to_string(),
            ttl_seconds: 600,
            rollback_ref: "rollback:response-action-partial".to_string(),
            reason: "partial execution needs rollback".to_string(),
            started_at: now,
            completed_at: now,
            evidence_bundle: EndpointEvidenceBundleReference {
                bundle_id: "bundle-partial".to_string(),
                graph_slice_id: "graph-slice".to_string(),
                content_hash: "0xabc".to_string(),
                node_count: 1,
                edge_count: 0,
                created_at: now,
            },
            actor: None,
            effects: vec![effect],
            summary: "partial execution".to_string(),
        }
    }

    #[test]
    fn partial_quarantine_execution_can_build_rollback_report() {
        let execution = rollbackable_execution(
            EndpointDecisionAction::QuarantineFile,
            EndpointResponseExecutionStatus::Partial,
            EndpointResponseExecutionEffect::quarantine_file(
                "/tmp/source.txt",
                "/tmp/quarantine/source.txt",
                "0xabc",
                3,
            ),
        );

        let rollback =
            EndpointResponseRollbackReport::quarantine_file(&execution, "ttl rollback", Utc::now())
                .expect("partial quarantine rollback report");

        assert_eq!(rollback.effects[0].effect_type, "restore_quarantine_file");
    }

    #[test]
    fn partial_suspend_execution_can_build_rollback_report() {
        let execution = rollbackable_execution(
            EndpointDecisionAction::SuspendProcessTree,
            EndpointResponseExecutionStatus::Partial,
            EndpointResponseExecutionEffect::suspend_process_tree(42, &[42, 43]),
        );

        let rollback = EndpointResponseRollbackReport::suspend_process_tree(
            &execution,
            "ttl rollback",
            Utc::now(),
        )
        .expect("partial suspend rollback report");

        assert_eq!(rollback.effects[0].effect_type, "resume_process_tree");
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointResponseExecutionStatus {
    #[default]
    Succeeded,
    Failed,
    Partial,
    RollbackPending,
    RollbackFailed,
    Expired,
    Cancelled,
    RolledBack,
}

impl EndpointResponseExecutionStatus {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::RollbackPending => "rollback_pending",
            Self::RollbackFailed => "rollback_failed",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::RolledBack => "rolled_back",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseExecutionEffect {
    pub effect_id: String,
    pub effect_type: String,
    pub target: String,
    pub artifact: Option<String>,
    pub content_hash: Option<String>,
    pub byte_count: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointResponseProcessIdentityBinding {
    pub pid: u32,
    pub process_identity_key: String,
}

impl EndpointResponseExecutionEffect {
    #[must_use]
    pub fn quarantine_file(
        original_path: impl AsRef<str>,
        quarantine_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Self {
        let original_path = original_path.as_ref();
        let quarantine_path = quarantine_path.as_ref();
        let content_hash = content_hash.as_ref();
        let effect_id = stable_id(
            "response_effect_quarantine_file",
            [original_path, quarantine_path, content_hash],
        );
        Self {
            effect_id,
            effect_type: "quarantine_file".to_string(),
            target: original_path.to_string(),
            artifact: Some(quarantine_path.to_string()),
            content_hash: Some(content_hash.to_string()),
            byte_count: Some(byte_count),
        }
    }

    #[must_use]
    pub fn restore_quarantine_file(
        original_path: impl AsRef<str>,
        quarantine_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Self {
        let original_path = original_path.as_ref();
        let quarantine_path = quarantine_path.as_ref();
        let content_hash = content_hash.as_ref();
        let effect_id = stable_id(
            "response_effect_restore_quarantine_file",
            [original_path, quarantine_path, content_hash],
        );
        Self {
            effect_id,
            effect_type: "restore_quarantine_file".to_string(),
            target: original_path.to_string(),
            artifact: Some(quarantine_path.to_string()),
            content_hash: Some(content_hash.to_string()),
            byte_count: Some(byte_count),
        }
    }

    #[must_use]
    pub fn disable_persistence(
        original_path: impl AsRef<str>,
        disabled_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Self {
        let original_path = original_path.as_ref();
        let disabled_path = disabled_path.as_ref();
        let content_hash = content_hash.as_ref();
        let effect_id = stable_id(
            "response_effect_disable_persistence",
            [original_path, disabled_path, content_hash],
        );
        Self {
            effect_id,
            effect_type: "disable_persistence".to_string(),
            target: original_path.to_string(),
            artifact: Some(disabled_path.to_string()),
            content_hash: Some(content_hash.to_string()),
            byte_count: Some(byte_count),
        }
    }

    #[must_use]
    pub fn restore_persistence_file(
        original_path: impl AsRef<str>,
        disabled_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Self {
        let original_path = original_path.as_ref();
        let disabled_path = disabled_path.as_ref();
        let content_hash = content_hash.as_ref();
        let effect_id = stable_id(
            "response_effect_restore_persistence_file",
            [original_path, disabled_path, content_hash],
        );
        Self {
            effect_id,
            effect_type: "restore_persistence_file".to_string(),
            target: original_path.to_string(),
            artifact: Some(disabled_path.to_string()),
            content_hash: Some(content_hash.to_string()),
            byte_count: Some(byte_count),
        }
    }

    #[must_use]
    pub fn revoke_grant(target: impl AsRef<str>, revoked_grant_hash: impl AsRef<str>) -> Self {
        let target = target.as_ref();
        let revoked_grant_hash = revoked_grant_hash.as_ref();
        let effect_id = stable_id("response_effect_revoke_grant", [target, revoked_grant_hash]);
        Self {
            effect_id,
            effect_type: "revoke_grant".to_string(),
            target: target.to_string(),
            artifact: None,
            content_hash: Some(revoked_grant_hash.to_string()),
            byte_count: None,
        }
    }

    #[must_use]
    pub fn restrict_egress(primary_target: impl AsRef<str>, targets: &[String]) -> Self {
        let primary_target = primary_target.as_ref();
        let mut targets = targets.to_vec();
        targets.sort();
        targets.dedup();
        let target_list = targets.join(",");
        let content_hash = sha256(target_list.as_bytes()).to_hex_prefixed();
        let target = format!("egress:{primary_target}");
        let effect_id = stable_id(
            "response_effect_restrict_egress",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "restrict_egress".to_string(),
            target,
            artifact: Some(target_list),
            content_hash: Some(content_hash),
            byte_count: Some(targets.len() as u64),
        }
    }

    #[must_use]
    pub fn restore_egress(primary_target: impl AsRef<str>, targets: &[String]) -> Self {
        let primary_target = primary_target.as_ref();
        let mut targets = targets.to_vec();
        targets.sort();
        targets.dedup();
        let target_list = targets.join(",");
        let content_hash = sha256(target_list.as_bytes()).to_hex_prefixed();
        let target = format!("egress:{primary_target}");
        let effect_id = stable_id(
            "response_effect_restore_egress",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "restore_egress".to_string(),
            target,
            artifact: Some(target_list),
            content_hash: Some(content_hash),
            byte_count: Some(targets.len() as u64),
        }
    }

    #[must_use]
    pub fn suspend_process_tree(root_pid: u32, pids: &[u32]) -> Self {
        let mut pids = pids.to_vec();
        pids.sort_unstable();
        pids.dedup();
        let pid_list = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let content_hash = sha256(pid_list.as_bytes()).to_hex_prefixed();
        let target = format!("pid:{root_pid}");
        let effect_id = stable_id(
            "response_effect_suspend_process_tree",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "suspend_process_tree".to_string(),
            target,
            artifact: Some(pid_list),
            content_hash: Some(content_hash),
            byte_count: Some(pids.len() as u64),
        }
    }

    #[must_use]
    pub fn suspend_process_tree_with_identities(
        root_pid: u32,
        bindings: &[EndpointResponseProcessIdentityBinding],
    ) -> Self {
        let (artifact, content_hash, count) = process_identity_binding_artifact(bindings);
        let target = format!("pid:{root_pid}");
        let effect_id = stable_id(
            "response_effect_suspend_process_tree",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "suspend_process_tree".to_string(),
            target,
            artifact: Some(artifact),
            content_hash: Some(content_hash),
            byte_count: Some(count),
        }
    }

    #[must_use]
    pub fn resume_process_tree(root_pid: u32, pids: &[u32]) -> Self {
        let mut pids = pids.to_vec();
        pids.sort_unstable();
        pids.dedup();
        let pid_list = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let content_hash = sha256(pid_list.as_bytes()).to_hex_prefixed();
        let target = format!("pid:{root_pid}");
        let effect_id = stable_id(
            "response_effect_resume_process_tree",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "resume_process_tree".to_string(),
            target,
            artifact: Some(pid_list),
            content_hash: Some(content_hash),
            byte_count: Some(pids.len() as u64),
        }
    }

    #[must_use]
    pub fn resume_process_tree_from_artifact(root_pid: u32, artifact: impl AsRef<str>) -> Self {
        let artifact = canonical_process_tree_artifact(artifact.as_ref())
            .unwrap_or_else(|_| artifact.as_ref().trim().to_string());
        let count = artifact
            .split(',')
            .filter(|item| !item.trim().is_empty())
            .count() as u64;
        let content_hash = sha256(artifact.as_bytes()).to_hex_prefixed();
        let target = format!("pid:{root_pid}");
        let effect_id = stable_id(
            "response_effect_resume_process_tree",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "resume_process_tree".to_string(),
            target,
            artifact: Some(artifact),
            content_hash: Some(content_hash),
            byte_count: Some(count),
        }
    }

    #[must_use]
    pub fn terminate_process_tree(root_pid: u32, pids: &[u32]) -> Self {
        let mut pids = pids.to_vec();
        pids.sort_unstable();
        pids.dedup();
        let pid_list = pids
            .iter()
            .map(u32::to_string)
            .collect::<Vec<_>>()
            .join(",");
        let content_hash = sha256(pid_list.as_bytes()).to_hex_prefixed();
        let target = format!("pid:{root_pid}");
        let effect_id = stable_id(
            "response_effect_terminate_process_tree",
            [target.as_str(), content_hash.as_str()],
        );
        Self {
            effect_id,
            effect_type: "terminate_process_tree".to_string(),
            target,
            artifact: Some(pid_list),
            content_hash: Some(content_hash),
            byte_count: Some(pids.len() as u64),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseExecutionReport {
    pub execution_id: String,
    pub action_id: String,
    pub action: EndpointDecisionAction,
    pub status: EndpointResponseExecutionStatus,
    pub dry_run: bool,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub ttl_seconds: u64,
    pub rollback_ref: String,
    pub reason: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    pub evidence_bundle: EndpointEvidenceBundleReference,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<EndpointDecisionActor>,
    #[serde(default)]
    pub effects: Vec<EndpointResponseExecutionEffect>,
    pub summary: String,
}

impl Default for EndpointResponseExecutionReport {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            execution_id: String::new(),
            action_id: String::new(),
            action: EndpointDecisionAction::CollectEvidence,
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: String::new(),
            graph_slice_id: String::new(),
            ttl_seconds: 0,
            rollback_ref: String::new(),
            reason: String::new(),
            started_at: now,
            completed_at: now,
            evidence_bundle: EndpointEvidenceBundleReference::default(),
            actor: None,
            effects: Vec::new(),
            summary: String::new(),
        }
    }
}

impl EndpointResponseExecutionReport {
    pub fn collect_evidence(plan: &EndpointResponsePlan, graph: &CausalGraph) -> Result<Self> {
        if plan.action != EndpointDecisionAction::CollectEvidence {
            return Err(anyhow!(
                "collect evidence execution report requires collect_evidence action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "collect evidence execution report requires a non-dry-run plan"
            ));
        }

        let content_hash = response_graph_content_hash(&plan.root_node_id, graph)?;
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                content_hash.as_str(),
            ],
        );
        let execution_id = stable_id(
            "response_execution",
            [
                plan.action_id.as_str(),
                evidence_bundle_id.as_str(),
                content_hash.as_str(),
            ],
        );
        let started_at = Utc::now();
        let completed_at = started_at;
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let summary = format!(
            "Collected endpoint evidence graph slice {} with {} nodes and {} edges.",
            plan.graph_slice_id, evidence_bundle.node_count, evidence_bundle.edge_count
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects: Vec::new(),
            summary,
        })
    }

    pub fn failed(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        failure: impl AsRef<str>,
    ) -> Result<Self> {
        if plan.dry_run {
            return Err(anyhow!(
                "failed execution report requires a non-dry-run plan"
            ));
        }
        let failure = failure.as_ref().trim();
        if failure.is_empty() {
            return Err(anyhow!("failed execution report requires a failure reason"));
        }

        let content_hash = response_graph_content_hash(&plan.root_node_id, graph)?;
        let reason = format!("{}; failure: {failure}", plan.reason);
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                content_hash.as_str(),
                "failed",
            ],
        );
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_failed",
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            plan.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Failed,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason,
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects: Vec::new(),
            summary: format!(
                "Endpoint response action {} failed before local effects: {failure}",
                plan.action.as_str()
            ),
        })
    }

    pub fn restrict_egress(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        targets: &[String],
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::RestrictEgress {
            return Err(anyhow!(
                "restrict egress execution report requires restrict_egress action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "restrict egress execution report requires a non-dry-run plan"
            ));
        }
        let primary_target = targets
            .first()
            .ok_or_else(|| anyhow!("restrict egress execution report requires a target"))?;

        let graph_content_hash = response_graph_content_hash(&plan.root_node_id, graph)?;
        let effect = EndpointResponseExecutionEffect::restrict_egress(primary_target, targets);
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            std::slice::from_ref(&effect),
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let target_count = effect.byte_count.unwrap_or(0);
        let summary = format!(
            "Restricted local egress to {target_count} network targets from graph slice {}.",
            plan.graph_slice_id
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects: vec![effect],
            summary,
        })
    }

    pub fn quarantine_file(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        original_path: impl AsRef<str>,
        quarantine_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::QuarantineFile {
            return Err(anyhow!(
                "quarantine file execution report requires quarantine_file action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "quarantine file execution report requires a non-dry-run plan"
            ));
        }

        let original_path = original_path.as_ref();
        let quarantine_path = quarantine_path.as_ref();
        let content_hash = content_hash.as_ref();
        let graph_content_hash = response_graph_content_hash(&plan.root_node_id, graph)?;
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let effects = vec![EndpointResponseExecutionEffect::quarantine_file(
            original_path,
            quarantine_path,
            content_hash,
            byte_count,
        )];
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            &effects,
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let summary = format!(
            "Quarantined file {} to {} with hash {}.",
            original_path, quarantine_path, content_hash
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects,
            summary,
        })
    }

    pub fn disable_persistence(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        original_path: impl AsRef<str>,
        disabled_path: impl AsRef<str>,
        content_hash: impl AsRef<str>,
        byte_count: u64,
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::DisablePersistence {
            return Err(anyhow!(
                "disable persistence execution report requires disable_persistence action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "disable persistence execution report requires a non-dry-run plan"
            ));
        }

        let original_path = original_path.as_ref();
        let disabled_path = disabled_path.as_ref();
        let content_hash = content_hash.as_ref();
        let graph_content_hash = response_graph_content_hash(&plan.root_node_id, graph)?;
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let effects = vec![EndpointResponseExecutionEffect::disable_persistence(
            original_path,
            disabled_path,
            content_hash,
            byte_count,
        )];
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            &effects,
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let summary = format!(
            "Disabled persistence file {} to {} with hash {}.",
            original_path, disabled_path, content_hash
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects,
            summary,
        })
    }

    pub fn revoke_grant(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        grant_target: impl AsRef<str>,
        revoked_grant_hash: impl AsRef<str>,
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::RevokeGrant {
            return Err(anyhow!(
                "revoke grant execution report requires revoke_grant action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "revoke grant execution report requires a non-dry-run plan"
            ));
        }

        let grant_target = grant_target.as_ref();
        let revoked_grant_hash = revoked_grant_hash.as_ref();
        let graph_content_hash = response_graph_content_hash(&plan.root_node_id, graph)?;
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let effects = vec![EndpointResponseExecutionEffect::revoke_grant(
            grant_target,
            revoked_grant_hash,
        )];
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            &effects,
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let summary = format!(
            "Revoked local grant {grant_target} and recorded bounded credential revocation effect."
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects,
            summary,
        })
    }

    pub fn suspend_process_tree(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        root_pid: u32,
        pids: &[u32],
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::SuspendProcessTree {
            return Err(anyhow!(
                "suspend process tree execution report requires suspend_process_tree action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "suspend process tree execution report requires a non-dry-run plan"
            ));
        }
        if pids.is_empty() {
            return Err(anyhow!(
                "suspend process tree execution report requires at least one pid"
            ));
        }

        let graph_content_hash = response_graph_content_hash(&plan.root_node_id, graph)?;
        let effect = EndpointResponseExecutionEffect::suspend_process_tree(root_pid, pids);
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            std::slice::from_ref(&effect),
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let pid_count = effect.byte_count.unwrap_or(0);
        let summary =
            format!("Suspended process tree rooted at pid {root_pid} with {pid_count} processes.");

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects: vec![effect],
            summary,
        })
    }

    pub fn suspend_process_tree_with_identity_bindings(
        plan: &EndpointResponsePlan,
        graph: &CausalGraph,
        root_pid: u32,
        bindings: &[EndpointResponseProcessIdentityBinding],
    ) -> Result<Self> {
        if plan.action != EndpointDecisionAction::SuspendProcessTree {
            return Err(anyhow!(
                "suspend process tree execution report requires suspend_process_tree action"
            ));
        }
        if plan.dry_run {
            return Err(anyhow!(
                "suspend process tree execution report requires a non-dry-run plan"
            ));
        }
        if bindings.is_empty() {
            return Err(anyhow!(
                "suspend process tree execution report requires at least one identity-bound pid"
            ));
        }

        let graph_content_hash = response_graph_content_hash(&plan.root_node_id, graph)?;
        let effect = EndpointResponseExecutionEffect::suspend_process_tree_with_identities(
            root_pid, bindings,
        );
        let evidence_bundle_id = stable_id(
            "evidence_bundle",
            [
                plan.action_id.as_str(),
                plan.graph_slice_id.as_str(),
                graph_content_hash.as_str(),
            ],
        );
        let execution_id = response_execution_id_from_effects(
            plan.action_id.as_str(),
            evidence_bundle_id.as_str(),
            std::slice::from_ref(&effect),
        )?;
        let completed_at = Utc::now();
        let evidence_bundle = EndpointEvidenceBundleReference {
            bundle_id: evidence_bundle_id,
            graph_slice_id: plan.graph_slice_id.clone(),
            content_hash: graph_content_hash,
            node_count: graph.nodes.len(),
            edge_count: graph.edges.len(),
            created_at: completed_at,
        };
        let pid_count = effect.byte_count.unwrap_or(0);
        let summary = format!(
            "Suspended process tree rooted at pid {root_pid} with {pid_count} identity-bound processes."
        );

        Ok(Self {
            execution_id,
            action_id: plan.action_id.clone(),
            action: plan.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            dry_run: false,
            root_node_id: plan.root_node_id.clone(),
            graph_slice_id: plan.graph_slice_id.clone(),
            ttl_seconds: plan.ttl_seconds,
            rollback_ref: plan.rollback_ref.clone(),
            reason: plan.reason.clone(),
            started_at: completed_at,
            completed_at,
            evidence_bundle,
            actor: None,
            effects: vec![effect],
            summary,
        })
    }

    pub fn terminate_process_tree(
        _plan: &EndpointResponsePlan,
        _graph: &CausalGraph,
        _root_pid: u32,
        _pids: &[u32],
    ) -> Result<Self> {
        Err(anyhow!(
            "terminate_process_tree execution reports are disabled because the action is not rollback-capable; use dry-run modeling or suspend_process_tree"
        ))
    }

    #[must_use]
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.started_at + chrono::Duration::seconds(self.ttl_seconds as i64)
    }

    #[must_use]
    pub fn expired_from(execution: &Self, completed_at: DateTime<Utc>) -> Self {
        let reason = format!("response execution {} TTL expired", execution.execution_id);
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_expired",
            execution.action_id.as_str(),
            execution.evidence_bundle.bundle_id.as_str(),
            execution.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        Self {
            execution_id,
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Expired,
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason,
            started_at: execution.started_at,
            completed_at,
            evidence_bundle: execution.evidence_bundle.clone(),
            actor: execution.actor.clone(),
            effects: execution.effects.clone(),
            summary: format!(
                "Response execution {} expired after {} seconds; rollback ref {}.",
                execution.execution_id, execution.ttl_seconds, execution.rollback_ref
            ),
        }
    }

    #[must_use]
    pub fn cancelled_from(
        execution: &Self,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Self {
        let reason = reason.into();
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_cancelled",
            execution.action_id.as_str(),
            execution.evidence_bundle.bundle_id.as_str(),
            execution.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        Self {
            execution_id,
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Cancelled,
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason,
            started_at: execution.started_at,
            completed_at,
            evidence_bundle: execution.evidence_bundle.clone(),
            actor: execution.actor.clone(),
            effects: execution.effects.clone(),
            summary: format!(
                "Response execution {} was cancelled; rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        }
    }

    #[must_use]
    pub fn rolled_back_from(
        execution: &Self,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Self {
        let reason = reason.into();
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_rolled_back",
            execution.action_id.as_str(),
            execution.evidence_bundle.bundle_id.as_str(),
            execution.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        Self {
            execution_id,
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::RolledBack,
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason,
            started_at: execution.started_at,
            completed_at,
            evidence_bundle: execution.evidence_bundle.clone(),
            actor: execution.actor.clone(),
            effects: execution.effects.clone(),
            summary: format!(
                "Response execution {} was rolled back; rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        }
    }

    #[must_use]
    pub fn rollback_pending_from(
        execution: &Self,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Self {
        let reason = reason.into();
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_rollback_pending",
            execution.action_id.as_str(),
            execution.evidence_bundle.bundle_id.as_str(),
            execution.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        Self {
            execution_id,
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::RollbackPending,
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason,
            started_at: execution.started_at,
            completed_at,
            evidence_bundle: execution.evidence_bundle.clone(),
            actor: execution.actor.clone(),
            effects: execution.effects.clone(),
            summary: format!(
                "Response execution {} rollback was durably requested before local rollback side effects; rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        }
    }

    #[must_use]
    pub fn rollback_failed_from(
        execution: &Self,
        reason: impl Into<String>,
        failure: impl AsRef<str>,
        completed_at: DateTime<Utc>,
    ) -> Self {
        let failure = failure.as_ref().trim();
        let reason = format!("{}; rollback failure: {failure}", reason.into());
        let reason_hash = sha256(reason.as_bytes()).to_hex_prefixed();
        let execution_id = response_execution_transition_id_from_reason_hash(
            "response_execution_rollback_failed",
            execution.action_id.as_str(),
            execution.evidence_bundle.bundle_id.as_str(),
            execution.rollback_ref.as_str(),
            reason_hash.as_str(),
        );
        Self {
            execution_id,
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::RollbackFailed,
            dry_run: execution.dry_run,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason,
            started_at: execution.started_at,
            completed_at,
            evidence_bundle: execution.evidence_bundle.clone(),
            actor: execution.actor.clone(),
            effects: execution.effects.clone(),
            summary: format!(
                "Response execution {} rollback failed after durable rollback intent; rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        }
    }
}

fn response_graph_content_hash(root_node_id: &str, graph: &CausalGraph) -> Result<String> {
    EndpointGraphReference::for_subgraph(root_node_id, graph)
        .content_hash
        .ok_or_else(|| anyhow!("response graph content hash is required"))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseRollbackReport {
    pub rollback_id: String,
    pub execution_id: String,
    pub action_id: String,
    pub action: EndpointDecisionAction,
    pub status: EndpointResponseExecutionStatus,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub ttl_seconds: u64,
    pub rollback_ref: String,
    pub reason: String,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
    #[serde(default)]
    pub effects: Vec<EndpointResponseExecutionEffect>,
    pub summary: String,
}

impl Default for EndpointResponseRollbackReport {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            rollback_id: String::new(),
            execution_id: String::new(),
            action_id: String::new(),
            action: EndpointDecisionAction::QuarantineFile,
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: String::new(),
            graph_slice_id: String::new(),
            ttl_seconds: 0,
            rollback_ref: String::new(),
            reason: String::new(),
            started_at: now,
            completed_at: now,
            effects: Vec::new(),
            summary: String::new(),
        }
    }
}

impl EndpointResponseRollbackReport {
    pub fn restrict_egress(
        execution: &EndpointResponseExecutionReport,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if execution.action != EndpointDecisionAction::RestrictEgress {
            return Err(anyhow!(
                "egress rollback report requires restrict_egress execution"
            ));
        }
        if !execution_status_has_rollback_effects(&execution.status) {
            return Err(anyhow!(
                "egress rollback report requires succeeded or partial execution"
            ));
        }
        let effect = execution
            .effects
            .iter()
            .find(|effect| effect.effect_type == "restrict_egress")
            .ok_or_else(|| anyhow!("egress rollback report requires restrict_egress effect"))?;
        let artifact = effect
            .artifact
            .as_deref()
            .ok_or_else(|| anyhow!("egress rollback report requires target artifact"))?;
        let content_hash = effect
            .content_hash
            .as_deref()
            .ok_or_else(|| anyhow!("egress rollback report requires content hash"))?;
        let byte_count = effect
            .byte_count
            .ok_or_else(|| anyhow!("egress rollback report requires target count"))?;
        let primary_target = effect
            .target
            .strip_prefix("egress:")
            .ok_or_else(|| anyhow!("egress rollback target must be egress-prefixed"))?;
        let targets = parse_string_artifact(artifact, "egress target")?;
        let restore_effect =
            EndpointResponseExecutionEffect::restore_egress(primary_target, &targets);
        if restore_effect.content_hash.as_deref() != Some(content_hash)
            || restore_effect.byte_count != Some(byte_count)
        {
            return Err(anyhow!(
                "egress rollback effect does not match original restricted target set"
            ));
        }
        let effects = vec![restore_effect];
        let rollback_id = response_rollback_id_from_effects(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            &effects,
        )?;
        Ok(Self {
            rollback_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: reason.into(),
            started_at: completed_at,
            completed_at,
            effects,
            summary: format!(
                "Rolled back egress restriction execution {} using rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        })
    }

    pub fn quarantine_file(
        execution: &EndpointResponseExecutionReport,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if execution.action != EndpointDecisionAction::QuarantineFile {
            return Err(anyhow!(
                "quarantine rollback report requires quarantine_file execution"
            ));
        }
        if !execution_status_has_rollback_effects(&execution.status) {
            return Err(anyhow!(
                "quarantine rollback report requires succeeded or partial execution"
            ));
        }
        let effect = execution
            .effects
            .iter()
            .find(|effect| effect.effect_type == "quarantine_file")
            .ok_or_else(|| anyhow!("quarantine rollback report requires quarantine_file effect"))?;
        let artifact = effect
            .artifact
            .as_deref()
            .ok_or_else(|| anyhow!("quarantine rollback report requires artifact path"))?;
        let content_hash = effect
            .content_hash
            .as_deref()
            .ok_or_else(|| anyhow!("quarantine rollback report requires content hash"))?;
        let byte_count = effect
            .byte_count
            .ok_or_else(|| anyhow!("quarantine rollback report requires byte count"))?;
        let effects = vec![EndpointResponseExecutionEffect::restore_quarantine_file(
            effect.target.as_str(),
            artifact,
            content_hash,
            byte_count,
        )];
        let rollback_id = response_rollback_id_from_effects(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            &effects,
        )?;
        Ok(Self {
            rollback_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: reason.into(),
            started_at: completed_at,
            completed_at,
            effects,
            summary: format!(
                "Rolled back quarantine execution {} using rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        })
    }

    pub fn disable_persistence(
        execution: &EndpointResponseExecutionReport,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if execution.action != EndpointDecisionAction::DisablePersistence {
            return Err(anyhow!(
                "persistence rollback report requires disable_persistence execution"
            ));
        }
        if !execution_status_has_rollback_effects(&execution.status) {
            return Err(anyhow!(
                "persistence rollback report requires succeeded or partial execution"
            ));
        }
        let effect = execution
            .effects
            .iter()
            .find(|effect| effect.effect_type == "disable_persistence")
            .ok_or_else(|| {
                anyhow!("persistence rollback report requires disable_persistence effect")
            })?;
        let artifact = effect
            .artifact
            .as_deref()
            .ok_or_else(|| anyhow!("persistence rollback report requires artifact path"))?;
        let content_hash = effect
            .content_hash
            .as_deref()
            .ok_or_else(|| anyhow!("persistence rollback report requires content hash"))?;
        let byte_count = effect
            .byte_count
            .ok_or_else(|| anyhow!("persistence rollback report requires byte count"))?;
        let effects = vec![EndpointResponseExecutionEffect::restore_persistence_file(
            effect.target.as_str(),
            artifact,
            content_hash,
            byte_count,
        )];
        let rollback_id = response_rollback_id_from_effects(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            &effects,
        )?;
        Ok(Self {
            rollback_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: reason.into(),
            started_at: completed_at,
            completed_at,
            effects,
            summary: format!(
                "Rolled back persistence-disable execution {} using rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        })
    }

    pub fn suspend_process_tree(
        execution: &EndpointResponseExecutionReport,
        reason: impl Into<String>,
        completed_at: DateTime<Utc>,
    ) -> Result<Self> {
        if execution.action != EndpointDecisionAction::SuspendProcessTree {
            return Err(anyhow!(
                "process tree rollback report requires suspend_process_tree execution"
            ));
        }
        if !execution_status_has_rollback_effects(&execution.status) {
            return Err(anyhow!(
                "process tree rollback report requires succeeded or partial execution"
            ));
        }
        let effect = execution
            .effects
            .iter()
            .find(|effect| effect.effect_type == "suspend_process_tree")
            .ok_or_else(|| {
                anyhow!("process tree rollback report requires suspend_process_tree effect")
            })?;
        let artifact = effect
            .artifact
            .as_deref()
            .ok_or_else(|| anyhow!("process tree rollback report requires pid artifact"))?;
        let content_hash = effect
            .content_hash
            .as_deref()
            .ok_or_else(|| anyhow!("process tree rollback report requires content hash"))?;
        let byte_count = effect
            .byte_count
            .ok_or_else(|| anyhow!("process tree rollback report requires pid count"))?;
        let root_pid = effect
            .target
            .strip_prefix("pid:")
            .ok_or_else(|| anyhow!("process tree rollback target must be pid-prefixed"))?
            .parse::<u32>()
            .context("parse process tree rollback root pid")?;
        let resume_effect =
            EndpointResponseExecutionEffect::resume_process_tree_from_artifact(root_pid, artifact);
        if resume_effect.content_hash.as_deref() != Some(content_hash)
            || resume_effect.byte_count != Some(byte_count)
        {
            return Err(anyhow!(
                "process tree rollback effect does not match original suspended pid set"
            ));
        }
        let effects = vec![resume_effect];
        let rollback_id = response_rollback_id_from_effects(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            &effects,
        )?;
        Ok(Self {
            rollback_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            reason: reason.into(),
            started_at: completed_at,
            completed_at,
            effects,
            summary: format!(
                "Resumed suspended process tree execution {} using rollback ref {}.",
                execution.execution_id, execution.rollback_ref
            ),
        })
    }
}

fn execution_status_has_rollback_effects(status: &EndpointResponseExecutionStatus) -> bool {
    matches!(
        status,
        EndpointResponseExecutionStatus::Succeeded
            | EndpointResponseExecutionStatus::Partial
            | EndpointResponseExecutionStatus::RollbackPending
            | EndpointResponseExecutionStatus::RollbackFailed
    )
}

fn process_identity_binding_artifact(
    bindings: &[EndpointResponseProcessIdentityBinding],
) -> (String, String, u64) {
    let mut items = bindings
        .iter()
        .map(|binding| (binding.pid, binding.process_identity_key.trim().to_string()))
        .filter(|(_, identity)| !identity.is_empty())
        .collect::<Vec<_>>();
    items.sort();
    items.dedup();
    let artifact = items
        .iter()
        .map(|(pid, identity)| format!("{pid}={identity}"))
        .collect::<Vec<_>>()
        .join(",");
    let content_hash = sha256(artifact.as_bytes()).to_hex_prefixed();
    (artifact, content_hash, items.len() as u64)
}

fn canonical_process_tree_artifact(artifact: &str) -> Result<String> {
    let mut entries = Vec::new();
    for item in artifact.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (pid, identity) = match item.split_once('=') {
            Some((pid, identity)) => (
                pid.trim()
                    .parse::<u32>()
                    .with_context(|| format!("parse process tree effect pid {pid}"))?,
                Some(identity.trim().to_string()),
            ),
            None => (
                item.parse::<u32>()
                    .with_context(|| format!("parse process tree effect pid {item}"))?,
                None,
            ),
        };
        if identity.as_deref().is_some_and(str::is_empty) {
            return Err(anyhow!(
                "process tree effect identity binding for pid {pid} is empty"
            ));
        }
        entries.push((pid, identity));
    }
    if entries.is_empty() {
        return Err(anyhow!("process tree effect contains no pids"));
    }
    entries.sort();
    entries.dedup();
    Ok(entries
        .into_iter()
        .map(|(pid, identity)| match identity {
            Some(identity) => format!("{pid}={identity}"),
            None => pid.to_string(),
        })
        .collect::<Vec<_>>()
        .join(","))
}

fn parse_pid_artifact(artifact: &str) -> Result<Vec<u32>> {
    let mut pids = Vec::new();
    for item in artifact.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let item = item
            .split_once('=')
            .map_or(item, |(pid, _identity)| pid.trim());
        pids.push(
            item.parse::<u32>()
                .with_context(|| format!("parse pid artifact item {item}"))?,
        );
    }
    if pids.is_empty() {
        return Err(anyhow!("pid artifact must contain at least one pid"));
    }
    pids.sort_unstable();
    pids.dedup();
    Ok(pids)
}

fn parse_string_artifact(artifact: &str, item_name: &str) -> Result<Vec<String>> {
    let mut items = Vec::new();
    for item in artifact.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        items.push(item.to_string());
    }
    if items.is_empty() {
        return Err(anyhow!(
            "{item_name} artifact must contain at least one item"
        ));
    }
    items.sort();
    items.dedup();
    Ok(items)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseControlCorrelation {
    pub response_action_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery_id: Option<String>,
    pub target_kind: String,
    pub target_id: String,
    pub ack_token_hash: String,
    pub ack_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resulting_state: Option<String>,
}

impl Default for EndpointResponseControlCorrelation {
    fn default() -> Self {
        Self {
            response_action_id: String::new(),
            delivery_id: None,
            target_kind: String::new(),
            target_id: String::new(),
            ack_token_hash: String::new(),
            ack_status: "acknowledged".to_string(),
            resulting_state: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointResponseAcknowledgementReport {
    pub acknowledgement_id: String,
    pub execution_id: String,
    pub action_id: String,
    pub action: EndpointDecisionAction,
    pub status: EndpointResponseExecutionStatus,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub ttl_seconds: u64,
    pub rollback_ref: String,
    pub acknowledged_by: String,
    pub note: Option<String>,
    pub acknowledged_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_correlation: Option<EndpointResponseControlCorrelation>,
    #[serde(default)]
    pub effects: Vec<EndpointResponseExecutionEffect>,
    pub summary: String,
}

impl Default for EndpointResponseAcknowledgementReport {
    fn default() -> Self {
        Self {
            acknowledgement_id: String::new(),
            execution_id: String::new(),
            action_id: String::new(),
            action: EndpointDecisionAction::Observe,
            status: EndpointResponseExecutionStatus::Succeeded,
            root_node_id: String::new(),
            graph_slice_id: String::new(),
            ttl_seconds: 0,
            rollback_ref: String::new(),
            acknowledged_by: String::new(),
            note: None,
            acknowledged_at: Utc::now(),
            control_correlation: None,
            effects: Vec::new(),
            summary: String::new(),
        }
    }
}

impl EndpointResponseAcknowledgementReport {
    #[must_use]
    pub fn from_execution(
        execution: &EndpointResponseExecutionReport,
        acknowledged_by: impl Into<String>,
        note: Option<String>,
        acknowledged_at: DateTime<Utc>,
    ) -> Self {
        let acknowledged_by = acknowledged_by.into();
        let acknowledgement_id = response_acknowledgement_id_from_report_fields(
            execution.execution_id.as_str(),
            execution.action_id.as_str(),
            execution.rollback_ref.as_str(),
            acknowledged_by.as_str(),
            note.as_deref(),
            &execution.effects,
        );
        Self {
            acknowledgement_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            action: execution.action.clone(),
            status: execution.status.clone(),
            root_node_id: execution.root_node_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            ttl_seconds: execution.ttl_seconds,
            rollback_ref: execution.rollback_ref.clone(),
            acknowledged_by,
            note,
            acknowledged_at,
            control_correlation: None,
            effects: execution.effects.clone(),
            summary: format!(
                "Acknowledged response execution {} with status {}.",
                execution.execution_id,
                execution.status.as_str()
            ),
        }
    }

    #[must_use]
    pub fn with_control_correlation(
        mut self,
        control_correlation: Option<EndpointResponseControlCorrelation>,
    ) -> Self {
        self.control_correlation = control_correlation;
        self.acknowledgement_id = response_acknowledgement_id_from_report_fields_with_control(
            self.execution_id.as_str(),
            self.action_id.as_str(),
            self.rollback_ref.as_str(),
            self.acknowledged_by.as_str(),
            self.note.as_deref(),
            &self.effects,
            self.control_correlation.as_ref(),
        );
        self
    }
}
