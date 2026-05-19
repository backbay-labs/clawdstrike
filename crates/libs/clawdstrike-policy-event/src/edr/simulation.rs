use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use hush_core::canonicalize_json;
use serde::{Deserialize, Serialize};

use super::action::EndpointDecisionAction;
use super::causal::{CausalGraph, CausalNode, CausalNodeKind};
use super::receipt::evidence::EndpointGraphReference;
use super::{stable_id};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationRule {
    pub rule_id: String,
    pub action: EndpointDecisionAction,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointSimulationImpactLevel {
    #[default]
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl EndpointSimulationImpactLevel {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationAffectedNode {
    pub node_id: String,
    pub kind: CausalNodeKind,
    pub label: String,
    pub breakage_score: u8,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationIdentityContext {
    pub identity_kind: String,
    pub value: String,
    pub source_node_id: String,
    pub source_node_kind: CausalNodeKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationToolContext {
    pub tool_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    pub source_node_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySimulationReport {
    pub simulation_id: String,
    pub rule_id: String,
    pub action: EndpointDecisionAction,
    pub root_node_id: String,
    pub graph_slice_id: String,
    pub would_block: bool,
    pub created_at: DateTime<Utc>,
    pub affected_node_count: usize,
    pub affected_edge_count: usize,
    pub affected_process_count: usize,
    pub affected_file_count: usize,
    pub affected_network_count: usize,
    pub affected_credential_count: usize,
    pub affected_tool_count: usize,
    pub developer_breakage_score: u8,
    pub impact_level: EndpointSimulationImpactLevel,
    pub summary: String,
    pub affected_nodes: Vec<EndpointPolicySimulationAffectedNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_identities: Vec<EndpointPolicySimulationIdentityContext>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub affected_tools: Vec<EndpointPolicySimulationToolContext>,
}

impl EndpointPolicySimulationReport {
    #[must_use]
    pub fn for_rule(
        rule: EndpointPolicySimulationRule,
        root_node_id: impl Into<String>,
        graph: &CausalGraph,
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
        let mut affected_nodes: Vec<_> = graph
            .nodes
            .values()
            .map(classify_simulated_affected_node)
            .collect();
        affected_nodes.sort_by(|left, right| {
            right
                .breakage_score
                .cmp(&left.breakage_score)
                .then_with(|| left.node_id.cmp(&right.node_id))
        });

        let affected_node_count = graph.nodes.len();
        let affected_edge_count = graph.edges.len();
        let affected_process_count = count_nodes_by_kind(graph, CausalNodeKind::Process);
        let affected_file_count = count_nodes_by_kind(graph, CausalNodeKind::File);
        let affected_network_count = count_nodes_by_kind(graph, CausalNodeKind::Network);
        let affected_credential_count = count_nodes_by_kind(graph, CausalNodeKind::Credential);
        let affected_tool_count = count_nodes_by_kind(graph, CausalNodeKind::Tool);
        let affected_identities = simulation_identity_contexts(graph);
        let affected_tools = simulation_tool_contexts(graph);
        let would_block = simulation_action_would_block(&rule.action);
        let developer_breakage_score = if would_block {
            score_simulated_breakage(
                &affected_nodes,
                affected_node_count,
                affected_edge_count,
                affected_process_count,
                affected_credential_count,
            )
        } else {
            0
        };
        let impact_level = impact_level_for_score(developer_breakage_score);
        let action_name = rule.action.as_str();
        let score = developer_breakage_score.to_string();
        let simulation_id = stable_id(
            "policy_simulation",
            [
                root_node_id.as_str(),
                graph_slice_id.as_str(),
                rule.rule_id.as_str(),
                action_name,
                score.as_str(),
            ],
        );
        let summary = if would_block {
            format!(
                "Simulating {} for {} would affect {} nodes, {} edges, {} processes, {} network targets, and {} credential nodes; developer breakage score {}/100.",
                rule.rule_id,
                action_name,
                affected_node_count,
                affected_edge_count,
                affected_process_count,
                affected_network_count,
                affected_credential_count,
                developer_breakage_score
            )
        } else {
            format!(
                "Simulating {} for {} does not enforce a blocking action; developer breakage score 0/100.",
                rule.rule_id, action_name
            )
        };

        Self {
            simulation_id,
            rule_id: rule.rule_id,
            action: rule.action,
            root_node_id,
            graph_slice_id,
            would_block,
            created_at: Utc::now(),
            affected_node_count,
            affected_edge_count,
            affected_process_count,
            affected_file_count,
            affected_network_count,
            affected_credential_count,
            affected_tool_count,
            developer_breakage_score,
            impact_level,
            summary,
            affected_nodes,
            affected_identities,
            affected_tools,
        }
    }
}

fn simulation_identity_contexts(
    graph: &CausalGraph,
) -> Vec<EndpointPolicySimulationIdentityContext> {
    let mut contexts = BTreeMap::new();

    for node in graph.nodes.values() {
        collect_simulation_identity_context(
            &mut contexts,
            "host",
            &node.attributes,
            "hostId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "user",
            &node.attributes,
            "userId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "session",
            &node.attributes,
            "sessionId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "agent",
            &node.attributes,
            "agentId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "workload",
            &node.attributes,
            "workloadId",
            node,
        );
        collect_simulation_identity_context(
            &mut contexts,
            "approval",
            &node.attributes,
            "approvalId",
            node,
        );
    }

    contexts.into_values().collect()
}

fn collect_simulation_identity_context(
    contexts: &mut BTreeMap<(String, String), EndpointPolicySimulationIdentityContext>,
    identity_kind: &str,
    attributes: &BTreeMap<String, serde_json::Value>,
    attribute_key: &str,
    node: &CausalNode,
) {
    let Some(value) = attributes
        .get(attribute_key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return;
    };

    contexts
        .entry((identity_kind.to_string(), value.to_string()))
        .or_insert_with(|| EndpointPolicySimulationIdentityContext {
            identity_kind: identity_kind.to_string(),
            value: value.to_string(),
            source_node_id: node.node_id.clone(),
            source_node_kind: node.kind.clone(),
        });
}

fn simulation_tool_contexts(graph: &CausalGraph) -> Vec<EndpointPolicySimulationToolContext> {
    let mut contexts = BTreeMap::new();

    for node in graph.nodes.values() {
        if node.kind != CausalNodeKind::Tool {
            continue;
        }
        let tool_name = node.label.trim();
        if tool_name.is_empty() {
            continue;
        }
        let tool_call_id = node
            .attributes
            .get("toolCallId")
            .and_then(serde_json::Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        contexts
            .entry((tool_name.to_string(), tool_call_id.clone()))
            .or_insert_with(|| EndpointPolicySimulationToolContext {
                tool_name: tool_name.to_string(),
                tool_call_id,
                source_node_id: node.node_id.clone(),
            });
    }

    contexts.into_values().collect()
}

pub(crate) fn simulation_context_evidence_value<T: Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| canonicalize_json(&value).ok())
        .unwrap_or_else(|| "null".to_string())
}

fn classify_simulated_affected_node(node: &CausalNode) -> EndpointPolicySimulationAffectedNode {
    let (base_score, reason) = match node.kind {
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
        CausalNodeKind::Process => {
            if label_looks_like_developer_runtime(&node.label) {
                (
                    45,
                    "blocking this process affects a developer runtime or automation tool",
                )
            } else {
                (30, "blocking this process affects local execution")
            }
        }
        CausalNodeKind::File => {
            if label_looks_like_developer_artifact(&node.label) {
                (
                    35,
                    "blocking this file interaction may affect source, dependency, or build artifacts",
                )
            } else {
                (18, "blocking this file interaction may affect local files")
            }
        }
        CausalNodeKind::Network => {
            if label_looks_like_developer_network(&node.label) {
                (
                    40,
                    "blocking this network target may affect registry, source-control, or cloud workflows",
                )
            } else {
                (24, "blocking this network target may affect egress")
            }
        }
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

    EndpointPolicySimulationAffectedNode {
        node_id: node.node_id.clone(),
        kind: node.kind.clone(),
        label: node.label.clone(),
        breakage_score: base_score,
        reason: reason.to_string(),
    }
}

pub(crate) fn simulation_action_would_block(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::Block
            | EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
    )
}

fn score_simulated_breakage(
    affected_nodes: &[EndpointPolicySimulationAffectedNode],
    affected_node_count: usize,
    affected_edge_count: usize,
    affected_process_count: usize,
    affected_credential_count: usize,
) -> u8 {
    let max_node_score = affected_nodes
        .iter()
        .map(|node| node.breakage_score)
        .max()
        .unwrap_or(0);
    let breadth = affected_node_count
        .saturating_sub(1)
        .saturating_mul(4)
        .min(24) as u8;
    let edge_weight = affected_edge_count.saturating_mul(2).min(16) as u8;
    let process_weight = affected_process_count
        .saturating_sub(1)
        .saturating_mul(6)
        .min(18) as u8;
    let credential_weight = if affected_credential_count > 0 { 10 } else { 0 };

    max_node_score
        .saturating_add(breadth)
        .saturating_add(edge_weight)
        .saturating_add(process_weight)
        .saturating_add(credential_weight)
        .min(100)
}

pub(crate) fn impact_level_for_score(score: u8) -> EndpointSimulationImpactLevel {
    match score {
        0 => EndpointSimulationImpactLevel::None,
        1..=24 => EndpointSimulationImpactLevel::Low,
        25..=49 => EndpointSimulationImpactLevel::Medium,
        50..=74 => EndpointSimulationImpactLevel::High,
        _ => EndpointSimulationImpactLevel::Critical,
    }
}

fn count_nodes_by_kind(graph: &CausalGraph, kind: CausalNodeKind) -> usize {
    graph
        .nodes
        .values()
        .filter(|node| node.kind == kind)
        .count()
}

fn label_looks_like_developer_runtime(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    [
        "node",
        "npm",
        "pnpm",
        "yarn",
        "python",
        "pip",
        "cargo",
        "rustc",
        "go",
        "git",
        "gh ",
        "docker",
        "kubectl",
        "aws",
        "gcloud",
        "az",
        "terraform",
        "claude",
        "cursor",
        "code",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn label_looks_like_developer_artifact(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    [
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "cargo.toml",
        "cargo.lock",
        "pyproject.toml",
        "requirements.txt",
        ".npmrc",
        ".pypirc",
        ".aws/",
        ".ssh/",
        ".git/",
        "node_modules",
        "target/",
        ".venv",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

fn label_looks_like_developer_network(label: &str) -> bool {
    let lower = label.to_ascii_lowercase();
    [
        "github.com",
        "api.github.com",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
        "crates.io",
        "index.crates.io",
        "rubygems.org",
        "docker.io",
        "ghcr.io",
        "amazonaws.com",
        "googleapis.com",
        "azure.com",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

