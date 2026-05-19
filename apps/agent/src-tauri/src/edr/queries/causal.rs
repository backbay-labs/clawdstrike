//! Pure helpers for causal graph queries: identity extraction and filtering.

use crate::api_server::node_attribute_string;
use crate::edr::dto::{
    EdrPolicyEventHistoryAffectedIdentities, EdrPolicyEventHistoryAffectedIdentity,
};
use clawdstrike_policy_event::edr::{CausalGraph, CausalNodeKind};

pub(crate) fn identity_filter_matches(expected: &Option<String>, actual: Option<&str>) -> bool {
    match expected.as_deref() {
        Some(expected) => actual == Some(expected),
        None => true,
    }
}

pub(crate) fn affected_identities_for_causal_impact(
    graph: &CausalGraph,
) -> EdrPolicyEventHistoryAffectedIdentities {
    let mut identities = EdrPolicyEventHistoryAffectedIdentities::default();
    for node in graph.nodes.values() {
        let target = match node.kind {
            CausalNodeKind::Host => Some((&mut identities.hosts, "hostId")),
            CausalNodeKind::User => Some((&mut identities.users, "userId")),
            CausalNodeKind::Session => Some((&mut identities.sessions, "sessionId")),
            CausalNodeKind::Agent => Some((&mut identities.agents, "agentId")),
            CausalNodeKind::Workload => Some((&mut identities.workloads, "workloadId")),
            CausalNodeKind::Approval => Some((&mut identities.approvals, "approvalId")),
            _ => None,
        };
        let Some((bucket, attribute_key)) = target else {
            continue;
        };
        let id = node_attribute_string(&node.attributes, attribute_key)
            .unwrap_or_else(|| node.label.clone());
        push_affected_identity(bucket, &node.node_id, &node.label, &id);
    }
    for node in graph.nodes.values() {
        if let Some(id) = node_attribute_string(&node.attributes, "hostId") {
            push_affected_identity(&mut identities.hosts, &node.node_id, &id, &id);
        }
        if let Some(id) = node_attribute_string(&node.attributes, "userId") {
            push_affected_identity(&mut identities.users, &node.node_id, &id, &id);
        }
        if let Some(id) = node_attribute_string(&node.attributes, "sessionId") {
            push_affected_identity(&mut identities.sessions, &node.node_id, &id, &id);
        }
        if let Some(id) = node_attribute_string(&node.attributes, "agentId") {
            push_affected_identity(&mut identities.agents, &node.node_id, &id, &id);
        }
        if let Some(id) = node_attribute_string(&node.attributes, "workloadId") {
            push_affected_identity(&mut identities.workloads, &node.node_id, &id, &id);
        }
        if let Some(id) = node_attribute_string(&node.attributes, "approvalId") {
            push_affected_identity(&mut identities.approvals, &node.node_id, &id, &id);
        }
    }
    identities
}

fn push_affected_identity(
    bucket: &mut Vec<EdrPolicyEventHistoryAffectedIdentity>,
    node_id: &str,
    label: &str,
    id: &str,
) {
    let id = id.trim();
    if id.is_empty() || bucket.iter().any(|identity| identity.id == id) {
        return;
    }
    bucket.push(EdrPolicyEventHistoryAffectedIdentity {
        node_id: node_id.to_string(),
        label: label.to_string(),
        id: id.to_string(),
    });
}
