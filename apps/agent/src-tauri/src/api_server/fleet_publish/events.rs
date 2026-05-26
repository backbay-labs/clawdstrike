//! JSON builders for fleet hunt event payloads (agent-secret-touch and evidence-bundle-archive).

use super::super::*;
use std::collections::BTreeSet;

pub(crate) fn fleet_hunt_event_for_agent_secret_touch(
    touch: &EdrAgentSecretTouch,
    tenant_id: &str,
    endpoint_agent_id: &str,
) -> serde_json::Value {
    let receipt_id = touch
        .receipt
        .receipt
        .receipt_id
        .clone()
        .unwrap_or_else(|| touch.credential_node_id.clone());
    let occurred_at = touch.receipt.receipt.timestamp.clone();
    let credential_kind = touch
        .credential_kind
        .clone()
        .unwrap_or_else(|| "credential".to_string());
    let session_id = first_graph_attribute(&touch.graph, "sessionId");
    serde_json::json!({
        "eventId": format!("agent-secret-touch:{endpoint_agent_id}:{receipt_id}"),
        "tenantId": tenant_id,
        "source": "receipt",
        "kind": "guard_decision",
        "occurredAt": occurred_at,
        "ingestedAt": chrono::Utc::now().to_rfc3339(),
        "severity": "high",
        "verdict": "warn",
        "summary": format!("AI agent touched {credential_kind}: {}", touch.credential_label),
        "actionType": "secret_access",
        "principal": {
            "endpointAgentId": endpoint_agent_id,
            "principalType": "endpoint_agent"
        },
        "sessionId": session_id,
        "detectionIds": ["agent_secret_touch"],
        "target": {
            "kind": "credential",
            "id": touch.credential_node_id,
            "name": touch.credential_label
        },
        "evidence": {
            "rawRef": format!("endpoint-receipt:{receipt_id}"),
            "schemaName": "clawdstrike.edr.agent_secret_touch.v1"
        },
        "attributes": {
            "credentialKind": credential_kind,
            "credentialPath": touch.path,
            "credentialName": touch.name,
            "agentNodeIds": touch.agent_node_ids,
            "agentLabels": touch.agent_labels,
            "processNodeIds": touch.process_node_ids,
            "graphNodeCount": touch.graph.nodes.len(),
            "graphEdgeCount": touch.graph.edges.len(),
            "endpointReceipt": touch.receipt
        }
    })
}

pub(crate) fn fleet_hunt_event_for_evidence_bundle_archive(
    archive_id: &str,
    archive_hash: &str,
    archive: &EdrEvidenceBundleArchive,
    verification: &EdrEvidenceBundleArchiveVerification,
    tenant_id: &str,
    endpoint_agent_id: &str,
) -> serde_json::Value {
    let receipt_ids = archive
        .receipts
        .iter()
        .filter_map(|receipt| receipt.receipt.receipt_id.clone())
        .collect::<Vec<_>>();
    let receipt_hashes = archive
        .receipts
        .iter()
        .filter_map(|receipt| {
            canonical_json_hash(receipt, "endpoint evidence bundle archive fleet receipt").ok()
        })
        .collect::<Vec<_>>();
    let receipt_families = archive
        .receipts
        .iter()
        .filter_map(|receipt| receipt_endpoint_decision_str(receipt, &["receiptFamily"]))
        .map(ToString::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let verification = serde_json::to_value(verification).unwrap_or_else(|_| {
        serde_json::json!({
            "verified": verification.verified,
            "receiptFailureCount": verification.receipt_failure_count
        })
    });

    serde_json::json!({
        "eventId": format!("evidence-bundle-archive:{endpoint_agent_id}:{archive_id}"),
        "tenantId": tenant_id,
        "source": "receipt",
        "kind": "detection_fired",
        "occurredAt": archive.bundle.created_at.to_rfc3339(),
        "ingestedAt": chrono::Utc::now().to_rfc3339(),
        "severity": "info",
        "verdict": "none",
        "summary": format!(
            "Endpoint evidence bundle archive ready: {}",
            archive.bundle.bundle_id
        ),
        "actionType": "evidence_bundle_archive",
        "principal": {
            "endpointAgentId": endpoint_agent_id,
            "principalType": "endpoint_agent"
        },
        "detectionIds": ["evidence_bundle_archive"],
        "target": {
            "kind": "evidence_bundle",
            "id": archive.bundle.bundle_id,
            "name": archive.bundle.graph_slice_id
        },
        "evidence": {
            "rawRef": evidence_bundle_archive_raw_ref(archive_id, archive_hash),
            "schemaName": "clawdstrike.edr.evidence_bundle_archive.v1"
        },
        "attributes": {
            "archiveId": archive_id,
            "archiveHash": archive_hash,
            "bundleId": archive.bundle.bundle_id,
            "graphSliceId": archive.bundle.graph_slice_id,
            "contentHash": archive.bundle.content_hash,
            "graphNodeCount": archive.bundle.node_count,
            "graphEdgeCount": archive.bundle.edge_count,
            "artifactByteCount": archive.artifact.byte_count,
            "receiptCount": archive.receipts.len(),
            "receiptIds": receipt_ids,
            "receiptHashes": receipt_hashes,
            "receiptFamilies": receipt_families,
            "verification": verification
        }
    })
}

pub(crate) fn evidence_bundle_archive_raw_ref(archive_id: &str, archive_hash: &str) -> String {
    format!("endpoint-evidence-bundle-archive:{archive_id}:{archive_hash}")
}
