use super::super::*;

pub(crate) fn require_evidence_bundle_manifest_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_bundle_id: Option<&str>,
    graph_slice_id: Option<&str>,
    content_hash: Option<&str>,
    node_count: usize,
    edge_count: usize,
) -> Result<()> {
    let signed_bundle_id =
        signed_bundle_id.ok_or_else(|| anyhow!("evidence bundle id signed id is required"))?;
    let graph_slice_id =
        graph_slice_id.ok_or_else(|| anyhow!("evidence bundle graph slice id is required"))?;
    let content_hash =
        content_hash.ok_or_else(|| anyhow!("evidence bundle content hash is required"))?;
    require_evidence_value_hash(
        evidence,
        "evidenceBundleId",
        signed_bundle_id,
        "evidence bundle id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "evidence bundle graph slice evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        content_hash,
        "evidence bundle content hash evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "nodeCount",
        node_count.to_string(),
        "evidence bundle node count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "edgeCount",
        edge_count.to_string(),
        "evidence bundle edge count evidence",
    )
}
