use super::super::*;

pub(crate) fn require_graph_slice_content_hash_evidence(
    evidence: &[EndpointReceiptEvidence],
    content_hash: Option<&str>,
) -> Result<()> {
    let content_hash =
        content_hash.ok_or_else(|| anyhow!("graph slice content hash is required"))?;
    require_evidence_value_hash(
        evidence,
        "contentHash",
        content_hash,
        "graph slice content hash evidence",
    )
}

pub(crate) fn require_graph_slice_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_graph_slice_id: Option<&str>,
    graph_slice_id: Option<&str>,
    root_node_id: Option<&str>,
    node_count: usize,
    edge_count: usize,
) -> Result<()> {
    let signed_graph_slice_id =
        signed_graph_slice_id.ok_or_else(|| anyhow!("graph slice signed id is required"))?;
    let graph_slice_id = graph_slice_id.ok_or_else(|| anyhow!("graph slice id is required"))?;
    let root_node_id =
        root_node_id.ok_or_else(|| anyhow!("graph slice root node id is required"))?;
    if signed_graph_slice_id != graph_slice_id {
        return Err(anyhow!(
            "graph slice signed id must match graph reference id"
        ));
    }
    require_evidence_value_hash(
        evidence,
        "graphSliceId",
        graph_slice_id,
        "graph slice id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "rootNodeId",
        root_node_id,
        "graph slice root node evidence",
    )?;
    require_nonempty_hashed_evidence(evidence, "sliceKind", "graph slice kind evidence")?;
    require_evidence_value_hash(
        evidence,
        "nodeCount",
        node_count.to_string(),
        "graph slice node count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "edgeCount",
        edge_count.to_string(),
        "graph slice edge count evidence",
    )
}
