//! Graph root resolution, slice export, evidence-bundle builders, and bounded validators.

use super::super::*;
use anyhow::Result;
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::{
    CausalGraph, EndpointEvidenceBundleReference, EndpointGraphReference, EndpointProcess,
};

pub(crate) fn resolve_causal_subgraph_root(
    input: &EdrCausalSubgraphInput,
) -> Result<String, (StatusCode, String)> {
    resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())
}

pub(crate) fn graph_slice_export_kind(value: Option<&str>) -> Result<String, (StatusCode, String)> {
    let kind = non_empty(value).unwrap_or("causal_subgraph");
    match kind {
        "causal_subgraph" | "causal_context" => Ok(kind.to_string()),
        _ => Err((
            StatusCode::BAD_REQUEST,
            "slice_kind must be causal_subgraph or causal_context".to_string(),
        )),
    }
}

pub(crate) fn graph_slice_for_export(
    graph: &CausalGraph,
    root_node_id: &str,
    slice_kind: &str,
    input: &EdrGraphSliceExportInput,
) -> Result<CausalGraph, (StatusCode, String)> {
    match slice_kind {
        "causal_context" => {
            let upstream_depth = bounded_graph_depth("upstreamDepth", input.upstream_depth)?;
            let downstream_depth = bounded_graph_depth("downstreamDepth", input.downstream_depth)?;
            graph
                .causal_context_around(root_node_id, upstream_depth, downstream_depth)
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        format!("graph slice export root not found: {root_node_id}"),
                    )
                })
        }
        "causal_subgraph" => {
            let max_depth = bounded_graph_depth("maxDepth", input.max_depth)?;
            graph
                .causal_subgraph_from(root_node_id, max_depth)
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        format!("graph slice export root not found: {root_node_id}"),
                    )
                })
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            "slice_kind must be causal_subgraph or causal_context".to_string(),
        )),
    }
}

pub(crate) fn evidence_bundle_for_graph_slice(
    root_node_id: &str,
    slice_kind: &str,
    reason: Option<&str>,
    graph: &CausalGraph,
) -> Result<EndpointEvidenceBundleReference> {
    let canonical_graph = canonical_evidence_graph(graph)?;
    let content_hash = canonical_graph.content_hash;
    let graph_ref = EndpointGraphReference::for_subgraph(root_node_id, graph);
    let graph_slice_id = graph_ref
        .graph_slice_id
        .ok_or_else(|| anyhow::anyhow!("exported graph slice id missing"))?;
    let reason = non_empty(reason).unwrap_or("operator_export");
    let bundle_id = local_stable_id(
        "evidence_bundle",
        [
            root_node_id,
            graph_slice_id.as_str(),
            slice_kind,
            reason,
            content_hash.as_str(),
        ],
    );
    Ok(EndpointEvidenceBundleReference {
        bundle_id,
        graph_slice_id,
        content_hash,
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
        created_at: chrono::Utc::now(),
    })
}

fn resolve_graph_root(
    root_node_id: Option<&str>,
    process: Option<&EndpointProcess>,
) -> Result<String, (StatusCode, String)> {
    if let Some(root_node_id) = root_node_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return Ok(root_node_id.to_string());
    }

    if let Some(process) = process {
        return Ok(process.stable_node_id());
    }

    Err((
        StatusCode::BAD_REQUEST,
        "root_node_id or process must be provided".to_string(),
    ))
}

fn graph_root_process_selector(input: &EdrGraphRootProcessSelectorInput) -> EndpointProcess {
    EndpointProcess {
        pid: input.pid,
        ppid: input.ppid,
        process_guid: trimmed_owned(input.process_guid.as_deref()),
        parent_process_guid: trimmed_owned(input.parent_process_guid.as_deref()),
        image: trimmed_owned(input.image.as_deref()),
        command_line: trimmed_owned(input.command_line.as_deref()),
        cwd: trimmed_owned(input.cwd.as_deref()),
        ..EndpointProcess::default()
    }
}

pub(crate) fn resolve_graph_root_from_selector(
    root_node_id: Option<&str>,
    process: Option<&EdrGraphRootProcessSelectorInput>,
) -> Result<String, (StatusCode, String)> {
    let process = process.map(graph_root_process_selector);
    resolve_graph_root(root_node_id, process.as_ref())
}

pub(crate) fn bounded_graph_depth(
    field: &str,
    depth: Option<usize>,
) -> Result<usize, (StatusCode, String)> {
    let depth = depth.unwrap_or(EDR_MAX_CAUSAL_SUBGRAPH_DEPTH);
    if depth <= EDR_MAX_CAUSAL_SUBGRAPH_DEPTH {
        return Ok(depth);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be at most {EDR_MAX_CAUSAL_SUBGRAPH_DEPTH}"),
    ))
}

pub(crate) fn bounded_request_limit(
    field: &str,
    limit: Option<usize>,
    default: usize,
    max: usize,
) -> Result<usize, (StatusCode, String)> {
    let limit = limit.unwrap_or(default);
    if (1..=max).contains(&limit) {
        return Ok(limit);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be between 1 and {max}"),
    ))
}

pub(crate) fn bounded_provider_timeout_ms(
    field: &str,
    timeout_ms: Option<u64>,
) -> Result<u64, (StatusCode, String)> {
    let timeout_ms = timeout_ms.unwrap_or(EDR_DEFAULT_PROVIDER_ACK_TIMEOUT_MS);
    if (1..=EDR_MAX_PROVIDER_ACK_TIMEOUT_MS).contains(&timeout_ms) {
        return Ok(timeout_ms);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} must be between 1 and {EDR_MAX_PROVIDER_ACK_TIMEOUT_MS}"),
    ))
}

pub(crate) fn edr_policy_simulation_graph_slice(
    graph: &CausalGraph,
    root_node_id: &str,
    max_depth: usize,
) -> Option<CausalGraph> {
    graph
        .causal_context_around(root_node_id, max_depth, max_depth)
        .or_else(|| graph.causal_subgraph_from(root_node_id, max_depth))
}
