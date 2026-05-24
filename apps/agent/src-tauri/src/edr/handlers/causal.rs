//! Causal graph and flight recorder handlers.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::{Path, Query, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use clawdstrike_policy_event::event::PolicyEvent;
#[allow(unused_imports)]
use hush_core::SignedReceipt;
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::Value;
#[allow(unused_imports)]
use std::collections::{BTreeMap, BTreeSet, HashMap};
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_finding_groups(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrFindingGroupsQuery>,
) -> Result<Json<EdrFindingGroupsResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", query.limit, 50, EDR_MAX_STORED_FINDINGS)?;
    let max_depth = bounded_graph_depth("maxDepth", query.max_depth)?;
    let findings = state
        .edr_recent_findings
        .lock()
        .await
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let pending = build_finding_groups(&graph, &findings, max_depth);
    let mut groups = Vec::new();

    for group in pending.into_iter().take(limit) {
        let group_graph = graph_slice_for_node_ids(&graph, &group.node_ids);
        if group_graph.nodes.is_empty() {
            continue;
        }
        let receipt = emit_edr_graph_slice_receipt(
            &state,
            &group.root_node_id,
            "finding_group",
            &group_graph,
        )
        .await
        .map_err(internal_error)?;
        let mut rule_ids = group
            .findings
            .iter()
            .map(|finding| finding.rule_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut finding_ids = group
            .findings
            .iter()
            .map(|finding| finding.finding_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        rule_ids.sort();
        finding_ids.sort();
        let mut group_id_parts = vec![group.root_node_id.as_str()];
        group_id_parts.extend(finding_ids.iter().map(String::as_str));
        let group_id = local_stable_id("finding_group", group_id_parts);
        let affected_identities = affected_identities_for_causal_impact(&group_graph);
        let affected_identity_count = affected_identities.count();
        let affected_tools = affected_tools_for_causal_impact(&group_graph);
        let affected_tool_count = affected_tools.len();
        groups.push(EdrFindingGroup {
            group_id,
            root_node_id: group.root_node_id,
            root_label: group.root_label,
            finding_count: group.findings.len(),
            node_count: group_graph.nodes.len(),
            edge_count: group_graph.edges.len(),
            rule_ids,
            finding_ids,
            findings: group.findings,
            affected_identity_count,
            affected_tool_count,
            affected_identities,
            affected_tools,
            graph: group_graph,
            receipt,
        });
    }

    let finding_count = groups.iter().map(|group| group.finding_count).sum();
    Ok(Json(EdrFindingGroupsResponse {
        group_count: groups.len(),
        finding_count,
        groups,
    }))
}

pub(crate) async fn agent_edr_causal_graph(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrCausalGraphInput>,
) -> Result<Json<EdrCausalGraphResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_edr_request_sizes(input.observations.len(), 0)?;

    let graph = if input.observations.is_empty() {
        state.edr_flight_recorder.lock().await.graph().clone()
    } else {
        let observations = redact_endpoint_observations(&input.observations);
        let mut recorder = CausalGraphRecorder::new();
        for observation in &observations {
            recorder.record_observation(observation);
        }
        recorder.into_graph()
    };

    Ok(Json(EdrCausalGraphResponse {
        observation_count: input.observations.len(),
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
        graph,
    }))
}

pub(crate) async fn agent_edr_causal_subgraph(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrCausalSubgraphInput>,
) -> Result<Json<EdrCausalSubgraphResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let root_node_id = resolve_causal_subgraph_root(&input)?;
    let max_depth = bounded_graph_depth("maxDepth", input.max_depth)?;

    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let subgraph = graph
        .causal_subgraph_from(root_node_id.as_str(), max_depth)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("causal graph root not found: {root_node_id}"),
            )
        })?;
    let receipt = emit_edr_graph_slice_receipt(&state, &root_node_id, "causal_subgraph", &subgraph)
        .await
        .map_err(internal_error)?;
    let affected_identities = affected_identities_for_causal_impact(&subgraph);
    let affected_identity_count = affected_identities.count();
    let affected_tools = affected_tools_for_causal_impact(&subgraph);
    let affected_tool_count = affected_tools.len();

    Ok(Json(EdrCausalSubgraphResponse {
        root_node_id,
        max_depth,
        node_count: subgraph.nodes.len(),
        edge_count: subgraph.edges.len(),
        affected_identity_count,
        affected_tool_count,
        affected_identities,
        affected_tools,
        graph: subgraph,
        receipt,
    }))
}

pub(crate) async fn agent_edr_causal_context(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrCausalContextInput>,
) -> Result<Json<EdrCausalContextResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let root_node_id =
        resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())?;
    let upstream_depth = bounded_graph_depth("upstreamDepth", input.upstream_depth)?;
    let downstream_depth = bounded_graph_depth("downstreamDepth", input.downstream_depth)?;

    let (graph, durable_graph_edge_index) = {
        let recorder = state.edr_flight_recorder.lock().await;
        let graph = recorder.graph().clone();
        let durable_graph_edge_index = recorder.read_graph_edge_index().ok();
        (graph, durable_graph_edge_index)
    };
    let durable_graph_edge_index = durable_graph_edge_index
        .as_ref()
        .map(|(path, entries)| (path.as_path(), entries.as_slice()));
    let (context_expansion_strategy, edge_index_source, edge_index_path, edge_index_count, context) =
        if let Some((edge_index_path, edge_entries)) = durable_graph_edge_index {
            let context = causal_context_around_with_edge_index(
                &graph,
                root_node_id.as_str(),
                upstream_depth,
                downstream_depth,
                edge_entries,
            )
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("causal graph root not found: {root_node_id}"),
                )
            })?;
            (
                "durable_graph_edge_sidecar_adjacency".to_string(),
                "durable_graph_edge_sidecar".to_string(),
                Some(edge_index_path.to_path_buf()),
                edge_entries.len(),
                context,
            )
        } else {
            let context = graph
                .causal_context_around(root_node_id.as_str(), upstream_depth, downstream_depth)
                .ok_or_else(|| {
                    (
                        StatusCode::NOT_FOUND,
                        format!("causal graph root not found: {root_node_id}"),
                    )
                })?;
            (
                "in_memory_graph_scan".to_string(),
                "in_memory_graph".to_string(),
                None,
                graph.edges.len(),
                context,
            )
        };
    let receipt = emit_edr_graph_slice_receipt(&state, &root_node_id, "causal_context", &context)
        .await
        .map_err(internal_error)?;
    let affected_identities = affected_identities_for_causal_impact(&context);
    let affected_identity_count = affected_identities.count();
    let affected_tools = affected_tools_for_causal_impact(&context);
    let affected_tool_count = affected_tools.len();

    Ok(Json(EdrCausalContextResponse {
        root_node_id,
        upstream_depth,
        downstream_depth,
        context_expansion_strategy,
        edge_index_source,
        edge_index_path,
        edge_index_count,
        node_count: context.nodes.len(),
        edge_count: context.edges.len(),
        affected_identity_count,
        affected_tool_count,
        affected_identities,
        affected_tools,
        graph: context,
        receipt,
    }))
}

pub(crate) async fn agent_edr_graph_search(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrGraphSearchInput>,
) -> Result<Json<EdrGraphSearchResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    validate_graph_search_input(&input)?;
    let upstream_depth = bounded_graph_depth("upstreamDepth", input.upstream_depth)?;
    let downstream_depth = bounded_graph_depth("downstreamDepth", input.downstream_depth)?;
    let limit = bounded_request_limit("limit", input.limit, 50, EDR_MAX_STORED_FINDINGS)?;

    let (graph, durable_graph_index, durable_graph_edge_index) = {
        let recorder = state.edr_flight_recorder.lock().await;
        let graph = recorder.graph().clone();
        let durable_graph_index = recorder.read_graph_node_index().ok();
        let durable_graph_edge_index = recorder.read_graph_edge_index().ok();
        (graph, durable_graph_index, durable_graph_edge_index)
    };
    let durable_graph_index = durable_graph_index
        .as_ref()
        .map(|(path, entries)| (path.as_path(), entries.as_slice()));
    let durable_graph_edge_index = durable_graph_edge_index
        .as_ref()
        .map(|(path, entries)| (path.as_path(), entries.as_slice()));
    let (pending_matches, total_match_count, query_plan) = build_graph_search_matches(
        &graph,
        durable_graph_index,
        durable_graph_edge_index,
        &input,
        upstream_depth,
        downstream_depth,
        limit,
    );
    let mut matches = Vec::with_capacity(pending_matches.len());
    for pending in pending_matches {
        let receipt = emit_edr_graph_slice_receipt(
            &state,
            &pending.root_node_id,
            "graph_search",
            &pending.graph,
        )
        .await
        .map_err(internal_error)?;
        let affected_identities = affected_identities_for_causal_impact(&pending.graph);
        let affected_identity_count = affected_identities.count();
        let affected_tools = affected_tools_for_causal_impact(&pending.graph);
        let affected_tool_count = affected_tools.len();
        matches.push(EdrGraphSearchMatch {
            root_node_id: pending.root_node_id,
            root_label: pending.root_label,
            root_kind: pending.root_kind,
            node_count: pending.graph.nodes.len(),
            edge_count: pending.graph.edges.len(),
            affected_identity_count,
            affected_tool_count,
            affected_identities,
            affected_tools,
            graph: pending.graph,
            receipt,
        });
    }

    Ok(Json(EdrGraphSearchResponse {
        match_count: matches.len(),
        total_match_count,
        upstream_depth,
        downstream_depth,
        query_plan,
        matches,
    }))
}

pub(crate) async fn agent_edr_graph_slice_export(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrGraphSliceExportInput>,
) -> Result<Json<EdrGraphSliceExportResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let root_node_id =
        resolve_graph_root_from_selector(input.root_node_id.as_deref(), input.process.as_ref())?;
    let slice_kind = graph_slice_export_kind(input.slice_kind.as_deref())?;
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let exported_graph = graph_slice_for_export(&graph, &root_node_id, &slice_kind, &input)?;
    let bundle = evidence_bundle_for_graph_slice(
        &root_node_id,
        &slice_kind,
        input.reason.as_deref(),
        &exported_graph,
    )
    .map_err(internal_error)?;
    let stored = state
        .edr_evidence_bundle_store
        .lock()
        .await
        .store(&bundle, &exported_graph)
        .map_err(internal_error)?;
    let receipt = emit_edr_graph_slice_receipt(&state, &root_node_id, &slice_kind, &exported_graph)
        .await
        .map_err(internal_error)?;
    let affected_identities = affected_identities_for_causal_impact(&exported_graph);
    let affected_identity_count = affected_identities.count();
    let affected_tools = affected_tools_for_causal_impact(&exported_graph);
    let affected_tool_count = affected_tools.len();

    Ok(Json(EdrGraphSliceExportResponse {
        root_node_id,
        slice_kind,
        node_count: exported_graph.nodes.len(),
        edge_count: exported_graph.edges.len(),
        affected_identity_count,
        affected_tool_count,
        affected_identities,
        affected_tools,
        graph: exported_graph,
        bundle,
        artifact: EdrEvidenceBundleArtifact::from_stored(&stored),
        receipt,
    }))
}

pub(crate) async fn agent_edr_flight_recorder(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
) -> Result<Json<EdrFlightRecorderResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let recorder = state.edr_flight_recorder.lock().await;
    let graph = recorder.graph();
    Ok(Json(EdrFlightRecorderResponse {
        path: recorder.path().map(|path| path.display().to_string()),
        observation_count: recorder.observation_count(),
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
    }))
}

pub(crate) async fn agent_edr_flight_recorder_compact(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrFlightRecorderCompactionInput>,
) -> Result<Json<EdrFlightRecorderCompactionResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    if input.max_observations.is_none() && input.min_age_seconds.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "max_observations or min_age_seconds must be provided".to_string(),
        ));
    }
    let dry_run = input.dry_run.unwrap_or(true);
    let min_age_seconds = input.min_age_seconds.unwrap_or(0);
    let now = chrono::Utc::now();

    let receipt_protected_observation_ids = {
        let graph = state.edr_flight_recorder.lock().await.graph().clone();
        let ledger = state.edr_receipt_ledger.lock().await;
        let receipts = ledger.all().map_err(internal_error)?;
        protected_observation_ids_for_receipts(&receipts, &graph)
    };

    let mut recorder = state.edr_flight_recorder.lock().await;
    let path = recorder.path().map(|path| path.display().to_string());
    if path.is_none() {
        return Err((
            StatusCode::CONFLICT,
            "flight recorder compaction requires a durable backing path".to_string(),
        ));
    }
    let report = recorder
        .compact(
            input.max_observations,
            min_age_seconds,
            &receipt_protected_observation_ids,
            dry_run,
            now,
        )
        .map_err(internal_error)?;
    let graph = recorder.graph();

    Ok(Json(EdrFlightRecorderCompactionResponse {
        path,
        dry_run,
        max_observations: input.max_observations,
        min_age_seconds,
        observation_count: report.observation_count,
        candidate_count: report.records.len(),
        removed_count: report
            .records
            .iter()
            .filter(|record| record.removed)
            .count(),
        retained_count: report.retained_count,
        protected_count: report.protected_count,
        node_count: graph.nodes.len(),
        edge_count: graph.edges.len(),
        records: report.records,
    }))
}
