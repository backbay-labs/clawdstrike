use super::*;

pub(crate) fn build_policy_event_history_causal_impact(
    selection: &EdrPolicyEventHistorySelection,
    changes: &[EdrPolicyEventImpactEntry],
    graph: &CausalGraph,
    context_depth: usize,
    promotion_stage: Option<&str>,
    cross_window_hashes: Option<(&str, &str)>,
) -> EdrPolicyEventHistoryCausalImpact {
    let observations = selection
        .observations
        .iter()
        .map(|observation| (observation.observation_id.as_str(), observation))
        .collect::<BTreeMap<_, _>>();
    let changed = changes
        .iter()
        .filter(|change| change.changed)
        .collect::<Vec<_>>();
    let mut contexts = Vec::new();
    let mut union_node_ids = BTreeSet::new();
    let mut missing_graph_context_count = 0usize;

    for change in changed
        .iter()
        .take(EDR_MAX_POLICY_EVENT_IMPACT_CONTEXTS)
        .copied()
    {
        let Some(observation) = observations.get(change.event_id.as_str()) else {
            missing_graph_context_count = missing_graph_context_count.saturating_add(1);
            continue;
        };
        let touched_node_ids = graph_node_ids_for_observation(graph, &observation.observation_id);
        let Some(root_node_id) =
            finding_group_root_node_id(graph, &observation.observation_id, &touched_node_ids)
        else {
            missing_graph_context_count = missing_graph_context_count.saturating_add(1);
            continue;
        };
        let context = graph
            .causal_context_around(&root_node_id, context_depth, context_depth)
            .unwrap_or_else(|| {
                graph_slice_for_node_ids(graph, &BTreeSet::from([root_node_id.clone()]))
            });
        union_node_ids.extend(context.nodes.keys().cloned());
        let root_label = graph
            .nodes
            .get(&root_node_id)
            .map(|node| node.label.clone())
            .unwrap_or_else(|| root_node_id.clone());
        let chains =
            causal_chains_for_changed_observation(&context, &root_node_id, &touched_node_ids);
        contexts.push(EdrPolicyEventHistoryCausalContext {
            event_id: change.event_id.clone(),
            current_outcome: change.current_outcome.clone(),
            proposed_outcome: change.proposed_outcome.clone(),
            current_guard: change.current_decision.guard.clone(),
            proposed_guard: change.proposed_decision.guard.clone(),
            current_reason_code: change.current_decision.reason_code.clone(),
            proposed_reason_code: change.proposed_decision.reason_code.clone(),
            root_node_id,
            root_label,
            node_count: context.nodes.len(),
            edge_count: context.edges.len(),
            chain_count: chains.len(),
            chains,
            node_kinds: causal_node_kind_counts(&context),
            graph: context,
        });
    }

    let union_graph = graph_slice_for_node_ids(graph, &union_node_ids);
    let omitted_context_count = (changed.len())
        .saturating_sub(contexts.len())
        .saturating_sub(missing_graph_context_count);
    let chain_drivers = causal_chain_drivers_for_contexts(&contexts);
    let promotion_suggestions = promotion_suggestions_for_causal_impact(
        &contexts,
        context_depth,
        promotion_stage,
        cross_window_hashes,
    );
    let affected_identities = affected_identities_for_causal_impact(&union_graph);
    let affected_identity_count = affected_identities.count();
    let affected_tools = affected_tools_for_causal_impact(&union_graph);
    let affected_tool_count = affected_tools.len();
    let blocking_change_count = changed
        .iter()
        .filter(|change| change.proposed_outcome == "blocked")
        .count() as u64;
    let mut breakage_drivers = breakage_drivers_for_causal_impact(&union_graph);
    let developer_breakage_score = if blocking_change_count > 0 {
        score_policy_event_history_breakage(&breakage_drivers, &union_graph)
    } else {
        0
    };
    let impact_level = policy_event_history_impact_level_for_score(developer_breakage_score);
    let breakage_driver_count = breakage_drivers.len();
    breakage_drivers.truncate(EDR_MAX_POLICY_EVENT_IMPACT_BREAKAGE_DRIVERS);

    EdrPolicyEventHistoryCausalImpact {
        changed_event_count: changed.len() as u64,
        context_count: contexts.len(),
        chain_count: contexts.iter().map(|context| context.chain_count).sum(),
        chain_driver_count: chain_drivers.len(),
        promotion_suggestion_count: promotion_suggestions.len(),
        affected_identity_count,
        affected_tool_count,
        blocking_change_count,
        developer_breakage_score,
        impact_level,
        breakage_driver_count,
        omitted_context_count,
        missing_graph_context_count,
        context_depth,
        node_count: union_graph.nodes.len(),
        edge_count: union_graph.edges.len(),
        node_kinds: causal_node_kind_counts(&union_graph),
        affected_identities,
        affected_tools,
        top_breakage_drivers: breakage_drivers,
        contexts,
        chain_drivers,
        promotion_suggestions,
        receipt: None,
    }
}

// affected_identities_for_causal_impact and push_affected_identity moved to crate::edr::queries::causal
pub(crate) fn affected_tools_for_causal_impact(
    graph: &CausalGraph,
) -> Vec<EdrPolicyEventHistoryAffectedTool> {
    graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Tool)
        .map(|node| EdrPolicyEventHistoryAffectedTool {
            node_id: node.node_id.clone(),
            label: node.label.clone(),
            tool_name: node.label.clone(),
        })
        .collect()
}

fn breakage_drivers_for_causal_impact(
    graph: &CausalGraph,
) -> Vec<EdrPolicyEventHistoryBreakageDriver> {
    let mut drivers = graph
        .nodes
        .values()
        .map(policy_event_history_breakage_driver)
        .collect::<Vec<_>>();
    drivers.sort_by(|left, right| {
        right
            .breakage_score
            .cmp(&left.breakage_score)
            .then_with(|| left.node_id.cmp(&right.node_id))
    });
    drivers
}

fn policy_event_history_breakage_driver(node: &CausalNode) -> EdrPolicyEventHistoryBreakageDriver {
    let (breakage_score, reason) = match node.kind {
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
        CausalNodeKind::Process => (30, "blocking this process affects local execution"),
        CausalNodeKind::File => (18, "blocking this file interaction may affect local files"),
        CausalNodeKind::Network => (24, "blocking this network target may affect egress"),
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

    EdrPolicyEventHistoryBreakageDriver {
        node_id: node.node_id.clone(),
        kind: node.kind.clone(),
        label: node.label.clone(),
        workflow_category: policy_event_history_workflow_category(node).to_string(),
        breakage_score,
        reason: reason.to_string(),
    }
}

fn policy_event_history_workflow_category(node: &CausalNode) -> &'static str {
    match node.kind {
        CausalNodeKind::Host => "endpoint_identity",
        CausalNodeKind::User => "user_identity",
        CausalNodeKind::Session => "session_identity",
        CausalNodeKind::Agent => "agent_identity",
        CausalNodeKind::Workload => "workload_identity",
        CausalNodeKind::Approval => "approval_context",
        CausalNodeKind::Process => "process_execution",
        CausalNodeKind::File => "file_activity",
        CausalNodeKind::Network => "network_egress",
        CausalNodeKind::DnsName => "dns_resolution",
        CausalNodeKind::PackageScript => "package_manager_script",
        CausalNodeKind::Credential => "credential_access",
        CausalNodeKind::Tool => {
            if node.label.starts_with("mcp__") {
                "mcp_tool_call"
            } else if node.label.contains("browser") {
                "browser_automation_tool"
            } else if node.label.contains("shell") || node.label.contains("terminal") {
                "shell_tool_call"
            } else {
                "agent_tool_call"
            }
        }
        CausalNodeKind::BrowserDownload => "browser_download",
        CausalNodeKind::BrowserExtension => "browser_extension",
        CausalNodeKind::PolicyDecision => "policy_decision",
        CausalNodeKind::DeceptionArtifact => "endpoint_deception",
        CausalNodeKind::Other => "other_endpoint_activity",
    }
}

fn score_policy_event_history_breakage(
    drivers: &[EdrPolicyEventHistoryBreakageDriver],
    graph: &CausalGraph,
) -> u8 {
    let max_node_score = drivers
        .iter()
        .map(|driver| driver.breakage_score)
        .max()
        .unwrap_or(0);
    let breadth = graph
        .nodes
        .len()
        .saturating_sub(1)
        .saturating_mul(4)
        .min(24) as u8;
    let edge_weight = graph.edges.len().saturating_mul(2).min(16) as u8;
    let process_weight = count_causal_nodes_by_kind(graph, CausalNodeKind::Process)
        .saturating_sub(1)
        .saturating_mul(6)
        .min(18) as u8;
    let credential_weight = if count_causal_nodes_by_kind(graph, CausalNodeKind::Credential) > 0 {
        10
    } else {
        0
    };

    max_node_score
        .saturating_add(breadth)
        .saturating_add(edge_weight)
        .saturating_add(process_weight)
        .saturating_add(credential_weight)
        .min(100)
}

fn policy_event_history_impact_level_for_score(score: u8) -> EndpointSimulationImpactLevel {
    match score {
        0 => EndpointSimulationImpactLevel::None,
        1..=24 => EndpointSimulationImpactLevel::Low,
        25..=49 => EndpointSimulationImpactLevel::Medium,
        50..=74 => EndpointSimulationImpactLevel::High,
        _ => EndpointSimulationImpactLevel::Critical,
    }
}

fn count_causal_nodes_by_kind(graph: &CausalGraph, kind: CausalNodeKind) -> usize {
    graph
        .nodes
        .values()
        .filter(|node| node.kind == kind)
        .count()
}

fn causal_chain_drivers_for_contexts(
    contexts: &[EdrPolicyEventHistoryCausalContext],
) -> Vec<EdrPolicyEventHistoryCausalChainDriver> {
    let mut buckets = BTreeMap::<
        EdrPolicyEventHistoryCausalChainDriverKey,
        EdrPolicyEventHistoryCausalChainDriverBucket,
    >::new();

    for context in contexts {
        for chain in &context.chains {
            let Some(target_node) = context.graph.nodes.get(&chain.target_node_id) else {
                continue;
            };
            let action = default_detection_candidate_action(target_node);
            if !supported_edr_simulation_action(&action) {
                continue;
            }
            let key = EdrPolicyEventHistoryCausalChainDriverKey {
                current_outcome: context.current_outcome.clone(),
                proposed_outcome: context.proposed_outcome.clone(),
                current_guard: context.current_guard.clone(),
                proposed_guard: context.proposed_guard.clone(),
                current_reason_code: context.current_reason_code.clone(),
                proposed_reason_code: context.proposed_reason_code.clone(),
                target_kind: chain.target_kind.clone(),
                action: action.as_str().to_string(),
                edge_kinds: chain.edge_kinds.clone(),
            };
            let bucket = buckets.entry(key).or_default();
            bucket.count = bucket.count.saturating_add(1);
            push_limited_unique_chain_driver_sample(
                &mut bucket.sample_event_ids,
                context.event_id.clone(),
            );
            push_limited_unique_chain_driver_sample(
                &mut bucket.sample_target_node_ids,
                chain.target_node_id.clone(),
            );
            push_limited_unique_chain_driver_sample(
                &mut bucket.sample_target_labels,
                chain.target_label.clone(),
            );
        }
    }

    let mut drivers = buckets
        .into_iter()
        .filter_map(|(key, bucket)| {
            let action = endpoint_decision_action_from_str(&key.action)?;
            let edge_kinds_material = key.edge_kinds.join(">");
            let driver_id = local_stable_id(
                "chain_driver",
                [
                    key.current_outcome.as_str(),
                    key.proposed_outcome.as_str(),
                    key.current_guard.as_deref().unwrap_or(""),
                    key.proposed_guard.as_deref().unwrap_or(""),
                    key.current_reason_code.as_str(),
                    key.proposed_reason_code.as_str(),
                    key.target_kind.as_str(),
                    key.action.as_str(),
                    edge_kinds_material.as_str(),
                ],
            );
            Some(EdrPolicyEventHistoryCausalChainDriver {
                driver_id,
                current_outcome: key.current_outcome,
                proposed_outcome: key.proposed_outcome,
                current_guard: key.current_guard,
                proposed_guard: key.proposed_guard,
                current_reason_code: key.current_reason_code,
                proposed_reason_code: key.proposed_reason_code,
                target_kind: key.target_kind,
                action,
                edge_kinds: key.edge_kinds,
                count: bucket.count,
                sample_event_ids: bucket.sample_event_ids,
                sample_target_node_ids: bucket.sample_target_node_ids,
                sample_target_labels: bucket.sample_target_labels,
            })
        })
        .collect::<Vec<_>>();
    drivers.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.target_kind.cmp(&right.target_kind))
            .then_with(|| left.action.as_str().cmp(right.action.as_str()))
            .then_with(|| left.edge_kinds.cmp(&right.edge_kinds))
            .then_with(|| left.driver_id.cmp(&right.driver_id))
    });
    drivers
}

fn push_limited_unique_chain_driver_sample(samples: &mut Vec<String>, sample: String) {
    if samples.len() >= EDR_MAX_POLICY_EVENT_IMPACT_CHAIN_DRIVER_SAMPLES {
        return;
    }
    if samples.iter().any(|existing| existing == &sample) {
        return;
    }
    samples.push(sample);
}

fn endpoint_decision_action_from_str(value: &str) -> Option<EndpointDecisionAction> {
    match value {
        "allow" => Some(EndpointDecisionAction::Allow),
        "observe" => Some(EndpointDecisionAction::Observe),
        "warn" => Some(EndpointDecisionAction::Warn),
        "alert" => Some(EndpointDecisionAction::Alert),
        "block" => Some(EndpointDecisionAction::Block),
        "restrict_egress" => Some(EndpointDecisionAction::RestrictEgress),
        "suspend_process_tree" => Some(EndpointDecisionAction::SuspendProcessTree),
        "terminate_process_tree" => Some(EndpointDecisionAction::TerminateProcessTree),
        "quarantine_file" => Some(EndpointDecisionAction::QuarantineFile),
        "revoke_grant" => Some(EndpointDecisionAction::RevokeGrant),
        "disable_persistence" => Some(EndpointDecisionAction::DisablePersistence),
        "collect_evidence" => Some(EndpointDecisionAction::CollectEvidence),
        _ => None,
    }
}
