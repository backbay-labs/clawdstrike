#[test]
fn causal_graph_links_process_to_file_secret_and_network() {
    let mut recorder = CausalGraphRecorder::new();

    let file = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/.npmrc".to_string(),
        source_url: None,
        content_preview: None,
    });
    let mut network = observation(EndpointEvent::NetworkFlow {
        host: "evil.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://evil.example/collect".to_string()),
    });
    network.observation_id = "network-1".to_string();

    let file_nodes = recorder.record_observation(&file);
    let network_nodes = recorder.record_observation(&network);
    let graph = recorder.graph();

    assert!(graph.nodes.len() >= 3);
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.kind == CausalEdgeKind::Read));
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.kind == CausalEdgeKind::Connected));

    let file_node = file_nodes.last().unwrap();
    let network_node = network_nodes.last().unwrap();
    let path = recorder.causal_path(file_node, network_node).unwrap();
    assert_eq!(path.first().unwrap(), file_node);
    assert_eq!(path.last().unwrap(), network_node);
}

#[test]
fn causal_graph_links_auth_open_policy_decision_to_target_file() {
    let mut recorder = CausalGraphRecorder::new();
    let auth_open = observation(EndpointEvent::PolicyDecision {
        action: "endpoint_security_auth_open".to_string(),
        target: Some("/Users/alice/.ssh/id_rsa".to_string()),
        decision: "blocked".to_string(),
        guard: Some("endpoint_security_auth".to_string()),
        severity: Some("high".to_string()),
    });

    recorder.record_observation(&auth_open);
    let graph = recorder.graph();

    assert!(graph.nodes.values().any(|node| {
        node.kind == CausalNodeKind::Credential && node.label == "/Users/alice/.ssh/id_rsa"
    }));
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == CausalEdgeKind::AccessedCredential
            && edge.observation_id == auth_open.observation_id
    }));
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == CausalEdgeKind::MadeDecision && edge.observation_id == auth_open.observation_id
    }));
}

#[test]
fn causal_graph_links_network_policy_decision_to_target_flow() {
    let mut recorder = CausalGraphRecorder::new();
    let decision = observation(EndpointEvent::PolicyDecision {
        action: "network_extension_egress".to_string(),
        target: Some("malware.example.invalid:443".to_string()),
        decision: "blocked".to_string(),
        guard: Some("network_extension_content_filter".to_string()),
        severity: Some("high".to_string()),
    });

    recorder.record_observation(&decision);
    let graph = recorder.graph();

    let network_node_id = graph
        .nodes
        .iter()
        .find_map(|(node_id, node)| {
            (node.kind == CausalNodeKind::Network && node.label == "malware.example.invalid:443")
                .then_some(node_id)
        })
        .unwrap_or_else(|| panic!("missing network target node"));
    let decision_node_id = graph
        .nodes
        .iter()
        .find_map(|(node_id, node)| {
            (node.kind == CausalNodeKind::PolicyDecision).then_some(node_id)
        })
        .unwrap_or_else(|| panic!("missing policy decision node"));

    assert!(graph.edges.iter().any(|edge| {
        edge.kind == CausalEdgeKind::Connected
            && edge.to == network_node_id.as_str()
            && edge.observation_id == decision.observation_id
    }));
    assert!(graph.edges.iter().any(|edge| {
        edge.kind == CausalEdgeKind::Related
            && edge.from == network_node_id.as_str()
            && edge.to == decision_node_id.as_str()
            && edge.observation_id == decision.observation_id
    }));
}

#[test]
fn causal_graph_links_process_to_dns_lookup() {
    let mut recorder = CausalGraphRecorder::new();
    let dns = observation(EndpointEvent::DnsLookup {
        query: "packages.example.invalid".to_string(),
        record_type: Some("A".to_string()),
        answers: vec!["192.0.2.10".to_string()],
        resolver: Some("10.0.0.53".to_string()),
        status: Some("noerror".to_string()),
    });

    let nodes = recorder.record_observation(&dns);
    let graph = recorder.graph();

    let dns_node_id = nodes.last().unwrap();
    let dns_node = graph
        .nodes
        .get(dns_node_id)
        .unwrap_or_else(|| panic!("missing DNS graph node"));
    assert_eq!(dns_node.kind, CausalNodeKind::DnsName);
    assert_eq!(dns_node.label, "packages.example.invalid");
    assert_eq!(dns_node.attributes["recordType"], "A");
    assert_eq!(dns_node.attributes["answers"][0], "192.0.2.10");
    assert!(graph
        .edges
        .iter()
        .any(|edge| edge.kind == CausalEdgeKind::ResolvedDns));
}

#[test]
fn causal_graph_promotes_identity_context_to_attribution_nodes() {
    let mut recorder = CausalGraphRecorder::new();
    let mut metadata = BTreeMap::new();
    metadata.insert(
        "agentId".to_string(),
        serde_json::Value::String("agent:codex".to_string()),
    );
    metadata.insert(
        "workloadId".to_string(),
        serde_json::Value::String("spiffe://example.test/workload/codex".to_string()),
    );
    metadata.insert(
        "approvalId".to_string(),
        serde_json::Value::String("approval-123".to_string()),
    );
    metadata.insert(
        "posture".to_string(),
        serde_json::Value::String("managed".to_string()),
    );
    let mut network = observation(EndpointEvent::NetworkFlow {
        host: "api.example.test".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://api.example.test/upload".to_string()),
    });
    network.host_id = Some("host-1".to_string());
    network.user_id = Some("alice".to_string());
    network.session_id = Some("session-identity-1".to_string());
    network.metadata = metadata;

    let nodes = recorder.record_observation(&network);
    let graph = recorder.graph();

    assert!(nodes.len() >= 8);
    assert!(graph
        .nodes
        .values()
        .any(|node| node.kind == CausalNodeKind::Host && node.label == "host-1"));
    assert!(graph
        .nodes
        .values()
        .any(|node| node.kind == CausalNodeKind::User && node.label == "alice"));
    assert!(graph.nodes.values().any(|node| {
        node.kind == CausalNodeKind::Session
            && node.label == "session-identity-1"
            && node
                .attributes
                .get("posture")
                .and_then(serde_json::Value::as_str)
                == Some("managed")
    }));
    assert!(graph
        .nodes
        .values()
        .any(|node| node.kind == CausalNodeKind::Agent && node.label == "agent:codex"));
    assert!(graph.nodes.values().any(|node| {
        node.kind == CausalNodeKind::Workload
            && node.label == "spiffe://example.test/workload/codex"
    }));
    assert!(graph
        .nodes
        .values()
        .any(|node| node.kind == CausalNodeKind::Approval && node.label == "approval-123"));
    for kind in [
        CausalEdgeKind::ObservedOn,
        CausalEdgeKind::RanAs,
        CausalEdgeKind::InSession,
        CausalEdgeKind::UsedAgent,
        CausalEdgeKind::UsedWorkload,
        CausalEdgeKind::AuthorizedBy,
    ] {
        assert!(graph.edges.iter().any(|edge| edge.kind == kind));
    }

    let agent_node_id = graph
        .nodes
        .values()
        .find(|node| node.kind == CausalNodeKind::Agent)
        .map(|node| node.node_id.clone())
        .unwrap_or_else(|| panic!("missing agent attribution node"));
    let network_node_id = graph
        .nodes
        .values()
        .find(|node| node.kind == CausalNodeKind::Network)
        .map(|node| node.node_id.clone())
        .unwrap_or_else(|| panic!("missing network node"));
    let path = recorder
        .causal_path(&agent_node_id, &network_node_id)
        .unwrap_or_else(|| panic!("missing agent-to-network causal path"));
    assert_eq!(path.first().unwrap(), &agent_node_id);
    assert_eq!(path.last().unwrap(), &network_node_id);
}

#[test]
fn causal_graph_exports_subgraph_for_process_cause_query() {
    let mut recorder = CausalGraphRecorder::new();
    let file = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/.npmrc".to_string(),
        source_url: None,
        content_preview: None,
    });
    let mut network = observation(EndpointEvent::NetworkFlow {
        host: "evil.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://evil.example/collect".to_string()),
    });
    network.observation_id = "network-subgraph-1".to_string();

    recorder.record_observation(&file);
    recorder.record_observation(&network);
    let process_node_id = file.process.stable_node_id();
    let subgraph = recorder
        .graph()
        .causal_subgraph_from(&process_node_id, 3)
        .unwrap();

    assert!(subgraph.nodes.contains_key(&process_node_id));
    assert!(subgraph
        .edges
        .iter()
        .any(|edge| edge.kind == CausalEdgeKind::Read));
    assert!(subgraph
        .edges
        .iter()
        .any(|edge| edge.kind == CausalEdgeKind::Connected));
    assert!(subgraph
        .nodes
        .values()
        .any(|node| node.label == ".npmrc" || node.label == "/Users/alice/.npmrc"));
    assert!(subgraph
        .nodes
        .values()
        .any(|node| node.label == "evil.example:443"));
}

#[test]
fn causal_graph_exports_upstream_and_downstream_context() {
    let mut recorder = CausalGraphRecorder::new();
    let file = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/.npmrc".to_string(),
        source_url: None,
        content_preview: None,
    });
    let mut network = observation(EndpointEvent::NetworkFlow {
        host: "evil.example".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: Some("https://evil.example/collect".to_string()),
    });
    network.observation_id = "network-context-1".to_string();

    recorder.record_observation(&file);
    let network_nodes = recorder.record_observation(&network);
    let network_node_id = network_nodes.last().unwrap();
    let context = recorder
        .graph()
        .causal_context_around(network_node_id, 2, 1)
        .unwrap();

    assert!(context.nodes.contains_key(network_node_id));
    assert!(context
        .edges
        .iter()
        .any(|edge| edge.kind == CausalEdgeKind::TemporalNext));
    assert!(context
        .nodes
        .values()
        .any(|node| node.label == ".npmrc" || node.label == "/Users/alice/.npmrc"));
    assert!(context
        .nodes
        .values()
        .any(|node| node.kind == CausalNodeKind::Process));
}

