#[test]
fn endpoint_flight_recorder_persists_and_rebuilds_graph() {
    let root = temp_root();
    let path = root.join("flight-recorder.jsonl");
    let mut recorder = EndpointFlightRecorder::open(&path).unwrap();

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
    network.observation_id = "network-rebuild-1".to_string();

    recorder
        .append_observations(&[file.clone(), network.clone()])
        .unwrap();
    assert_eq!(recorder.observation_count(), 2);
    assert!(path.is_file());
    let log_contents = fs::read_to_string(&path).unwrap();
    assert!(log_contents.contains("\"recordHash\""));
    assert!(log_contents.contains("\"previousRecordHash\""));
    assert!(recorder
        .graph()
        .edges
        .iter()
        .any(|edge| edge.kind == CausalEdgeKind::Connected));

    let reopened = EndpointFlightRecorder::open(&path).unwrap();
    assert_eq!(reopened.observation_count(), 2);
    assert_eq!(reopened.graph().nodes.len(), recorder.graph().nodes.len());
    assert_eq!(reopened.graph().edges.len(), recorder.graph().edges.len());
    assert_eq!(reopened.path(), Some(path.as_path()));
    assert!(endpoint_flight_recorder_index_path(&path).is_file());

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_flight_recorder_detects_hash_chain_rewrite() {
    let root = temp_root();
    let path = root.join("flight-recorder-tamper.jsonl");
    let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
    let file = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/.npmrc".to_string(),
        source_url: None,
        content_preview: None,
    });
    recorder.append_observations(&[file]).unwrap();

    let mut line: serde_json::Value =
        serde_json::from_str(fs::read_to_string(&path).unwrap().trim()).unwrap();
    line["observation"]["hostId"] = serde_json::Value::String("tampered-host".to_string());
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string(&line).unwrap()),
    )
    .unwrap();

    let err = EndpointFlightRecorder::open(&path).unwrap_err();
    assert!(
        err.to_string().contains("observation hash mismatch"),
        "expected observation hash mismatch, got {err}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_flight_recorder_detects_hash_chain_line_deletion() {
    let root = temp_root();
    let path = root.join("flight-recorder-deletion.jsonl");
    let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
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
    network.observation_id = "network-delete-1".to_string();
    recorder.append_observations(&[file, network]).unwrap();

    let contents = fs::read_to_string(&path).unwrap();
    let second_line = contents.lines().nth(1).unwrap().to_string();
    fs::write(&path, format!("{second_line}\n")).unwrap();

    let err = EndpointFlightRecorder::open(&path).unwrap_err();
    assert!(
        err.to_string().contains("sequence mismatch")
            || err.to_string().contains("previous hash mismatch"),
        "expected hash-chain deletion mismatch, got {err}"
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_flight_recorder_indexes_latest_matching_history_window() {
    let root = temp_root();
    let path = root.join("flight-recorder-window.jsonl");
    let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
    let base = Utc::now();
    let mut first_network = observation(EndpointEvent::NetworkFlow {
        host: "first.example.invalid".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: None,
    });
    first_network.observation_id = "network-window-1".to_string();
    first_network.timestamp = base;
    let mut file = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/.npmrc".to_string(),
        source_url: None,
        content_preview: None,
    });
    file.observation_id = "file-window-1".to_string();
    file.timestamp = base + chrono::Duration::seconds(1);
    let mut second_network = observation(EndpointEvent::NetworkFlow {
        host: "second.example.invalid".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: None,
    });
    second_network.observation_id = "network-window-2".to_string();
    second_network.timestamp = base + chrono::Duration::seconds(2);
    let mut third_network = observation(EndpointEvent::NetworkFlow {
        host: "third.example.invalid".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: None,
    });
    third_network.observation_id = "network-window-3".to_string();
    third_network.timestamp = base + chrono::Duration::seconds(3);

    recorder
        .append_observations(&[
            first_network,
            file,
            second_network.clone(),
            third_network.clone(),
        ])
        .unwrap();

    let window = recorder
        .read_indexed_observation_window(2, |entry| entry.event_kind == "network_flow")
        .unwrap();

    assert_eq!(window.selection_mode, "sidecar_index_seek");
    assert_eq!(
        window.index_path.as_deref(),
        Some(endpoint_flight_recorder_index_path(&path).as_path())
    );
    assert_eq!(window.total_observation_count, 4);
    assert_eq!(window.matched_observation_count, 3);
    assert_eq!(
        window
            .selected_observations
            .iter()
            .map(|observation| observation.observation_id.as_str())
            .collect::<Vec<_>>(),
        vec!["network-window-2", "network-window-3"]
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_flight_recorder_indexes_identity_metadata_for_history_selection() {
    let root = temp_root();
    let path = root.join("flight-recorder-identity-index.jsonl");
    let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
    let mut matching = observation(EndpointEvent::CredentialAccess {
        kind: CredentialKind::CloudCredential,
        path: Some("/Users/alice/.config/cloud/token".to_string()),
        name: Some("cloud-token".to_string()),
    });
    matching.observation_id = "identity-index-match".to_string();
    matching.host_id = Some("endpoint-a".to_string());
    matching.user_id = Some("alice@example.com".to_string());
    matching.session_id = Some("session-a".to_string());
    matching.process.process_guid = Some("process-a".to_string());
    matching.process.parent_process_guid = Some("parent-process-a".to_string());
    matching.process.image = Some("/usr/local/bin/codex".to_string());
    matching.process.command_line = Some("/usr/local/bin/codex exec task".to_string());
    matching.metadata.insert(
        "agentId".to_string(),
        serde_json::Value::String("agent-codex".to_string()),
    );
    matching.metadata.insert(
        "workloadId".to_string(),
        serde_json::Value::String("workload-local".to_string()),
    );
    matching.metadata.insert(
        "approvalId".to_string(),
        serde_json::Value::String("approval-123".to_string()),
    );
    matching.metadata.insert(
        "toolName".to_string(),
        serde_json::Value::String("mcp__browser__open_url".to_string()),
    );
    matching.metadata.insert(
        "toolCallId".to_string(),
        serde_json::Value::String("tool-call-123".to_string()),
    );
    let mut other = matching.clone();
    other.observation_id = "identity-index-other".to_string();
    other.session_id = Some("session-b".to_string());
    other.metadata.insert(
        "agentId".to_string(),
        serde_json::Value::String("agent-other".to_string()),
    );

    recorder
        .append_observations(&[matching.clone(), other])
        .unwrap();

    let entries =
        read_endpoint_observation_index(&endpoint_flight_recorder_index_path(&path)).unwrap();
    let indexed = entries
        .iter()
        .find(|entry| entry.observation_id == "identity-index-match")
        .unwrap();
    assert_eq!(indexed.host_id.as_deref(), Some("endpoint-a"));
    assert_eq!(indexed.user_id.as_deref(), Some("alice@example.com"));
    assert_eq!(indexed.session_id.as_deref(), Some("session-a"));
    assert_eq!(indexed.process_guid.as_deref(), Some("process-a"));
    assert_eq!(
        indexed.parent_process_guid.as_deref(),
        Some("parent-process-a")
    );
    assert_eq!(
        indexed.process_image_hash.as_deref(),
        Some(sha256(b"/usr/local/bin/codex").to_hex_prefixed().as_str())
    );
    assert_eq!(
        indexed.process_command_line_hash.as_deref(),
        Some(
            sha256(b"/usr/local/bin/codex exec task")
                .to_hex_prefixed()
                .as_str()
        )
    );
    assert_eq!(indexed.agent_id.as_deref(), Some("agent-codex"));
    assert_eq!(indexed.workload_id.as_deref(), Some("workload-local"));
    assert_eq!(indexed.approval_id.as_deref(), Some("approval-123"));
    assert_eq!(indexed.tool_name.as_deref(), Some("mcp__browser__open_url"));
    assert_eq!(indexed.tool_call_id.as_deref(), Some("tool-call-123"));
    assert_eq!(indexed.credential_kind.as_deref(), Some("cloud_credential"));
    assert_eq!(indexed.event_target.as_deref(), Some("cloud-token"));
    assert_eq!(
        indexed.event_target_hash.as_deref(),
        Some(sha256(b"cloud-token").to_hex_prefixed().as_str())
    );

    let window = recorder
        .read_indexed_observation_window(10, |entry| {
            entry.session_id.as_deref() == Some("session-a")
                && entry.agent_id.as_deref() == Some("agent-codex")
                && entry.parent_process_guid.as_deref() == Some("parent-process-a")
                && entry.process_image_hash.as_deref()
                    == Some(sha256(b"/usr/local/bin/codex").to_hex_prefixed().as_str())
                && entry.process_command_line_hash.as_deref()
                    == Some(
                        sha256(b"/usr/local/bin/codex exec task")
                            .to_hex_prefixed()
                            .as_str(),
                    )
                && entry.workload_id.as_deref() == Some("workload-local")
                && entry.approval_id.as_deref() == Some("approval-123")
                && entry.tool_name.as_deref() == Some("mcp__browser__open_url")
                && entry.tool_call_id.as_deref() == Some("tool-call-123")
                && entry.credential_kind.as_deref() == Some("cloud_credential")
                && entry.event_target.as_deref() == Some("cloud-token")
                && entry.event_target_hash.as_deref()
                    == Some(sha256(b"cloud-token").to_hex_prefixed().as_str())
        })
        .unwrap();

    assert_eq!(window.selection_mode, "sidecar_index_seek");
    assert_eq!(window.matched_observation_count, 1);
    assert_eq!(window.selected_observations.len(), 1);
    assert_eq!(window.selected_observations[0], matching);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_flight_recorder_rebuilds_corrupt_sidecar_index_on_seek_mismatch() {
    let root = temp_root();
    let path = root.join("flight-recorder-corrupt-index.jsonl");
    let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
    let mut network = observation(EndpointEvent::NetworkFlow {
        host: "corrupt-index.example.invalid".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: None,
    });
    network.observation_id = "network-corrupt-index-1".to_string();
    recorder.append_observations(&[network.clone()]).unwrap();

    let index_path = endpoint_flight_recorder_index_path(&path);
    let mut entries = read_endpoint_observation_index(&index_path).unwrap();
    assert_eq!(entries.len(), 1);
    entries[0].observation_id = "network-corrupt-index-tampered".to_string();
    replace_endpoint_observation_index(&path, &entries).unwrap();

    let window = recorder
        .read_indexed_observation_window(1, |entry| entry.event_kind == "network_flow")
        .unwrap();

    assert_eq!(window.selection_mode, "sidecar_index_seek");
    assert_eq!(window.selected_observations.len(), 1);
    assert_eq!(
        window.selected_observations[0].observation_id,
        "network-corrupt-index-1"
    );
    let rebuilt_entries = read_endpoint_observation_index(&index_path).unwrap();
    assert_eq!(rebuilt_entries[0].observation_id, "network-corrupt-index-1");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_flight_recorder_rebuilds_sidecar_index_on_event_kind_mismatch() {
    let root = temp_root();
    let path = root.join("flight-recorder-event-kind-index.jsonl");
    let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
    let mut file = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/.npmrc".to_string(),
        source_url: None,
        content_preview: None,
    });
    file.observation_id = "file-event-kind-index-1".to_string();
    recorder.append_observations(&[file]).unwrap();

    let index_path = endpoint_flight_recorder_index_path(&path);
    let mut entries = read_endpoint_observation_index(&index_path).unwrap();
    assert_eq!(entries.len(), 1);
    entries[0].event_kind = "network_flow".to_string();
    replace_endpoint_observation_index(&path, &entries).unwrap();

    let window = recorder
        .read_indexed_observation_window(1, |entry| entry.event_kind == "network_flow")
        .unwrap();

    assert_eq!(window.selection_mode, "sidecar_index_seek");
    assert_eq!(window.total_observation_count, 1);
    assert_eq!(window.matched_observation_count, 0);
    assert!(window.selected_observations.is_empty());
    let rebuilt_entries = read_endpoint_observation_index(&index_path).unwrap();
    assert_eq!(rebuilt_entries[0].event_kind, "file_access");

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_flight_recorder_rebuilds_sidecar_index_on_timestamp_mismatch() {
    let root = temp_root();
    let path = root.join("flight-recorder-timestamp-index.jsonl");
    let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
    let base = Utc::now();
    let mut file = observation(EndpointEvent::FileAccess {
        operation: FileOperation::Read,
        path: "/Users/alice/.npmrc".to_string(),
        source_url: None,
        content_preview: None,
    });
    file.observation_id = "file-timestamp-index-1".to_string();
    file.timestamp = base;
    recorder.append_observations(&[file]).unwrap();

    let index_path = endpoint_flight_recorder_index_path(&path);
    let mut entries = read_endpoint_observation_index(&index_path).unwrap();
    assert_eq!(entries.len(), 1);
    entries[0].timestamp = base + chrono::Duration::hours(1);
    replace_endpoint_observation_index(&path, &entries).unwrap();

    let cutoff = base + chrono::Duration::minutes(30);
    let window = recorder
        .read_indexed_observation_window(1, |entry| entry.timestamp >= cutoff)
        .unwrap();

    assert_eq!(window.selection_mode, "sidecar_index_seek");
    assert_eq!(window.total_observation_count, 1);
    assert_eq!(window.matched_observation_count, 0);
    assert!(window.selected_observations.is_empty());
    let rebuilt_entries = read_endpoint_observation_index(&index_path).unwrap();
    assert_eq!(rebuilt_entries[0].timestamp, base);

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_flight_recorder_rebuilds_sidecar_indexes_with_unknown_fields() {
    let root = temp_root();
    let path = root.join("flight-recorder-unknown-index-field.jsonl");
    let mut recorder = EndpointFlightRecorder::open(&path).unwrap();
    let mut network = observation(EndpointEvent::NetworkFlow {
        host: "unknown-index.example.invalid".to_string(),
        port: 443,
        protocol: Some("tcp".to_string()),
        url: None,
    });
    network.observation_id = "network-unknown-index-field-1".to_string();
    recorder.append_observations(&[network]).unwrap();

    let history_index_path = endpoint_flight_recorder_index_path(&path);
    let history_entries = read_endpoint_observation_index(&history_index_path).unwrap();
    assert_eq!(history_entries.len(), 1);
    let mut unknown_history_entry = serde_json::to_value(&history_entries[0]).unwrap();
    unknown_history_entry["shadowByteOffset"] =
        serde_json::Value::String("must not be ignored".to_string());
    write_jsonl_value(&history_index_path, &unknown_history_entry);
    assert_anyhow_error_mentions_unknown_field(
        read_endpoint_observation_index(&history_index_path).unwrap_err(),
        "shadowByteOffset",
    );

    let window = recorder
        .read_indexed_observation_window(1, |entry| entry.event_kind == "network_flow")
        .unwrap();
    assert_eq!(window.selection_mode, "sidecar_index_seek");
    assert_eq!(window.selected_observations.len(), 1);
    let rebuilt_history_entries = read_endpoint_observation_index(&history_index_path).unwrap();
    assert_eq!(
        rebuilt_history_entries[0].observation_id,
        "network-unknown-index-field-1"
    );

    let (node_index_path, node_entries) = recorder.read_graph_node_index().unwrap();
    assert!(!node_entries.is_empty());
    let mut unknown_node_entry = serde_json::to_value(&node_entries[0]).unwrap();
    unknown_node_entry["shadowAttribute"] =
        serde_json::Value::String("must not be ignored".to_string());
    write_jsonl_value(&node_index_path, &unknown_node_entry);
    assert_anyhow_error_mentions_unknown_field(
        read_endpoint_graph_node_index(&node_index_path).unwrap_err(),
        "shadowAttribute",
    );
    let (_, rebuilt_node_entries) = recorder.read_graph_node_index().unwrap();
    assert_eq!(
        rebuilt_node_entries,
        endpoint_graph_node_index_entries(recorder.graph())
    );

    let (edge_index_path, edge_entries) = recorder.read_graph_edge_index().unwrap();
    assert!(!edge_entries.is_empty());
    let mut unknown_edge_entry = serde_json::to_value(&edge_entries[0]).unwrap();
    unknown_edge_entry["shadowObservationId"] =
        serde_json::Value::String("must not be ignored".to_string());
    write_jsonl_value(&edge_index_path, &unknown_edge_entry);
    assert_anyhow_error_mentions_unknown_field(
        read_endpoint_graph_edge_index(&edge_index_path).unwrap_err(),
        "shadowObservationId",
    );
    let (_, rebuilt_edge_entries) = recorder.read_graph_edge_index().unwrap();
    assert_eq!(
        rebuilt_edge_entries,
        endpoint_graph_edge_index_entries(recorder.graph())
    );

    let _ = fs::remove_dir_all(root);
}

#[test]
fn endpoint_flight_recorder_reports_corrupt_jsonl_line() {
    let root = temp_root();
    let path = root.join("flight-recorder.jsonl");
    fs::create_dir_all(&root).unwrap();
    fs::write(&path, "{not-json}\n").unwrap();

    let err = EndpointFlightRecorder::open(&path).unwrap_err();
    assert!(err
        .to_string()
        .contains("invalid endpoint observation JSONL"));
    assert!(err.to_string().contains(":1"));

    let _ = fs::remove_dir_all(root);
}

