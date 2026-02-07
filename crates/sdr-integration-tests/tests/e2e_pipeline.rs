//! End-to-end pipeline integration test:
//!
//! 1. Simulate Tetragon events (ProcessExec)
//! 2. Map to Spine facts via the bridge mapper
//! 3. Sign into Spine envelopes
//! 4. "Publish" to a simulated transport (in-memory channel standing in for NATS)
//! 5. "Receive" envelopes on the correct subject
//! 6. Simulate the checkpointer: collect N envelopes, build Merkle tree, create checkpoint
//! 7. Verify checkpoint has correct Merkle root
//! 8. Generate an inclusion proof for one of the envelopes
//! 9. Verify the inclusion proof against the checkpoint
//! 10. Witness co-signs the checkpoint and signature is verified
//!
//! Self-contained: no external services (NATS, Tetragon, Hubble) required.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::HashMap;

use hush_core::{Keypair, MerkleTree};
use serde_json::Value;
use tokio::sync::mpsc;

use tetragon_bridge::tetragon::proto::{
    self as tet, get_events_response::Event, GetEventsResponse,
};

/// NATS subject prefix matching the real tetragon-bridge.
const NATS_SUBJECT_PREFIX: &str = "clawdstrike.spine.envelope.tetragon";

/// A simulated message on the NATS transport.
struct NatsMessage {
    subject: String,
    payload: Vec<u8>,
}

/// Simulate Tetragon event kind -> NATS subject suffix (mirrors TetragonEventKind).
fn event_kind_suffix(resp: &GetEventsResponse) -> &'static str {
    match &resp.event {
        Some(Event::ProcessExec(_)) => "process_exec",
        Some(Event::ProcessExit(_)) => "process_exit",
        Some(Event::ProcessKprobe(_)) => "process_kprobe",
        None => "unknown",
    }
}

/// Helper: create a Tetragon Process.
fn make_process(binary: &str, ns: &str) -> tet::Process {
    tet::Process {
        exec_id: None,
        pid: Some(1234),
        uid: Some(0),
        cwd: "/".to_string(),
        binary: binary.to_string(),
        arguments: String::new(),
        flags: String::new(),
        start_time: None,
        auid: None,
        pod: Some(tet::Pod {
            namespace: Some(tet::Namespace {
                value: ns.to_string(),
            }),
            name: "test-pod".to_string(),
            container: None,
            pod_labels: Default::default(),
            workload: None,
        }),
        docker: String::new(),
        parent_exec_id: None,
        cap: None,
        ns: None,
        tid: None,
    }
}

/// Full end-to-end pipeline: Tetragon events -> bridge -> NATS -> checkpointer -> proof.
#[tokio::test]
async fn test_e2e_tetragon_to_checkpoint_proof() {
    // --- Setup: signing keypair and simulated NATS channel ---
    let bridge_kp = Keypair::generate();
    let witness_kp = Keypair::generate();

    // Simulated NATS transport: mpsc channel stands in for NATS pub/sub.
    let (nats_tx, mut nats_rx) = mpsc::channel::<NatsMessage>(64);

    // --- Phase 1: Simulate Tetragon events ---
    let tetragon_events: Vec<GetEventsResponse> = vec![
        GetEventsResponse {
            event: Some(Event::ProcessExec(tet::ProcessExec {
                process: Some(make_process("/usr/bin/curl", "default")),
                parent: Some(make_process("/usr/bin/bash", "default")),
                ancestors: String::new(),
            })),
            node_name: "worker-1".to_string(),
            time: None,
            aggregation_info_count: 0,
        },
        GetEventsResponse {
            event: Some(Event::ProcessExec(tet::ProcessExec {
                process: Some(make_process("/usr/bin/wget", "production")),
                parent: None,
                ancestors: String::new(),
            })),
            node_name: "worker-2".to_string(),
            time: None,
            aggregation_info_count: 0,
        },
        GetEventsResponse {
            event: Some(Event::ProcessExec(tet::ProcessExec {
                process: Some(make_process("/usr/bin/python3", "staging")),
                parent: None,
                ancestors: String::new(),
            })),
            node_name: "worker-3".to_string(),
            time: None,
            aggregation_info_count: 0,
        },
        GetEventsResponse {
            event: Some(Event::ProcessKprobe(tet::ProcessKprobe {
                process: Some(make_process("/usr/bin/cat", "default")),
                parent: None,
                function_name: "security_file_open".to_string(),
                args: vec![tet::KprobeArgument {
                    arg: Some(tet::kprobe_argument::Arg::FileArg(tet::KprobeFile {
                        mount: String::new(),
                        path: "/etc/shadow".to_string(),
                        flags: String::new(),
                        permission: String::new(),
                    })),
                    label: "file".to_string(),
                }],
                action: String::new(),
                policy_name: "file-monitor".to_string(),
                message: String::new(),
                tags: vec![],
            })),
            node_name: "worker-1".to_string(),
            time: None,
            aggregation_info_count: 0,
        },
        GetEventsResponse {
            event: Some(Event::ProcessExec(tet::ProcessExec {
                process: Some(make_process("/bin/sh", "kube-system")),
                parent: None,
                ancestors: String::new(),
            })),
            node_name: "control-1".to_string(),
            time: None,
            aggregation_info_count: 0,
        },
    ];

    let num_events = tetragon_events.len() as u64;

    // --- Phase 2: Bridge simulation (mapper + envelope signing + NATS publish) ---
    {
        let mut seq = 1u64;
        let mut prev_hash: Option<String> = None;

        for resp in &tetragon_events {
            // Step 2a: Map event to fact via tetragon-bridge mapper.
            let fact = tetragon_bridge::mapper::map_event(resp);
            let Some(fact) = fact else {
                continue;
            };

            // Step 2b: Sign into a Spine envelope.
            let envelope = spine::build_signed_envelope(
                &bridge_kp,
                seq,
                prev_hash.clone(),
                fact,
                spine::now_rfc3339(),
            )
            .unwrap();

            // Track chain.
            prev_hash = envelope
                .get("envelope_hash")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // Step 2c: Determine the NATS subject (mirrors real bridge logic).
            let suffix = event_kind_suffix(resp);
            let subject = format!("{NATS_SUBJECT_PREFIX}.{suffix}.v1");

            // Step 2d: Publish to simulated NATS.
            let payload = serde_json::to_vec(&envelope).unwrap();
            nats_tx
                .send(NatsMessage { subject, payload })
                .await
                .unwrap();

            seq += 1;
        }
    }

    // Close the sender so the receiver knows there are no more messages.
    drop(nats_tx);

    // --- Phase 3: Consumer receives envelopes from simulated NATS ---
    let mut received_envelopes: Vec<Value> = Vec::new();
    let mut subject_counts: HashMap<String, usize> = HashMap::new();

    while let Some(msg) = nats_rx.recv().await {
        // Step 3a: Parse the envelope from the NATS payload.
        let envelope: Value = serde_json::from_slice(&msg.payload).unwrap();

        // Step 3b: Verify the envelope was published on the correct subject.
        let fact = envelope.get("fact").unwrap();
        let event_type = fact.get("event_type").and_then(|v| v.as_str()).unwrap();
        let expected_subject = format!("{NATS_SUBJECT_PREFIX}.{event_type}.v1");
        assert_eq!(
            msg.subject, expected_subject,
            "envelope published on wrong NATS subject"
        );

        // Step 3c: Verify Ed25519 signature of the received envelope.
        assert!(
            spine::verify_envelope(&envelope).unwrap(),
            "received envelope has invalid signature"
        );

        *subject_counts.entry(msg.subject).or_insert(0) += 1;
        received_envelopes.push(envelope);
    }

    // Step 3d: Verify we received all events.
    assert_eq!(received_envelopes.len(), num_events as usize);

    // Verify subject routing: 4 process_exec, 1 process_kprobe.
    assert_eq!(
        subject_counts
            .get(&format!("{NATS_SUBJECT_PREFIX}.process_exec.v1"))
            .copied()
            .unwrap_or(0),
        4
    );
    assert_eq!(
        subject_counts
            .get(&format!("{NATS_SUBJECT_PREFIX}.process_kprobe.v1"))
            .copied()
            .unwrap_or(0),
        1
    );

    // --- Phase 4: Simulate checkpointer ---
    // Step 4a: Serialize envelopes to leaf bytes for Merkle tree.
    let leaves: Vec<Vec<u8>> = received_envelopes
        .iter()
        .map(|e| serde_json::to_vec(e).unwrap())
        .collect();

    // Step 4b: Build Merkle tree.
    let tree = MerkleTree::from_leaves(&leaves).unwrap();
    let merkle_root = tree.root();

    assert_eq!(tree.leaf_count(), num_events as usize);

    // Step 4c: Build checkpoint statement.
    let checkpoint = spine::checkpoint_statement(
        "sdr-test-log",
        1,
        None,
        merkle_root.to_hex_prefixed(),
        num_events,
        spine::now_rfc3339(),
    );

    // Step 4d: Verify checkpoint fields.
    assert_eq!(checkpoint["log_id"], "sdr-test-log");
    assert_eq!(checkpoint["checkpoint_seq"], 1);
    assert_eq!(checkpoint["merkle_root"], merkle_root.to_hex_prefixed());
    assert_eq!(checkpoint["tree_size"], num_events);

    // --- Phase 5: Witness co-signs the checkpoint ---
    let witness_sig = spine::sign_checkpoint_statement(&witness_kp, &checkpoint).unwrap();
    let witness_id = witness_sig
        .get("witness_node_id")
        .and_then(|v| v.as_str())
        .unwrap();
    let sig_hex = witness_sig
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap();

    assert!(
        spine::verify_witness_signature(&checkpoint, witness_id, sig_hex).unwrap(),
        "witness signature on checkpoint should be valid"
    );

    // --- Phase 6: Generate and verify inclusion proofs ---
    // Step 6a: Verify inclusion proof for every envelope.
    for (idx, leaf) in leaves.iter().enumerate() {
        let proof = tree.inclusion_proof(idx).unwrap();
        assert!(
            proof.verify(leaf, &merkle_root),
            "inclusion proof failed for envelope at index {idx}"
        );
    }

    // Step 6b: Specifically test the kprobe envelope (index 3).
    let kprobe_idx = 3;
    let kprobe_proof = tree.inclusion_proof(kprobe_idx).unwrap();
    assert!(kprobe_proof.verify(&leaves[kprobe_idx], &merkle_root));

    // Verify the kprobe envelope's fact has the expected severity.
    let kprobe_fact = received_envelopes[kprobe_idx].get("fact").unwrap();
    assert_eq!(kprobe_fact["event_type"], "process_kprobe");
    assert_eq!(kprobe_fact["severity"], "critical"); // /etc/shadow

    // Step 6c: Verify proof rejects wrong data.
    assert!(
        !kprobe_proof.verify(b"tampered-data", &merkle_root),
        "proof should reject wrong leaf data"
    );

    // Step 6d: Verify proof rejects wrong root.
    let wrong_root = hush_core::sha256(b"not-the-real-root");
    assert!(
        !kprobe_proof.verify(&leaves[kprobe_idx], &wrong_root),
        "proof should reject wrong Merkle root"
    );
}

/// Test envelope chain integrity: prev_envelope_hash links form an ordered chain.
#[tokio::test]
async fn test_envelope_chain_integrity() {
    let kp = Keypair::generate();

    let events: Vec<GetEventsResponse> = (0..5)
        .map(|i| GetEventsResponse {
            event: Some(Event::ProcessExec(tet::ProcessExec {
                process: Some(make_process(&format!("/usr/bin/tool-{i}"), "default")),
                parent: None,
                ancestors: String::new(),
            })),
            node_name: format!("node-{i}"),
            time: None,
            aggregation_info_count: 0,
        })
        .collect();

    let mut envelopes = Vec::new();
    let mut prev_hash: Option<String> = None;

    for (seq, resp) in events.iter().enumerate() {
        let fact = tetragon_bridge::mapper::map_event(resp).unwrap();
        let envelope = spine::build_signed_envelope(
            &kp,
            (seq + 1) as u64,
            prev_hash.clone(),
            fact,
            spine::now_rfc3339(),
        )
        .unwrap();

        prev_hash = envelope
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        envelopes.push(envelope);
    }

    // Verify chain: each envelope's prev_envelope_hash matches the previous envelope_hash.
    for i in 1..envelopes.len() {
        let expected_prev = envelopes[i - 1]
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap();
        let actual_prev = envelopes[i]
            .get("prev_envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap();
        assert_eq!(
            actual_prev, expected_prev,
            "chain broken at index {i}: prev_envelope_hash mismatch"
        );
    }

    // First envelope should have null prev_envelope_hash.
    assert!(envelopes[0]["prev_envelope_hash"].is_null());

    // Every envelope should have a valid signature.
    for (i, env) in envelopes.iter().enumerate() {
        assert!(
            spine::verify_envelope(env).unwrap(),
            "invalid signature at index {i}"
        );
    }

    // All envelope_hashes should be unique.
    let hashes: Vec<&str> = envelopes
        .iter()
        .map(|e| e["envelope_hash"].as_str().unwrap())
        .collect();
    let unique: std::collections::HashSet<&&str> = hashes.iter().collect();
    assert_eq!(
        hashes.len(),
        unique.len(),
        "envelope hashes should be unique"
    );
}

/// Test mixed Tetragon + Hubble events flowing through the same checkpoint.
#[tokio::test]
async fn test_mixed_bridge_checkpoint() {
    use hubble_bridge::hubble::proto::{self as hub};

    let kp = Keypair::generate();
    let mut envelopes = Vec::new();
    let mut prev_hash: Option<String> = None;
    let mut seq = 1u64;

    // Tetragon event
    let tet_resp = GetEventsResponse {
        event: Some(Event::ProcessExec(tet::ProcessExec {
            process: Some(make_process("/usr/bin/curl", "default")),
            parent: None,
            ancestors: String::new(),
        })),
        node_name: "worker-1".to_string(),
        time: None,
        aggregation_info_count: 0,
    };
    let tet_fact = tetragon_bridge::mapper::map_event(&tet_resp).unwrap();
    let tet_env =
        spine::build_signed_envelope(&kp, seq, prev_hash.clone(), tet_fact, spine::now_rfc3339())
            .unwrap();
    prev_hash = tet_env
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    envelopes.push(tet_env);
    seq += 1;

    // Hubble event
    let hub_flow = hub::Flow {
        time: None,
        verdict: hub::Verdict::Dropped.into(),
        drop_reason: 0,
        ethernet: None,
        ip: Some(hub::Ip {
            source: "10.0.0.1".to_string(),
            destination: "10.0.0.2".to_string(),
            ip_version: hub::IpVersion::IPv4.into(),
            encrypted: false,
        }),
        l4: Some(hub::Layer4 {
            protocol: Some(hub::layer4::Protocol::Tcp(hub::Tcp {
                source_port: 12345,
                destination_port: 443,
                flags: None,
            })),
        }),
        source: Some(hub::Endpoint {
            id: 1,
            identity: 100,
            namespace: "kube-system".to_string(),
            labels: vec![],
            pod_name: "coredns".to_string(),
            workloads: vec![],
            cluster_name: "default".to_string(),
        }),
        destination: Some(hub::Endpoint {
            id: 2,
            identity: 200,
            namespace: "default".to_string(),
            labels: vec![],
            pod_name: "app".to_string(),
            workloads: vec![],
            cluster_name: "default".to_string(),
        }),
        r#type: hub::FlowType::L3L4.into(),
        node_name: "worker-1".to_string(),
        source_names: vec![],
        destination_names: vec![],
        l7: None,
        reply: false,
        event_type: None,
        source_service: None,
        destination_service: None,
        traffic_direction: hub::TrafficDirection::Egress.into(),
        policy_match_type: 0,
        drop_reason_desc: 0,
        is_reply: false,
        trace_observation_point: String::new(),
        drop_reason_extra: vec![],
        summary: "TCP SYN".to_string(),
    };
    let hub_resp = hub::GetFlowsResponse {
        response_types: Some(hub::get_flows_response::ResponseTypes::Flow(hub_flow)),
        node_name: "worker-1".to_string(),
        time: None,
    };
    let hub_fact = hubble_bridge::mapper::map_flow(&hub_resp).unwrap();
    let hub_env =
        spine::build_signed_envelope(&kp, seq, prev_hash.clone(), hub_fact, spine::now_rfc3339())
            .unwrap();
    prev_hash = hub_env
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    envelopes.push(hub_env);
    seq += 1;

    // Another Tetragon event
    let tet_resp_2 = GetEventsResponse {
        event: Some(Event::ProcessExec(tet::ProcessExec {
            process: Some(make_process("/usr/bin/python3", "staging")),
            parent: None,
            ancestors: String::new(),
        })),
        node_name: "worker-2".to_string(),
        time: None,
        aggregation_info_count: 0,
    };
    let tet_fact_2 = tetragon_bridge::mapper::map_event(&tet_resp_2).unwrap();
    let tet_env_2 =
        spine::build_signed_envelope(&kp, seq, prev_hash, tet_fact_2, spine::now_rfc3339())
            .unwrap();
    envelopes.push(tet_env_2);

    // All envelopes should verify.
    for (i, env) in envelopes.iter().enumerate() {
        assert!(
            spine::verify_envelope(env).unwrap(),
            "envelope {i} signature invalid"
        );
    }

    // Build checkpoint from mixed envelopes.
    let leaves: Vec<Vec<u8>> = envelopes
        .iter()
        .map(|e| serde_json::to_vec(e).unwrap())
        .collect();
    let tree = MerkleTree::from_leaves(&leaves).unwrap();
    let root = tree.root();

    let checkpoint = spine::checkpoint_statement(
        "mixed-log",
        1,
        None,
        root.to_hex_prefixed(),
        envelopes.len() as u64,
        spine::now_rfc3339(),
    );

    // Verify each envelope has a valid inclusion proof.
    for (idx, leaf) in leaves.iter().enumerate() {
        let proof = tree.inclusion_proof(idx).unwrap();
        assert!(proof.verify(leaf, &root), "proof failed at index {idx}");
    }

    // Verify the Hubble envelope (index 1) fact type.
    assert_eq!(
        envelopes[1]["fact"]["schema"],
        "clawdstrike.sdr.fact.hubble_flow.v1"
    );
    assert_eq!(envelopes[1]["fact"]["verdict"], "DROPPED");
    assert_eq!(envelopes[1]["fact"]["severity"], "critical");

    // Verify checkpoint can be witnessed.
    let witness = spine::sign_checkpoint_statement(&kp, &checkpoint).unwrap();
    let wid = witness["witness_node_id"].as_str().unwrap();
    let wsig = witness["signature"].as_str().unwrap();
    assert!(spine::verify_witness_signature(&checkpoint, wid, wsig).unwrap());
}
