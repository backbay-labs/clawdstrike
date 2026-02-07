//! Bridge mapper tests: raw events -> Spine envelopes -> verification
//!
//! These tests verify that Tetragon and Hubble events are correctly mapped
//! to Spine fact envelopes with valid signatures.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hush_core::Keypair;
use serde_json::json;

// Tetragon protobuf types
use tetragon_bridge::tetragon::proto::{
    self as tet, get_events_response::Event, GetEventsResponse,
};

// Hubble protobuf types
use hubble_bridge::hubble::proto::{self as hub};

/// Helper: create a Tetragon Process with optional namespace.
fn make_tetragon_process(binary: &str, ns: Option<&str>) -> tet::Process {
    tet::Process {
        exec_id: None,
        pid: Some(1234),
        uid: Some(0),
        cwd: "/".to_string(),
        binary: binary.to_string(),
        arguments: "--help".to_string(),
        flags: String::new(),
        start_time: None,
        auid: None,
        pod: ns.map(|n| tet::Pod {
            namespace: Some(tet::Namespace {
                value: n.to_string(),
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

/// Helper: create a Hubble endpoint.
fn make_hubble_endpoint(ns: &str, pod: &str) -> hub::Endpoint {
    hub::Endpoint {
        id: 1,
        identity: 100,
        namespace: ns.to_string(),
        labels: vec!["app=test".to_string()],
        pod_name: pod.to_string(),
        workloads: vec![],
        cluster_name: "default".to_string(),
    }
}

/// Helper: create a basic Hubble flow.
fn make_hubble_flow(verdict: hub::Verdict, src_ns: &str, dst_ns: &str) -> hub::Flow {
    hub::Flow {
        time: None,
        verdict: verdict.into(),
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
                destination_port: 80,
                flags: None,
            })),
        }),
        source: Some(make_hubble_endpoint(src_ns, "src-pod")),
        destination: Some(make_hubble_endpoint(dst_ns, "dst-pod")),
        r#type: hub::FlowType::L3L4.into(),
        node_name: "node-1".to_string(),
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
        summary: "TCP Flags: SYN".to_string(),
    }
}

/// Create a simulated ProcessExec event, run through tetragon mapper,
/// verify the resulting Spine envelope has correct fact type and severity.
#[tokio::test]
async fn test_tetragon_process_exec_mapping() {
    let resp = GetEventsResponse {
        event: Some(Event::ProcessExec(tet::ProcessExec {
            process: Some(make_tetragon_process("/usr/bin/curl", Some("default"))),
            parent: Some(make_tetragon_process("/usr/bin/bash", Some("default"))),
            ancestors: String::new(),
        })),
        node_name: "worker-1".to_string(),
        time: None,
        aggregation_info_count: 0,
    };

    let fact = tetragon_bridge::mapper::map_event(&resp);
    assert!(
        fact.is_some(),
        "mapper should produce a fact for ProcessExec"
    );
    let fact = fact.unwrap();

    assert_eq!(
        fact["schema"], "clawdstrike.sdr.fact.tetragon_event.v1",
        "fact schema should match FACT_SCHEMA"
    );
    assert_eq!(fact["event_type"], "process_exec");
    assert_eq!(fact["severity"], "medium"); // normal namespace, normal binary
    assert_eq!(fact["node_name"], "worker-1");
    assert!(fact["process"].is_object());
    assert_eq!(fact["process"]["binary"], "/usr/bin/curl");
    assert_eq!(fact["process"]["pid"], 1234);
}

/// Test file event mapping through kprobe with sensitive path detection.
#[tokio::test]
async fn test_tetragon_file_event_mapping() {
    let resp = GetEventsResponse {
        event: Some(Event::ProcessKprobe(tet::ProcessKprobe {
            process: Some(make_tetragon_process("/usr/bin/cat", Some("default"))),
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
            action: "Override".to_string(),
            policy_name: "sensitive-file-access".to_string(),
            message: "file access to /etc/shadow".to_string(),
            tags: vec!["security".to_string()],
        })),
        node_name: "worker-2".to_string(),
        time: None,
        aggregation_info_count: 0,
    };

    let fact = tetragon_bridge::mapper::map_event(&resp);
    assert!(fact.is_some(), "mapper should produce a fact for kprobe");
    let fact = fact.unwrap();

    assert_eq!(fact["schema"], "clawdstrike.sdr.fact.tetragon_event.v1");
    assert_eq!(fact["event_type"], "process_kprobe");
    // /etc/shadow triggers critical severity
    assert_eq!(fact["severity"], "critical");
    assert_eq!(fact["node_name"], "worker-2");
    assert_eq!(fact["function_name"], "security_file_open");
    assert_eq!(fact["policy_name"], "sensitive-file-access");
}

/// Create a simulated Hubble flow, run through hubble mapper, verify envelope.
#[tokio::test]
async fn test_hubble_flow_mapping() {
    let flow = make_hubble_flow(hub::Verdict::Forwarded, "default", "app-ns");
    let resp = hub::GetFlowsResponse {
        response_types: Some(hub::get_flows_response::ResponseTypes::Flow(flow)),
        node_name: "worker-1".to_string(),
        time: None,
    };

    let fact = hubble_bridge::mapper::map_flow(&resp);
    assert!(fact.is_some(), "mapper should produce a fact for a flow");
    let fact = fact.unwrap();

    assert_eq!(
        fact["schema"], "clawdstrike.sdr.fact.hubble_flow.v1",
        "fact schema should match Hubble FACT_SCHEMA"
    );
    assert_eq!(fact["verdict"], "FORWARDED");
    assert_eq!(fact["severity"], "low"); // forwarded, no L7 errors
    assert_eq!(fact["node_name"], "worker-1");
    assert_eq!(fact["traffic_direction"], "EGRESS");
    assert_eq!(fact["source"]["namespace"], "default");
    assert_eq!(fact["destination"]["namespace"], "app-ns");
    assert_eq!(fact["ip"]["source"], "10.0.0.1");
    assert_eq!(fact["ip"]["destination"], "10.0.0.2");
    assert_eq!(fact["l4"]["protocol"], "TCP");
    assert_eq!(fact["l4"]["destination_port"], 80);
}

/// Test L7 DNS flow mapping.
#[tokio::test]
async fn test_hubble_dns_flow_mapping() {
    let mut flow = make_hubble_flow(hub::Verdict::Forwarded, "default", "kube-system");
    flow.l7 = Some(hub::Layer7 {
        r#type: hub::Layer7FlowType::Request.into(),
        latency_ns: 1500,
        record: Some(hub::layer7::Record::Dns(hub::Dns {
            query: "api.example.com.".to_string(),
            ips: vec!["10.0.1.5".to_string()],
            ttl: 60,
            cnames: vec![],
            observation_source: String::new(),
            rcode: 0,
            qtypes: vec!["A".to_string()],
            rrtypes: vec!["A".to_string()],
        })),
    });

    let resp = hub::GetFlowsResponse {
        response_types: Some(hub::get_flows_response::ResponseTypes::Flow(flow)),
        node_name: "dns-node".to_string(),
        time: None,
    };

    let fact = hubble_bridge::mapper::map_flow(&resp);
    assert!(fact.is_some());
    let fact = fact.unwrap();

    assert_eq!(fact["schema"], "clawdstrike.sdr.fact.hubble_flow.v1");
    assert_eq!(fact["severity"], "low"); // successful DNS, rcode=0
    assert!(fact["l7"].is_object());
    assert_eq!(fact["l7"]["flow_type"], "REQUEST");
    assert_eq!(fact["l7"]["record"]["type"], "dns");
    assert_eq!(fact["l7"]["record"]["query"], "api.example.com.");
    assert_eq!(fact["l7"]["record"]["rcode"], 0);
}

/// Test ProcessExit event mapping: verify event_type and severity.
#[tokio::test]
async fn test_tetragon_process_exit_mapping() {
    let resp = GetEventsResponse {
        event: Some(Event::ProcessExit(tet::ProcessExit {
            process: Some(make_tetragon_process("/usr/bin/sleep", Some("default"))),
            parent: Some(make_tetragon_process("/usr/bin/bash", Some("default"))),
            signal: "SIGTERM".to_string(),
            status: 143,
            time: None,
        })),
        node_name: "worker-1".to_string(),
        time: None,
        aggregation_info_count: 0,
    };

    let fact = tetragon_bridge::mapper::map_event(&resp);
    assert!(
        fact.is_some(),
        "mapper should produce a fact for ProcessExit"
    );
    let fact = fact.unwrap();

    assert_eq!(fact["schema"], "clawdstrike.sdr.fact.tetragon_event.v1");
    assert_eq!(fact["event_type"], "process_exit");
    assert_eq!(fact["severity"], "low"); // exit events are always low
    assert_eq!(fact["node_name"], "worker-1");
    assert_eq!(fact["signal"], "SIGTERM");
    assert_eq!(fact["status"], 143);
    assert!(fact["process"].is_object());
    assert_eq!(fact["process"]["binary"], "/usr/bin/sleep");
}

/// Test that a GetEventsResponse with event: None returns None from map_event.
#[tokio::test]
async fn test_tetragon_none_event_mapping() {
    let resp = GetEventsResponse {
        event: None,
        node_name: "worker-1".to_string(),
        time: None,
        aggregation_info_count: 0,
    };

    let fact = tetragon_bridge::mapper::map_event(&resp);
    assert!(fact.is_none(), "mapper should return None for event: None");
}

/// Test that a Hubble flow with Verdict::Error maps to high severity.
#[tokio::test]
async fn test_hubble_error_verdict_mapping() {
    let flow = make_hubble_flow(hub::Verdict::Error, "default", "app-ns");
    let resp = hub::GetFlowsResponse {
        response_types: Some(hub::get_flows_response::ResponseTypes::Flow(flow)),
        node_name: "worker-1".to_string(),
        time: None,
    };

    let fact = hubble_bridge::mapper::map_flow(&resp);
    assert!(
        fact.is_some(),
        "mapper should produce a fact for Error verdict"
    );
    let fact = fact.unwrap();

    assert_eq!(fact["schema"], "clawdstrike.sdr.fact.hubble_flow.v1");
    assert_eq!(fact["verdict"], "ERROR");
    assert_eq!(fact["severity"], "high"); // Error verdict = high severity
    assert_eq!(fact["node_name"], "worker-1");
}

/// Map an event through bridge, verify the resulting envelope's Ed25519 signature is valid.
#[tokio::test]
async fn test_bridge_envelope_signature_valid() {
    let kp = Keypair::generate();

    // --- Tetragon: map event to fact, wrap in signed envelope, verify ---
    let tet_resp = GetEventsResponse {
        event: Some(Event::ProcessExec(tet::ProcessExec {
            process: Some(make_tetragon_process("/usr/bin/ls", Some("production"))),
            parent: None,
            ancestors: String::new(),
        })),
        node_name: "sig-test-node".to_string(),
        time: None,
        aggregation_info_count: 0,
    };

    let tet_fact = tetragon_bridge::mapper::map_event(&tet_resp).unwrap();

    let tet_envelope =
        spine::build_signed_envelope(&kp, 1, None, tet_fact, spine::now_rfc3339()).unwrap();

    assert!(
        spine::verify_envelope(&tet_envelope).unwrap(),
        "tetragon envelope Ed25519 signature should be valid"
    );

    // Verify the fact is embedded correctly
    assert_eq!(
        tet_envelope["fact"]["schema"],
        "clawdstrike.sdr.fact.tetragon_event.v1"
    );
    assert_eq!(tet_envelope["fact"]["event_type"], "process_exec");

    // --- Hubble: map flow to fact, wrap in signed envelope, verify ---
    let hub_flow = make_hubble_flow(hub::Verdict::Dropped, "kube-system", "default");
    let hub_resp = hub::GetFlowsResponse {
        response_types: Some(hub::get_flows_response::ResponseTypes::Flow(hub_flow)),
        node_name: "sig-test-node".to_string(),
        time: None,
    };

    let hub_fact = hubble_bridge::mapper::map_flow(&hub_resp).unwrap();

    // Chain it after the tetragon envelope
    let prev_hash = tet_envelope
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let hub_envelope =
        spine::build_signed_envelope(&kp, 2, prev_hash.clone(), hub_fact, spine::now_rfc3339())
            .unwrap();

    assert!(
        spine::verify_envelope(&hub_envelope).unwrap(),
        "hubble envelope Ed25519 signature should be valid"
    );

    // Verify chain integrity
    assert_eq!(
        hub_envelope
            .get("prev_envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap(),
        prev_hash.unwrap()
    );

    // Verify the fact is embedded correctly
    assert_eq!(
        hub_envelope["fact"]["schema"],
        "clawdstrike.sdr.fact.hubble_flow.v1"
    );
    assert_eq!(hub_envelope["fact"]["verdict"], "DROPPED");
    assert_eq!(hub_envelope["fact"]["severity"], "critical"); // dropped in kube-system

    // Tampered envelope should fail verification
    let mut tampered = hub_envelope.clone();
    tampered["fact"]["severity"] = json!("low");
    assert!(
        spine::verify_envelope(&tampered).is_err(),
        "tampered envelope should fail verification"
    );
}
