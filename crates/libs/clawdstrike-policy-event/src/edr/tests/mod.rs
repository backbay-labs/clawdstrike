#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

static TEMP_ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn observation(event: EndpointEvent) -> EndpointObservation {
    EndpointObservation {
        observation_id: stable_id("test", ["obs", event_name(&event)]),
        timestamp: Utc::now(),
        host_id: Some("host-1".to_string()),
        user_id: Some("alice".to_string()),
        session_id: Some("session-1".to_string()),
        process: EndpointProcess {
            pid: Some(42),
            process_guid: Some("proc-42".to_string()),
            image: Some("/usr/bin/npm".to_string()),
            command_line: Some("npm install".to_string()),
            signing: CodeSignatureStatus {
                trust: SignatureTrust::Notarized,
                notarized: Some(true),
                ..CodeSignatureStatus::default()
            },
            ..EndpointProcess::default()
        },
        event,
        metadata: BTreeMap::new(),
    }
}

fn event_name(event: &EndpointEvent) -> &'static str {
    match event {
        EndpointEvent::PackageScript { .. } => "script",
        EndpointEvent::ProcessExec { .. } => "exec",
        EndpointEvent::FileAccess { .. } => "file",
        EndpointEvent::NetworkFlow { .. } => "network",
        EndpointEvent::DnsLookup { .. } => "dns",
        EndpointEvent::CredentialAccess { .. } => "credential",
        _ => "other",
    }
}

fn assert_unknown_field_rejected<T>(mut value: serde_json::Value, field: &str)
where
    T: serde::de::DeserializeOwned,
{
    value[field] = serde_json::Value::String("must not be ignored".to_string());
    let Err(err) = serde_json::from_value::<T>(value) else {
        panic!("expected unknown field {field} to be rejected");
    };
    let err = err.to_string();
    assert!(
        err.contains("unknown field") && err.contains(field),
        "expected unknown field {field} to be rejected, got {err}"
    );
}

fn write_jsonl_value(path: &Path, value: &serde_json::Value) {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    fs::write(path, bytes).unwrap();
}

fn assert_anyhow_error_mentions_unknown_field(err: anyhow::Error, field: &str) {
    let chain = err
        .chain()
        .map(std::string::ToString::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        chain.contains("unknown field") && chain.contains(field),
        "expected unknown field {field} to be rejected, got {chain}"
    );
}

include!("parts/conversion_privacy.rs");
include!("parts/supply_chain.rs");
include!("parts/deception.rs");
include!("parts/causal_graph.rs");
include!("parts/flight_recorder.rs");
include!("parts/receipts_part_1.rs");
include!("parts/receipts_part_2.rs");
include!("parts/receipts_part_3.rs");
include!("parts/receipts_part_4.rs");

fn response_actor(endpoint_id: &str) -> EndpointDecisionActor {
    EndpointDecisionActor {
        endpoint_id: endpoint_id.to_string(),
        session_id: Some("session-response".to_string()),
        posture: Some("restricted".to_string()),
        agent_id: Some("agent-api:test".to_string()),
        workload_id: Some("endpoint-response-engine".to_string()),
        ..EndpointDecisionActor::default()
    }
}

fn valid_detection_receipt(
    local_sequence: u64,
    endpoint_id: &str,
    signer_identity: &str,
    observation: &EndpointObservation,
    finding: &DetectionFinding,
    graph: &CausalGraph,
) -> EndpointDecisionReceipt {
    EndpointDecisionReceipt::for_detection(EndpointDetectionReceiptInput {
        local_sequence,
        endpoint_id,
        signer_identity,
        policy: EndpointPolicySnapshot {
            policy_version: "test-policy@1".to_string(),
            policy_hash: sha256(b"test-policy").to_hex_prefixed(),
            policy_epoch: 7,
        },
        sensor_state: EndpointSensorState::single_active_agent("agent-api:test"),
        observation,
        finding,
        graph,
    })
}

fn temp_root() -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let counter = TEMP_ROOT_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "clawdstrike-edr-test-{}-{millis}-{counter}",
        std::process::id(),
    ))
}
