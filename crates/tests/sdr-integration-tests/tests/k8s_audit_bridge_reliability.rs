#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use futures::StreamExt;
use k8s_audit_bridge::{Bridge, BridgeConfig};
use serde_json::{json, Value};

const STREAM_NAME: &str = "CLAWDSTRIKE_K8S_AUDIT";
const SUBJECT: &str = "clawdstrike.spine.envelope.k8s_audit.create.v1";

#[derive(Debug)]
struct DockerContainer {
    id: String,
}

impl DockerContainer {
    fn start_nats(port: u16) -> Result<Self, String> {
        let port_map = format!("{port}:4222");
        let output = Command::new("docker")
            .args([
                "run",
                "-d",
                "--rm",
                "-p",
                port_map.as_str(),
                "nats:2.10-alpine",
                "-js",
            ])
            .output()
            .map_err(|e| format!("failed to execute docker run: {e}"))?;

        if !output.status.success() {
            return Err(format!(
                "docker run failed: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let id = String::from_utf8(output.stdout)
            .map_err(|e| format!("docker container id utf8: {e}"))?
            .trim()
            .to_string();
        if id.is_empty() {
            return Err("docker run returned empty container id".to_string());
        }
        Ok(Self { id })
    }
}

impl Drop for DockerContainer {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.id]).status();
    }
}

#[derive(Debug)]
struct LocalNatsProcess {
    child: Child,
}

impl LocalNatsProcess {
    fn start(port: u16) -> Result<Self, String> {
        let child = Command::new("nats-server")
            .args(["-js", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("failed to spawn nats-server: {e}"))?;
        Ok(Self { child })
    }
}

impl Drop for LocalNatsProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[derive(Debug)]
struct NatsHarness {
    url: String,
    client: async_nats::Client,
    _docker: Option<DockerContainer>,
    _local: Option<LocalNatsProcess>,
}

impl NatsHarness {
    async fn start() -> Result<Self, String> {
        let mut errors = Vec::new();

        if docker_available() {
            let port = free_local_port();
            match DockerContainer::start_nats(port) {
                Ok(container) => {
                    let url = format!("nats://127.0.0.1:{port}");
                    wait_for_nats(&url).await?;
                    let client = async_nats::connect(&url)
                        .await
                        .map_err(|e| format!("connect nats after docker startup: {e}"))?;
                    return Ok(Self {
                        url,
                        client,
                        _docker: Some(container),
                        _local: None,
                    });
                }
                Err(err) => errors.push(err),
            }
        } else {
            errors.push("docker unavailable".to_string());
        }

        if command_available("nats-server") {
            let port = free_local_port();
            match LocalNatsProcess::start(port) {
                Ok(process) => {
                    let url = format!("nats://127.0.0.1:{port}");
                    wait_for_nats(&url).await?;
                    let client = async_nats::connect(&url)
                        .await
                        .map_err(|e| format!("connect nats after local startup: {e}"))?;
                    return Ok(Self {
                        url,
                        client,
                        _docker: None,
                        _local: Some(process),
                    });
                }
                Err(err) => errors.push(err),
            }
        } else {
            errors.push("nats-server unavailable".to_string());
        }

        Err(format!(
            "unable to start NATS backend: {}",
            errors.join(" | ")
        ))
    }
}

struct BridgeHarness {
    base_url: String,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for BridgeHarness {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

fn command_available(name: &str) -> bool {
    Command::new("which")
        .arg(name)
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn docker_available() -> bool {
    Command::new("docker")
        .args(["info"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

fn free_local_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local addr").port()
}

async fn wait_for_nats(url: &str) -> Result<(), String> {
    for _ in 0..80 {
        match async_nats::connect(url).await {
            Ok(client) => {
                let _ = client.flush().await;
                return Ok(());
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(150)).await,
        }
    }
    Err(format!("timed out waiting for NATS at {url}"))
}

async fn start_bridge(
    nats_url: &str,
    outbox_enabled: bool,
    outbox_flush_interval_ms: u64,
) -> BridgeHarness {
    let listen_port = free_local_port();
    let listen_addr = format!("127.0.0.1:{listen_port}");
    let bridge = Bridge::new(BridgeConfig {
        listen_addr: listen_addr.clone(),
        nats_url: nats_url.to_string(),
        outbox_enabled,
        outbox_path: Some(format!("/tmp/k8s-audit-bridge-it-{listen_port}.db")),
        outbox_flush_interval_ms,
        ..BridgeConfig::default()
    })
    .await
    .expect("bridge should construct");

    let handle = tokio::spawn(async move {
        let _ = bridge.run().await;
    });

    let base_url = format!("http://{listen_addr}");
    for _ in 0..60 {
        let ok = reqwest::Client::new()
            .get(format!("{base_url}/healthz"))
            .send()
            .await
            .map(|resp| resp.status().is_success())
            .unwrap_or(false);
        if ok {
            return BridgeHarness { base_url, handle };
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    panic!("bridge did not become ready in time");
}

async fn post_audit_event(base_url: &str, audit_id: &str) -> reqwest::StatusCode {
    let payload = json!({
        "auditID": audit_id,
        "verb": "create",
        "stage": "ResponseComplete",
        "user": {"username": "integration"},
        "objectRef": {"resource": "pods", "namespace": "default", "name": "it-pod"},
        "requestURI": "/api/v1/namespaces/default/pods"
    });

    reqwest::Client::new()
        .post(format!("{base_url}/webhook"))
        .json(&payload)
        .send()
        .await
        .expect("webhook request")
        .status()
}

async fn recv_seq(sub: &mut async_nats::Subscriber) -> u64 {
    let msg = tokio::time::timeout(Duration::from_secs(5), sub.next())
        .await
        .expect("timed out waiting for envelope")
        .expect("subscriber stream ended");
    let envelope: Value = serde_json::from_slice(&msg.payload).expect("valid envelope payload");
    envelope["seq"].as_u64().expect("envelope seq")
}

async fn try_recv_seq(sub: &mut async_nats::Subscriber, timeout: Duration) -> Option<u64> {
    let msg = match tokio::time::timeout(timeout, sub.next()).await {
        Ok(Some(msg)) => msg,
        Ok(None) | Err(_) => return None,
    };
    let envelope: Value = serde_json::from_slice(&msg.payload).ok()?;
    envelope["seq"].as_u64()
}

async fn wait_for_seq(
    sub: &mut async_nats::Subscriber,
    expected_seq: u64,
    timeout: Duration,
) -> bool {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(seq) = try_recv_seq(sub, Duration::from_millis(500)).await {
                if seq == expected_seq {
                    break true;
                }
            }
        }
    })
    .await
    .unwrap_or(false)
}

async fn fetch_metrics(base_url: &str) -> String {
    reqwest::Client::new()
        .get(format!("{base_url}/metrics"))
        .send()
        .await
        .expect("metrics request")
        .text()
        .await
        .expect("metrics body")
}

fn extract_metric_u64(metrics: &str, metric_name: &str) -> Option<u64> {
    metrics.lines().find_map(|line| {
        let line = line.trim();
        if !line.starts_with(metric_name) || line.starts_with('#') {
            return None;
        }
        line.split_whitespace()
            .last()
            .and_then(|v| v.parse::<u64>().ok())
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn webhook_returns_200_then_503_on_forced_publish_failure() {
    let harness = match NatsHarness::start().await {
        Ok(h) => h,
        Err(err) => {
            eprintln!("skipping integration test: {err}");
            return;
        }
    };

    let _bridge = start_bridge(&harness.url, false, 1_000).await;

    let status_ok = post_audit_event(&_bridge.base_url, "ok-1").await;
    assert_eq!(status_ok, reqwest::StatusCode::OK);

    let js = async_nats::jetstream::new(harness.client.clone());
    js.delete_stream(STREAM_NAME)
        .await
        .expect("delete stream to force publish failures");

    let status_fail = post_audit_event(&_bridge.base_url, "fail-1").await;
    assert_eq!(status_fail, reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sequence_continuity_is_preserved_across_failed_publishes() {
    let harness = match NatsHarness::start().await {
        Ok(h) => h,
        Err(err) => {
            eprintln!("skipping integration test: {err}");
            return;
        }
    };

    let bridge = start_bridge(&harness.url, false, 1_000).await;

    let mut sub = harness
        .client
        .subscribe(SUBJECT.to_string())
        .await
        .expect("subscribe subject");
    harness.client.flush().await.expect("nats flush");

    let status_first = post_audit_event(&bridge.base_url, "seq-1").await;
    assert_eq!(status_first, reqwest::StatusCode::OK);
    let first_seq = recv_seq(&mut sub).await;
    assert_eq!(first_seq, 1);

    let js = async_nats::jetstream::new(harness.client.clone());
    js.delete_stream(STREAM_NAME)
        .await
        .expect("delete stream to force publish failures");

    let status_failed = post_audit_event(&bridge.base_url, "seq-fail").await;
    assert_eq!(status_failed, reqwest::StatusCode::SERVICE_UNAVAILABLE);

    spine::nats_transport::ensure_stream(
        &js,
        STREAM_NAME,
        vec!["clawdstrike.spine.envelope.k8s_audit.>".to_string()],
        1,
    )
    .await
    .expect("recreate stream");

    let status_second = post_audit_event(&bridge.base_url, "seq-2").await;
    assert_eq!(status_second, reqwest::StatusCode::OK);
    let second_seq = recv_seq(&mut sub).await;
    assert_eq!(second_seq, 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn outbox_replays_after_publish_path_recovers() {
    let harness = match NatsHarness::start().await {
        Ok(h) => h,
        Err(err) => {
            eprintln!("skipping integration test: {err}");
            return;
        }
    };

    let bridge = start_bridge(&harness.url, true, 200).await;

    let mut sub = harness
        .client
        .subscribe(SUBJECT.to_string())
        .await
        .expect("subscribe subject");
    harness.client.flush().await.expect("nats flush");

    let js = async_nats::jetstream::new(harness.client.clone());
    js.delete_stream(STREAM_NAME)
        .await
        .expect("delete stream to force publish failures");

    let status_failed_publish = post_audit_event(&bridge.base_url, "outbox-replay-1").await;
    assert_eq!(status_failed_publish, reqwest::StatusCode::OK);

    let publish_failures_observed = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let metrics = fetch_metrics(&bridge.base_url).await;
            let failures = extract_metric_u64(&metrics, "publish_failures_total").unwrap_or(0);
            if failures >= 1 {
                break true;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        publish_failures_observed,
        "expected publish failure metric increment before replay"
    );

    spine::nats_transport::ensure_stream(
        &js,
        STREAM_NAME,
        vec!["clawdstrike.spine.envelope.k8s_audit.>".to_string()],
        1,
    )
    .await
    .expect("recreate stream");

    let replay_seq = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(seq) = try_recv_seq(&mut sub, Duration::from_millis(500)).await {
                break seq;
            }
        }
    })
    .await
    .expect("timed out waiting for outbox replay");
    assert_eq!(replay_seq, 1);

    let status_live_publish = post_audit_event(&bridge.base_url, "outbox-replay-2").await;
    assert_eq!(status_live_publish, reqwest::StatusCode::OK);

    assert!(
        wait_for_seq(&mut sub, 2, Duration::from_secs(10)).await,
        "expected eventual seq=2 publish after replay recovery"
    );
}
