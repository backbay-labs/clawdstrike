#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use async_nats::jetstream::Context as JetStreamContext;
use serde_json::{json, Value};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct CommandResult {
    status: ExitStatus,
    stdout: String,
    stderr: String,
}

impl CommandResult {
    fn status_code(&self) -> Option<i32> {
        self.status.code()
    }
}

fn is_ci() -> bool {
    std::env::var("CI")
        .map(|v| {
            let lowered = v.trim().to_ascii_lowercase();
            lowered == "1" || lowered == "true" || lowered == "yes"
        })
        .unwrap_or(false)
}

fn keep_artifacts() -> bool {
    std::env::var("HUSH_HUNT_E2E_KEEP_ARTIFACTS")
        .map(|v| {
            let lowered = v.trim().to_ascii_lowercase();
            lowered == "1" || lowered == "true" || lowered == "yes"
        })
        .unwrap_or(false)
}

fn command_timeout(default: Duration) -> Duration {
    std::env::var("HUSH_HUNT_E2E_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|ms| *ms > 0)
        .map(Duration::from_millis)
        .unwrap_or(default)
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

fn resolve_hush_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_hush") {
        return PathBuf::from(path);
    }
    if let Some(path) = resolve_hush_binary_from_current_target() {
        return path;
    }

    let candidate = workspace_root()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "hush.exe" } else { "hush" });

    let status = Command::new("cargo")
        .current_dir(workspace_root())
        .arg("build")
        .arg("-p")
        .arg("hush-cli")
        .arg("--bin")
        .arg("hush")
        .status()
        .expect("build hush binary for hunt e2e");
    assert!(status.success(), "failed to build hush binary for hunt e2e");

    candidate
}

fn resolve_hush_binary_from_current_target() -> Option<PathBuf> {
    let current_exe = std::env::current_exe().ok()?;
    let target_dir = current_exe.parent()?.parent()?;
    let candidate = target_dir.join(if cfg!(windows) { "hush.exe" } else { "hush" });
    candidate.is_file().then_some(candidate)
}

fn run_hush(args: &[String], timeout: Duration) -> CommandResult {
    let mut cmd = Command::new(resolve_hush_binary());
    cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn hush");
    let started = Instant::now();
    loop {
        match child.try_wait().expect("try_wait hush") {
            Some(_) => {
                let output = child.wait_with_output().expect("wait_with_output hush");
                return CommandResult {
                    status: output.status,
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                };
            }
            None => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let output = child
                        .wait_with_output()
                        .expect("wait_with_output after kill");
                    return CommandResult {
                        status: output.status,
                        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    };
                }
                thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn parse_stdout_json(result: &CommandResult) -> Value {
    serde_json::from_str(&result.stdout).unwrap_or_else(|e| {
        panic!(
            "expected JSON stdout, got parse error: {e}\nstdout:\n{}\nstderr:\n{}",
            result.stdout, result.stderr
        )
    })
}

fn create_temp_dir(prefix: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), seq));
    fs::create_dir_all(&path).expect("create temp dir");
    path
}

#[derive(Debug)]
struct TestWorkspace {
    root: PathBuf,
    keep: bool,
}

impl TestWorkspace {
    fn new(prefix: &str) -> Self {
        Self {
            root: create_temp_dir(prefix),
            keep: keep_artifacts(),
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }
}

impl Drop for TestWorkspace {
    fn drop(&mut self) {
        if self.keep {
            eprintln!("hunt e2e: keeping artifacts at {}", self.root.display());
            return;
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}

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
#[allow(dead_code)]
enum NatsBackend {
    Docker(DockerContainer),
    Local(LocalNatsProcess),
}

#[derive(Debug)]
struct NatsHarness {
    url: String,
    client: async_nats::Client,
    _backend: NatsBackend,
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
                    let js = async_nats::jetstream::new(client.clone());
                    ensure_hunt_streams(&js).await?;
                    return Ok(Self {
                        url,
                        client,
                        _backend: NatsBackend::Docker(container),
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
                    let js = async_nats::jetstream::new(client.clone());
                    ensure_hunt_streams(&js).await?;
                    return Ok(Self {
                        url,
                        client,
                        _backend: NatsBackend::Local(process),
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

async fn ensure_hunt_streams(js: &JetStreamContext) -> Result<(), String> {
    let streams = [
        (
            "CLAWDSTRIKE_TETRAGON",
            "clawdstrike.sdr.fact.tetragon_event.>",
        ),
        ("CLAWDSTRIKE_HUBBLE", "clawdstrike.sdr.fact.hubble_flow.>"),
        ("CLAWDSTRIKE_RECEIPTS", "clawdstrike.sdr.fact.receipt.>"),
        ("CLAWDSTRIKE_SCANS", "clawdstrike.sdr.fact.scan.>"),
    ];
    for (name, subject) in streams {
        let err_ctx = format!("ensure stream {name}");
        let _stream = spine::nats_transport::ensure_stream(js, name, vec![subject.to_string()], 1)
            .await
            .map_err(|e| format!("{err_ctx}: {e}"))?;
    }
    Ok(())
}

#[derive(Debug)]
struct MockMcpServer {
    base_url: String,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl MockMcpServer {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind mock mcp server");
        let addr = listener.local_addr().expect("mock mcp local addr");
        listener
            .set_nonblocking(true)
            .expect("set nonblocking mock mcp");

        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = Arc::clone(&stop);
        let handle = thread::spawn(move || loop {
            if stop_for_thread.load(Ordering::Relaxed) {
                return;
            }

            match listener.accept() {
                Ok((mut stream, _)) => {
                    if let Some((method, path, body)) = read_http_request(&mut stream) {
                        handle_mock_mcp_request(&mut stream, &method, &path, &body);
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        });

        Self {
            base_url: format!("http://{addr}"),
            stop,
            handle: Some(handle),
        }
    }
}

impl Drop for MockMcpServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set mock mcp read timeout");

    let mut buf = Vec::<u8>::new();
    let mut chunk = [0u8; 1024];
    let mut header_end = None;
    while header_end.is_none() {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
        header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4);
        if buf.len() > 64 * 1024 {
            return None;
        }
    }

    let header_end = header_end?;
    let head = std::str::from_utf8(&buf[..header_end]).ok()?;
    let mut lines = head.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();

    let mut content_len = 0usize;
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_len = v.trim().parse().ok()?;
        }
    }

    let mut body = buf[header_end..].to_vec();
    while body.len() < content_len {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(content_len);

    Some((method, path, body))
}

fn write_http_response(stream: &mut TcpStream, status: &str, content_type: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

fn handle_mock_mcp_request(stream: &mut TcpStream, method: &str, path: &str, body: &[u8]) {
    match (method, path) {
        ("GET", "/sse") => {
            let sse = b"event: endpoint\ndata: /mcp\n\n";
            write_http_response(stream, "200 OK", "text/event-stream", sse);
        }
        ("POST", "/mcp") => {
            let req: Value = serde_json::from_slice(body).unwrap_or_else(|_| json!({}));
            let rpc_method = req.get("method").and_then(Value::as_str).unwrap_or("");
            let id = req.get("id").cloned().unwrap_or_else(|| json!(1));
            let resp = match rpc_method {
                "initialize" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "capabilities": { "tools": {} },
                        "serverInfo": {
                            "name": "hunt-e2e-mock",
                            "version": "1.0.0"
                        }
                    }
                }),
                "tools/list" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": {
                        "tools": [
                            {
                                "name": "hunt_e2e_ping",
                                "description": "mock MCP e2e tool",
                                "inputSchema": { "type": "object", "properties": {} }
                            }
                        ]
                    }
                }),
                "prompts/list" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "prompts": [] }
                }),
                "resources/list" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "resources": [] }
                }),
                "resources/templates/list" => json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": { "resourceTemplates": [] }
                }),
                _ => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
            };
            let bytes = serde_json::to_vec(&resp).expect("serialize mock mcp response");
            write_http_response(stream, "200 OK", "application/json", &bytes);
        }
        _ => write_http_response(stream, "404 Not Found", "text/plain", b"not found"),
    }
}

#[derive(Debug)]
struct WatchProcess {
    child: Child,
    stdout_lines: Arc<Mutex<Vec<String>>>,
    stderr_lines: Arc<Mutex<Vec<String>>>,
    stdout_thread: Option<thread::JoinHandle<()>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
}

impl WatchProcess {
    fn spawn(args: &[String]) -> Self {
        let mut cmd = Command::new(resolve_hush_binary());
        cmd.args(args).stdout(Stdio::piped()).stderr(Stdio::piped());

        let mut child = cmd.spawn().expect("spawn watch process");
        let stdout = child.stdout.take().expect("watch stdout");
        let stderr = child.stderr.take().expect("watch stderr");

        let stdout_lines = Arc::new(Mutex::new(Vec::<String>::new()));
        let stderr_lines = Arc::new(Mutex::new(Vec::<String>::new()));

        let stdout_sink = Arc::clone(&stdout_lines);
        let stdout_thread = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                let mut sink = stdout_sink.lock().unwrap_or_else(|p| p.into_inner());
                sink.push(line);
            }
        });

        let stderr_sink = Arc::clone(&stderr_lines);
        let stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                let mut sink = stderr_sink.lock().unwrap_or_else(|p| p.into_inner());
                sink.push(line);
            }
        });

        Self {
            child,
            stdout_lines,
            stderr_lines,
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
        }
    }

    fn wait_for_stdout_contains(&self, needle: &str, timeout: Duration) -> bool {
        wait_for_lines_contains(&self.stdout_lines, needle, timeout)
    }

    fn wait_for_stderr_contains(&self, needle: &str, timeout: Duration) -> bool {
        wait_for_lines_contains(&self.stderr_lines, needle, timeout)
    }

    fn interrupt(&self) {
        #[cfg(unix)]
        {
            let _ = Command::new("kill")
                .args(["-INT", &self.child.id().to_string()])
                .status();
        }
        #[cfg(not(unix))]
        {
            let _ = Command::new("taskkill")
                .args(["/PID", &self.child.id().to_string(), "/T", "/F"])
                .status();
        }
    }

    fn wait_for_exit(mut self, timeout: Duration) -> CommandResult {
        let started = Instant::now();
        let status = loop {
            match self.child.try_wait().expect("watch try_wait") {
                Some(status) => break status,
                None => {
                    if started.elapsed() >= timeout {
                        let _ = self.child.kill();
                        let status = self.child.wait().expect("watch wait after timeout kill");
                        break status;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
        };

        if let Some(handle) = self.stdout_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_thread.take() {
            let _ = handle.join();
        }

        CommandResult {
            status,
            stdout: clone_lines_joined(&self.stdout_lines),
            stderr: clone_lines_joined(&self.stderr_lines),
        }
    }
}

fn wait_for_lines_contains(
    lines: &Arc<Mutex<Vec<String>>>,
    needle: &str,
    timeout: Duration,
) -> bool {
    let started = Instant::now();
    loop {
        {
            let snapshot = lines.lock().unwrap_or_else(|p| p.into_inner());
            if snapshot.iter().any(|line| line.contains(needle)) {
                return true;
            }
        }
        if started.elapsed() >= timeout {
            return false;
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn clone_lines_joined(lines: &Arc<Mutex<Vec<String>>>) -> String {
    lines
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .clone()
        .join("\n")
}

fn make_envelope(issued_at: &str, fact: Value) -> Value {
    json!({
        "issued_at": issued_at,
        "fact": fact,
    })
}

fn receipt_fact(guard: &str, decision: &str, action_type: &str) -> Value {
    json!({
        "schema": "clawdstrike.sdr.fact.receipt.v1",
        "guard": guard,
        "decision": decision,
        "action_type": action_type,
        "severity": "low",
    })
}

fn hubble_fact(summary: &str, verdict: &str) -> Value {
    json!({
        "schema": "clawdstrike.sdr.fact.hubble_flow.v1",
        "verdict": verdict,
        "traffic_direction": "EGRESS",
        "summary": summary,
        "source": {
            "namespace": "prod",
            "pod_name": "agent-pod-01"
        }
    })
}

async fn publish_envelope(
    client: &async_nats::Client,
    subject: &str,
    issued_at: &str,
    fact: Value,
) -> Result<(), String> {
    let envelope = make_envelope(issued_at, fact);
    let payload = serde_json::to_vec(&envelope).map_err(|e| format!("serialize envelope: {e}"))?;
    client
        .publish(subject.to_string(), payload.into())
        .await
        .map_err(|e| format!("publish to {subject}: {e}"))?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hush_hunt_e2e_realistic_battery() {
    let workspace = TestWorkspace::new("hush-hunt-e2e");

    let nats = match NatsHarness::start().await {
        Ok(harness) => harness,
        Err(err) => {
            if is_ci() {
                panic!("CI requires a usable NATS backend for hunt e2e: {err}");
            }
            eprintln!("Skipping hunt e2e: {err}");
            return;
        }
    };

    let mock_mcp = MockMcpServer::start();

    let mcp_config_path = workspace.path("mock_mcp.json");
    fs::write(
        &mcp_config_path,
        format!(
            r#"{{
  "mcpServers": {{
    "mock-http": {{
      "type": "http",
      "url": "{}"
    }}
  }}
}}"#,
            mock_mcp.base_url
        ),
    )
    .expect("write mock mcp config");

    let scan_args = vec![
        "hunt".to_string(),
        "scan".to_string(),
        "--target".to_string(),
        mcp_config_path.to_string_lossy().to_string(),
        "--json".to_string(),
        "--timeout".to_string(),
        "3".to_string(),
    ];
    let scan_result = run_hush(&scan_args, command_timeout(Duration::from_secs(30)));
    assert_eq!(
        scan_result.status_code(),
        Some(0),
        "scan command failed\nstdout:\n{}\nstderr:\n{}",
        scan_result.stdout,
        scan_result.stderr
    );

    let scan_json = parse_stdout_json(&scan_result);
    assert_eq!(scan_json["command"], "hunt scan");
    assert!(
        scan_json["data"]["summary"]["servers_found"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
    assert!(
        scan_json["data"]["summary"]["tools_found"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );

    let rule_path = workspace.path("hunt_rule.yaml");
    fs::write(
        &rule_path,
        r#"
schema: clawdstrike.hunt.correlation.v1
name: "Hunt E2E Exfil Sequence"
severity: high
description: "Detect allow file access followed by evil egress."
window: 5m
conditions:
  - source: receipt
    action_type: file
    verdict: allow
    target_pattern: "secret_file_access"
    bind: file_access
  - source: hubble
    action_type: egress
    verdict: forwarded
    target_pattern: "evil\\.example"
    after: file_access
    within: 1m
    bind: egress_event
output:
  title: "Potential exfiltration"
  evidence:
    - file_access
    - egress_event
"#,
    )
    .expect("write rule file");

    let watch_rule_path = workspace.path("hunt_watch_rule.yaml");
    fs::write(
        &watch_rule_path,
        r#"
schema: clawdstrike.hunt.correlation.v1
name: "Hunt E2E Watch Trigger"
severity: medium
description: "Single-condition rule for stable watch-path validation."
window: 5m
conditions:
  - source: receipt
    action_type: file
    verdict: allow
    target_pattern: "watch_tripwire"
    bind: watch_event
output:
  title: "Watch trigger fired"
  evidence:
    - watch_event
"#,
    )
    .expect("write watch rule file");

    let ioc_feed_path = workspace.path("ioc_feed.txt");
    fs::write(&ioc_feed_path, "evil.example\n").expect("write ioc feed");

    publish_envelope(
        &nats.client,
        "clawdstrike.sdr.fact.receipt.guard.v1",
        "2026-02-03T00:00:00Z",
        receipt_fact("secret_file_access", "allow", "file"),
    )
    .await
    .expect("publish receipt event 1");
    publish_envelope(
        &nats.client,
        "clawdstrike.sdr.fact.hubble_flow.egress.v1",
        "2026-02-03T00:00:10Z",
        hubble_fact("TCP flow to evil.example:443", "FORWARDED"),
    )
    .await
    .expect("publish hubble event 1");
    publish_envelope(
        &nats.client,
        "clawdstrike.sdr.fact.receipt.guard.v1",
        "2026-02-03T00:00:20Z",
        receipt_fact("normal_guard", "deny", "file"),
    )
    .await
    .expect("publish receipt event 2");
    nats.client.flush().await.expect("flush historical events");

    let query_args = vec![
        "hunt".to_string(),
        "query".to_string(),
        "--nats-url".to_string(),
        nats.url.clone(),
        "--source".to_string(),
        "receipt,hubble".to_string(),
        "--json".to_string(),
        "--limit".to_string(),
        "50".to_string(),
    ];
    let query_result = run_hush(&query_args, command_timeout(Duration::from_secs(30)));
    assert_eq!(
        query_result.status_code(),
        Some(0),
        "query failed\nstdout:\n{}\nstderr:\n{}",
        query_result.stdout,
        query_result.stderr
    );
    let query_json = parse_stdout_json(&query_result);
    assert_eq!(query_json["command"], "hunt query");
    assert!(
        query_json["data"]["summary"]["total_events"]
            .as_u64()
            .unwrap_or(0)
            >= 2
    );

    let timeline_args = vec![
        "hunt".to_string(),
        "timeline".to_string(),
        "--nats-url".to_string(),
        nats.url.clone(),
        "--source".to_string(),
        "receipt,hubble".to_string(),
        "--json".to_string(),
        "--limit".to_string(),
        "50".to_string(),
    ];
    let timeline_result = run_hush(&timeline_args, command_timeout(Duration::from_secs(30)));
    assert_eq!(
        timeline_result.status_code(),
        Some(0),
        "timeline failed\nstdout:\n{}\nstderr:\n{}",
        timeline_result.stdout,
        timeline_result.stderr
    );
    let timeline_json = parse_stdout_json(&timeline_result);
    assert_eq!(timeline_json["command"], "hunt timeline");
    let events = timeline_json["data"]["events"]
        .as_array()
        .expect("timeline events array");
    let mut ts_values: Vec<String> = events
        .iter()
        .filter_map(|ev| {
            ev.get("timestamp")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect();
    let mut sorted = ts_values.clone();
    sorted.sort();
    assert_eq!(
        ts_values, sorted,
        "timeline output must be sorted by timestamp"
    );
    ts_values.clear();

    let correlate_args = vec![
        "hunt".to_string(),
        "correlate".to_string(),
        "--rules".to_string(),
        rule_path.to_string_lossy().to_string(),
        "--nats-url".to_string(),
        nats.url.clone(),
        "--source".to_string(),
        "receipt,hubble".to_string(),
        "--json".to_string(),
        "--limit".to_string(),
        "50".to_string(),
    ];
    let correlate_result = run_hush(&correlate_args, command_timeout(Duration::from_secs(30)));
    assert_eq!(
        correlate_result.status_code(),
        Some(1),
        "correlate should return warn(1) when alerts fire\nstdout:\n{}\nstderr:\n{}",
        correlate_result.stdout,
        correlate_result.stderr
    );
    let correlate_json = parse_stdout_json(&correlate_result);
    assert_eq!(correlate_json["command"], "hunt correlate");
    assert!(
        correlate_json["data"]["summary"]["alerts_generated"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );

    let watch_args = vec![
        "hunt".to_string(),
        "watch".to_string(),
        "--rules".to_string(),
        watch_rule_path.to_string_lossy().to_string(),
        "--nats-url".to_string(),
        nats.url.clone(),
        "--json".to_string(),
    ];
    let watch = WatchProcess::spawn(&watch_args);
    assert!(
        watch.wait_for_stderr_contains(
            "waiting for events",
            command_timeout(Duration::from_secs(12))
        ),
        "watch process never reached ready state"
    );

    let watch_alert_needle = "\"rule_name\":\"Hunt E2E Watch Trigger\"";
    let mut watch_alert_observed = false;
    for attempt in 0..5 {
        let receipt_ts = format!("2026-02-03T00:01:{:02}Z", attempt);

        publish_envelope(
            &nats.client,
            "clawdstrike.sdr.fact.receipt.live.v1",
            &receipt_ts,
            receipt_fact("watch_tripwire", "allow", "file"),
        )
        .await
        .expect("publish watch receipt");
        nats.client.flush().await.expect("flush watch events");

        if watch
            .wait_for_stdout_contains(watch_alert_needle, command_timeout(Duration::from_secs(6)))
        {
            watch_alert_observed = true;
            break;
        }
    }

    assert!(
        watch_alert_observed,
        "watch did not emit expected alert JSON line\nwatch stdout:\n{}\nwatch stderr:\n{}",
        clone_lines_joined(&watch.stdout_lines),
        clone_lines_joined(&watch.stderr_lines)
    );

    watch.interrupt();
    let watch_result = watch.wait_for_exit(command_timeout(Duration::from_secs(10)));
    assert_eq!(
        watch_result.status_code(),
        Some(0),
        "watch should exit cleanly\nstdout:\n{}\nstderr:\n{}",
        watch_result.stdout,
        watch_result.stderr
    );
    assert!(
        watch_result.stderr.contains("alerts from"),
        "watch JSON mode should print session summary to stderr\nstderr:\n{}",
        watch_result.stderr
    );

    let ioc_args = vec![
        "hunt".to_string(),
        "ioc".to_string(),
        "--feed".to_string(),
        ioc_feed_path.to_string_lossy().to_string(),
        "--nats-url".to_string(),
        nats.url.clone(),
        "--source".to_string(),
        "hubble".to_string(),
        "--json".to_string(),
        "--limit".to_string(),
        "50".to_string(),
    ];
    let ioc_result = run_hush(&ioc_args, command_timeout(Duration::from_secs(30)));
    assert_eq!(
        ioc_result.status_code(),
        Some(1),
        "ioc should return warn(1) when matches are found\nstdout:\n{}\nstderr:\n{}",
        ioc_result.stdout,
        ioc_result.stderr
    );
    let ioc_json = parse_stdout_json(&ioc_result);
    assert_eq!(ioc_json["command"], "hunt ioc");
    assert!(
        ioc_json["data"]["summary"]["matches_found"]
            .as_u64()
            .unwrap_or(0)
            > 0
    );

    let offline_dir = workspace.path("offline_events");
    fs::create_dir_all(&offline_dir).expect("create offline dir");
    let offline_event = make_envelope(
        "2026-02-03T00:02:00Z",
        receipt_fact("local_fallback_guard", "deny", "file"),
    );
    fs::write(
        offline_dir.join("events.jsonl"),
        format!(
            "{}\n",
            serde_json::to_string(&offline_event).expect("serialize offline event")
        ),
    )
    .expect("write offline events file");

    let fallback_args = vec![
        "hunt".to_string(),
        "query".to_string(),
        "--nats-url".to_string(),
        // Use an invalid NATS URL so fallback is deterministic in CI and local.
        "nats://127.0.0.1:abc".to_string(),
        "--source".to_string(),
        "receipt".to_string(),
        "--local-dir".to_string(),
        offline_dir.to_string_lossy().to_string(),
        "--json".to_string(),
        "--limit".to_string(),
        "50".to_string(),
    ];
    let fallback_result = run_hush(&fallback_args, command_timeout(Duration::from_secs(30)));
    assert_eq!(
        fallback_result.status_code(),
        Some(0),
        "fallback query should succeed\nstdout:\n{}\nstderr:\n{}",
        fallback_result.stdout,
        fallback_result.stderr
    );
    assert!(
        fallback_result
            .stderr
            .contains("falling back to local files"),
        "fallback query should explicitly log local fallback\nstderr:\n{}",
        fallback_result.stderr
    );
    let fallback_json = parse_stdout_json(&fallback_result);
    assert_eq!(
        fallback_json["data"]["summary"]["data_source"], "local_fallback",
        "fallback query should report local_fallback data source"
    );
    assert!(
        fallback_json["data"]["summary"]["fallback_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("NATS replay failed"),
        "fallback query should include explicit replay failure reason"
    );
    assert!(
        fallback_json["data"]["summary"]["total_events"]
            .as_u64()
            .unwrap_or(0)
            >= 1
    );
}
