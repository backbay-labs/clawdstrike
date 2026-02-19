#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn parse_proxy_url(line: &str) -> Option<String> {
    line.find("Proxy listening on ")
        .map(|idx| line[idx + "Proxy listening on ".len()..].trim().to_string())
}

fn proxy_listen_timeout() -> Duration {
    let ms = std::env::var("HUSH_TEST_PROXY_LISTEN_TIMEOUT_MS")
        .ok()
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(30_000);
    Duration::from_millis(ms)
}

#[derive(Debug)]
struct HarnessProcess {
    child: Child,
    stderr_logs: Arc<Mutex<Vec<String>>>,
    stdout_thread: Option<thread::JoinHandle<()>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
    work_dir: PathBuf,
    proxy_url: String,
}

#[derive(Debug)]
struct HarnessResult {
    status: std::process::ExitStatus,
    stderr: Vec<String>,
}

impl HarnessProcess {
    fn spawn(
        policy_yaml: &str,
        sleep_secs: u64,
        extra_args: &[String],
        envs: &[(&str, String)],
    ) -> Self {
        let work_dir = create_temp_dir("hush-abuse-harness");
        let policy_path = work_dir.join("policy.yaml");
        let events_path = work_dir.join("events.jsonl");
        let receipt_path = work_dir.join("receipt.json");
        let key_path = work_dir.join("hush.key");
        fs::write(&policy_path, policy_yaml).expect("write policy");

        let hush_bin = resolve_hush_binary();
        let mut cmd = Command::new(hush_bin);
        cmd.arg("run")
            .arg("--policy")
            .arg(&policy_path)
            .arg("--events-out")
            .arg(&events_path)
            .arg("--receipt-out")
            .arg(&receipt_path)
            .arg("--signing-key")
            .arg(&key_path)
            .arg("--proxy-port")
            .arg("0");

        for arg in extra_args {
            cmd.arg(arg);
        }

        cmd.arg("--").arg("sleep").arg(sleep_secs.to_string());
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }

        let mut child = cmd.spawn().expect("spawn hush run");
        let stdout = child.stdout.take().expect("child stdout");
        let stderr = child.stderr.take().expect("child stderr");
        let stderr_logs = Arc::new(Mutex::new(Vec::<String>::new()));
        let (proxy_tx, proxy_rx) = mpsc::channel::<String>();
        let proxy_tx_stdout = proxy_tx.clone();

        let stdout_thread = thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(url) = parse_proxy_url(&line) {
                    let _ = proxy_tx_stdout.send(url);
                }
            }
        });

        let stderr_logs_for_thread = Arc::clone(&stderr_logs);
        let stderr_thread = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines().map_while(Result::ok) {
                if let Some(url) = parse_proxy_url(&line) {
                    let _ = proxy_tx.send(url);
                }
                let mut logs = match stderr_logs_for_thread.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                logs.push(line);
            }
        });

        let proxy_timeout = proxy_listen_timeout();
        let proxy_url = match proxy_rx.recv_timeout(proxy_timeout) {
            Ok(url) => url,
            Err(_) => {
                let stderr = {
                    let logs = match stderr_logs.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    logs.join("\n")
                };
                panic!(
                    "proxy url from stderr/stdout timeout after {:?}; stderr:\n{}",
                    proxy_timeout, stderr
                );
            }
        };

        Self {
            child,
            stderr_logs,
            stdout_thread: Some(stdout_thread),
            stderr_thread: Some(stderr_thread),
            work_dir,
            proxy_url,
        }
    }

    fn proxy_addr(&self) -> SocketAddr {
        let raw = self
            .proxy_url
            .strip_prefix("http://")
            .unwrap_or(self.proxy_url.as_str());
        raw.parse::<SocketAddr>().expect("parse proxy socket addr")
    }

    fn terminate(mut self) -> HarnessResult {
        let _ = self.child.kill();
        let status = self.child.wait().expect("wait child");
        self.finish(status)
    }

    fn wait_for_exit(mut self, timeout: Duration) -> HarnessResult {
        let started = Instant::now();
        loop {
            match self.child.try_wait().expect("try_wait") {
                Some(status) => return self.finish(status),
                None => {
                    if started.elapsed() >= timeout {
                        let _ = self.child.kill();
                        let status = self.child.wait().expect("wait child after timeout kill");
                        return self.finish(status);
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    fn finish(&mut self, status: std::process::ExitStatus) -> HarnessResult {
        if let Some(handle) = self.stdout_thread.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.stderr_thread.take() {
            let _ = handle.join();
        }

        let stderr = {
            let logs = match self.stderr_logs.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            logs.clone()
        };

        let _ = fs::remove_dir_all(&self.work_dir);

        HarnessResult { status, stderr }
    }
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

    let candidate = workspace_root()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "hush.exe" } else { "hush" });

    if candidate.exists() {
        return candidate;
    }

    let status = Command::new("cargo")
        .current_dir(workspace_root())
        .arg("build")
        .arg("-p")
        .arg("hush-cli")
        .arg("--bin")
        .arg("hush")
        .status()
        .expect("build hush binary for abuse harness");
    assert!(
        status.success(),
        "failed to build hush binary for abuse harness"
    );
    candidate
}

fn create_temp_dir(prefix: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), seq));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn read_response(stream: &mut TcpStream) -> String {
    let mut out = [0u8; 1024];
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let n = stream.read(&mut out).expect("read response");
    String::from_utf8_lossy(&out[..n]).to_string()
}

fn default_policy_yaml() -> &'static str {
    r#"
version: "1.1.0"
name: "abuse-harness-default"
"#
}

fn rebind_policy_yaml() -> &'static str {
    r#"
version: "1.1.0"
name: "abuse-harness-rebind"
guards:
  egress_allowlist:
    allow: ["rebind.test"]
    default_action: block
"#
}

fn sni_mismatch_policy_yaml() -> &'static str {
    r#"
version: "1.1.0"
name: "abuse-harness-sni-mismatch"
guards:
  egress_allowlist:
    allow: ["example.com"]
    default_action: block
"#
}

fn scenario_ip_connect_with_allowlisted_sni_mismatch_is_rejected() {
    let upstream = TcpListener::bind(("127.0.0.1", 0)).expect("bind upstream listener");
    upstream
        .set_nonblocking(true)
        .expect("set nonblocking upstream listener");
    let upstream_port = upstream.local_addr().expect("upstream addr").port();

    let proc = HarnessProcess::spawn(
        sni_mismatch_policy_yaml(),
        10,
        &[],
        &[("HUSH_TEST_PROXY_HEADER_TIMEOUT_MS", "800".to_string())],
    );
    let addr = proc.proxy_addr();

    let mut client = TcpStream::connect(addr).expect("connect mismatch client");
    let req = format!(
        "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
        upstream_port, upstream_port
    );
    client
        .write_all(req.as_bytes())
        .expect("write connect request");
    let response = read_response(&mut client);
    assert!(
        response.contains("403 Forbidden"),
        "blocked IP CONNECT target must not be bypassed by allowlisted SNI, got: {response}"
    );

    let hello = include_bytes!("../../../libs/hush-proxy/testdata/client_hello_example.bin");
    let _ = client.write_all(hello);
    thread::sleep(Duration::from_millis(300));
    let upstream_attempt = upstream.accept();
    assert!(
        matches!(upstream_attempt, Err(err) if err.kind() == std::io::ErrorKind::WouldBlock),
        "proxy must not connect upstream when CONNECT IP target is blocked"
    );

    let _ = proc.terminate();
}

fn scenario_slowloris_header_timeout() {
    let proc = HarnessProcess::spawn(
        default_policy_yaml(),
        15,
        &[],
        &[
            ("HUSH_TEST_PROXY_MAX_IN_FLIGHT", "8".to_string()),
            ("HUSH_TEST_PROXY_HEADER_TIMEOUT_MS", "400".to_string()),
        ],
    );
    let addr = proc.proxy_addr();

    let mut slow = TcpStream::connect(addr).expect("connect slow client");
    slow.write_all(b"CON").expect("write slow bytes");
    thread::sleep(Duration::from_millis(700));
    let slow_response = read_response(&mut slow);
    assert!(
        slow_response.contains("408 Request Timeout"),
        "slowloris request should timeout with 408, got: {slow_response}"
    );

    let mut probe = TcpStream::connect(addr).expect("connect probe client");
    probe
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .expect("write probe");
    let probe_response = read_response(&mut probe);
    assert!(
        probe_response.contains("501 Not Implemented"),
        "proxy should remain responsive after slowloris timeout, got: {probe_response}"
    );

    let _ = proc.terminate();
}

fn scenario_connection_flood_inflight_cap() {
    let proc = HarnessProcess::spawn(
        default_policy_yaml(),
        15,
        &[],
        &[
            ("HUSH_TEST_PROXY_MAX_IN_FLIGHT", "8".to_string()),
            ("HUSH_TEST_PROXY_HEADER_TIMEOUT_MS", "5000".to_string()),
        ],
    );
    let addr = proc.proxy_addr();

    let mut held = Vec::new();
    for _ in 0..8 {
        held.push(TcpStream::connect(addr).expect("connect held socket"));
    }
    thread::sleep(Duration::from_millis(120));

    let mut overflow = TcpStream::connect(addr).expect("connect overflow socket");
    let response = read_response(&mut overflow);
    assert!(
        response.contains("503 Service Unavailable"),
        "flood overflow connection must be rejected with 503, got: {response}"
    );

    drop(held);
    let _ = proc.terminate();
}

fn scenario_dns_rebind_like_resolution_is_pinned() {
    let accept_timeout = Duration::from_secs(5);
    let listener_a = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener A");
    let listener_b = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener B");

    let a_addr = listener_a.local_addr().expect("listener A addr");
    let b_addr = listener_b.local_addr().expect("listener B addr");
    let connect_port = 443u16;

    let (a_tx, a_rx) = mpsc::channel::<()>();
    let (b_tx, b_rx) = mpsc::channel::<()>();

    thread::spawn(move || {
        listener_a
            .set_nonblocking(true)
            .expect("set nonblocking A listener");
        let deadline = Instant::now() + accept_timeout;
        loop {
            match listener_a.accept() {
                Ok((_stream, _)) => {
                    let _ = a_tx.send(());
                    return;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });

    thread::spawn(move || {
        listener_b
            .set_nonblocking(true)
            .expect("set nonblocking B listener");
        let deadline = Instant::now() + accept_timeout;
        loop {
            match listener_b.accept() {
                Ok((_stream, _)) => {
                    let _ = b_tx.send(());
                    return;
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });

    let resolver_spec = format!(
        "rebind.test:{}=127.0.0.1:{}|127.0.0.1:{}",
        connect_port,
        a_addr.port(),
        b_addr.port()
    );

    let proc = HarnessProcess::spawn(
        rebind_policy_yaml(),
        12,
        &["--proxy-allow-private-ips".to_string()],
        &[
            ("HUSH_TEST_RESOLVER_SEQUENCE", resolver_spec),
            // Keep this above typical CI jitter so the pinning assertion is stable.
            ("HUSH_TEST_PROXY_DNS_TIMEOUT_MS", "1000".to_string()),
        ],
    );
    let addr = proc.proxy_addr();

    let mut client = TcpStream::connect(addr).expect("connect rebind client");
    let req = format!(
        "CONNECT rebind.test:{} HTTP/1.1\r\nHost: rebind.test:{}\r\n\r\n",
        connect_port, connect_port
    );
    client
        .write_all(req.as_bytes())
        .expect("write connect request");
    let response = read_response(&mut client);
    assert!(
        response.contains("200 Connection Established"),
        "expected successful CONNECT tunnel establishment, got: {response}"
    );

    assert!(
        a_rx.recv_timeout(Duration::from_secs(3)).is_ok(),
        "pinned connect target should dial first-resolution address"
    );
    assert!(
        b_rx.recv_timeout(Duration::from_secs(2)).is_err(),
        "proxy must not dial second-stage rebind address"
    );

    let _ = proc.terminate();
}

fn scenario_stalled_forwarder_is_bounded_and_times_out() {
    let stalled_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind stalled listener");
    let stalled_addr = stalled_listener
        .local_addr()
        .expect("stalled listener addr");
    let forwarder_stop = Arc::new(AtomicU64::new(0));
    let forwarder_stop_for_thread = Arc::clone(&forwarder_stop);

    let accept_thread = thread::spawn(move || {
        stalled_listener
            .set_nonblocking(true)
            .expect("set nonblocking stalled listener");
        while forwarder_stop_for_thread.load(Ordering::Relaxed) == 0 {
            match stalled_listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                    let mut buf = [0u8; 512];
                    let _ = stream.read(&mut buf);
                    thread::sleep(Duration::from_secs(2));
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => return,
            }
        }
    });

    let proc = HarnessProcess::spawn(
        default_policy_yaml(),
        3,
        &[
            "--hushd-url".to_string(),
            format!("http://{}", stalled_addr),
        ],
        &[
            ("HUSH_TEST_EVENT_QUEUE_CAPACITY", "8".to_string()),
            ("HUSH_TEST_FORWARD_TIMEOUT_MS", "40".to_string()),
            ("HUSH_TEST_PROXY_MAX_IN_FLIGHT", "16".to_string()),
        ],
    );
    let addr = proc.proxy_addr();

    for _ in 0..96 {
        let mut client = TcpStream::connect(addr).expect("connect flood event client");
        let req = "CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n";
        client
            .write_all(req.as_bytes())
            .expect("write event flood request");
        let _ = read_response(&mut client);
    }

    let result = proc.wait_for_exit(Duration::from_secs(15));
    forwarder_stop.store(1, Ordering::Relaxed);
    let _ = accept_thread.join();

    let stderr_joined = result.stderr.join("\n");
    assert!(
        stderr_joined.contains("event queue is full") || stderr_joined.contains("dropped"),
        "stalled forwarder scenario should report bounded-queue drops; stderr:\n{}",
        stderr_joined
    );
    assert!(
        result.status.code().is_some(),
        "hush run process should complete cleanly under stalled forwarder pressure"
    );
}

#[test]
fn hush_run_abuse_battery_smoke() {
    scenario_ip_connect_with_allowlisted_sni_mismatch_is_rejected();
    scenario_slowloris_header_timeout();
    scenario_connection_flood_inflight_cap();
    scenario_dns_rebind_like_resolution_is_pinned();
    scenario_stalled_forwarder_is_bounded_and_times_out();
}
