#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use chrono::Utc;
use clawdstrike::{GuardContext, GuardResult, HushEngine, Severity};
use hush_core::{sha256, Keypair, PublicKey, Receipt, SignedReceipt, Signer, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::policy_diff::{self, LoadedPolicy};
use crate::policy_event::{
    CommandEventData, CustomEventData, NetworkEventData, PolicyEvent, PolicyEventData,
    PolicyEventType,
};
use crate::remote_extends;
use crate::ExitCode;

const EVENT_QUEUE_CAPACITY: usize = 1024;
const PROXY_MAX_IN_FLIGHT_CONNECTIONS: usize = 256;
const PROXY_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
const PROXY_TLS_SNI_TIMEOUT: Duration = Duration::from_secs(3);
const HUSHD_FORWARD_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Debug)]
struct RunOutcome {
    // 0 = ok, 1 = warn, 2 = fail
    max: Arc<AtomicU8>,
}

impl RunOutcome {
    fn new() -> Self {
        Self {
            max: Arc::new(AtomicU8::new(0)),
        }
    }

    fn observe_guard_result(&self, result: &GuardResult) {
        let level = guard_result_level(result);
        if level == 0 {
            return;
        }

        loop {
            let current = self.max.load(Ordering::Relaxed);
            if level <= current {
                return;
            }
            if self
                .max
                .compare_exchange(current, level, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return;
            }
        }
    }

    fn exit_code(&self) -> i32 {
        match self.max.load(Ordering::Relaxed) {
            0 => ExitCode::Ok.as_i32(),
            1 => ExitCode::Warn.as_i32(),
            _ => ExitCode::Fail.as_i32(),
        }
    }

    fn verdict(&self) -> Verdict {
        if self.max.load(Ordering::Relaxed) >= 2 {
            Verdict::fail()
        } else {
            Verdict::pass()
        }
    }
}

fn guard_result_level(result: &GuardResult) -> u8 {
    if !result.allowed {
        return 2;
    }
    match result.severity {
        Severity::Warning => 1,
        _ => 0,
    }
}

#[derive(Clone, Debug)]
struct HushdForwarder {
    base_url: String,
    token: Option<String>,
    client: reqwest::Client,
}

impl HushdForwarder {
    fn new(base_url: String, token: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(HUSHD_FORWARD_TIMEOUT)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            client,
        }
    }

    #[cfg(test)]
    fn new_with_timeout(base_url: String, token: Option<String>, timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            client,
        }
    }

    async fn forward_event(&self, event: &PolicyEvent) {
        let mut req = self
            .client
            .post(format!("{}/api/v1/eval", self.base_url))
            .json(event);

        if let Some(token) = self.token.as_ref() {
            req = req.bearer_auth(token);
        }

        // Best-effort; ignore errors.
        let _ = req.send().await;
    }
}

#[derive(Clone, Debug)]
struct EventEmitter {
    tx: mpsc::Sender<PolicyEvent>,
    dropped_full: Arc<AtomicUsize>,
}

impl EventEmitter {
    fn new(tx: mpsc::Sender<PolicyEvent>) -> Self {
        Self {
            tx,
            dropped_full: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn emit(&self, event: PolicyEvent) {
        if let Err(err) = self.tx.try_send(event) {
            match err {
                mpsc::error::TrySendError::Full(_) => {
                    self.dropped_full.fetch_add(1, Ordering::Relaxed);
                }
                mpsc::error::TrySendError::Closed(_) => {}
            }
        }
    }

    fn dropped_count(&self) -> usize {
        self.dropped_full.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug)]
pub struct RunArgs {
    pub policy: String,
    pub events_out: String,
    pub receipt_out: String,
    pub signing_key: String,
    pub no_proxy: bool,
    pub proxy_port: u16,
    pub sandbox: bool,
    pub hushd_url: Option<String>,
    pub hushd_token: Option<String>,
    pub command: Vec<String>,
}

pub async fn cmd_run(
    args: RunArgs,
    remote_extends: &remote_extends::RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let RunArgs {
        policy,
        events_out,
        receipt_out,
        signing_key,
        no_proxy,
        proxy_port,
        sandbox,
        hushd_url,
        hushd_token,
        command,
    } = args;

    if command.is_empty() {
        let _ = writeln!(stderr, "Error: missing command");
        return ExitCode::InvalidArgs.as_i32();
    }

    let loaded = match load_policy(&policy, remote_extends) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {}", e);
            return ExitCode::ConfigError.as_i32();
        }
    };

    let signer = match load_or_create_signer(Path::new(&signing_key), stderr) {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {}", e);
            return ExitCode::RuntimeError.as_i32();
        }
    };

    let engine = match HushEngine::builder(loaded.policy).build() {
        Ok(engine) => engine,
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to initialize engine: {}", e);
            return ExitCode::ConfigError.as_i32();
        }
    };
    let engine = Arc::new(engine);

    let session_id = Uuid::new_v4().to_string();

    let base_context = GuardContext::new()
        .with_session_id(&session_id)
        .with_agent_id("hush run");

    let forwarder = hushd_url.map(|url| {
        let token = hushd_token
            .or_else(|| std::env::var("CLAWDSTRIKE_ADMIN_KEY").ok())
            .or_else(|| std::env::var("CLAWDSTRIKE_API_KEY").ok());
        HushdForwarder::new(url, token)
    });

    let events_path = PathBuf::from(&events_out);
    let receipt_path = PathBuf::from(&receipt_out);

    let (event_tx, mut event_rx) = mpsc::channel::<PolicyEvent>(EVENT_QUEUE_CAPACITY);
    let event_emitter = EventEmitter::new(event_tx);

    let writer_forwarder = forwarder.clone();
    let writer_handle = tokio::spawn(async move {
        let file = tokio::fs::File::create(&events_path)
            .await
            .with_context(|| format!("create events log at {}", events_path.display()))?;
        let mut w = tokio::io::BufWriter::new(file);

        while let Some(event) = event_rx.recv().await {
            let line = serde_json::to_string(&event).context("serialize PolicyEvent")?;
            w.write_all(line.as_bytes()).await?;
            w.write_all(b"\n").await?;

            if let Some(fwd) = writer_forwarder.as_ref() {
                fwd.forward_event(&event).await;
            }
        }

        w.flush().await?;
        Ok::<(), anyhow::Error>(())
    });

    // Emit command_exec event (audit-only; no guard currently enforces this).
    let command_event = PolicyEvent {
        event_id: Uuid::new_v4().to_string(),
        event_type: PolicyEventType::CommandExec,
        timestamp: Utc::now(),
        session_id: Some(session_id.clone()),
        data: PolicyEventData::Command(CommandEventData {
            command: command[0].clone(),
            args: command.iter().skip(1).cloned().collect(),
        }),
        metadata: None,
        context: None,
    };
    event_emitter.emit(command_event);

    let outcome = RunOutcome::new();

    let mut env_proxy_url = None;
    let mut proxy_rejected_connections: Option<Arc<AtomicUsize>> = None;
    let proxy_handle = if no_proxy {
        None
    } else {
        match start_connect_proxy(
            proxy_port,
            engine.clone(),
            base_context.clone(),
            event_emitter.clone(),
            outcome.clone(),
            PROXY_MAX_IN_FLIGHT_CONNECTIONS,
            PROXY_HEADER_READ_TIMEOUT,
            stderr,
        )
        .await
        {
            Ok((listen_url, handle, rejected_connections)) => {
                env_proxy_url = Some(listen_url);
                proxy_rejected_connections = Some(rejected_connections);
                Some(handle)
            }
            Err(e) => {
                let _ = writeln!(stderr, "Warning: failed to start proxy: {}", e);
                None
            }
        }
    };

    let (sandbox_wrapper, sandbox_note) = match maybe_prepare_sandbox(sandbox, stderr) {
        Ok(v) => v,
        Err(e) => {
            let _ = writeln!(stderr, "Warning: failed to prepare sandbox: {}", e);
            (SandboxWrapper::None, "disabled".to_string())
        }
    };

    let child_status = match spawn_and_wait_child(
        &command,
        sandbox_wrapper,
        env_proxy_url.as_deref(),
        &session_id,
        stderr,
    )
    .await
    {
        Ok(status) => status,
        Err(e) => {
            let _ = writeln!(stderr, "Error: {}", e);
            drop(event_emitter);
            let _ = writer_handle.await;
            if let Some(h) = proxy_handle {
                h.abort();
            }
            return ExitCode::RuntimeError.as_i32();
        }
    };

    let child_exit_code = child_exit_code(child_status);

    // Emit a best-effort session end marker.
    let mut extra = serde_json::Map::new();
    extra.insert(
        "childExitCode".to_string(),
        serde_json::Value::Number(child_exit_code.into()),
    );
    extra.insert(
        "policyExitCode".to_string(),
        serde_json::Value::Number(outcome.exit_code().into()),
    );
    extra.insert(
        "sandbox".to_string(),
        serde_json::Value::String(sandbox_note.clone()),
    );
    extra.insert(
        "proxy".to_string(),
        serde_json::Value::Bool(env_proxy_url.is_some()),
    );
    let dropped_events = event_emitter.dropped_count();
    extra.insert(
        "droppedEventCount".to_string(),
        serde_json::Value::Number((dropped_events as u64).into()),
    );
    let rejected_proxy_connections = proxy_rejected_connections
        .as_ref()
        .map(|count| count.load(Ordering::Relaxed))
        .unwrap_or(0);
    extra.insert(
        "proxyRejectedConnections".to_string(),
        serde_json::Value::Number((rejected_proxy_connections as u64).into()),
    );

    event_emitter.emit(PolicyEvent {
        event_id: Uuid::new_v4().to_string(),
        event_type: PolicyEventType::Custom,
        timestamp: Utc::now(),
        session_id: Some(session_id.clone()),
        data: PolicyEventData::Custom(CustomEventData {
            custom_type: "hush_run_end".to_string(),
            extra,
        }),
        metadata: None,
        context: None,
    });

    // Stop accepting new proxy connections (best-effort).
    if let Some(h) = proxy_handle {
        h.abort();
    }

    drop(event_emitter);
    match writer_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = writeln!(stderr, "Warning: failed to write events log: {}", e);
        }
        Err(e) => {
            let _ = writeln!(stderr, "Warning: event writer task failed: {}", e);
        }
    }
    if dropped_events > 0 {
        let _ = writeln!(
            stderr,
            "Warning: dropped {} policy events because the event queue is full (capacity={})",
            dropped_events, EVENT_QUEUE_CAPACITY
        );
    }
    if rejected_proxy_connections > 0 {
        let _ = writeln!(
            stderr,
            "Warning: rejected {} proxy connections due to in-flight limit ({})",
            rejected_proxy_connections, PROXY_MAX_IN_FLIGHT_CONNECTIONS
        );
    }

    let events_bytes = match tokio::fs::read(&events_out).await {
        Ok(b) => b,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "Error: failed to read events log for receipt hashing: {}",
                e
            );
            return ExitCode::RuntimeError.as_i32();
        }
    };

    let content_hash = sha256(&events_bytes);
    let receipt = match engine.create_receipt(content_hash).await {
        Ok(r) => r
            .with_id(session_id.clone())
            .merge_metadata(serde_json::json!({
                "hush": {
                    "command": command,
                    "events": events_out,
                    "proxy": env_proxy_url,
                    "sandbox": sandbox_note,
                    "child_exit_code": child_exit_code,
                    "policy_exit_code": outcome.exit_code(),
                }
            })),
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to create receipt: {}", e);
            return ExitCode::RuntimeError.as_i32();
        }
    };

    // Override verdict with the run outcome (warns are pass; blocks are fail).
    let receipt = Receipt {
        verdict: outcome.verdict(),
        ..receipt
    };

    let signed = SignedReceipt::sign_with(receipt, signer.as_ref()).map_err(anyhow::Error::from);

    let signed = match signed {
        Ok(s) => s,
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to sign receipt: {}", e);
            return ExitCode::RuntimeError.as_i32();
        }
    };

    if let Some(parent) = receipt_path.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(e) = std::fs::create_dir_all(parent) {
                let _ = writeln!(
                    stderr,
                    "Error: failed to create receipt output directory: {}",
                    e
                );
                return ExitCode::RuntimeError.as_i32();
            }
        }
    }

    match signed.to_json() {
        Ok(json) => {
            if let Err(e) = std::fs::write(&receipt_path, json) {
                let _ = writeln!(
                    stderr,
                    "Error: failed to write receipt {}: {}",
                    receipt_path.display(),
                    e
                );
                return ExitCode::RuntimeError.as_i32();
            }
        }
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to serialize receipt: {}", e);
            return ExitCode::RuntimeError.as_i32();
        }
    }

    let _ = writeln!(stdout, "Session: {}", session_id);
    let _ = writeln!(stdout, "Events: {}", Path::new(&events_out).display());
    let _ = writeln!(stdout, "Receipt: {}", receipt_path.display());
    if let Some(url) = env_proxy_url.as_ref() {
        let _ = writeln!(stdout, "Proxy: {}", url);
    } else {
        let _ = writeln!(stdout, "Proxy: disabled");
    }
    let _ = writeln!(stdout, "Sandbox: {}", sandbox_note);

    // Exit behavior:
    // - Policy outcomes (warn/block) override child process exit.
    // - Otherwise, pass through the child's exit code.
    let policy_exit = outcome.exit_code();
    if policy_exit != 0 {
        return policy_exit;
    }

    child_exit_code
}

fn child_exit_code(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    // On Unix, a signal-terminated process yields None. Use a conventional non-zero value.
    1
}

fn load_policy(
    policy: &str,
    remote_extends: &remote_extends::RemoteExtendsConfig,
) -> anyhow::Result<LoadedPolicy> {
    let loaded = policy_diff::load_policy_from_arg(policy, true, remote_extends)
        .map_err(|e| anyhow::anyhow!("Failed to load policy {}: {}", e.source, e.message))?;

    Ok(loaded)
}

fn load_or_create_signer(path: &Path, stderr: &mut dyn Write) -> anyhow::Result<Box<dyn Signer>> {
    if path.exists() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read signing key {}", path.display()))?;
        let raw = raw.trim();

        if raw.starts_with('{') {
            let blob: hush_core::TpmSealedBlob =
                serde_json::from_str(raw).context("parse TPM sealed key blob JSON")?;
            let pub_path = PathBuf::from(format!("{}.pub", path.display()));
            let pub_hex = std::fs::read_to_string(&pub_path)
                .with_context(|| format!("read public key {}", pub_path.display()))?;
            let public_key = PublicKey::from_hex(pub_hex.trim()).context("parse public key hex")?;
            return Ok(Box::new(hush_core::TpmSealedSeedSigner::new(
                public_key, blob,
            )));
        }

        let keypair = Keypair::from_hex(raw)
            .map_err(|e| anyhow::anyhow!("Invalid signing key {}: {}", path.display(), e))?;
        return Ok(Box::new(keypair));
    }

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("create key directory {}", parent.display()))?;
        }
    }

    let keypair = Keypair::generate();
    std::fs::write(path, keypair.to_hex())
        .with_context(|| format!("write new signing key {}", path.display()))?;

    let pub_path = PathBuf::from(format!("{}.pub", path.display()));
    std::fs::write(&pub_path, keypair.public_key().to_hex())
        .with_context(|| format!("write public key {}", pub_path.display()))?;

    let _ = writeln!(
        stderr,
        "Generated new signing keypair: {} (public: {})",
        path.display(),
        pub_path.display()
    );

    Ok(Box::new(keypair))
}

#[derive(Clone, Debug)]
enum SandboxWrapper {
    None,
    #[cfg(target_os = "macos")]
    SandboxExec {
        profile_path: PathBuf,
    },
    #[cfg(target_os = "linux")]
    Bwrap {
        args: Vec<String>,
    },
}

fn maybe_prepare_sandbox(
    enabled: bool,
    stderr: &mut dyn Write,
) -> anyhow::Result<(SandboxWrapper, String)> {
    if !enabled {
        return Ok((SandboxWrapper::None, "disabled".to_string()));
    }

    #[cfg(target_os = "macos")]
    {
        let tool = Path::new("/usr/bin/sandbox-exec");
        if !tool.exists() {
            let _ = writeln!(stderr, "Warning: sandbox-exec not found; sandbox disabled");
            return Ok((SandboxWrapper::None, "disabled".to_string()));
        }

        let cwd = std::env::current_dir().context("get current directory")?;
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let profile = generate_macos_sandbox_profile(home.as_deref(), &cwd);

        let profile_path = std::env::temp_dir().join(format!("hush.sandbox.{}.sb", Uuid::new_v4()));
        std::fs::write(&profile_path, profile)
            .with_context(|| format!("write sandbox profile {}", profile_path.display()))?;

        Ok((
            SandboxWrapper::SandboxExec { profile_path },
            "sandbox-exec".to_string(),
        ))
    }

    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(target_os = "linux")]
        {
            if find_in_path("bwrap").is_none() {
                let _ = writeln!(stderr, "Warning: bwrap not found; sandbox disabled");
                return Ok((SandboxWrapper::None, "disabled".to_string()));
            }

            let cwd = std::env::current_dir().context("get current directory")?;
            let args = generate_bwrap_args(&cwd);
            Ok((SandboxWrapper::Bwrap { args }, "bwrap".to_string()))
        }

        #[cfg(not(target_os = "linux"))]
        {
            let _ = writeln!(
                stderr,
                "Warning: sandbox wrapper not implemented for this OS; sandbox disabled"
            );
            Ok((SandboxWrapper::None, "disabled".to_string()))
        }
    }
}

#[cfg(target_os = "macos")]
fn generate_macos_sandbox_profile(home: Option<&Path>, workspace: &Path) -> String {
    // Seatbelt "deny" rules cannot be overridden by later "allow" rules. To avoid breaking
    // workspaces under $HOME, we deny only high-value secret subpaths by default.
    //
    // This is best-effort hardening, not a complete OS sandbox.
    let mut out = String::new();
    out.push_str("(version 1)\n");
    out.push_str("(allow default)\n");

    let Some(home) = home else {
        return out;
    };

    let home = home.to_string_lossy();
    let workspace = workspace.to_string_lossy();

    // If the workspace is not inside $HOME, we can safely deny all of $HOME.
    if !workspace.starts_with(home.as_ref()) {
        out.push_str(&format!("(deny file-read* (subpath \"{home}\"))\n"));
        out.push_str(&format!("(deny file-write* (subpath \"{home}\"))\n"));
        return out;
    }

    for sub in [
        ".ssh",
        ".gnupg",
        ".aws",
        ".config/gcloud",
        ".config/gh",
        ".config/git",
        ".config/hush",
        ".kube",
    ] {
        let path = format!("{home}/{sub}");
        out.push_str(&format!("(deny file-read* (subpath \"{path}\"))\n"));
        out.push_str(&format!("(deny file-write* (subpath \"{path}\"))\n"));
    }

    out
}

async fn spawn_and_wait_child(
    command: &[String],
    sandbox: SandboxWrapper,
    proxy_url: Option<&str>,
    session_id: &str,
    stderr: &mut dyn Write,
) -> anyhow::Result<std::process::ExitStatus> {
    let mut cmd = match sandbox {
        SandboxWrapper::None => {
            let mut c = Command::new(&command[0]);
            c.args(&command[1..]);
            c
        }
        #[cfg(target_os = "macos")]
        SandboxWrapper::SandboxExec { profile_path } => {
            let mut c = Command::new("/usr/bin/sandbox-exec");
            c.arg("-f").arg(profile_path);
            c.arg(&command[0]);
            c.args(&command[1..]);
            c
        }
        #[cfg(target_os = "linux")]
        SandboxWrapper::Bwrap { args } => {
            let mut c = Command::new("bwrap");
            c.args(args);
            c.arg(&command[0]);
            c.args(&command[1..]);
            c
        }
    };

    cmd.env("HUSH_SESSION_ID", session_id);
    if let Some(proxy_url) = proxy_url {
        cmd.env("HTTPS_PROXY", proxy_url);
        cmd.env("ALL_PROXY", proxy_url);
    }

    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let _ = writeln!(stderr, "Running: {}", command.join(" "));

    let mut child = cmd.spawn().context("spawn child process")?;
    let status = child.wait().await.context("wait on child process")?;
    Ok(status)
}

#[allow(clippy::too_many_arguments)]
async fn start_connect_proxy(
    port: u16,
    engine: Arc<HushEngine>,
    context: GuardContext,
    event_emitter: EventEmitter,
    outcome: RunOutcome,
    max_in_flight_connections: usize,
    header_read_timeout: Duration,
    stderr: &mut dyn Write,
) -> anyhow::Result<(String, tokio::task::JoinHandle<()>, Arc<AtomicUsize>)> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .context("bind proxy listener")?;
    let local = listener.local_addr().context("proxy local_addr")?;

    let url = format!("http://127.0.0.1:{}", local.port());
    let _ = writeln!(stderr, "Proxy listening on {}", url);

    let rejected_connections = Arc::new(AtomicUsize::new(0));
    let in_flight = Arc::new(tokio::sync::Semaphore::new(max_in_flight_connections));
    let rejected_connections_for_loop = rejected_connections.clone();
    let handle = tokio::spawn(async move {
        loop {
            let (mut socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };

            let permit = match in_flight.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    rejected_connections_for_loop.fetch_add(1, Ordering::Relaxed);
                    let _ = socket
                        .write_all(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n")
                        .await;
                    continue;
                }
            };

            let engine = engine.clone();
            let context = context.clone();
            let event_emitter = event_emitter.clone();
            let outcome = outcome.clone();

            tokio::spawn(async move {
                let _permit = permit;
                let _ = handle_connect_proxy_client(
                    socket,
                    engine,
                    context,
                    event_emitter,
                    outcome,
                    header_read_timeout,
                )
                .await;
            });
        }
    });

    Ok((url, handle, rejected_connections))
}

async fn handle_connect_proxy_client(
    mut client: TcpStream,
    engine: Arc<HushEngine>,
    context: GuardContext,
    event_emitter: EventEmitter,
    outcome: RunOutcome,
    header_read_timeout: Duration,
) -> anyhow::Result<()> {
    let header =
        match tokio::time::timeout(header_read_timeout, read_http_header(&mut client, 8 * 1024))
            .await
        {
            Ok(Ok(header)) => header,
            Ok(Err(err)) => return Err(err).context("read proxy request header"),
            Err(_) => {
                let _ = client
                    .write_all(b"HTTP/1.1 408 Request Timeout\r\nConnection: close\r\n\r\n")
                    .await;
                return Ok(());
            }
        };

    let header_str = std::str::from_utf8(&header).context("proxy request header must be UTF-8")?;
    let mut lines = header_str.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing request line"))?;

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if !method.eq_ignore_ascii_case("CONNECT") {
        client
            .write_all(b"HTTP/1.1 501 Not Implemented\r\n\r\n")
            .await?;
        return Ok(());
    }

    let (connect_host, connect_port) = parse_connect_target(target)?;
    let connect_result = engine
        .check_egress(&connect_host, connect_port, &context)
        .await
        .context("check egress policy")?;

    outcome.observe_guard_result(&connect_result);

    event_emitter.emit(network_event(
        &context,
        connect_host.clone(),
        connect_port,
        &connect_result,
    ));

    if !connect_result.allowed {
        client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        return Ok(());
    }

    let connect_ip = connect_host.parse::<IpAddr>().ok();
    let mut buffered_tls_record: Option<Vec<u8>> = None;

    if let Some(ip) = connect_ip {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Best-effort: read one TLS record to extract SNI and enforce CONNECT target consistency.
        if let Ok(Ok(record)) =
            tokio::time::timeout(PROXY_TLS_SNI_TIMEOUT, read_tls_record(&mut client)).await
        {
            buffered_tls_record = Some(record.clone());
            if let Ok(Some(sni_host)) = hush_proxy::sni::extract_sni(&record) {
                let sni_result = engine
                    .check_egress(&sni_host, connect_port, &context)
                    .await
                    .context("check egress policy for SNI host")?;

                outcome.observe_guard_result(&sni_result);
                event_emitter.emit(network_event(
                    &context,
                    sni_host.clone(),
                    connect_port,
                    &sni_result,
                ));

                if !sni_result.allowed {
                    return Ok(());
                }

                if !sni_host_matches_connect_ip(&sni_host, connect_port, ip).await {
                    let mismatch = GuardResult::block(
                        "connect_proxy_sni_consistency",
                        Severity::Error,
                        format!(
                            "CONNECT target {} does not match SNI host {}",
                            connect_host, sni_host
                        ),
                    );
                    outcome.observe_guard_result(&mismatch);
                    event_emitter.emit(network_event(&context, sni_host, connect_port, &mismatch));
                    return Ok(());
                }
            }
        }
    }

    // Connect to the requested endpoint.
    let mut upstream = TcpStream::connect((connect_host.as_str(), connect_port))
        .await
        .context("connect upstream")?;

    // If we already answered CONNECT for IP targets, do not send it twice.
    if connect_ip.is_none() {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }

    // Forward the already-read TLS bytes, if any.
    if let Some(sni_buf) = buffered_tls_record {
        upstream.write_all(&sni_buf).await?;
    }

    // Tunnel bytes both ways until EOF.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;

    Ok(())
}

async fn sni_host_matches_connect_ip(host: &str, port: u16, connect_ip: IpAddr) -> bool {
    let lookup = tokio::time::timeout(Duration::from_secs(2), lookup_host((host, port))).await;
    let Ok(Ok(addrs)) = lookup else {
        return false;
    };

    addrs.into_iter().any(|addr| addr.ip() == connect_ip)
}

async fn read_http_header(stream: &mut TcpStream, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1024];

    loop {
        if buf.len() >= max_bytes {
            anyhow::bail!("proxy header exceeded max size");
        }

        let n = stream.read(&mut scratch).await?;
        if n == 0 {
            anyhow::bail!("unexpected EOF reading proxy header");
        }
        buf.extend_from_slice(&scratch[..n]);

        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            // Truncate to header boundary; ignore any extra bytes (CONNECT should not send any).
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                buf.truncate(pos + 4);
            }
            return Ok(buf);
        }
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn parse_connect_target(target: &str) -> anyhow::Result<(String, u16)> {
    let mut parts = target.split(':');
    let host = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid CONNECT target"))?
        .to_string();
    let port = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid CONNECT target"))?;
    if parts.next().is_some() {
        anyhow::bail!("invalid CONNECT target");
    }

    let port: u16 = port.parse().context("CONNECT port must be u16")?;
    Ok((host, port))
}

async fn read_tls_record(stream: &mut TcpStream) -> anyhow::Result<Vec<u8>> {
    let mut hdr = [0u8; 5];
    stream.read_exact(&mut hdr).await?;
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    let mut out = Vec::with_capacity(5 + len);
    out.extend_from_slice(&hdr);
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await?;
    out.extend_from_slice(&body);
    Ok(out)
}

fn network_event(
    context: &GuardContext,
    host: String,
    port: u16,
    result: &GuardResult,
) -> PolicyEvent {
    let severity = match result.severity {
        Severity::Info => "info",
        Severity::Warning => "warning",
        Severity::Error => "error",
        Severity::Critical => "critical",
    };

    PolicyEvent {
        event_id: Uuid::new_v4().to_string(),
        event_type: PolicyEventType::NetworkEgress,
        timestamp: Utc::now(),
        session_id: context.session_id.clone(),
        data: PolicyEventData::Network(NetworkEventData {
            host,
            port,
            protocol: Some("tcp".to_string()),
            url: None,
        }),
        metadata: Some(serde_json::json!({
            "decision": {
                "allowed": result.allowed,
                "guard": result.guard,
                "severity": severity,
                "message": result.message,
            }
        })),
        context: None,
    }
}

#[cfg(target_os = "linux")]
fn find_in_path(cmd: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for p in std::env::split_paths(&path) {
        let candidate = p.join(cmd);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn generate_bwrap_args(workspace: &Path) -> Vec<String> {
    // Best-effort bwrap sandbox:
    // - bind the workspace into a new mount namespace
    // - provide read-only access to common system directories
    // - do not mount /home by default (deny home unless the workspace is there)
    let mut args: Vec<String> = Vec::new();

    args.push("--unshare-all".to_string());
    args.push("--die-with-parent".to_string());

    // Create parent directories for the workspace path inside the sandbox.
    let mut cur = PathBuf::new();
    for component in workspace.components() {
        cur.push(component);
        if cur.as_os_str().is_empty() {
            continue;
        }
        args.push("--dir".to_string());
        args.push(cur.to_string_lossy().to_string());
    }

    args.push("--bind".to_string());
    args.push(workspace.to_string_lossy().to_string());
    args.push(workspace.to_string_lossy().to_string());

    for ro in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
        if Path::new(ro).exists() {
            args.push("--ro-bind".to_string());
            args.push(ro.to_string());
            args.push(ro.to_string());
        }
    }

    if Path::new("/dev").exists() {
        args.push("--dev-bind".to_string());
        args.push("/dev".to_string());
        args.push("/dev".to_string());
    }
    if Path::new("/proc").exists() {
        args.push("--proc".to_string());
        args.push("/proc".to_string());
    }

    args.push("--tmpfs".to_string());
    args.push("/tmp".to_string());

    args.push("--chdir".to_string());
    args.push(workspace.to_string_lossy().to_string());

    args.push("--".to_string());

    args
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdstrike::Policy;

    fn test_custom_event(id: usize) -> PolicyEvent {
        PolicyEvent {
            event_id: format!("event-{id}"),
            event_type: PolicyEventType::Custom,
            timestamp: Utc::now(),
            session_id: Some("session-test".to_string()),
            data: PolicyEventData::Custom(CustomEventData {
                custom_type: "test_event".to_string(),
                extra: serde_json::Map::new(),
            }),
            metadata: None,
            context: None,
        }
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_profile_denies_sensitive_home_subpaths() {
        let home = Path::new("/Users/alice");
        let workspace = Path::new("/Users/alice/work/project");
        let profile = generate_macos_sandbox_profile(Some(home), workspace);
        assert!(profile.contains("(allow default)"));
        assert!(profile.contains("/Users/alice/.ssh"));
        assert!(profile.contains("/Users/alice/.gnupg"));
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn macos_profile_denies_entire_home_when_safe() {
        let home = Path::new("/Users/alice");
        let workspace = Path::new("/tmp/project");
        let profile = generate_macos_sandbox_profile(Some(home), workspace);
        assert!(profile.contains("(deny file-read* (subpath \"/Users/alice\"))"));
        assert!(profile.contains("(deny file-write* (subpath \"/Users/alice\"))"));
    }

    #[tokio::test]
    async fn sni_host_is_used_when_connect_target_is_ip() {
        use clawdstrike::Policy;

        let policy_yaml = r#"
version: "1.1.0"
name: test
guards:
  egress_allowlist:
    allow: ["example.com"]
    default_action: block
"#;
        let policy = Policy::from_yaml(policy_yaml).unwrap();
        let engine = Arc::new(HushEngine::builder(policy).build().unwrap());
        let ctx = GuardContext::new().with_session_id("s");

        // TLS ClientHello from hush-proxy test (SNI = example.com)
        let hello = include_bytes!("../../../libs/hush-proxy/testdata/client_hello_example.bin");

        let outcome = RunOutcome::new();

        // Build a fake CONNECT target of an IP, and ensure policy host uses SNI.
        let result = engine.check_egress("example.com", 443, &ctx).await.unwrap();
        assert!(result.allowed);

        let ev = network_event(&ctx, "example.com".to_string(), 443, &result);
        assert_eq!(ev.event_type.as_str(), "network_egress");
        assert_eq!(
            hush_proxy::sni::extract_sni(hello).unwrap(),
            Some("example.com".to_string())
        );

        // Ensure outcome tracking is updated for allowed events.
        outcome.observe_guard_result(&result);
        assert_eq!(outcome.exit_code(), 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn bwrap_args_include_workspace_bind() {
        let ws = Path::new("/work/project");
        let args = generate_bwrap_args(ws);
        let joined = args.join(" ");
        assert!(joined.contains("--bind /work/project /work/project"));
        assert!(joined.contains("--tmpfs /tmp"));
    }

    #[test]
    fn event_emitter_drops_events_when_queue_is_full() {
        let (tx, mut rx) = mpsc::channel::<PolicyEvent>(2);
        let emitter = EventEmitter::new(tx);

        for i in 0..10 {
            emitter.emit(test_custom_event(i));
        }

        assert_eq!(emitter.dropped_count(), 8);

        let mut queued = 0usize;
        while rx.try_recv().is_ok() {
            queued += 1;
        }
        assert_eq!(queued, 2, "queue must stay bounded at channel capacity");
    }

    #[tokio::test]
    async fn proxy_rejects_connections_when_in_flight_limit_is_reached() {
        let policy_yaml = r#"
version: "1.1.0"
name: "proxy-limit"
"#;
        let policy = Policy::from_yaml(policy_yaml).expect("policy");
        let engine = Arc::new(HushEngine::builder(policy).build().expect("engine"));
        let context = GuardContext::new().with_session_id("session-1");
        let (tx, _rx) = mpsc::channel::<PolicyEvent>(32);
        let emitter = EventEmitter::new(tx);
        let outcome = RunOutcome::new();
        let mut stderr = Vec::<u8>::new();

        let (url, handle, rejected_counter) = match start_connect_proxy(
            0,
            engine,
            context,
            emitter,
            outcome,
            1,
            Duration::from_secs(2),
            &mut stderr,
        )
        .await
        {
            Ok(v) => v,
            Err(err) => {
                if err.to_string().contains("Permission denied") {
                    eprintln!("skipping proxy limit test: {}", err);
                    return;
                }
                panic!("failed to start proxy: {err}");
            }
        };

        let addr = url.trim_start_matches("http://");
        let mut first = TcpStream::connect(addr).await.expect("first connect");
        tokio::time::sleep(Duration::from_millis(100)).await;

        let mut second = TcpStream::connect(addr).await.expect("second connect");
        let mut buf = [0u8; 128];
        let read_result = tokio::time::timeout(Duration::from_secs(2), second.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read");
        let response = String::from_utf8_lossy(&buf[..read_result]).to_string();
        assert!(
            response.contains("503 Service Unavailable"),
            "expected 503 when proxy is saturated, got: {response}"
        );
        assert!(
            rejected_counter.load(Ordering::Relaxed) >= 1,
            "rejected connection counter must increment when limit is reached"
        );

        let _ = first.shutdown().await;
        let _ = second.shutdown().await;
        handle.abort();
    }

    #[tokio::test]
    async fn connect_proxy_rejects_ip_target_with_allowlisted_sni_mismatch() {
        let policy_yaml = r#"
version: "1.1.0"
name: "sni-mismatch"
guards:
  egress_allowlist:
    allow: ["example.com"]
    default_action: block
"#;
        let policy = Policy::from_yaml(policy_yaml).expect("policy");
        let engine = Arc::new(HushEngine::builder(policy).build().expect("engine"));
        let context = GuardContext::new().with_session_id("session-sni");
        let (tx, _rx) = mpsc::channel::<PolicyEvent>(32);
        let emitter = EventEmitter::new(tx);
        let outcome = RunOutcome::new();
        let mut stderr = Vec::<u8>::new();

        let upstream = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind upstream");
        let upstream_port = upstream.local_addr().expect("upstream addr").port();

        let (url, handle, _rejected_counter) = start_connect_proxy(
            0,
            engine,
            context,
            emitter,
            outcome,
            4,
            Duration::from_secs(2),
            &mut stderr,
        )
        .await
        .expect("start proxy");

        let addr = url.trim_start_matches("http://");
        let mut client = TcpStream::connect(addr).await.expect("proxy connect");

        let req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n\r\n",
            upstream_port, upstream_port
        );
        client
            .write_all(req.as_bytes())
            .await
            .expect("write connect");

        let mut buf = [0u8; 256];
        let n = tokio::time::timeout(Duration::from_secs(1), client.read(&mut buf))
            .await
            .expect("read timeout")
            .expect("read response");
        let response = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(
            response.contains("403 Forbidden"),
            "blocked IP CONNECT target must not be bypassed by allowlisted SNI, got: {response}"
        );

        let hello = include_bytes!("../../../libs/hush-proxy/testdata/client_hello_example.bin");
        let _ = client.write_all(hello).await;

        let upstream_accept =
            tokio::time::timeout(Duration::from_millis(300), upstream.accept()).await;
        assert!(
            upstream_accept.is_err(),
            "proxy must not connect upstream when CONNECT IP target is blocked"
        );

        handle.abort();
    }

    #[tokio::test]
    async fn proxy_slowloris_does_not_exceed_connection_cap() {
        let policy_yaml = r#"
version: "1.1.0"
name: "slowloris-cap"
"#;
        let policy = Policy::from_yaml(policy_yaml).expect("policy");
        let engine = Arc::new(HushEngine::builder(policy).build().expect("engine"));
        let context = GuardContext::new().with_session_id("session-slowloris");
        let (tx, _rx) = mpsc::channel::<PolicyEvent>(32);
        let emitter = EventEmitter::new(tx);
        let outcome = RunOutcome::new();
        let mut stderr = Vec::<u8>::new();

        let (url, handle, rejected_counter) = start_connect_proxy(
            0,
            engine,
            context,
            emitter,
            outcome,
            1,
            Duration::from_millis(150),
            &mut stderr,
        )
        .await
        .expect("start proxy");

        let addr = url.trim_start_matches("http://");
        let mut slow = TcpStream::connect(addr).await.expect("slow connect");
        slow.write_all(b"CON").await.expect("write partial header");

        let mut second = TcpStream::connect(addr).await.expect("second connect");
        let mut second_buf = [0u8; 128];
        let second_n = tokio::time::timeout(Duration::from_secs(1), second.read(&mut second_buf))
            .await
            .expect("second read timeout")
            .expect("second read");
        let second_response = String::from_utf8_lossy(&second_buf[..second_n]).to_string();
        assert!(
            second_response.contains("503 Service Unavailable"),
            "expected 503 while slowloris connection holds the only slot, got: {second_response}"
        );

        tokio::time::sleep(Duration::from_millis(250)).await;

        let mut third = TcpStream::connect(addr).await.expect("third connect");
        third
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write full request");
        let mut third_buf = [0u8; 128];
        let third_n = tokio::time::timeout(Duration::from_secs(1), third.read(&mut third_buf))
            .await
            .expect("third read timeout")
            .expect("third read");
        let third_response = String::from_utf8_lossy(&third_buf[..third_n]).to_string();
        assert!(
            third_response.contains("501 Not Implemented"),
            "proxy should remain responsive after slowloris timeout, got: {third_response}"
        );
        assert!(
            rejected_counter.load(Ordering::Relaxed) >= 1,
            "rejected connection counter should increment under slowloris saturation"
        );

        let _ = slow.shutdown().await;
        let _ = second.shutdown().await;
        let _ = third.shutdown().await;
        handle.abort();
    }

    #[tokio::test]
    async fn event_forwarding_backpressure_keeps_memory_bounded() {
        let stalled_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind stalled target");
        let stalled_addr = stalled_listener.local_addr().expect("stalled addr");
        let stalled_handle = tokio::spawn(async move {
            while let Ok((mut stream, _)) = stalled_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ =
                        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });

        let (tx, mut rx) = mpsc::channel::<PolicyEvent>(4);
        let emitter = EventEmitter::new(tx);
        let forwarder = HushdForwarder::new_with_timeout(
            format!("http://{}", stalled_addr),
            None,
            Duration::from_millis(50),
        );

        let writer = tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                forwarder.forward_event(&event).await;
            }
        });

        for i in 0..200 {
            emitter.emit(test_custom_event(i));
        }

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            emitter.dropped_count() > 0,
            "bounded queue should drop events under stalled forwarding pressure"
        );

        drop(emitter);
        let _ = tokio::time::timeout(Duration::from_secs(2), writer).await;
        stalled_handle.abort();
    }

    #[tokio::test]
    async fn forwarder_test_timeout_is_respected() {
        let stalled_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind stalled target");
        let stalled_addr = stalled_listener.local_addr().expect("stalled addr");
        let stalled_handle = tokio::spawn(async move {
            while let Ok((mut stream, _)) = stalled_listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ =
                        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await;
                    tokio::time::sleep(Duration::from_secs(5)).await;
                });
            }
        });

        let forwarder = HushdForwarder::new_with_timeout(
            format!("http://{}", stalled_addr),
            None,
            Duration::from_millis(50),
        );
        let event = test_custom_event(0);

        let started = tokio::time::Instant::now();
        tokio::time::timeout(Duration::from_millis(300), forwarder.forward_event(&event))
            .await
            .expect("forward_event should honor test timeout");
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_millis(300),
            "forward_event exceeded expected test timeout; elapsed: {elapsed:?}"
        );

        stalled_handle.abort();
    }
}
