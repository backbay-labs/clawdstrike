#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::io::Write;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use chrono::Utc;
use clawdstrike::{GuardContext, GuardResult, HushEngine, Severity};
use hush_core::{sha256, Keypair, PublicKey, Receipt, SignedReceipt, Signer, Verdict};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            client: reqwest::Client::new(),
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

    let (event_tx, mut event_rx) = mpsc::unbounded_channel::<PolicyEvent>();

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
    let _ = event_tx.send(command_event);

    let outcome = RunOutcome::new();

    let mut env_proxy_url = None;
    let proxy_handle = if no_proxy {
        None
    } else {
        match start_connect_proxy(
            proxy_port,
            engine.clone(),
            base_context.clone(),
            event_tx.clone(),
            outcome.clone(),
            stderr,
        )
        .await
        {
            Ok((listen_url, handle)) => {
                env_proxy_url = Some(listen_url);
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
            drop(event_tx);
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

    let _ = event_tx.send(PolicyEvent {
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

    drop(event_tx);
    match writer_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = writeln!(stderr, "Warning: failed to write events log: {}", e);
        }
        Err(e) => {
            let _ = writeln!(stderr, "Warning: event writer task failed: {}", e);
        }
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

async fn start_connect_proxy(
    port: u16,
    engine: Arc<HushEngine>,
    context: GuardContext,
    event_tx: mpsc::UnboundedSender<PolicyEvent>,
    outcome: RunOutcome,
    stderr: &mut dyn Write,
) -> anyhow::Result<(String, tokio::task::JoinHandle<()>)> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .context("bind proxy listener")?;
    let local = listener.local_addr().context("proxy local_addr")?;

    let url = format!("http://127.0.0.1:{}", local.port());
    let _ = writeln!(stderr, "Proxy listening on {}", url);

    let handle = tokio::spawn(async move {
        loop {
            let (socket, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };

            let engine = engine.clone();
            let context = context.clone();
            let event_tx = event_tx.clone();
            let outcome = outcome.clone();

            tokio::spawn(async move {
                let _ =
                    handle_connect_proxy_client(socket, engine, context, event_tx, outcome).await;
            });
        }
    });

    Ok((url, handle))
}

async fn handle_connect_proxy_client(
    mut client: TcpStream,
    engine: Arc<HushEngine>,
    context: GuardContext,
    event_tx: mpsc::UnboundedSender<PolicyEvent>,
    outcome: RunOutcome,
) -> anyhow::Result<()> {
    let header = read_http_header(&mut client, 8 * 1024)
        .await
        .context("read proxy request header")?;

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

    // If the CONNECT target is an IP address, try to use TLS SNI as the policy host.
    let mut sni_buf = Vec::new();
    let host_for_policy = if connect_host.parse::<IpAddr>().is_ok() {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        // Best-effort: read one TLS record to extract SNI.
        match tokio::time::timeout(Duration::from_secs(3), read_tls_record(&mut client)).await {
            Ok(Ok(record)) => {
                sni_buf = record.clone();
                match hush_proxy::sni::extract_sni(&record) {
                    Ok(Some(host)) => host,
                    _ => connect_host.clone(),
                }
            }
            _ => connect_host.clone(),
        }
    } else {
        connect_host.clone()
    };

    let result = engine
        .check_egress(&host_for_policy, connect_port, &context)
        .await
        .context("check egress policy")?;

    outcome.observe_guard_result(&result);

    let _ = event_tx.send(network_event(
        &context,
        host_for_policy.clone(),
        connect_port,
        &result,
    ));

    if !result.allowed {
        // If we already sent 200 (IP + SNI path), we can only close the tunnel.
        if sni_buf.is_empty() {
            client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
        }
        return Ok(());
    }

    // Connect to the requested endpoint.
    let mut upstream = TcpStream::connect((connect_host.as_str(), connect_port))
        .await
        .context("connect upstream")?;

    // If we used the SNI path, forward the already-read TLS bytes.
    if !sni_buf.is_empty() {
        upstream.write_all(&sni_buf).await?;
    } else {
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }

    // Tunnel bytes both ways until EOF.
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;

    Ok(())
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
        let hello = include_bytes!("../../hush-proxy/testdata/client_hello_example.bin");

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
}
