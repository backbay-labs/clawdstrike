#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::collections::HashMap;
use std::future::Future;
use std::io::Write;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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
use crate::sandbox_nono;
use crate::ExitCode;
use crate::SandboxMode;

const EVENT_QUEUE_CAPACITY_DEFAULT: usize = 1024;
const PROXY_MAX_IN_FLIGHT_CONNECTIONS_DEFAULT: usize = 256;
const PROXY_HEADER_READ_TIMEOUT_DEFAULT: Duration = Duration::from_secs(5);
const PROXY_TLS_SNI_TIMEOUT: Duration = Duration::from_secs(3);
const PROXY_DNS_RESOLVE_TIMEOUT_DEFAULT: Duration = Duration::from_secs(2);
const HUSHD_FORWARD_TIMEOUT_DEFAULT: Duration = Duration::from_secs(3);

static TEST_RESOLVER_CALLS: OnceLock<Mutex<HashMap<String, usize>>> = OnceLock::new();

fn parse_test_override_usize(name: &str) -> Option<usize> {
    let raw = std::env::var(name).ok()?;
    raw.parse::<usize>().ok()
}

fn parse_test_override_duration_ms(name: &str) -> Option<Duration> {
    let raw = std::env::var(name).ok()?;
    let ms = raw.parse::<u64>().ok()?;
    Some(Duration::from_millis(ms))
}

fn event_queue_capacity() -> usize {
    parse_test_override_usize("HUSH_TEST_EVENT_QUEUE_CAPACITY")
        .filter(|v| *v > 0)
        .unwrap_or(EVENT_QUEUE_CAPACITY_DEFAULT)
}

fn proxy_max_in_flight_connections() -> usize {
    parse_test_override_usize("HUSH_TEST_PROXY_MAX_IN_FLIGHT")
        .filter(|v| *v > 0)
        .unwrap_or(PROXY_MAX_IN_FLIGHT_CONNECTIONS_DEFAULT)
}

fn proxy_header_read_timeout() -> Duration {
    parse_test_override_duration_ms("HUSH_TEST_PROXY_HEADER_TIMEOUT_MS")
        .filter(|v| !v.is_zero())
        .unwrap_or(PROXY_HEADER_READ_TIMEOUT_DEFAULT)
}

fn proxy_dns_resolve_timeout() -> Duration {
    parse_test_override_duration_ms("HUSH_TEST_PROXY_DNS_TIMEOUT_MS")
        .filter(|v| !v.is_zero())
        .unwrap_or(PROXY_DNS_RESOLVE_TIMEOUT_DEFAULT)
}

fn hushd_forward_timeout() -> Duration {
    parse_test_override_duration_ms("HUSH_TEST_FORWARD_TIMEOUT_MS")
        .filter(|v| !v.is_zero())
        .unwrap_or(HUSHD_FORWARD_TIMEOUT_DEFAULT)
}

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
            .timeout(hushd_forward_timeout())
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
    pub events_out: Option<String>,
    pub receipt_out: Option<String>,
    pub signing_key: String,
    pub no_proxy: bool,
    pub proxy_port: u16,
    pub proxy_allow_private_ips: bool,
    pub sandbox: SandboxMode,
    pub hushd_url: Option<String>,
    pub hushd_token: Option<String>,
    pub supervised: bool,
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
        proxy_allow_private_ips,
        sandbox,
        hushd_url,
        hushd_token,
        supervised,
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

    let sandbox_policy = loaded.policy.clone();
    let engine = match HushEngine::builder(loaded.policy).build() {
        Ok(engine) => engine,
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to initialize engine: {}", e);
            return ExitCode::ConfigError.as_i32();
        }
    };
    let engine = Arc::new(engine);

    let session_id = Uuid::new_v4().to_string();
    let (events_out, receipt_out) =
        default_run_artifact_paths(&session_id, events_out.as_deref(), receipt_out.as_deref());

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

    let event_queue_capacity = event_queue_capacity();
    let proxy_max_in_flight_connections = proxy_max_in_flight_connections();
    let proxy_header_timeout = proxy_header_read_timeout();

    let (event_tx, mut event_rx) = mpsc::channel::<PolicyEvent>(event_queue_capacity);
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
            proxy_max_in_flight_connections,
            proxy_header_timeout,
            proxy_allow_private_ips,
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

    let (sandbox_execution, sandbox_note) = match sandbox {
        SandboxMode::Nono => {
            let working_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

            // Extract proxy port from proxy URL
            let proxy_port = env_proxy_url
                .as_ref()
                .and_then(|url| url.rsplit(':').next().and_then(|p| p.parse::<u16>().ok()));

            // Build capability set from policy using CapabilityBuilder
            let supervisor_policy = if supervised {
                Some(sandbox_policy.clone())
            } else {
                None
            };
            let mut builder =
                clawdstrike::sandbox::CapabilityBuilder::new(sandbox_policy, working_dir.clone());
            if let Some(port) = proxy_port {
                builder = builder.with_proxy_port(port);
            }

            match builder.build_with_diagnostics() {
                Ok((caps, translation_warnings)) => {
                    // Log translation warnings
                    for tw in &translation_warnings {
                        match tw.severity {
                            clawdstrike::sandbox::WarningSeverity::Warning => {
                                let _ = writeln!(
                                    stderr,
                                    "[nono] warning: {}: {}",
                                    tw.guard, tw.message
                                );
                            }
                            clawdstrike::sandbox::WarningSeverity::Info => {
                                // Only show info in verbose mode (skip for now)
                            }
                        }
                    }

                    // Pre-flight validation
                    let preflight =
                        clawdstrike::sandbox::preflight_check(&caps, &command, &working_dir);
                    for e in &preflight.errors {
                        let _ = writeln!(stderr, "[nono] error: {}", e);
                    }
                    for w in &preflight.warnings {
                        let _ = writeln!(stderr, "[nono] warning: {}", w);
                    }

                    if !preflight.is_ok() {
                        let _ = writeln!(
                            stderr,
                            "[nono] aborting: sandbox pre-flight failed (fail-closed)"
                        );
                        drop(event_emitter);
                        await_event_writer(writer_handle, stderr).await;
                        return ExitCode::RuntimeError.as_i32();
                    } else {
                        // Check platform support
                        if !nono::Sandbox::is_supported() {
                            let support = nono::Sandbox::support_info();
                            let _ = writeln!(
                                stderr,
                                "[nono] warning: sandbox not supported: {}",
                                support.details
                            );
                        }

                        if let Some(ref sp) = supervisor_policy {
                            // Build never-grant list and supervisor context
                            let never_grant_paths =
                                clawdstrike::sandbox::build_never_grant_list(sp);
                            match nono::NeverGrantChecker::new(&never_grant_paths) {
                                Ok(never_grant) => {
                                    let context = GuardContext::new();
                                    let _ = writeln!(
                                        stderr,
                                        "[nono] supervised mode: {} never-grant paths",
                                        never_grant.len()
                                    );
                                    (
                                        SandboxExecution::Supervised(Box::new(SupervisedData {
                                            caps: Box::new(caps),
                                            engine: Arc::clone(&engine),
                                            context,
                                            never_grant,
                                        })),
                                        "nono+supervised".to_string(),
                                    )
                                }
                                Err(e) => {
                                    let _ = writeln!(
                                        stderr,
                                        "[nono] error: failed to activate supervised mode: {}",
                                        e
                                    );
                                    drop(event_emitter);
                                    await_event_writer(writer_handle, stderr).await;
                                    return ExitCode::RuntimeError.as_i32();
                                }
                            }
                        } else {
                            (
                                SandboxExecution::Nono {
                                    caps: Box::new(caps),
                                    working_dir,
                                },
                                "nono".to_string(),
                            )
                        }
                    }
                }
                Err(e) => {
                    let _ = writeln!(
                        stderr,
                        "[nono] FATAL: failed to build sandbox: {}. Aborting -- will not run unsandboxed.",
                        e
                    );
                    return ExitCode::RuntimeError.as_i32();
                }
            }
        }
        SandboxMode::Legacy => match maybe_prepare_sandbox(true, stderr) {
            Ok((wrapper, note)) => (SandboxExecution::Legacy(wrapper), note),
            Err(e) => {
                let _ = writeln!(stderr, "Warning: failed to prepare sandbox: {}", e);
                (SandboxExecution::None, "disabled".to_string())
            }
        },
        SandboxMode::None => (SandboxExecution::None, "disabled".to_string()),
    };

    let sandbox_run = match sandbox_execution {
        SandboxExecution::Nono { caps, .. } => {
            // Build env overrides for the child
            let mut env_overrides = HashMap::new();
            env_overrides.insert("HUSH_SESSION_ID".to_string(), session_id.clone());
            if let Some(ref proxy_url) = env_proxy_url {
                env_overrides.insert("HTTPS_PROXY".to_string(), proxy_url.clone());
                env_overrides.insert("ALL_PROXY".to_string(), proxy_url.clone());
            }
            let _ = writeln!(stderr, "Running: {}", command.join(" "));
            match sandbox_nono::spawn_sandboxed_child(&caps, &command, &env_overrides) {
                Ok(result) => SandboxRunResult {
                    child_status: exit_status_from_code(result.exit_code),
                    sandbox_attestation_json: serde_json::to_value(
                        clawdstrike::sandbox::build_attestation(
                            &caps,
                            clawdstrike::sandbox::SandboxRuntimeState::static_mode(
                                result.sandbox_applied,
                                result.sandbox_error.clone(),
                            ),
                        ),
                    )
                    .ok(),
                    sandbox_failure: result.sandbox_error,
                },
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {}", e);
                    if let Some(h) = proxy_handle {
                        h.abort();
                    }
                    drop(event_emitter);
                    await_event_writer(writer_handle, stderr).await;
                    return ExitCode::RuntimeError.as_i32();
                }
            }
        }
        SandboxExecution::Supervised(data) => {
            let SupervisedData {
                caps,
                engine: sup_engine,
                context,
                never_grant,
            } = *data;
            let mut env_overrides = HashMap::new();
            env_overrides.insert("HUSH_SESSION_ID".to_string(), session_id.clone());
            if let Some(ref proxy_url) = env_proxy_url {
                env_overrides.insert("HTTPS_PROXY".to_string(), proxy_url.clone());
                env_overrides.insert("ALL_PROXY".to_string(), proxy_url.clone());
            }
            let _ = writeln!(stderr, "Running (supervised): {}", command.join(" "));
            match crate::supervised_exec::spawn_supervised_child(
                &caps,
                &command,
                &env_overrides,
                sup_engine,
                context,
                never_grant,
            ) {
                Ok(result) => {
                    let mut attestation = clawdstrike::sandbox::build_attestation(
                        &caps,
                        clawdstrike::sandbox::SandboxRuntimeState::supervised_mode(
                            result.sandbox_applied,
                            result.supervised_active,
                            result.sandbox_error.clone(),
                        ),
                    );
                    if result.supervised_active {
                        attestation.supervisor = Some(result.stats.clone());
                    }
                    if !result.denials.is_empty() {
                        attestation.denials = result.denials.clone();
                    }
                    let _ = writeln!(
                        stderr,
                        "[nono] supervisor stats: {} requests ({} granted, {} denied, {} never-grant)",
                        result.stats.requests_total,
                        result.stats.requests_granted,
                        result.stats.requests_denied,
                        result.stats.never_grant_blocks,
                    );
                    SandboxRunResult {
                        child_status: exit_status_from_code(result.exit_code),
                        sandbox_attestation_json: serde_json::to_value(&attestation).ok(),
                        sandbox_failure: result.sandbox_error,
                    }
                }
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {}", e);
                    if let Some(h) = proxy_handle {
                        h.abort();
                    }
                    drop(event_emitter);
                    await_event_writer(writer_handle, stderr).await;
                    return ExitCode::RuntimeError.as_i32();
                }
            }
        }
        SandboxExecution::Legacy(wrapper) => {
            match spawn_and_wait_child(
                &command,
                wrapper,
                env_proxy_url.as_deref(),
                &session_id,
                stderr,
            )
            .await
            {
                Ok(status) => SandboxRunResult {
                    child_status: status,
                    sandbox_attestation_json: None,
                    sandbox_failure: None,
                },
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {}", e);
                    if let Some(h) = proxy_handle {
                        h.abort();
                    }
                    drop(event_emitter);
                    await_event_writer(writer_handle, stderr).await;
                    return ExitCode::RuntimeError.as_i32();
                }
            }
        }
        SandboxExecution::None => {
            match spawn_and_wait_child(
                &command,
                SandboxWrapper::None,
                env_proxy_url.as_deref(),
                &session_id,
                stderr,
            )
            .await
            {
                Ok(status) => SandboxRunResult {
                    child_status: status,
                    sandbox_attestation_json: None,
                    sandbox_failure: None,
                },
                Err(e) => {
                    let _ = writeln!(stderr, "Error: {}", e);
                    if let Some(h) = proxy_handle {
                        h.abort();
                    }
                    drop(event_emitter);
                    await_event_writer(writer_handle, stderr).await;
                    return ExitCode::RuntimeError.as_i32();
                }
            }
        }
    };

    let SandboxRunResult {
        child_status,
        sandbox_attestation_json,
        sandbox_failure,
    } = sandbox_run;

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
    await_event_writer(writer_handle, stderr).await;
    if dropped_events > 0 {
        let _ = writeln!(
            stderr,
            "Warning: dropped {} policy events because the event queue is full (capacity={})",
            dropped_events, event_queue_capacity
        );
    }
    if rejected_proxy_connections > 0 {
        let _ = writeln!(
            stderr,
            "Warning: rejected {} proxy connections due to in-flight limit ({})",
            rejected_proxy_connections, proxy_max_in_flight_connections
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
                    "sandbox_failure": sandbox_failure.clone(),
                    "child_exit_code": child_exit_code,
                    "policy_exit_code": outcome.exit_code(),
                }
            })),
        Err(e) => {
            let _ = writeln!(stderr, "Error: failed to create receipt: {}", e);
            return ExitCode::RuntimeError.as_i32();
        }
    };

    // Merge sandbox attestation into receipt metadata
    let receipt = if let Some(sandbox_json) = sandbox_attestation_json {
        receipt.merge_metadata(serde_json::json!({ "sandbox": sandbox_json }))
    } else {
        receipt
    };

    let receipt_verdict = if sandbox_failure.is_some() {
        Verdict::fail()
    } else {
        outcome.verdict()
    };
    let receipt = Receipt {
        verdict: receipt_verdict,
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

    let events_abs = absolutize_output_path(Path::new(&events_out));
    let receipt_abs = absolutize_output_path(&receipt_path);
    let _ = writeln!(stdout, "Session: {}", session_id);
    let _ = writeln!(stdout, "Events: {}", events_abs.display());
    let _ = writeln!(stdout, "Receipt: {}", receipt_abs.display());
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

fn exit_status_from_code(code: i32) -> std::process::ExitStatus {
    std::process::ExitStatus::from_raw(code << 8)
}

async fn await_event_writer(
    writer_handle: tokio::task::JoinHandle<Result<(), anyhow::Error>>,
    stderr: &mut dyn Write,
) {
    match writer_handle.await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            let _ = writeln!(stderr, "Warning: failed to write events log: {}", e);
        }
        Err(e) => {
            let _ = writeln!(stderr, "Warning: event writer task failed: {}", e);
        }
    }
}

fn default_run_artifact_paths(
    session_id: &str,
    events_out: Option<&str>,
    receipt_out: Option<&str>,
) -> (String, String) {
    let events = events_out
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| format!("clawdstrike.events.{session_id}.jsonl"));
    let receipt = receipt_out
        .map(std::string::ToString::to_string)
        .unwrap_or_else(|| format!("clawdstrike.run.receipt.{session_id}.json"));
    (events, receipt)
}

fn absolutize_output_path(path: &Path) -> PathBuf {
    if path.is_absolute() {
        return path.to_path_buf();
    }
    match std::env::current_dir() {
        Ok(cwd) => cwd.join(path),
        Err(_) => path.to_path_buf(),
    }
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

/// Data for supervised nono execution, boxed to keep enum variant sizes balanced.
struct SupervisedData {
    caps: Box<nono::CapabilitySet>,
    engine: Arc<HushEngine>,
    context: GuardContext,
    never_grant: nono::NeverGrantChecker,
}

struct SandboxRunResult {
    child_status: std::process::ExitStatus,
    sandbox_attestation_json: Option<serde_json::Value>,
    sandbox_failure: Option<String>,
}

/// Execution mode for the child process sandbox.
enum SandboxExecution {
    /// Nono kernel-level sandbox
    Nono {
        caps: Box<nono::CapabilitySet>,
        #[allow(dead_code)] // reserved for Phase 2 diagnostics
        working_dir: PathBuf,
    },
    /// Nono kernel-level sandbox with supervisor dynamic enforcement
    Supervised(Box<SupervisedData>),
    /// Legacy sandbox-exec/bwrap wrapper
    Legacy(SandboxWrapper),
    /// No sandboxing
    None,
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
    allow_private_ips: bool,
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
                    allow_private_ips,
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
    allow_private_ips: bool,
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
    let pinned_target = if let Some(ip) = connect_ip {
        PinnedConnectTarget::for_ip(ip, connect_port)
    } else {
        match resolve_connect_hostname_target(&connect_host, connect_port, allow_private_ips).await
        {
            Ok(target) => {
                let resolution_result = GuardResult::allow("connect_proxy_resolution").with_details(
                    serde_json::json!({
                        "host": connect_host.clone(),
                        "port": connect_port,
                        "allow_private_ips": allow_private_ips,
                        "resolved_ips": target.resolved_ips.iter().map(IpAddr::to_string).collect::<Vec<_>>(),
                        "pinned_ip": target.selected_addr.ip().to_string(),
                    }),
                );
                outcome.observe_guard_result(&resolution_result);
                event_emitter.emit(network_event(
                    &context,
                    connect_host.clone(),
                    connect_port,
                    &resolution_result,
                ));
                target
            }
            Err(result) => {
                outcome.observe_guard_result(&result);
                event_emitter.emit(network_event(
                    &context,
                    connect_host.clone(),
                    connect_port,
                    &result,
                ));
                client.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await?;
                return Ok(());
            }
        }
    };
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

    // Connect to one of the policy-approved, pinned resolution candidates.
    let mut upstream = connect_to_pinned_target(&pinned_target).await?;

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

#[derive(Clone, Debug)]
struct PinnedConnectTarget {
    selected_addr: SocketAddr,
    candidate_addrs: Vec<SocketAddr>,
    resolved_ips: Vec<IpAddr>,
}

impl PinnedConnectTarget {
    fn for_ip(ip: IpAddr, port: u16) -> Self {
        let selected_addr = SocketAddr::new(ip, port);
        Self {
            selected_addr,
            candidate_addrs: vec![selected_addr],
            resolved_ips: vec![ip],
        }
    }
}

async fn resolve_connect_hostname_target(
    host: &str,
    port: u16,
    allow_private_ips: bool,
) -> Result<PinnedConnectTarget, GuardResult> {
    resolve_connect_hostname_target_with_resolver(
        host,
        port,
        allow_private_ips,
        |hostname, port| async move { resolve_socket_addrs(&hostname, port).await },
    )
    .await
}

async fn resolve_connect_hostname_target_with_resolver<R, Fut>(
    host: &str,
    port: u16,
    allow_private_ips: bool,
    mut resolver: R,
) -> Result<PinnedConnectTarget, GuardResult>
where
    R: FnMut(String, u16) -> Fut,
    Fut: Future<Output = anyhow::Result<Vec<SocketAddr>>>,
{
    let resolved_addrs = match resolver(host.to_string(), port).await {
        Ok(addrs) => addrs,
        Err(err) => {
            return Err(connect_resolution_block_result(
                host,
                port,
                format!("CONNECT target DNS resolution failed: {}", err),
                Vec::new(),
                allow_private_ips,
            ));
        }
    };

    if resolved_addrs.is_empty() {
        return Err(connect_resolution_block_result(
            host,
            port,
            "CONNECT target DNS resolution returned no addresses",
            Vec::new(),
            allow_private_ips,
        ));
    }

    let resolved_ips = collect_unique_ips(&resolved_addrs);
    let candidate_addrs: Vec<SocketAddr> = resolved_addrs
        .into_iter()
        .filter(|addr| allow_private_ips || is_public_ip(addr.ip()))
        .collect();

    let Some(selected_addr) = candidate_addrs.first().copied() else {
        return Err(connect_resolution_block_result(
            host,
            port,
            "CONNECT target resolved only to non-public IP addresses",
            resolved_ips,
            allow_private_ips,
        ));
    };

    Ok(PinnedConnectTarget {
        selected_addr,
        candidate_addrs,
        resolved_ips,
    })
}

async fn connect_to_pinned_target(target: &PinnedConnectTarget) -> anyhow::Result<TcpStream> {
    let mut errors = Vec::new();
    for addr in &target.candidate_addrs {
        match TcpStream::connect(*addr).await {
            Ok(stream) => return Ok(stream),
            Err(err) => errors.push(format!("{addr}: {err}")),
        }
    }

    let attempted = target
        .candidate_addrs
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "connect upstream failed for pinned candidates [{}] (attempted: [{}])",
        errors.join("; "),
        attempted
    )
}

fn connect_resolution_block_result(
    host: &str,
    port: u16,
    message: impl Into<String>,
    resolved_ips: Vec<IpAddr>,
    allow_private_ips: bool,
) -> GuardResult {
    GuardResult::block("connect_proxy_resolution", Severity::Error, message).with_details(
        serde_json::json!({
            "host": host,
            "port": port,
            "allow_private_ips": allow_private_ips,
            "resolved_ips": resolved_ips.into_iter().map(|ip| ip.to_string()).collect::<Vec<_>>(),
        }),
    )
}

fn collect_unique_ips(addrs: &[SocketAddr]) -> Vec<IpAddr> {
    let mut ips = Vec::new();
    for addr in addrs {
        let ip = addr.ip();
        if !ips.contains(&ip) {
            ips.push(ip);
        }
    }
    ips
}

async fn resolve_socket_addrs(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddr>> {
    if let Some(hook_result) = resolve_socket_addrs_from_test_hook(host, port) {
        return hook_result;
    }

    let lookup = tokio::time::timeout(proxy_dns_resolve_timeout(), lookup_host((host, port))).await;
    match lookup {
        Ok(Ok(addrs)) => Ok(addrs.into_iter().collect()),
        Ok(Err(err)) => Err(err).with_context(|| format!("lookup host {}:{}", host, port)),
        Err(_) => anyhow::bail!("lookup host {}:{} timed out", host, port),
    }
}

fn resolve_socket_addrs_from_test_hook(
    host: &str,
    port: u16,
) -> Option<anyhow::Result<Vec<SocketAddr>>> {
    let raw = std::env::var("HUSH_TEST_RESOLVER_SEQUENCE").ok()?;
    let host_lc = host.to_ascii_lowercase();
    let key_with_port = format!("{}:{}", host_lc, port);

    for entry in raw.split(';').map(str::trim).filter(|e| !e.is_empty()) {
        let (target, stages) = match entry.split_once('=') {
            Some(parts) => parts,
            None => {
                return Some(Err(anyhow::anyhow!(
                    "invalid HUSH_TEST_RESOLVER_SEQUENCE entry: {}",
                    entry
                )));
            }
        };

        let target_lc = target.trim().to_ascii_lowercase();
        if target_lc != host_lc && target_lc != key_with_port {
            continue;
        }

        let stage_list: Vec<&str> = stages
            .split('|')
            .map(str::trim)
            .filter(|stage| !stage.is_empty())
            .collect();
        if stage_list.is_empty() {
            return Some(Err(anyhow::anyhow!(
                "empty resolver stage list in HUSH_TEST_RESOLVER_SEQUENCE for {}",
                target
            )));
        }

        let calls = TEST_RESOLVER_CALLS.get_or_init(|| Mutex::new(HashMap::new()));
        let stage_idx = {
            let mut guard = match calls.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let idx = guard.entry(key_with_port.clone()).or_insert(0);
            let out = *idx;
            *idx = idx.saturating_add(1);
            out
        };

        let selected_stage = stage_list
            .get(stage_idx)
            .copied()
            .or_else(|| stage_list.last().copied())
            .unwrap_or("");

        let mut addrs = Vec::new();
        for item in selected_stage
            .split(',')
            .map(str::trim)
            .filter(|it| !it.is_empty())
        {
            if let Ok(addr) = item.parse::<SocketAddr>() {
                addrs.push(addr);
                continue;
            }
            if let Ok(ip) = item.parse::<IpAddr>() {
                addrs.push(SocketAddr::new(ip, port));
                continue;
            }
            return Some(Err(anyhow::anyhow!(
                "invalid resolver address '{}' in HUSH_TEST_RESOLVER_SEQUENCE",
                item
            )));
        }

        if addrs.is_empty() {
            return Some(Err(anyhow::anyhow!(
                "resolver stage for {} produced no addresses",
                target
            )));
        }

        return Some(Ok(addrs));
    }

    None
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4.octets()),
        IpAddr::V6(v6) => is_public_ipv6(v6),
    }
}

fn is_public_ipv4(octets: [u8; 4]) -> bool {
    let [a, b, c, d] = octets;

    // 0.0.0.0/8 (this host / "current network")
    if a == 0 {
        return false;
    }
    // 10.0.0.0/8
    if a == 10 {
        return false;
    }
    // 100.64.0.0/10 (shared address space / CGNAT)
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    // 127.0.0.0/8 (loopback)
    if a == 127 {
        return false;
    }
    // 169.254.0.0/16 (link-local)
    if a == 169 && b == 254 {
        return false;
    }
    // 172.16.0.0/12
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    // 192.0.0.0/24 (IETF protocol assignments), except 192.0.0.9/32 and 192.0.0.10/32.
    if a == 192 && b == 0 && c == 0 && d != 9 && d != 10 {
        return false;
    }
    // 192.0.2.0/24 (TEST-NET-1)
    if a == 192 && b == 0 && c == 2 {
        return false;
    }
    // 192.88.99.0/24 (deprecated 6to4 relay anycast)
    if a == 192 && b == 88 && c == 99 {
        return false;
    }
    // 192.168.0.0/16
    if a == 192 && b == 168 {
        return false;
    }
    // 198.18.0.0/15 (benchmarking)
    if a == 198 && (18..=19).contains(&b) {
        return false;
    }
    // 198.51.100.0/24 (TEST-NET-2)
    if a == 198 && b == 51 && c == 100 {
        return false;
    }
    // 203.0.113.0/24 (TEST-NET-3)
    if a == 203 && b == 0 && c == 113 {
        return false;
    }
    // 224.0.0.0/4 (multicast) and 240.0.0.0/4 (reserved)
    if a >= 224 {
        return false;
    }
    // 255.255.255.255 (limited broadcast)
    if a == 255 && b == 255 && c == 255 && d == 255 {
        return false;
    }
    true
}

fn is_public_ipv6(addr: Ipv6Addr) -> bool {
    if let Some(v4) = addr.to_ipv4() {
        return is_public_ipv4(v4.octets());
    }

    let segments = addr.segments();
    let [s0, s1, s2, s3, _s4, _s5, _s6, _s7] = segments;

    // ::/128 (unspecified)
    if segments == [0, 0, 0, 0, 0, 0, 0, 0] {
        return false;
    }
    // ::1/128 (loopback)
    if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
        return false;
    }
    // fc00::/7 (unique local)
    if (s0 & 0xfe00) == 0xfc00 {
        return false;
    }
    // fe80::/10 (link-local unicast)
    if (s0 & 0xffc0) == 0xfe80 {
        return false;
    }
    // ff00::/8 (multicast)
    if (s0 & 0xff00) == 0xff00 {
        return false;
    }
    // 2001:db8::/32 (documentation)
    if s0 == 0x2001 && s1 == 0x0db8 {
        return false;
    }
    // 100::/64 (discard-only)
    if s0 == 0x0100 && s1 == 0 && s2 == 0 && s3 == 0 {
        return false;
    }
    true
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
                "details": result.details.clone(),
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

    #[test]
    fn absolutize_output_path_resolves_relative_paths() {
        let rel = Path::new("clawdstrike.run.receipt.json");
        let abs = absolutize_output_path(rel);
        assert!(abs.is_absolute());
        assert!(abs.ends_with(rel));
    }

    #[test]
    fn default_run_artifact_paths_use_session_id_when_unspecified() {
        let session_id = "sess-123";
        let (events, receipt) = default_run_artifact_paths(session_id, None, None);
        assert_eq!(events, "clawdstrike.events.sess-123.jsonl");
        assert_eq!(receipt, "clawdstrike.run.receipt.sess-123.json");
    }

    #[test]
    fn default_run_artifact_paths_preserve_explicit_values() {
        let (events, receipt) = default_run_artifact_paths(
            "sess-123",
            Some("/tmp/custom.events.jsonl"),
            Some("/tmp/custom.receipt.json"),
        );
        assert_eq!(events, "/tmp/custom.events.jsonl");
        assert_eq!(receipt, "/tmp/custom.receipt.json");
    }

    #[tokio::test]
    async fn cmd_run_spawn_failure_does_not_hang_with_proxy_enabled() {
        let temp = tempfile::tempdir().expect("tempdir");
        let policy_path = temp.path().join("policy.yaml");
        std::fs::write(
            &policy_path,
            "version: \"1.1.0\"\nname: \"spawn-failure\"\n",
        )
        .expect("write policy");

        let args = RunArgs {
            policy: policy_path.display().to_string(),
            events_out: Some(temp.path().join("events.jsonl").display().to_string()),
            receipt_out: Some(temp.path().join("receipt.json").display().to_string()),
            signing_key: temp.path().join("clawdstrike.key").display().to_string(),
            no_proxy: false,
            proxy_port: 0,
            proxy_allow_private_ips: false,
            sandbox: SandboxMode::None,
            hushd_url: None,
            hushd_token: None,
            supervised: false,
            command: vec!["echo ~/.ssh".to_string()],
        };

        let remote = crate::remote_extends::RemoteExtendsConfig::disabled();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        let code = tokio::time::timeout(
            Duration::from_secs(5),
            cmd_run(args, &remote, &mut stdout, &mut stderr),
        )
        .await
        .expect("cmd_run should return even when command spawn fails");

        assert_eq!(code, ExitCode::RuntimeError.as_i32());
        let stderr_text = String::from_utf8_lossy(&stderr);
        assert!(
            stderr_text.contains("Proxy listening on"),
            "test requires proxy startup; stderr was:\n{}",
            stderr_text
        );
        assert!(
            stderr_text.contains("Error: spawn child process"),
            "expected spawn failure in stderr; stderr was:\n{}",
            stderr_text
        );
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
            false,
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
            false,
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
    async fn connect_proxy_hostname_target_is_ip_pinned_after_policy_check() {
        let check_phase_addr = SocketAddr::from(([93, 184, 216, 34], 443));
        let dial_phase_addr = SocketAddr::from(([1, 1, 1, 1], 443));
        let resolver_calls = Arc::new(AtomicUsize::new(0));
        let resolver_calls_for_resolver = resolver_calls.clone();

        let pinned = resolve_connect_hostname_target_with_resolver(
            "example.com",
            443,
            true,
            move |_host, _port| {
                let resolver_calls = resolver_calls_for_resolver.clone();
                async move {
                    let call_idx = resolver_calls.fetch_add(1, Ordering::Relaxed);
                    if call_idx == 0 {
                        Ok(vec![check_phase_addr])
                    } else {
                        Ok(vec![dial_phase_addr])
                    }
                }
            },
        )
        .await
        .expect("resolve and pin CONNECT hostname target");

        assert_eq!(
            resolver_calls.load(Ordering::Relaxed),
            1,
            "CONNECT hostname resolution must happen exactly once before dialing"
        );
        assert_eq!(
            pinned.selected_addr, check_phase_addr,
            "dial target must stay pinned to check-phase resolution"
        );
        assert_ne!(
            pinned.selected_addr, dial_phase_addr,
            "dial target must not switch to a rebind address"
        );
        assert_eq!(
            pinned.candidate_addrs,
            vec![check_phase_addr],
            "pinned candidate set must remain tied to check-phase resolution"
        );
    }

    #[tokio::test]
    async fn connect_proxy_hostname_target_retries_within_pinned_candidate_set() {
        let dead_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind dead listener");
        let dead_addr = dead_listener.local_addr().expect("dead listener addr");
        drop(dead_listener);

        let live_listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind live listener");
        let live_addr = live_listener.local_addr().expect("live listener addr");
        let accept_task = tokio::spawn(async move { live_listener.accept().await });

        let target = PinnedConnectTarget {
            selected_addr: dead_addr,
            candidate_addrs: vec![dead_addr, live_addr],
            resolved_ips: vec![dead_addr.ip(), live_addr.ip()],
        };

        let stream = connect_to_pinned_target(&target)
            .await
            .expect("should connect to healthy pinned candidate");
        drop(stream);

        let accepted = tokio::time::timeout(Duration::from_secs(1), accept_task)
            .await
            .expect("accept timeout")
            .expect("accept join")
            .expect("accept connection");
        assert_eq!(accepted.1.ip(), IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    #[tokio::test]
    async fn connect_proxy_hostname_target_rejects_non_public_resolution_when_private_disallowed() {
        let result = resolve_connect_hostname_target_with_resolver(
            "example.com",
            443,
            false,
            |_host, _port| async { Ok(vec![SocketAddr::from(([127, 0, 0, 1], 443))]) },
        )
        .await;

        let denied = result.expect_err("non-public resolution should be denied");
        assert!(
            !denied.allowed,
            "hostname targets resolving only to non-public IPs must be blocked"
        );
        assert!(
            denied.message.contains("non-public"),
            "deny reason should mention non-public IP policy: {}",
            denied.message
        );
    }

    #[test]
    fn is_public_ipv4_classifies_ietf_special_use_ranges() {
        assert!(!is_public_ipv4([192, 0, 0, 1]));
        assert!(
            is_public_ipv4([192, 0, 0, 9]),
            "192.0.0.9 is a global anycast exception in 192.0.0.0/24"
        );
        assert!(!is_public_ipv4([198, 51, 100, 42]));
        assert!(is_public_ipv4([8, 8, 8, 8]));
    }

    #[tokio::test]
    async fn connect_proxy_hostname_target_rejects_192_0_0_1_when_private_disallowed() {
        let result = resolve_connect_hostname_target_with_resolver(
            "example.com",
            443,
            false,
            |_host, _port| async { Ok(vec![SocketAddr::from(([192, 0, 0, 1], 443))]) },
        )
        .await;

        let denied = result.expect_err("192.0.0.1 must be treated as non-public");
        assert!(
            !denied.allowed,
            "hostname targets resolving to 192.0.0.1 must be blocked when private IPs are disallowed"
        );
        assert!(
            denied.message.contains("non-public"),
            "deny reason should mention non-public IP policy: {}",
            denied.message
        );
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
            false,
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
