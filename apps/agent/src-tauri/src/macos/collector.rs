use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use tauri::path::BaseDirectory;
use tauri::{AppHandle, Manager, Runtime};
use tokio::process::Command;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};

use super::host::{
    MacosHostRefreshRequest, MacosHostService, MacosNetworkExtensionReloadError,
    MacosNetworkExtensionReloadRequest, MacosNetworkExtensionReloadResult,
};
use super::status::{
    CombinedSystemExtensionStatus, EvidenceArtifact, MdmProfileState, ProviderAttestationState,
    ProviderAvailability, ProviderReloadObservation, ProviderRuntimeState, ProviderStatus,
    SystemExtensionActivationState, SystemExtensionApproval, SystemExtensionInstallState,
};

const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(60);
const STATUS_TOOL_TIMEOUT: Duration = Duration::from_secs(10);
const RUNTIME_SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(120);
const ENDPOINT_SECURITY_TOOL_ENV: &str = "CLAWDSTRIKE_ENDPOINT_SECURITY_STATUS_TOOL";
const ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_ENV: &str =
    "CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH";
const NETWORK_EXTENSION_TOOL_ENV: &str = "CLAWDSTRIKE_NETWORK_EXTENSION_STATUS_TOOL";
const NETWORK_EXTENSION_EGRESS_POLICY_ENV: &str =
    "CLAWDSTRIKE_NETWORK_EXTENSION_EGRESS_POLICY_PATH";
const NETWORK_EXTENSION_RUNTIME_SNAPSHOT_ENV: &str =
    "CLAWDSTRIKE_NETWORK_EXTENSION_RUNTIME_SNAPSHOT_PATH";
const ALLOW_SWIFT_RUN_STATUS_TOOLS_ENV: &str = "CLAWDSTRIKE_ALLOW_SWIFT_RUN_STATUS_TOOLS";
const ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV: &str =
    "CLAWDSTRIKE_ALLOW_DIRECT_STATUS_TOOL_OVERRIDES";
const ENDPOINT_SECURITY_TOOL_NAME: &str = "endpoint-security-status-tool";
const NETWORK_EXTENSION_TOOL_NAME: &str = "network-extension-status-tool";
const STATUS_TOOL_ENV_ALLOWLIST: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "TEMP",
    "TMP",
    "DEVELOPER_DIR",
    "SDKROOT",
    "TOOLCHAINS",
    "XCODE_DEVELOPER_DIR_PATH",
];

#[derive(Debug, Clone)]
enum ToolInvocation {
    Direct {
        program: PathBuf,
        args: Vec<OsString>,
    },
    SwiftRun {
        package_path: PathBuf,
        executable: &'static str,
    },
}

impl ToolInvocation {
    fn command(&self) -> Command {
        match self {
            Self::Direct { args, .. } => self.command_with_args(args),
            Self::SwiftRun { .. } => self.command_with_args(&[OsString::from("live")]),
        }
    }

    fn command_with_args(&self, args: &[OsString]) -> Command {
        match self {
            Self::Direct { program, .. } => {
                let mut command = Command::new(program);
                command.args(args);
                command
            }
            Self::SwiftRun {
                package_path,
                executable,
            } => {
                let mut command = Command::new("swift");
                command
                    .arg("run")
                    .arg("--package-path")
                    .arg(package_path)
                    .arg(executable)
                    .args(args);
                command
            }
        }
    }

    fn display_name(&self) -> String {
        match self {
            Self::Direct { args, .. } => self.display_name_with_args(args),
            Self::SwiftRun { .. } => self.display_name_with_args(&[OsString::from("live")]),
        }
    }

    fn display_name_with_args(&self, args: &[OsString]) -> String {
        let rendered_args = args
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join(" ");
        match self {
            Self::Direct { program, .. } => {
                if rendered_args.is_empty() {
                    program.display().to_string()
                } else {
                    format!("{} {rendered_args}", program.display())
                }
            }
            Self::SwiftRun {
                package_path,
                executable,
            } => format!(
                "swift run --package-path {} {}{}{}",
                package_path.display(),
                executable,
                if rendered_args.is_empty() { "" } else { " " },
                rendered_args
            ),
        }
    }
}

#[derive(Debug, Deserialize)]
struct EndpointSecurityStatusSample {
    host_status: EndpointSecurityHostStatus,
    #[serde(default)]
    provider_state: Option<ProviderAttestationState>,
    #[serde(default)]
    counters: BTreeMap<String, u64>,
    #[serde(default)]
    evidence_paths: Vec<EvidenceArtifact>,
    #[serde(default)]
    policy_epoch: Option<u64>,
    #[serde(default)]
    last_error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct EndpointSecurityHostStatus {
    install_state: SystemExtensionInstallState,
    approval: SystemExtensionApproval,
    endpoint_security: ProviderStatus,
}

#[derive(Debug, Deserialize)]
struct NetworkExtensionStatusSample {
    install_state: SystemExtensionInstallState,
    approval: SystemExtensionApproval,
    host_status: ProviderStatus,
    #[serde(default, rename = "attestation_state")]
    provider_state: Option<ProviderAttestationState>,
    #[serde(default)]
    counters: BTreeMap<String, u64>,
    #[serde(default)]
    evidence_paths: Vec<EvidenceArtifact>,
    #[serde(default)]
    policy_epoch: Option<u64>,
    #[serde(default)]
    policy_synced: Option<bool>,
    #[serde(default)]
    enforcement_ready: Option<bool>,
    #[serde(default)]
    last_error: Option<String>,
    #[serde(default)]
    last_reload_observation: Option<ProviderReloadObservation>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NetworkExtensionReloadToolResponse {
    request_id: String,
    command: String,
    policy_snapshot_path: String,
    generation: u64,
    saved: bool,
}

struct ProviderStatusEnrichment {
    provider_state: Option<ProviderAttestationState>,
    counters: BTreeMap<String, u64>,
    evidence_paths: Vec<EvidenceArtifact>,
    policy_epoch: Option<u64>,
    policy_synced: Option<bool>,
    enforcement_ready: Option<bool>,
    last_error: Option<String>,
    last_reload_observation: Option<ProviderReloadObservation>,
}

pub fn start_status_collector<R: Runtime + 'static>(
    app: AppHandle<R>,
    macos_host: Arc<MacosHostService>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let endpoint_tool = resolve_status_tool(
        &app,
        ENDPOINT_SECURITY_TOOL_ENV,
        "macos/system-extension/endpoint-security",
        ENDPOINT_SECURITY_TOOL_NAME,
    );
    let network_tool = resolve_status_tool(
        &app,
        NETWORK_EXTENSION_TOOL_ENV,
        "macos/system-extension/network-extension",
        NETWORK_EXTENSION_TOOL_NAME,
    );

    if endpoint_tool.is_none() {
        tracing::warn!(
            "macOS endpoint-security status helper is unavailable; host health will remain unknown until the helper can be executed"
        );
    }
    if network_tool.is_none() {
        tracing::warn!(
            "macOS network-extension status helper is unavailable; host health will remain unknown until the helper can be executed"
        );
    }

    let (refresh_tx, mut refresh_rx) = mpsc::channel::<super::host::MacosHostRefreshRequest>(4);
    let (network_reload_tx, mut network_reload_rx) =
        mpsc::channel::<super::host::MacosNetworkExtensionReloadRequest>(4);
    tokio::spawn(async move {
        macos_host.reset_unknown_state().await;
        macos_host.install_refresh_channel(refresh_tx).await;
        macos_host
            .install_network_extension_reload_channel(network_reload_tx)
            .await;

        let (status_tx, mut status_rx) = mpsc::channel::<(u64, CombinedSystemExtensionStatus)>(1);
        let mut next_poll = Box::pin(tokio::time::sleep(Duration::ZERO));
        let mut status_poll_generation = 0_u64;
        let mut active_status_probe_generation = None;
        let mut active_status_probe: Option<JoinHandle<()>> = None;
        let mut pending_refresh_replies = Vec::<MacosHostRefreshRequest>::new();
        let mut active_reload_requests = Vec::<JoinHandle<()>>::new();

        loop {
            tokio::select! {
                biased;

                _ = shutdown.recv() => break,
                request = network_reload_rx.recv() => {
                    abort_status_probe(
                        &mut active_status_probe,
                        &mut active_status_probe_generation,
                        &mut status_rx,
                    );
                    let Some(request) = request else {
                        break;
                    };
                    active_reload_requests.retain(|handle| !handle.is_finished());
                    active_reload_requests.push(spawn_network_extension_reload(
                        network_tool.clone(),
                        request,
                    ));
                    retain_open_refresh_replies(&mut pending_refresh_replies);
                    if !pending_refresh_replies.is_empty() {
                        status_poll_generation = status_poll_generation.wrapping_add(1);
                        active_status_probe_generation = Some(status_poll_generation);
                        active_status_probe = Some(spawn_status_probe(
                            endpoint_tool.clone(),
                            network_tool.clone(),
                            status_tx.clone(),
                            status_poll_generation,
                        ));
                    }
                    next_poll.as_mut().reset(Instant::now() + STATUS_POLL_INTERVAL);
                }
                request = refresh_rx.recv() => {
                    let Some(reply_tx) = request else {
                        break;
                    };
                    retain_open_refresh_replies(&mut pending_refresh_replies);
                    pending_refresh_replies.push(reply_tx);
                    if active_status_probe_generation.is_none() {
                        status_poll_generation = status_poll_generation.wrapping_add(1);
                        active_status_probe_generation = Some(status_poll_generation);
                        active_status_probe = Some(spawn_status_probe(
                            endpoint_tool.clone(),
                            network_tool.clone(),
                            status_tx.clone(),
                            status_poll_generation,
                        ));
                    }
                }
                Some((generation, combined)) = status_rx.recv() => {
                    if active_status_probe_generation == Some(generation) {
                        let refresh_reply = combined.clone();
                        macos_host.replace_status(combined).await;
                        reply_to_pending_refreshes(&mut pending_refresh_replies, refresh_reply);
                        active_status_probe_generation = None;
                        active_status_probe = None;
                        next_poll.as_mut().reset(Instant::now() + STATUS_POLL_INTERVAL);
                    }
                }
                _ = &mut next_poll, if active_status_probe_generation.is_none() => {
                    status_poll_generation = status_poll_generation.wrapping_add(1);
                    active_status_probe_generation = Some(status_poll_generation);
                    active_status_probe = Some(spawn_status_probe(
                        endpoint_tool.clone(),
                        network_tool.clone(),
                        status_tx.clone(),
                        status_poll_generation,
                    ));
                }
            }
        }
        if let Some(handle) = active_status_probe {
            handle.abort();
        }
        for handle in active_reload_requests {
            handle.abort();
        }
    });
}

fn spawn_status_probe(
    endpoint_tool: Option<ToolInvocation>,
    network_tool: Option<ToolInvocation>,
    status_tx: mpsc::Sender<(u64, CombinedSystemExtensionStatus)>,
    generation: u64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let combined = collect_combined_status(endpoint_tool.as_ref(), network_tool.as_ref()).await;
        let _ = status_tx.send((generation, combined)).await;
    })
}

fn spawn_network_extension_reload(
    network_tool: Option<ToolInvocation>,
    request: MacosNetworkExtensionReloadRequest,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let result = request_network_extension_reload(
            network_tool.as_ref(),
            &request.policy_snapshot_path,
            request.generation,
            request.timeout_duration,
        )
        .await;
        let _ = request.reply_tx.send(result);
    })
}

fn abort_status_probe(
    active_status_probe: &mut Option<JoinHandle<()>>,
    active_status_probe_generation: &mut Option<u64>,
    status_rx: &mut mpsc::Receiver<(u64, CombinedSystemExtensionStatus)>,
) {
    if let Some(handle) = active_status_probe.take() {
        handle.abort();
    }
    *active_status_probe_generation = None;
    while status_rx.try_recv().is_ok() {}
}

fn reply_to_pending_refreshes(
    pending_refresh_replies: &mut Vec<MacosHostRefreshRequest>,
    combined: CombinedSystemExtensionStatus,
) {
    for reply_tx in pending_refresh_replies.drain(..) {
        let _ = reply_tx.send(combined.clone());
    }
}

fn retain_open_refresh_replies(refresh_replies: &mut Vec<MacosHostRefreshRequest>) {
    refresh_replies.retain(|reply_tx| !reply_tx.is_closed());
}

async fn collect_combined_status(
    endpoint_tool: Option<&ToolInvocation>,
    network_tool: Option<&ToolInvocation>,
) -> CombinedSystemExtensionStatus {
    let endpoint_sample = match endpoint_tool {
        Some(tool) => run_json_tool::<EndpointSecurityStatusSample>(tool).await,
        None => None,
    };
    let network_sample = match network_tool {
        Some(tool) => run_json_tool::<NetworkExtensionStatusSample>(tool).await,
        None => None,
    };
    merge_samples(endpoint_sample, network_sample)
}

async fn run_json_tool<T>(tool: &ToolInvocation) -> Option<T>
where
    T: for<'de> Deserialize<'de>,
{
    match timeout(STATUS_TOOL_TIMEOUT, execute_tool(tool)).await {
        Ok(Ok(stdout)) => match serde_json::from_slice::<T>(&stdout) {
            Ok(sample) => Some(sample),
            Err(error) => {
                tracing::warn!(
                    tool = %tool.display_name(),
                    error = %error,
                    "macOS status helper returned invalid JSON"
                );
                None
            }
        },
        Ok(Err(error)) => {
            tracing::warn!(
                tool = %tool.display_name(),
                error = %error,
                "macOS status helper execution failed"
            );
            None
        }
        Err(_) => {
            tracing::warn!(
                tool = %tool.display_name(),
                timeout_secs = STATUS_TOOL_TIMEOUT.as_secs(),
                "macOS status helper timed out"
            );
            None
        }
    }
}

async fn request_network_extension_reload(
    tool: Option<&ToolInvocation>,
    policy_snapshot_path: &Path,
    generation: u64,
    timeout_duration: Duration,
) -> Result<MacosNetworkExtensionReloadResult, MacosNetworkExtensionReloadError> {
    let tool = tool.ok_or(MacosNetworkExtensionReloadError::Unavailable)?;
    let args = network_extension_reload_args(policy_snapshot_path, generation);
    let stdout = match timeout(timeout_duration, execute_tool_with_args(tool, &args)).await {
        Ok(Ok(stdout)) => stdout,
        Ok(Err(error)) => {
            return Err(MacosNetworkExtensionReloadError::HelperFailed(
                error.to_string(),
            ));
        }
        Err(_) => return Err(MacosNetworkExtensionReloadError::TimedOut),
    };
    parse_network_extension_reload_response(&stdout, policy_snapshot_path, generation)
}

fn network_extension_reload_args(policy_snapshot_path: &Path, generation: u64) -> [OsString; 3] {
    [
        OsString::from("request-reload"),
        policy_snapshot_path.as_os_str().to_os_string(),
        OsString::from(generation.to_string()),
    ]
}

fn parse_network_extension_reload_response(
    stdout: &[u8],
    expected_policy_snapshot_path: &Path,
    expected_generation: u64,
) -> Result<MacosNetworkExtensionReloadResult, MacosNetworkExtensionReloadError> {
    let response = serde_json::from_slice::<NetworkExtensionReloadToolResponse>(stdout)
        .map_err(|error| MacosNetworkExtensionReloadError::InvalidResponse(error.to_string()))?;
    if response.command != "reload_policy" {
        return Err(MacosNetworkExtensionReloadError::InvalidResponse(format!(
            "unexpected command {}",
            response.command
        )));
    }
    if response.generation != expected_generation {
        return Err(MacosNetworkExtensionReloadError::InvalidResponse(format!(
            "generation mismatch: requested {expected_generation}, helper returned {}",
            response.generation
        )));
    }
    let expected_policy_snapshot_path = expected_policy_snapshot_path.display().to_string();
    if response.policy_snapshot_path != expected_policy_snapshot_path {
        return Err(MacosNetworkExtensionReloadError::InvalidResponse(format!(
            "policy snapshot path mismatch: requested {expected_policy_snapshot_path}, helper returned {}",
            response.policy_snapshot_path
        )));
    }

    Ok(MacosNetworkExtensionReloadResult {
        requested: true,
        saved: response.saved,
        request_id: response.request_id,
        policy_snapshot_path: response.policy_snapshot_path,
        generation: response.generation,
    })
}

async fn execute_tool(tool: &ToolInvocation) -> Result<Vec<u8>> {
    let command = tool.command();
    execute_tool_command(command, tool.display_name()).await
}

async fn execute_tool_with_args(tool: &ToolInvocation, args: &[OsString]) -> Result<Vec<u8>> {
    let command = tool.command_with_args(args);
    execute_tool_command(command, tool.display_name_with_args(args)).await
}

async fn execute_tool_command(mut command: Command, display_name: String) -> Result<Vec<u8>> {
    command.kill_on_drop(true);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.env_clear();
    propagate_status_tool_environment(&mut command);
    command.env(
        ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_ENV,
        default_endpoint_security_runtime_snapshot_path(),
    );
    command.env(
        NETWORK_EXTENSION_EGRESS_POLICY_ENV,
        default_network_extension_egress_policy_path(),
    );
    command.env(
        NETWORK_EXTENSION_RUNTIME_SNAPSHOT_ENV,
        default_network_extension_runtime_snapshot_path(),
    );

    let output = command
        .output()
        .await
        .with_context(|| format!("spawn {display_name}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(
            "{} exited with status {}{}",
            display_name,
            output.status,
            if stderr.is_empty() {
                String::new()
            } else {
                format!(": {stderr}")
            }
        ));
    }

    Ok(output.stdout)
}

fn propagate_status_tool_environment(command: &mut Command) {
    for key in STATUS_TOOL_ENV_ALLOWLIST {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

fn merge_samples(
    endpoint_sample: Option<EndpointSecurityStatusSample>,
    network_sample: Option<NetworkExtensionStatusSample>,
) -> CombinedSystemExtensionStatus {
    let install_state = match (endpoint_sample.as_ref(), network_sample.as_ref()) {
        (Some(endpoint_sample), Some(network_sample)) => merge_install_state(
            endpoint_sample.host_status.install_state,
            network_sample.install_state,
        ),
        _ => SystemExtensionInstallState::Unknown,
    };
    let approval = match (endpoint_sample.as_ref(), network_sample.as_ref()) {
        (Some(endpoint_sample), Some(network_sample)) => merge_approval_state(
            endpoint_sample.host_status.approval,
            network_sample.approval,
        ),
        _ => SystemExtensionApproval::Unknown,
    };

    let endpoint_security = endpoint_sample
        .map(endpoint_provider_status)
        .unwrap_or_else(ProviderStatus::unknown);
    let network_extension = network_sample
        .map(network_provider_status)
        .unwrap_or_else(ProviderStatus::unknown);
    let activation_state = derive_activation_state(
        install_state,
        approval,
        &endpoint_security,
        &network_extension,
    );

    CombinedSystemExtensionStatus {
        install_state,
        approval,
        activation_state,
        mdm_profile_state: MdmProfileState::Unknown,
        endpoint_security,
        network_extension,
        ..CombinedSystemExtensionStatus::default()
    }
}

fn endpoint_provider_status(sample: EndpointSecurityStatusSample) -> ProviderStatus {
    let mut status = sample.host_status.endpoint_security;
    enrich_provider_status(
        &mut status,
        ProviderStatusEnrichment {
            provider_state: sample.provider_state,
            counters: sample.counters,
            evidence_paths: sample.evidence_paths,
            policy_epoch: sample.policy_epoch,
            policy_synced: None,
            enforcement_ready: None,
            last_error: sample.last_error,
            last_reload_observation: None,
        },
    );
    downgrade_stale_runtime_snapshot(
        &mut status,
        "endpoint-security",
        &default_endpoint_security_runtime_snapshot_path(),
    );
    status
}

fn network_provider_status(sample: NetworkExtensionStatusSample) -> ProviderStatus {
    let mut status = sample.host_status;
    enrich_provider_status(
        &mut status,
        ProviderStatusEnrichment {
            provider_state: sample.provider_state,
            counters: sample.counters,
            evidence_paths: sample.evidence_paths,
            policy_epoch: sample.policy_epoch,
            policy_synced: sample.policy_synced,
            enforcement_ready: sample.enforcement_ready,
            last_error: sample.last_error,
            last_reload_observation: sample.last_reload_observation,
        },
    );
    downgrade_stale_runtime_snapshot(
        &mut status,
        "network-extension",
        &default_network_extension_runtime_snapshot_path(),
    );
    status
}

fn enrich_provider_status(status: &mut ProviderStatus, enrichment: ProviderStatusEnrichment) {
    if let Some(provider_state) = enrichment.provider_state {
        if status.last_healthy_timestamp.is_none() {
            status.last_healthy_timestamp = provider_state.last_healthy_timestamp.clone();
        }
        status.provider_state = Some(provider_state);
    }
    status.counters = enrichment.counters;
    status.evidence_paths = enrichment.evidence_paths;
    status.policy_epoch = enrichment.policy_epoch;
    status.policy_synced = enrichment.policy_synced;
    status.enforcement_ready = enrichment.enforcement_ready;
    status.last_error = enrichment.last_error;
    status.last_reload_observation = enrichment.last_reload_observation;
}

fn downgrade_stale_runtime_snapshot(status: &mut ProviderStatus, provider: &str, path: &Path) {
    if !matches!(status.runtime, ProviderRuntimeState::Active) || !runtime_snapshot_is_stale(path) {
        return;
    }

    mark_runtime_snapshot_stale(status, provider, path);
}

fn mark_runtime_snapshot_stale(status: &mut ProviderStatus, provider: &str, path: &Path) {
    let reason = "provider_runtime_snapshot_stale";
    status.runtime = ProviderRuntimeState::Degraded {
        reason: reason.to_string(),
    };
    status.last_error = Some(reason.to_string());
    status.evidence_paths.push(EvidenceArtifact {
        kind: "stale_runtime_snapshot".to_string(),
        path: path.display().to_string(),
        detail: format!("{provider} runtime snapshot is older than the freshness window"),
    });
    if let Some(provider_state) = status.provider_state.as_mut() {
        provider_state.active = false;
        provider_state.healthy = false;
        provider_state.availability = ProviderAvailability::Degraded;
        if !provider_state
            .degraded_reasons
            .iter()
            .any(|existing| existing == reason)
        {
            provider_state.degraded_reasons.push(reason.to_string());
        }
    }
}

fn runtime_snapshot_is_stale(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return true;
    };
    let Ok(modified_at) = metadata.modified() else {
        return true;
    };
    match SystemTime::now().duration_since(modified_at) {
        Ok(age) => age > RUNTIME_SNAPSHOT_MAX_AGE,
        Err(_) => true,
    }
}

fn default_endpoint_security_runtime_snapshot_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("endpoint-security-runtime.json")
}

fn default_network_extension_egress_policy_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("network-extension-egress-policy.json")
}

fn default_network_extension_runtime_snapshot_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("network-extension-egress-policy.json.provider-runtime.json")
}

fn derive_activation_state(
    install_state: SystemExtensionInstallState,
    approval: SystemExtensionApproval,
    endpoint_security: &ProviderStatus,
    network_extension: &ProviderStatus,
) -> SystemExtensionActivationState {
    if install_state == SystemExtensionInstallState::Unknown
        || approval == SystemExtensionApproval::Unknown
    {
        return SystemExtensionActivationState::Unknown;
    }
    if install_state == SystemExtensionInstallState::NotInstalled {
        return SystemExtensionActivationState::NotRequested;
    }
    if approval == SystemExtensionApproval::ApprovalBlocked {
        return SystemExtensionActivationState::Failed;
    }
    if matches!(endpoint_security.runtime, ProviderRuntimeState::Active)
        && matches!(network_extension.runtime, ProviderRuntimeState::Active)
    {
        return SystemExtensionActivationState::Active;
    }
    if matches!(
        endpoint_security.runtime,
        ProviderRuntimeState::Unknown | ProviderRuntimeState::Inactive
    ) || matches!(
        network_extension.runtime,
        ProviderRuntimeState::Unknown | ProviderRuntimeState::Inactive
    ) {
        return SystemExtensionActivationState::Pending;
    }
    SystemExtensionActivationState::Failed
}

fn merge_install_state(
    current: SystemExtensionInstallState,
    candidate: SystemExtensionInstallState,
) -> SystemExtensionInstallState {
    match (current, candidate) {
        (SystemExtensionInstallState::NotInstalled, _)
        | (_, SystemExtensionInstallState::NotInstalled) => {
            SystemExtensionInstallState::NotInstalled
        }
        (SystemExtensionInstallState::Installed, SystemExtensionInstallState::Installed) => {
            SystemExtensionInstallState::Installed
        }
        _ => SystemExtensionInstallState::Unknown,
    }
}

fn merge_approval_state(
    current: SystemExtensionApproval,
    candidate: SystemExtensionApproval,
) -> SystemExtensionApproval {
    match (current, candidate) {
        (SystemExtensionApproval::ApprovalBlocked, _)
        | (_, SystemExtensionApproval::ApprovalBlocked) => SystemExtensionApproval::ApprovalBlocked,
        (SystemExtensionApproval::Approved, SystemExtensionApproval::Approved) => {
            SystemExtensionApproval::Approved
        }
        _ => SystemExtensionApproval::Unknown,
    }
}

fn resolve_status_tool<R: Runtime>(
    app: &AppHandle<R>,
    env_var: &str,
    relative_package_path: &str,
    executable: &'static str,
) -> Option<ToolInvocation> {
    let allow_swift_run = swift_run_status_tools_enabled();

    if let Some(tool) = resolve_direct_tool_from_env(env_var) {
        return Some(tool);
    }

    if let Some(resource_package) = resolve_resource_package_path(app, relative_package_path) {
        if let Some(tool) =
            resolve_package_status_tool(&resource_package, executable, allow_swift_run)
        {
            return Some(tool);
        }
    }

    let source_package = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_package_path);
    if let Some(tool) = resolve_package_status_tool(&source_package, executable, allow_swift_run) {
        return Some(tool);
    }

    None
}

fn swift_run_status_tools_enabled() -> bool {
    std::env::var(ALLOW_SWIFT_RUN_STATUS_TOOLS_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn direct_status_tool_overrides_enabled() -> bool {
    std::env::var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn resolve_direct_tool_from_env(env_var: &str) -> Option<ToolInvocation> {
    let path = std::env::var_os(env_var)?;
    if !direct_status_tool_overrides_enabled() {
        tracing::warn!(
            env = env_var,
            "ignoring macOS status helper override because direct helper overrides are disabled"
        );
        return None;
    }
    let program = PathBuf::from(path);
    if !program.is_absolute() {
        tracing::warn!(
            path = %program.display(),
            env = env_var,
            "ignoring macOS status helper override because the path is not absolute"
        );
        return None;
    }
    if !program.is_file() {
        tracing::warn!(
            path = %program.display(),
            env = env_var,
            "ignoring macOS status helper override because the path does not exist"
        );
        return None;
    }
    Some(ToolInvocation::Direct {
        program,
        args: vec![OsString::from("live")],
    })
}

fn resolve_resource_package_path<R: Runtime>(
    app: &AppHandle<R>,
    relative_package_path: &str,
) -> Option<PathBuf> {
    app.path()
        .resolve(relative_package_path, BaseDirectory::Resource)
        .ok()
        .filter(|path| path.exists())
}

fn resolve_direct_built_tool(
    package_path: &Path,
    executable: &'static str,
) -> Option<ToolInvocation> {
    for candidate in direct_built_tool_candidates(package_path, executable) {
        if candidate.is_file() {
            return Some(ToolInvocation::Direct {
                program: candidate,
                args: vec![OsString::from("live")],
            });
        }
    }
    None
}

fn direct_built_tool_candidates(package_path: &Path, executable: &'static str) -> Vec<PathBuf> {
    let mut candidates = vec![package_path.join("bin").join(executable)];
    for profile in ["release", "debug"] {
        candidates.push(package_path.join(".build").join(profile).join(executable));
    }
    let build_dir = package_path.join(".build");
    if let Ok(entries) = std::fs::read_dir(&build_dir) {
        let mut platform_dirs = entries
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        platform_dirs.sort();
        for platform_dir in platform_dirs {
            for profile in ["release", "debug"] {
                candidates.push(platform_dir.join(profile).join(executable));
            }
        }
    }
    candidates
}

fn resolve_package_status_tool(
    package_path: &Path,
    executable: &'static str,
    allow_swift_run: bool,
) -> Option<ToolInvocation> {
    resolve_package_status_tool_with_swift_availability(
        package_path,
        executable,
        allow_swift_run,
        which::which("swift").is_ok(),
    )
}

fn resolve_package_status_tool_with_swift_availability(
    package_path: &Path,
    executable: &'static str,
    allow_swift_run: bool,
    swift_available: bool,
) -> Option<ToolInvocation> {
    if let Some(tool) = resolve_direct_built_tool(package_path, executable) {
        return Some(tool);
    }
    if allow_swift_run && swift_available && package_path.join("Package.swift").is_file() {
        return Some(ToolInvocation::SwiftRun {
            package_path: package_path.to_path_buf(),
            executable,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::await_holding_lock, clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::macos::status::{
        EvidenceArtifact, ProviderApprovalStatus, ProviderAttestationState, ProviderAvailability,
        ProviderRuntimeState, ProviderStatus,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;
    use std::time::{SystemTime, UNIX_EPOCH};

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn temp_script_path(name: &str) -> PathBuf {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_millis();
        std::env::temp_dir().join(format!(
            "clawdstrike-{name}-{millis}-{}",
            std::process::id()
        ))
    }

    fn write_script(name: &str, body: &str) -> PathBuf {
        let path = temp_script_path(name);
        fs::write(&path, body).expect("write temp script");
        let mut permissions = fs::metadata(&path).expect("stat temp script").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("chmod temp script");
        path
    }

    fn set_env_var(key: &str, value: impl AsRef<std::ffi::OsStr>) {
        unsafe {
            std::env::set_var(key, value);
        }
    }

    fn remove_env_var(key: &str) {
        unsafe {
            std::env::remove_var(key);
        }
    }

    fn temp_package_dir(name: &str) -> PathBuf {
        let path = temp_script_path(name);
        let _ = fs::remove_file(&path);
        fs::create_dir_all(&path).expect("create temp package dir");
        fs::write(path.join("Package.swift"), "// swift-tools-version: 5.9\n")
            .expect("write test package manifest");
        path
    }

    fn endpoint_sample(runtime: ProviderRuntimeState) -> EndpointSecurityStatusSample {
        EndpointSecurityStatusSample {
            host_status: EndpointSecurityHostStatus {
                install_state: SystemExtensionInstallState::Installed,
                approval: SystemExtensionApproval::Approved,
                endpoint_security: ProviderStatus {
                    runtime,
                    ..ProviderStatus::unknown()
                },
            },
            provider_state: None,
            counters: BTreeMap::new(),
            evidence_paths: Vec::new(),
            policy_epoch: None,
            last_error: None,
        }
    }

    fn network_sample(runtime: ProviderRuntimeState) -> NetworkExtensionStatusSample {
        NetworkExtensionStatusSample {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            host_status: ProviderStatus {
                runtime,
                ..ProviderStatus::unknown()
            },
            provider_state: None,
            counters: BTreeMap::new(),
            evidence_paths: Vec::new(),
            policy_epoch: None,
            policy_synced: None,
            enforcement_ready: None,
            last_error: None,
            last_reload_observation: None,
        }
    }

    #[tokio::test]
    async fn reply_to_pending_refreshes_completes_all_open_waiters() {
        let (first_tx, first_rx) = tokio::sync::oneshot::channel();
        let (second_tx, second_rx) = tokio::sync::oneshot::channel();
        let expected = CombinedSystemExtensionStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            ..CombinedSystemExtensionStatus::default()
        };
        let mut replies = vec![first_tx, second_tx];

        reply_to_pending_refreshes(&mut replies, expected.clone());

        assert!(replies.is_empty());
        assert_eq!(first_rx.await.expect("first refresh reply"), expected);
        assert_eq!(second_rx.await.expect("second refresh reply"), expected);
    }

    #[test]
    fn retain_open_refresh_replies_drops_closed_waiters() {
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        let (open_tx, _open_rx) = tokio::sync::oneshot::channel();
        drop(closed_rx);
        let mut replies = vec![closed_tx, open_tx];

        retain_open_refresh_replies(&mut replies);

        assert_eq!(replies.len(), 1);
    }

    #[tokio::test]
    async fn abort_status_probe_preserves_refresh_waiters_and_drains_results() {
        let handle = tokio::spawn(async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let (status_tx, mut status_rx) = mpsc::channel(1);
        status_tx
            .send((7, CombinedSystemExtensionStatus::default()))
            .await
            .expect("queue stale status");
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<CombinedSystemExtensionStatus>();
        let mut active_probe = Some(handle);
        let mut active_generation = Some(7);
        let pending_replies = vec![reply_tx];

        abort_status_probe(&mut active_probe, &mut active_generation, &mut status_rx);

        assert!(active_probe.is_none());
        assert_eq!(active_generation, None);
        assert_eq!(pending_replies.len(), 1);
        drop(pending_replies);
        assert!(reply_rx.await.is_err());
        assert!(status_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn invalid_helper_json_resets_provider_to_unknown() {
        let script = write_script("invalid-json", "#!/bin/sh\nprintf 'not-json'\n");
        let result = run_json_tool::<EndpointSecurityStatusSample>(&ToolInvocation::Direct {
            program: script.clone(),
            args: vec![OsString::from("live")],
        })
        .await;
        let _ = fs::remove_file(script);

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn timing_out_helper_resets_provider_to_unknown() {
        let script = write_script("slow-helper", "#!/bin/sh\nsleep 30\n");
        let timeout_result = timeout(
            Duration::from_millis(100),
            execute_tool(&ToolInvocation::Direct {
                program: script.clone(),
                args: vec![OsString::from("live")],
            }),
        )
        .await;
        let _ = fs::remove_file(script);

        assert!(
            timeout_result.is_err(),
            "helper should time out in the test harness"
        );
    }

    #[test]
    fn status_tool_resolution_does_not_use_swift_run_without_dev_override() {
        let package = temp_package_dir("status-tool-package");

        let resolved = resolve_package_status_tool_with_swift_availability(
            &package,
            ENDPOINT_SECURITY_TOOL_NAME,
            false,
            true,
        );
        let _ = fs::remove_dir_all(&package);

        assert!(
            resolved.is_none(),
            "production status collection must not execute Swift package sources via swift run"
        );
    }

    #[test]
    fn status_tool_resolution_prefers_bundled_bin_helper() {
        let package = temp_package_dir("status-tool-package-bin");
        let bin_dir = package.join("bin");
        fs::create_dir_all(&bin_dir).expect("create status tool bin dir");
        let helper = bin_dir.join(ENDPOINT_SECURITY_TOOL_NAME);
        fs::write(&helper, "#!/bin/sh\n").expect("write bundled helper");

        let resolved = resolve_package_status_tool_with_swift_availability(
            &package,
            ENDPOINT_SECURITY_TOOL_NAME,
            false,
            false,
        );
        let _ = fs::remove_dir_all(&package);

        match resolved {
            Some(ToolInvocation::Direct { program, args }) => {
                assert_eq!(program, helper);
                assert_eq!(args, vec![OsString::from("live")]);
            }
            other => panic!("expected bundled direct status helper, got {other:?}"),
        }
    }

    #[test]
    fn status_tool_resolution_finds_platform_scoped_swift_build_output() {
        let package = temp_package_dir("status-tool-package-platform-build");
        let helper_dir = package
            .join(".build")
            .join("arm64-apple-macosx")
            .join("release");
        fs::create_dir_all(&helper_dir).expect("create platform build dir");
        let helper = helper_dir.join(ENDPOINT_SECURITY_TOOL_NAME);
        fs::write(&helper, "#!/bin/sh\n").expect("write built helper");

        let resolved = resolve_package_status_tool_with_swift_availability(
            &package,
            ENDPOINT_SECURITY_TOOL_NAME,
            false,
            false,
        );
        let _ = fs::remove_dir_all(&package);

        match resolved {
            Some(ToolInvocation::Direct { program, args }) => {
                assert_eq!(program, helper);
                assert_eq!(args, vec![OsString::from("live")]);
            }
            other => panic!("expected platform-scoped direct status helper, got {other:?}"),
        }
    }

    #[test]
    fn status_tool_resolution_allows_swift_run_only_with_dev_override() {
        let package = temp_package_dir("status-tool-package-dev");

        let resolved = resolve_package_status_tool_with_swift_availability(
            &package,
            ENDPOINT_SECURITY_TOOL_NAME,
            true,
            true,
        );
        let _ = fs::remove_dir_all(&package);

        match resolved {
            Some(ToolInvocation::SwiftRun {
                package_path,
                executable,
            }) => {
                assert_eq!(package_path, package);
                assert_eq!(executable, ENDPOINT_SECURITY_TOOL_NAME);
            }
            other => panic!("expected dev-only SwiftRun helper, got {other:?}"),
        }
    }

    #[test]
    fn direct_status_tool_override_requires_dev_flag_and_absolute_path() {
        let _guard = ENV_LOCK.lock().expect("lock env");
        let script = write_script("direct-helper", "#!/bin/sh\nprintf '{}'\n");
        let previous_tool = std::env::var_os(ENDPOINT_SECURITY_TOOL_ENV);
        let previous_allow = std::env::var_os(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV);

        set_env_var(ENDPOINT_SECURITY_TOOL_ENV, &script);
        remove_env_var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV);
        assert!(resolve_direct_tool_from_env(ENDPOINT_SECURITY_TOOL_ENV).is_none());

        set_env_var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV, "1");
        match resolve_direct_tool_from_env(ENDPOINT_SECURITY_TOOL_ENV) {
            Some(ToolInvocation::Direct { program, args }) => {
                assert_eq!(program, script);
                assert_eq!(args, vec![OsString::from("live")]);
            }
            other => panic!("expected direct helper override with dev flag, got {other:?}"),
        }

        set_env_var(ENDPOINT_SECURITY_TOOL_ENV, "relative-helper");
        assert!(resolve_direct_tool_from_env(ENDPOINT_SECURITY_TOOL_ENV).is_none());

        if let Some(value) = previous_tool {
            set_env_var(ENDPOINT_SECURITY_TOOL_ENV, value);
        } else {
            remove_env_var(ENDPOINT_SECURITY_TOOL_ENV);
        }
        if let Some(value) = previous_allow {
            set_env_var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV, value);
        } else {
            remove_env_var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV);
        }
        let _ = fs::remove_file(script);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_tool_execution_does_not_inherit_ambient_secret_environment() {
        let _guard = ENV_LOCK.lock().expect("lock env");
        let previous_secret = std::env::var_os("CLAWDSTRIKE_TEST_AMBIENT_SECRET");
        set_env_var("CLAWDSTRIKE_TEST_AMBIENT_SECRET", "do-not-leak");
        let script = write_script(
            "env-helper",
            "#!/bin/sh\nprintf '%s' \"${CLAWDSTRIKE_TEST_AMBIENT_SECRET:-cleared}\"\n",
        );

        let output = execute_tool(&ToolInvocation::Direct {
            program: script.clone(),
            args: vec![OsString::from("live")],
        })
        .await
        .expect("execute helper");
        assert_eq!(String::from_utf8(output).expect("utf8 output"), "cleared");

        if let Some(value) = previous_secret {
            set_env_var("CLAWDSTRIKE_TEST_AMBIENT_SECRET", value);
        } else {
            remove_env_var("CLAWDSTRIKE_TEST_AMBIENT_SECRET");
        }
        let _ = fs::remove_file(script);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_tool_execution_preserves_swift_toolchain_environment() {
        let _guard = ENV_LOCK.lock().expect("lock env");
        let previous_home = std::env::var_os("HOME");
        let previous_developer_dir = std::env::var_os("DEVELOPER_DIR");
        let home = temp_script_path("swift-home");
        fs::create_dir_all(&home).expect("create test HOME");
        set_env_var("HOME", &home);
        set_env_var(
            "DEVELOPER_DIR",
            "/Applications/Xcode.app/Contents/Developer",
        );
        let script = write_script(
            "toolchain-env-helper",
            "#!/bin/sh\nprintf '%s\\n%s' \"${HOME:-missing}\" \"${DEVELOPER_DIR:-missing}\"\n",
        );

        let output = execute_tool(&ToolInvocation::Direct {
            program: script.clone(),
            args: vec![OsString::from("live")],
        })
        .await
        .expect("execute helper");
        let rendered = String::from_utf8(output).expect("utf8 output");
        assert!(rendered.contains(home.to_str().expect("home path should be utf8")));
        assert!(rendered.contains("/Applications/Xcode.app/Contents/Developer"));

        if let Some(value) = previous_home {
            set_env_var("HOME", value);
        } else {
            remove_env_var("HOME");
        }
        if let Some(value) = previous_developer_dir {
            set_env_var("DEVELOPER_DIR", value);
        } else {
            remove_env_var("DEVELOPER_DIR");
        }
        let _ = fs::remove_file(script);
        let _ = fs::remove_dir_all(home);
    }

    #[test]
    fn network_extension_reload_args_forward_policy_path_and_generation() {
        let args =
            network_extension_reload_args(Path::new("/tmp/clawdstrike-network-policy.json"), 5150);

        assert_eq!(args[0], OsString::from("request-reload"));
        assert_eq!(
            args[1],
            OsString::from("/tmp/clawdstrike-network-policy.json")
        );
        assert_eq!(args[2], OsString::from("5150"));
    }

    #[test]
    fn network_extension_reload_response_parser_validates_command_and_generation() {
        let expected_path = Path::new("/tmp/clawdstrike-network-policy.json");
        let result = parse_network_extension_reload_response(
            br#"{"requestId":"reload-test","command":"reload_policy","policySnapshotPath":"/tmp/clawdstrike-network-policy.json","generation":5150,"saved":true}"#,
            expected_path,
            5150,
        )
        .expect("valid reload helper response should parse");

        assert_eq!(
            result,
            MacosNetworkExtensionReloadResult {
                requested: true,
                saved: true,
                request_id: "reload-test".to_string(),
                policy_snapshot_path: "/tmp/clawdstrike-network-policy.json".to_string(),
                generation: 5150,
            }
        );

        assert_eq!(
            parse_network_extension_reload_response(
                br#"{"requestId":"reload-test","command":"other","policySnapshotPath":"/tmp/clawdstrike-network-policy.json","generation":5150,"saved":true}"#,
                expected_path,
                5150,
            ),
            Err(MacosNetworkExtensionReloadError::InvalidResponse(
                "unexpected command other".to_string()
            ))
        );
        assert_eq!(
            parse_network_extension_reload_response(
                br#"{"requestId":"reload-test","command":"reload_policy","policySnapshotPath":"/tmp/clawdstrike-network-policy.json","generation":5151,"saved":true}"#,
                expected_path,
                5150,
            ),
            Err(MacosNetworkExtensionReloadError::InvalidResponse(
                "generation mismatch: requested 5150, helper returned 5151".to_string()
            ))
        );
        assert_eq!(
            parse_network_extension_reload_response(
                br#"{"requestId":"reload-test","command":"reload_policy","policySnapshotPath":"/tmp/other-policy.json","generation":5150,"saved":true}"#,
                expected_path,
                5150,
            ),
            Err(MacosNetworkExtensionReloadError::InvalidResponse(
                "policy snapshot path mismatch: requested /tmp/clawdstrike-network-policy.json, helper returned /tmp/other-policy.json".to_string()
            ))
        );
    }

    #[tokio::test]
    async fn execute_tool_passes_provider_runtime_snapshot_paths() {
        let script = write_script(
            "network-env",
            r#"#!/bin/sh
printf '%s
%s
%s
' "$CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH" "$CLAWDSTRIKE_NETWORK_EXTENSION_EGRESS_POLICY_PATH" "$CLAWDSTRIKE_NETWORK_EXTENSION_RUNTIME_SNAPSHOT_PATH"
"#,
        );
        let stdout = execute_tool(&ToolInvocation::Direct {
            program: script.clone(),
            args: vec![OsString::from("live")],
        })
        .await
        .unwrap_or_else(|err| panic!("env helper should succeed: {err}"));
        let _ = fs::remove_file(script);
        let rendered = String::from_utf8(stdout).expect("helper stdout should be utf8");

        assert!(
            rendered.contains("endpoint-security-runtime.json\n"),
            "endpoint security runtime snapshot env path should be passed to the helper: {rendered}"
        );
        assert!(
            rendered.contains("network-extension-egress-policy.json\n"),
            "egress policy env path should be passed to the helper: {rendered}"
        );
        assert!(
            rendered.contains("network-extension-egress-policy.json.provider-runtime.json\n"),
            "network extension runtime snapshot env path should be passed to the helper: {rendered}"
        );
    }

    #[test]
    fn stale_runtime_snapshot_marker_downgrades_active_provider() {
        let path = Path::new("/tmp/clawdstrike-stale-runtime-snapshot.json");
        let mut status = ProviderStatus {
            runtime: ProviderRuntimeState::Active,
            provider_state: Some(ProviderAttestationState {
                provider: "endpoint_security".to_string(),
                installed: true,
                approval_status: ProviderApprovalStatus::Approved,
                active: true,
                healthy: true,
                availability: ProviderAvailability::Active,
                degraded_reasons: Vec::new(),
                last_healthy_timestamp: Some("2026-05-22T14:00:00Z".to_string()),
            }),
            ..ProviderStatus::unknown()
        };

        mark_runtime_snapshot_stale(&mut status, "endpoint-security", path);

        assert_eq!(
            status.runtime,
            ProviderRuntimeState::Degraded {
                reason: "provider_runtime_snapshot_stale".to_string()
            }
        );
        assert_eq!(
            status.last_error.as_deref(),
            Some("provider_runtime_snapshot_stale")
        );
        assert_eq!(status.evidence_paths.len(), 1);
        assert_eq!(status.evidence_paths[0].kind, "stale_runtime_snapshot");
        let provider_state = status
            .provider_state
            .as_ref()
            .expect("provider state should remain attached");
        assert!(!provider_state.active);
        assert!(!provider_state.healthy);
        assert_eq!(provider_state.availability, ProviderAvailability::Degraded);
        assert!(provider_state
            .degraded_reasons
            .contains(&"provider_runtime_snapshot_stale".to_string()));
    }

    #[test]
    fn missing_runtime_snapshot_downgrades_active_provider() {
        let path = temp_script_path("missing-runtime-snapshot");
        let _ = fs::remove_file(&path);
        let mut status = ProviderStatus {
            runtime: ProviderRuntimeState::Active,
            provider_state: Some(ProviderAttestationState {
                provider: "network_extension".to_string(),
                installed: true,
                approval_status: ProviderApprovalStatus::Approved,
                active: true,
                healthy: true,
                availability: ProviderAvailability::Active,
                degraded_reasons: Vec::new(),
                last_healthy_timestamp: Some("2026-05-22T14:00:00Z".to_string()),
            }),
            ..ProviderStatus::unknown()
        };

        downgrade_stale_runtime_snapshot(&mut status, "network-extension", &path);

        assert_eq!(
            status.runtime,
            ProviderRuntimeState::Degraded {
                reason: "provider_runtime_snapshot_stale".to_string()
            }
        );
        assert_eq!(
            status.last_error.as_deref(),
            Some("provider_runtime_snapshot_stale")
        );
    }

    #[test]
    fn merge_samples_preserves_valid_provider_status_and_marks_missing_sample_unknown() {
        let combined = merge_samples(Some(endpoint_sample(ProviderRuntimeState::Active)), None);

        assert_eq!(combined.install_state, SystemExtensionInstallState::Unknown);
        assert_eq!(combined.approval, SystemExtensionApproval::Unknown);
        assert_eq!(
            combined.endpoint_security,
            ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..ProviderStatus::unknown()
            }
        );
        assert_eq!(combined.network_extension, ProviderStatus::unknown());
    }

    #[test]
    fn merge_samples_promotes_consistent_install_and_approval_proof() {
        let combined = merge_samples(
            Some(endpoint_sample(ProviderRuntimeState::Active)),
            Some(network_sample(ProviderRuntimeState::Active)),
        );

        assert_eq!(
            combined.install_state,
            SystemExtensionInstallState::Installed
        );
        assert_eq!(combined.approval, SystemExtensionApproval::Approved);
        assert_eq!(
            combined.endpoint_security,
            ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..ProviderStatus::unknown()
            }
        );
        assert_eq!(
            combined.network_extension,
            ProviderStatus {
                runtime: ProviderRuntimeState::Active,
                ..ProviderStatus::unknown()
            }
        );
    }

    #[test]
    fn merge_samples_preserves_provider_runtime_readouts() {
        let mut endpoint = endpoint_sample(ProviderRuntimeState::Active);
        endpoint.provider_state = Some(ProviderAttestationState {
            provider: "endpoint_security".to_string(),
            installed: true,
            approval_status: ProviderApprovalStatus::Approved,
            active: true,
            healthy: true,
            availability: ProviderAvailability::Active,
            degraded_reasons: Vec::new(),
            last_healthy_timestamp: Some("2026-05-14T12:00:00Z".to_string()),
        });
        endpoint.counters.insert("auth_open_allowed".to_string(), 7);
        endpoint.policy_epoch = Some(42);
        endpoint.evidence_paths.push(EvidenceArtifact {
            kind: "status".to_string(),
            path: "/tmp/clawdstrike/es-status.json".to_string(),
            detail: "endpoint security helper output".to_string(),
        });

        let combined = merge_samples(
            Some(endpoint),
            Some(network_sample(ProviderRuntimeState::Active)),
        );

        assert_eq!(
            combined.activation_state,
            SystemExtensionActivationState::Active
        );
        assert_eq!(combined.endpoint_security.policy_epoch, Some(42));
        assert_eq!(
            combined.endpoint_security.counters.get("auth_open_allowed"),
            Some(&7)
        );
        assert_eq!(
            combined.endpoint_security.last_healthy_timestamp.as_deref(),
            Some("2026-05-14T12:00:00Z")
        );
        assert_eq!(combined.endpoint_security.evidence_paths.len(), 1);
        assert_eq!(
            combined
                .endpoint_security
                .provider_state
                .as_ref()
                .map(|state| state.provider.as_str()),
            Some("endpoint_security")
        );
    }

    #[test]
    fn merge_samples_preserves_network_extension_policy_readout() {
        let mut network = network_sample(ProviderRuntimeState::Unknown);
        network.policy_synced = Some(true);
        network.enforcement_ready = Some(true);
        network
            .counters
            .insert("remediation_requests".to_string(), 2);

        let combined = merge_samples(
            Some(endpoint_sample(ProviderRuntimeState::Active)),
            Some(network),
        );

        assert_eq!(combined.network_extension.policy_synced, Some(true));
        assert_eq!(combined.network_extension.enforcement_ready, Some(true));
        assert_eq!(
            combined
                .network_extension
                .counters
                .get("remediation_requests"),
            Some(&2)
        );
        assert_eq!(
            combined.network_extension.runtime,
            ProviderRuntimeState::Unknown
        );
        assert_eq!(
            combined.activation_state,
            SystemExtensionActivationState::Pending
        );
    }

    #[test]
    fn merge_install_state_fails_closed_for_partial_installation() {
        assert_eq!(
            merge_install_state(
                SystemExtensionInstallState::Installed,
                SystemExtensionInstallState::NotInstalled,
            ),
            SystemExtensionInstallState::NotInstalled
        );
        assert_eq!(
            merge_install_state(
                SystemExtensionInstallState::NotInstalled,
                SystemExtensionInstallState::Installed,
            ),
            SystemExtensionInstallState::NotInstalled
        );
        assert_eq!(
            merge_install_state(
                SystemExtensionInstallState::Installed,
                SystemExtensionInstallState::Unknown,
            ),
            SystemExtensionInstallState::Unknown
        );
        assert_eq!(
            merge_install_state(
                SystemExtensionInstallState::Unknown,
                SystemExtensionInstallState::Installed,
            ),
            SystemExtensionInstallState::Unknown
        );
    }

    #[test]
    fn merge_approval_state_requires_consistent_approval_proof() {
        assert_eq!(
            merge_approval_state(
                SystemExtensionApproval::Approved,
                SystemExtensionApproval::Unknown,
            ),
            SystemExtensionApproval::Unknown
        );
        assert_eq!(
            merge_approval_state(
                SystemExtensionApproval::Unknown,
                SystemExtensionApproval::Approved,
            ),
            SystemExtensionApproval::Unknown
        );
        assert_eq!(
            merge_approval_state(
                SystemExtensionApproval::Approved,
                SystemExtensionApproval::Approved,
            ),
            SystemExtensionApproval::Approved
        );
    }
}
