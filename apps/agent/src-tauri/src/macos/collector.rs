use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use tauri::path::BaseDirectory;
use tauri::{AppHandle, Manager, Runtime};
use tokio::process::Command;
use tokio::sync::broadcast;
use tokio::time::timeout;

use super::host::{
    MacosHostService, MacosNetworkExtensionReloadError, MacosNetworkExtensionReloadResult,
};
use super::status::{
    CombinedSystemExtensionStatus, EvidenceArtifact, MdmProfileState, ProviderAttestationState,
    ProviderReloadObservation, ProviderRuntimeState, ProviderStatus,
    SystemExtensionActivationState, SystemExtensionApproval, SystemExtensionInstallState,
};

const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(60);
const STATUS_TOOL_TIMEOUT: Duration = Duration::from_secs(10);
const ENDPOINT_SECURITY_TOOL_ENV: &str = "CLAWDSTRIKE_ENDPOINT_SECURITY_STATUS_TOOL";
const ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_ENV: &str =
    "CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH";
const NETWORK_EXTENSION_TOOL_ENV: &str = "CLAWDSTRIKE_NETWORK_EXTENSION_STATUS_TOOL";
const NETWORK_EXTENSION_EGRESS_POLICY_ENV: &str =
    "CLAWDSTRIKE_NETWORK_EXTENSION_EGRESS_POLICY_PATH";
const NETWORK_EXTENSION_RUNTIME_SNAPSHOT_ENV: &str =
    "CLAWDSTRIKE_NETWORK_EXTENSION_RUNTIME_SNAPSHOT_PATH";
const ENDPOINT_SECURITY_TOOL_NAME: &str = "endpoint-security-status-tool";
const NETWORK_EXTENSION_TOOL_NAME: &str = "network-extension-status-tool";

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

    let (refresh_tx, mut refresh_rx) =
        tokio::sync::mpsc::channel::<super::host::MacosHostRefreshRequest>(4);
    let (network_reload_tx, mut network_reload_rx) =
        tokio::sync::mpsc::channel::<super::host::MacosNetworkExtensionReloadRequest>(4);
    tokio::spawn(async move {
        macos_host.reset_unknown_state().await;
        macos_host.install_refresh_channel(refresh_tx).await;
        macos_host
            .install_network_extension_reload_channel(network_reload_tx)
            .await;

        loop {
            let combined =
                collect_combined_status(endpoint_tool.as_ref(), network_tool.as_ref()).await;
            macos_host.replace_status(combined).await;

            tokio::select! {
                _ = shutdown.recv() => break,
                request = refresh_rx.recv() => {
                    let Some(reply_tx) = request else {
                        break;
                    };
                    let combined =
                        collect_combined_status(endpoint_tool.as_ref(), network_tool.as_ref()).await;
                    macos_host.replace_status(combined.clone()).await;
                    let _ = reply_tx.send(combined);
                }
                request = network_reload_rx.recv() => {
                    let Some(request) = request else {
                        break;
                    };
                    let result = request_network_extension_reload(
                        network_tool.as_ref(),
                        &request.policy_snapshot_path,
                        request.generation,
                    )
                    .await;
                    let _ = request.reply_tx.send(result);
                }
                _ = tokio::time::sleep(STATUS_POLL_INTERVAL) => {}
            }
        }
    });
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
) -> Result<MacosNetworkExtensionReloadResult, MacosNetworkExtensionReloadError> {
    let tool = tool.ok_or(MacosNetworkExtensionReloadError::Unavailable)?;
    let args = network_extension_reload_args(policy_snapshot_path, generation);
    let stdout = match timeout(STATUS_TOOL_TIMEOUT, execute_tool_with_args(tool, &args)).await {
        Ok(Ok(stdout)) => stdout,
        Ok(Err(error)) => {
            return Err(MacosNetworkExtensionReloadError::HelperFailed(
                error.to_string(),
            ));
        }
        Err(_) => return Err(MacosNetworkExtensionReloadError::TimedOut),
    };
    parse_network_extension_reload_response(&stdout, generation)
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
    if let Some(tool) = resolve_direct_tool_from_env(env_var) {
        return Some(tool);
    }

    if let Some(resource_package) = resolve_resource_package_path(app, relative_package_path) {
        if let Some(tool) = resolve_direct_built_tool(&resource_package, executable) {
            return Some(tool);
        }
        if resource_package.join("Package.swift").is_file() && which::which("swift").is_ok() {
            return Some(ToolInvocation::SwiftRun {
                package_path: resource_package,
                executable,
            });
        }
    }

    let source_package = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_package_path);
    if let Some(tool) = resolve_direct_built_tool(&source_package, executable) {
        return Some(tool);
    }
    if source_package.join("Package.swift").is_file() && which::which("swift").is_ok() {
        return Some(ToolInvocation::SwiftRun {
            package_path: source_package,
            executable,
        });
    }

    None
}

fn resolve_direct_tool_from_env(env_var: &str) -> Option<ToolInvocation> {
    let path = std::env::var_os(env_var)?;
    let program = PathBuf::from(path);
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
    for profile in ["release", "debug"] {
        let candidate = package_path.join(".build").join(profile).join(executable);
        if candidate.is_file() {
            return Some(ToolInvocation::Direct {
                program: candidate,
                args: vec![OsString::from("live")],
            });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use crate::macos::status::{
        EvidenceArtifact, ProviderApprovalStatus, ProviderAttestationState, ProviderAvailability,
        ProviderRuntimeState, ProviderStatus,
    };
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let result = parse_network_extension_reload_response(
            br#"{"requestId":"reload-test","command":"reload_policy","policySnapshotPath":"/tmp/clawdstrike-network-policy.json","generation":5150,"saved":true}"#,
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
                5150,
            ),
            Err(MacosNetworkExtensionReloadError::InvalidResponse(
                "unexpected command other".to_string()
            ))
        );
        assert_eq!(
            parse_network_extension_reload_response(
                br#"{"requestId":"reload-test","command":"reload_policy","policySnapshotPath":"/tmp/clawdstrike-network-policy.json","generation":5151,"saved":true}"#,
                5150,
            ),
            Err(MacosNetworkExtensionReloadError::InvalidResponse(
                "generation mismatch: requested 5150, helper returned 5151".to_string()
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
