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

use super::host::MacosHostService;
use super::status::{
    CombinedSystemExtensionStatus, EvidenceArtifact, MdmProfileState, ProviderAttestationState,
    ProviderRuntimeState, ProviderStatus, SystemExtensionActivationState, SystemExtensionApproval,
    SystemExtensionInstallState,
};

const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(60);
const STATUS_TOOL_TIMEOUT: Duration = Duration::from_secs(10);
const ENDPOINT_SECURITY_TOOL_ENV: &str = "CLAWDSTRIKE_ENDPOINT_SECURITY_STATUS_TOOL";
const NETWORK_EXTENSION_TOOL_ENV: &str = "CLAWDSTRIKE_NETWORK_EXTENSION_STATUS_TOOL";
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
            Self::Direct { program, args } => {
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
                    .arg("live");
                command
            }
        }
    }

    fn display_name(&self) -> String {
        match self {
            Self::Direct { program, .. } => program.display().to_string(),
            Self::SwiftRun {
                package_path,
                executable,
            } => format!("swift run --package-path {} {}", package_path.display(), executable),
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
    last_error: Option<String>,
}

pub fn start_status_collector<R: Runtime + 'static>(
    app: AppHandle<R>,
    macos_host: Arc<MacosHostService>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let endpoint_tool =
        resolve_status_tool(&app, ENDPOINT_SECURITY_TOOL_ENV, "macos/system-extension/endpoint-security", ENDPOINT_SECURITY_TOOL_NAME);
    let network_tool =
        resolve_status_tool(&app, NETWORK_EXTENSION_TOOL_ENV, "macos/system-extension/network-extension", NETWORK_EXTENSION_TOOL_NAME);

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

    tokio::spawn(async move {
        macos_host.reset_unknown_state().await;

        loop {
            let combined = collect_combined_status(endpoint_tool.as_ref(), network_tool.as_ref()).await;
            macos_host.replace_status(combined).await;

            tokio::select! {
                _ = shutdown.recv() => break,
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

async fn execute_tool(tool: &ToolInvocation) -> Result<Vec<u8>> {
    let mut command = tool.command();
    command.kill_on_drop(true);
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());

    let output = command
        .output()
        .await
        .with_context(|| format!("spawn {}", tool.display_name()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(anyhow!(
            "{} exited with status {}{}",
            tool.display_name(),
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
        (Some(endpoint_sample), Some(network_sample)) => {
            merge_approval_state(endpoint_sample.host_status.approval, network_sample.approval)
        }
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
        sample.provider_state,
        sample.counters,
        sample.evidence_paths,
        sample.policy_epoch,
        sample.last_error,
    );
    status
}

fn network_provider_status(sample: NetworkExtensionStatusSample) -> ProviderStatus {
    let mut status = sample.host_status;
    enrich_provider_status(
        &mut status,
        sample.provider_state,
        sample.counters,
        sample.evidence_paths,
        sample.policy_epoch,
        sample.last_error,
    );
    status
}

fn enrich_provider_status(
    status: &mut ProviderStatus,
    provider_state: Option<ProviderAttestationState>,
    counters: BTreeMap<String, u64>,
    evidence_paths: Vec<EvidenceArtifact>,
    policy_epoch: Option<u64>,
    last_error: Option<String>,
) {
    if let Some(provider_state) = provider_state {
        if status.last_healthy_timestamp.is_none() {
            status.last_healthy_timestamp = provider_state.last_healthy_timestamp.clone();
        }
        status.provider_state = Some(provider_state);
    }
    status.counters = counters;
    status.evidence_paths = evidence_paths;
    status.policy_epoch = policy_epoch;
    status.last_error = last_error;
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
        | (_, SystemExtensionInstallState::NotInstalled) => SystemExtensionInstallState::NotInstalled,
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

fn resolve_direct_built_tool(package_path: &Path, executable: &'static str) -> Option<ToolInvocation> {
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
        std::env::temp_dir().join(format!("clawdstrike-{name}-{millis}-{}", std::process::id()))
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
            last_error: None,
        }
    }

    #[tokio::test]
    async fn invalid_helper_json_resets_provider_to_unknown() {
        let script = write_script(
            "invalid-json",
            "#!/bin/sh\nprintf 'not-json'\n",
        );
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
        let script = write_script(
            "slow-helper",
            "#!/bin/sh\nsleep 30\n",
        );
        let timeout_result =
            timeout(Duration::from_millis(100), execute_tool(&ToolInvocation::Direct {
                program: script.clone(),
                args: vec![OsString::from("live")],
            }))
            .await;
        let _ = fs::remove_file(script);

        assert!(timeout_result.is_err(), "helper should time out in the test harness");
    }

    #[test]
    fn merge_samples_preserves_valid_provider_status_and_marks_missing_sample_unknown() {
        let combined = merge_samples(
            Some(endpoint_sample(ProviderRuntimeState::Active)),
            None,
        );

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

        assert_eq!(combined.install_state, SystemExtensionInstallState::Installed);
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
            combined
                .endpoint_security
                .counters
                .get("auth_open_allowed"),
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
