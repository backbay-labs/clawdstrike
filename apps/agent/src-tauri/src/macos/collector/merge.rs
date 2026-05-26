//! Merge endpoint-security and network-extension helper samples into the
//! combined system-extension status the rest of the agent consumes.

use std::path::Path;
use std::time::{Duration, SystemTime};

use super::paths::{
    default_endpoint_security_runtime_snapshot_path,
    default_network_extension_runtime_snapshot_path,
};
use super::samples::{
    EndpointSecurityStatusSample, NetworkExtensionStatusSample, ProviderStatusEnrichment,
};
use super::tool::{run_json_tool, ToolInvocation};
use crate::macos::status::{
    CombinedSystemExtensionStatus, EvidenceArtifact, MdmProfileState, ProviderAvailability,
    ProviderRuntimeState, ProviderStatus, SystemExtensionActivationState, SystemExtensionApproval,
    SystemExtensionInstallState,
};

const RUNTIME_SNAPSHOT_MAX_AGE: Duration = Duration::from_secs(120);

pub(super) async fn collect_combined_status(
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

pub(super) fn merge_samples(
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

pub(super) fn endpoint_provider_status(sample: EndpointSecurityStatusSample) -> ProviderStatus {
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

pub(super) fn network_provider_status(sample: NetworkExtensionStatusSample) -> ProviderStatus {
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

pub(super) fn downgrade_stale_runtime_snapshot(
    status: &mut ProviderStatus,
    provider: &str,
    path: &Path,
) {
    if !matches!(status.runtime, ProviderRuntimeState::Active) || !runtime_snapshot_is_stale(path) {
        return;
    }

    mark_runtime_snapshot_stale(status, provider, path);
}

pub(super) fn mark_runtime_snapshot_stale(
    status: &mut ProviderStatus,
    provider: &str,
    path: &Path,
) {
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

pub(super) fn merge_install_state(
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

pub(super) fn merge_approval_state(
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
