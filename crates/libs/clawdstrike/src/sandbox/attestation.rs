//! Sandbox attestation types for receipt integration.
//!
//! These types capture the sandbox enforcement state for inclusion in
//! signed receipts. They are ClawdStrike-owned serializable types built
//! from nono's CapabilitySet accessors.

use chrono::Utc;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Complete sandbox attestation for receipt metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxAttestation {
    pub enforced: bool,
    pub enforcement_level: EnforcementLevel,
    pub platform: PlatformInfo,
    pub runtime: SandboxRuntimeState,
    pub capabilities: CapabilitySnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub supervisor: Option<SupervisorStats>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denials: Vec<TimestampedDenial>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub audit: Vec<AuditEntry>,
}

/// Enforcement mechanism.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementLevel {
    None,
    Kernel,
    KernelSupervised,
    Degraded,
}

impl std::fmt::Display for EnforcementLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnforcementLevel::None => write!(f, "none"),
            EnforcementLevel::Kernel => write!(f, "kernel"),
            EnforcementLevel::KernelSupervised => write!(f, "kernel_supervised"),
            EnforcementLevel::Degraded => write!(f, "degraded"),
        }
    }
}

impl std::str::FromStr for EnforcementLevel {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(EnforcementLevel::None),
            "kernel" => Ok(EnforcementLevel::Kernel),
            "kernel_supervised" => Ok(EnforcementLevel::KernelSupervised),
            "degraded" => Ok(EnforcementLevel::Degraded),
            _ => Err(format!("unknown enforcement level: {}", s)),
        }
    }
}

/// Platform sandbox information.
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub name: String,
    pub mechanisms: Vec<String>,
    pub abi_version: Option<u32>,
    pub details: String,
}

impl Serialize for PlatformInfo {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let field_count =
            3 + usize::from(self.abi_version.is_some()) + usize::from(!self.mechanisms.is_empty());
        let mut state = serializer.serialize_struct("PlatformInfo", field_count)?;
        state.serialize_field("name", &self.name)?;
        if let Some(mechanism) = self.mechanisms.first() {
            state.serialize_field("mechanism", mechanism)?;
        }
        state.serialize_field("mechanisms", &self.mechanisms)?;
        if let Some(abi_version) = self.abi_version {
            state.serialize_field("abi_version", &abi_version)?;
        }
        state.serialize_field("details", &self.details)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for PlatformInfo {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct PlatformInfoFields {
            name: String,
            #[serde(default)]
            mechanism: Option<String>,
            #[serde(default)]
            mechanisms: Vec<String>,
            abi_version: Option<u32>,
            details: String,
        }

        let fields = PlatformInfoFields::deserialize(deserializer)?;
        let mut mechanisms = fields.mechanisms;
        if mechanisms.is_empty() {
            if let Some(mechanism) = fields.mechanism {
                mechanisms.push(mechanism);
            }
        } else if let Some(mechanism) = fields.mechanism {
            if !mechanisms.iter().any(|value| value == &mechanism) {
                mechanisms.insert(0, mechanism);
            }
        }

        Ok(Self {
            name: fields.name,
            mechanisms,
            abi_version: fields.abi_version,
            details: fields.details,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderApprovalStatus {
    NotRequired,
    Approved,
    Blocked,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderAvailability {
    Unavailable,
    Inactive,
    Active,
    Degraded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderState {
    pub provider: String,
    pub installed: bool,
    pub approval_status: ProviderApprovalStatus,
    pub active: bool,
    pub healthy: bool,
    pub availability: ProviderAvailability,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded_reasons: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_healthy_timestamp: Option<String>,
}

impl ProviderState {
    #[must_use]
    pub fn active(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: true,
            approval_status: ProviderApprovalStatus::Approved,
            active: true,
            healthy: true,
            availability: ProviderAvailability::Active,
            degraded_reasons: Vec::new(),
            last_healthy_timestamp: Some(Utc::now().to_rfc3339()),
        }
    }

    #[must_use]
    pub fn active_without_approval(provider: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: true,
            approval_status: ProviderApprovalStatus::NotRequired,
            active: true,
            healthy: true,
            availability: ProviderAvailability::Active,
            degraded_reasons: Vec::new(),
            last_healthy_timestamp: Some(Utc::now().to_rfc3339()),
        }
    }

    #[must_use]
    pub fn unavailable(provider: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: false,
            approval_status: ProviderApprovalStatus::Unknown,
            active: false,
            healthy: false,
            availability: ProviderAvailability::Unavailable,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }

    #[must_use]
    pub fn unavailable_without_approval(
        provider: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            installed: false,
            approval_status: ProviderApprovalStatus::NotRequired,
            active: false,
            healthy: false,
            availability: ProviderAvailability::Unavailable,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }

    #[must_use]
    pub fn unknown(provider: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: false,
            approval_status: ProviderApprovalStatus::Unknown,
            active: false,
            healthy: false,
            availability: ProviderAvailability::Unavailable,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }

    #[must_use]
    pub fn inactive_missing_approval(
        provider: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            installed: true,
            approval_status: ProviderApprovalStatus::Missing,
            active: false,
            healthy: false,
            availability: ProviderAvailability::Inactive,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }

    #[must_use]
    pub fn inactive_blocked_approval(
        provider: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            provider: provider.into(),
            installed: true,
            approval_status: ProviderApprovalStatus::Blocked,
            active: false,
            healthy: false,
            availability: ProviderAvailability::Inactive,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }

    #[must_use]
    pub fn degraded(provider: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            provider: provider.into(),
            installed: true,
            approval_status: ProviderApprovalStatus::Approved,
            active: true,
            healthy: false,
            availability: ProviderAvailability::Degraded,
            degraded_reasons: vec![reason.into()],
            last_healthy_timestamp: None,
        }
    }
}

/// Runtime enforcement state captured after execution completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRuntimeState {
    pub supported: bool,
    pub applied: bool,
    pub supervised_requested: bool,
    pub supervised_active: bool,
    #[serde(default = "legacy_contract_default")]
    pub contract: String,
    #[serde(default = "legacy_authorization_model_default")]
    pub authorization_model: String,
    #[serde(default)]
    pub fd_injection_equivalent: bool,
    #[serde(default)]
    pub fail_open_possible: bool,
    #[serde(default)]
    pub deadline_miss_count: u64,
    #[serde(default)]
    pub dropped_event_count: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_states: Vec<ProviderState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl SandboxRuntimeState {
    #[must_use]
    pub fn static_mode(applied: bool, failure_reason: Option<String>) -> Self {
        let support = nono::Sandbox::support_info();
        let mut state = Self {
            supported: support.is_supported,
            applied,
            supervised_requested: false,
            supervised_active: false,
            contract: "static_kernel_sandbox".to_string(),
            authorization_model: "none".to_string(),
            fd_injection_equivalent: false,
            fail_open_possible: false,
            deadline_miss_count: 0,
            dropped_event_count: 0,
            degraded_reasons: Vec::new(),
            provider_states: default_provider_states(applied),
            failure_reason,
        };
        if !state.applied {
            state
                .degraded_reasons
                .push("sandbox_apply_failed".to_string());
        }
        state
    }

    #[must_use]
    pub fn supervised_mode(
        applied: bool,
        supervised_active: bool,
        failure_reason: Option<String>,
    ) -> Self {
        let support = nono::Sandbox::support_info();
        let mut state = Self {
            supported: support.is_supported,
            applied,
            supervised_requested: true,
            supervised_active,
            contract: supervised_contract_name().to_string(),
            authorization_model: supervised_authorization_model().to_string(),
            fd_injection_equivalent: cfg!(target_os = "linux"),
            fail_open_possible: cfg!(target_os = "macos"),
            deadline_miss_count: 0,
            dropped_event_count: 0,
            degraded_reasons: Vec::new(),
            provider_states: default_provider_states(applied),
            failure_reason,
        };

        if !applied {
            state
                .degraded_reasons
                .push("sandbox_apply_failed".to_string());
        }
        if !supervised_active {
            if cfg!(target_os = "macos") {
                state
                    .degraded_reasons
                    .push("macos_authorization_contract_unavailable".to_string());
            } else {
                state
                    .degraded_reasons
                    .push("supervised_interception_inactive".to_string());
            }
        }
        state
    }

    #[must_use]
    pub fn supervised_preflight_refused(failure_reason: impl Into<String>) -> Self {
        let support = nono::Sandbox::support_info();
        Self {
            supported: support.is_supported,
            applied: false,
            supervised_requested: true,
            supervised_active: false,
            contract: supervised_contract_name().to_string(),
            authorization_model: supervised_authorization_model().to_string(),
            fd_injection_equivalent: cfg!(target_os = "linux"),
            fail_open_possible: cfg!(target_os = "macos"),
            deadline_miss_count: 0,
            dropped_event_count: 0,
            degraded_reasons: vec![
                "macos_authorization_contract_unavailable".to_string(),
                "supervised_launch_refused_without_live_authorization_provider".to_string(),
            ],
            provider_states: default_provider_states(false),
            failure_reason: Some(failure_reason.into()),
        }
    }

    #[must_use]
    pub fn with_degraded_reason(mut self, reason: impl Into<String>) -> Self {
        self.degraded_reasons.push(reason.into());
        self
    }

    #[must_use]
    pub fn with_deadline_miss_count(mut self, deadline_miss_count: u64) -> Self {
        self.deadline_miss_count = deadline_miss_count;
        if deadline_miss_count > 0 {
            self.degraded_reasons
                .push("authorization_deadline_missed".to_string());
        }
        self
    }

    #[must_use]
    pub fn with_dropped_event_count(mut self, dropped_event_count: u64) -> Self {
        self.dropped_event_count = dropped_event_count;
        if dropped_event_count > 0 {
            self.degraded_reasons
                .push("dropped_enforcement_events".to_string());
        }
        self
    }

    pub fn set_dropped_event_count(&mut self, dropped_event_count: u64) {
        self.dropped_event_count = dropped_event_count;
        if dropped_event_count > 0
            && !self
                .degraded_reasons
                .iter()
                .any(|reason| reason == "dropped_enforcement_events")
        {
            self.degraded_reasons
                .push("dropped_enforcement_events".to_string());
        }
    }

    #[must_use]
    pub fn with_provider_states(mut self, provider_states: Vec<ProviderState>) -> Self {
        self.provider_states = provider_states;
        self
    }
}

/// Snapshot of filesystem and network capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub fs: Vec<FsCapSnapshot>,
    pub network_mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mediation_backend_hint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_port: Option<u16>,
    pub signal_mode: String,
    pub blocked_commands: Vec<String>,
    pub extensions_enabled: bool,
}

/// Serialized filesystem capability entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsCapSnapshot {
    pub original: String,
    pub resolved: String,
    pub access: String,
    pub is_file: bool,
}

/// A denial with timestamp.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampedDenial {
    pub path: String,
    pub access: String,
    pub reason: String,
    pub timestamp: String,
}

/// Supervisor enforcement statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SupervisorStats {
    pub enabled: bool,
    pub backend: String,
    pub requests_total: u64,
    pub requests_granted: u64,
    pub requests_denied: u64,
    pub deadline_miss_count: u64,
    pub dropped_event_count: u64,
    pub never_grant_blocks: u64,
    pub rate_limit_blocks: u64,
}

/// Audit trail entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub path: String,
    pub access: String,
    pub decision: String,
    pub backend: String,
    pub duration_ms: u64,
}

/// Build a `SandboxAttestation` from a `CapabilitySet` and runtime outcome.
///
/// Reads the CapabilitySet's accessors to build a serializable snapshot.
pub fn build_attestation(
    caps: &nono::CapabilitySet,
    runtime: SandboxRuntimeState,
) -> SandboxAttestation {
    let support = nono::Sandbox::support_info();

    let (network_mode, mediation_backend_hint, proxy_port) = describe_network_mode(caps);

    let cap_snapshot = CapabilitySnapshot {
        fs: caps
            .fs_capabilities()
            .iter()
            .map(|c| FsCapSnapshot {
                original: c.original.to_string_lossy().into_owned(),
                resolved: c.resolved.to_string_lossy().into_owned(),
                access: format!("{}", c.access),
                is_file: c.is_file,
            })
            .collect(),
        network_mode,
        mediation_backend_hint,
        proxy_port,
        signal_mode: format!("{:?}", caps.signal_mode()),
        blocked_commands: caps.blocked_commands().to_vec(),
        extensions_enabled: caps.extensions_enabled(),
    };

    let mut attestation = SandboxAttestation {
        enforced: false,
        enforcement_level: EnforcementLevel::None,
        platform: PlatformInfo {
            name: support.platform.to_string(),
            mechanisms: platform_mechanisms(&runtime),
            abi_version: None,
            details: support.details,
        },
        runtime,
        capabilities: cap_snapshot,
        supervisor: None,
        denials: vec![],
        audit: vec![],
    };
    attestation.recompute_status();
    attestation
}

impl SandboxAttestation {
    pub fn recompute_status(&mut self) {
        self.platform.mechanisms = platform_mechanisms(&self.runtime);
        self.enforcement_level = effective_enforcement_level(&self.runtime);
        self.enforced = matches!(
            self.enforcement_level,
            EnforcementLevel::Kernel | EnforcementLevel::KernelSupervised
        );
    }
}

fn legacy_contract_default() -> String {
    "legacy_attestation".to_string()
}

fn legacy_authorization_model_default() -> String {
    "unknown".to_string()
}

fn describe_network_mode(caps: &nono::CapabilitySet) -> (String, Option<String>, Option<u16>) {
    match caps.network_mode() {
        nono::NetworkMode::ProxyOnly { port, .. } => (
            format!("{}", caps.network_mode()),
            Some(if cfg!(target_os = "macos") {
                "legacy_proxy_only_runtime".to_string()
            } else {
                "proxy_only_runtime".to_string()
            }),
            Some(*port),
        ),
        _ => (format!("{}", caps.network_mode()), None, None),
    }
}

fn platform_mechanisms(runtime: &SandboxRuntimeState) -> Vec<String> {
    if cfg!(target_os = "macos") {
        let mut mechanisms = vec!["seatbelt".to_string()];
        for provider in runtime
            .provider_states
            .iter()
            .filter(|provider| provider.active)
        {
            match provider.provider.as_str() {
                "endpoint_security" => {
                    push_unique_mechanism(&mut mechanisms, "endpoint_security_contract")
                }
                "network_extension" => {
                    push_unique_mechanism(&mut mechanisms, "network_extension_contract")
                }
                _ => {}
            }
        }
        mechanisms
    } else if cfg!(target_os = "linux") {
        let mut mechanisms = vec!["landlock".to_string()];
        if runtime.supervised_active {
            mechanisms.push("seccomp_notify".to_string());
        }
        mechanisms
    } else {
        vec!["none".to_string()]
    }
}

fn push_unique_mechanism(mechanisms: &mut Vec<String>, mechanism: &str) {
    if !mechanisms.iter().any(|existing| existing == mechanism) {
        mechanisms.push(mechanism.to_string());
    }
}

fn effective_enforcement_level(runtime: &SandboxRuntimeState) -> EnforcementLevel {
    if !runtime.applied {
        return EnforcementLevel::None;
    }

    let has_degraded_runtime = !runtime.degraded_reasons.is_empty()
        || runtime.deadline_miss_count > 0
        || runtime.dropped_event_count > 0;
    let has_degraded_provider = runtime.provider_states.iter().any(|provider| {
        !provider.active || !provider.healthy || !provider.degraded_reasons.is_empty()
    });
    if has_degraded_runtime || has_degraded_provider {
        return EnforcementLevel::Degraded;
    }

    if runtime.supervised_requested && !runtime.supervised_active {
        return EnforcementLevel::Degraded;
    }

    if runtime.supervised_requested && runtime.supervised_active {
        EnforcementLevel::KernelSupervised
    } else {
        EnforcementLevel::Kernel
    }
}

fn default_provider_states(applied: bool) -> Vec<ProviderState> {
    if cfg!(target_os = "macos") {
        vec![if applied {
            ProviderState::active_without_approval("seatbelt")
        } else {
            ProviderState::unavailable_without_approval("seatbelt", "sandbox_apply_failed")
        }]
    } else {
        Vec::new()
    }
}

fn supervised_contract_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos_endpoint_security_auth_contract"
    } else if cfg!(target_os = "linux") {
        "linux_seccomp_notify_fd_injection"
    } else {
        "supervised_contract_unavailable"
    }
}

fn supervised_authorization_model() -> &'static str {
    if cfg!(target_os = "macos") {
        "auth_open_point_in_time"
    } else if cfg!(target_os = "linux") {
        "fd_injection"
    } else {
        "none"
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use nono::{AccessMode, CapabilitySet};

    #[test]
    fn test_build_attestation_basic() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = CapabilitySet::new()
            .allow_path(tmp.path(), AccessMode::ReadWrite)
            .unwrap()
            .block_network();

        let attestation = build_attestation(&caps, SandboxRuntimeState::static_mode(true, None));
        assert!(!attestation.capabilities.fs.is_empty());
        assert_eq!(attestation.capabilities.network_mode, "blocked");
        assert!(attestation.denials.is_empty());
        assert!(attestation.supervisor.is_none());
        assert!(attestation.runtime.applied);
    }

    #[test]
    fn test_build_attestation_supervised() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = CapabilitySet::new()
            .allow_path(tmp.path(), AccessMode::Read)
            .unwrap();

        let attestation = build_attestation(
            &caps,
            SandboxRuntimeState::supervised_mode(true, true, None),
        );
        assert_eq!(
            attestation.enforcement_level,
            EnforcementLevel::KernelSupervised
        );
    }

    #[test]
    fn test_build_attestation_failed_apply_is_not_enforced() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = CapabilitySet::new()
            .allow_path(tmp.path(), AccessMode::Read)
            .unwrap();

        let attestation = build_attestation(
            &caps,
            SandboxRuntimeState::static_mode(false, Some("sandbox apply failed".to_string())),
        );

        assert!(!attestation.enforced);
        assert_eq!(attestation.enforcement_level, EnforcementLevel::None);
        assert_eq!(
            attestation.runtime.failure_reason.as_deref(),
            Some("sandbox apply failed")
        );
    }

    #[test]
    fn test_attestation_serializes_to_json() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = CapabilitySet::new()
            .allow_path(tmp.path(), AccessMode::ReadWrite)
            .unwrap()
            .proxy_only(8080)
            .block_command("rm");

        let attestation = build_attestation(&caps, SandboxRuntimeState::static_mode(true, None));
        let json = serde_json::to_value(&attestation).unwrap();
        let expected_mechanism = if cfg!(target_os = "linux") {
            "landlock"
        } else if cfg!(target_os = "macos") {
            "seatbelt"
        } else {
            "none"
        };

        assert!(json["enforced"].is_boolean());
        assert!(json["runtime"]["applied"].is_boolean());
        assert!(json["capabilities"]["proxy_port"].as_u64().is_some());
        assert_eq!(json["capabilities"]["proxy_port"].as_u64().unwrap(), 8080);
        assert_eq!(
            json["platform"]["mechanism"].as_str(),
            Some(expected_mechanism)
        );
        assert!(json["platform"]["mechanisms"].is_array());
        assert!(
            json.get("provider_states").is_none(),
            "top-level provider_states should not be duplicated outside runtime"
        );
        assert!(!json["capabilities"]["blocked_commands"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_enforcement_level_roundtrip() {
        let level = EnforcementLevel::Kernel;
        let s = level.to_string();
        let parsed: EnforcementLevel = s.parse().unwrap();
        assert_eq!(parsed, level);
    }

    #[test]
    fn test_attestation_metadata_path() {
        // Verify the structure matches what is_kernel_enforced() expects
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = CapabilitySet::new()
            .allow_path(tmp.path(), AccessMode::Read)
            .unwrap()
            .block_network();

        let attestation = build_attestation(&caps, SandboxRuntimeState::static_mode(true, None));
        let sandbox_json = serde_json::to_value(&attestation).unwrap();
        let meta = serde_json::json!({ "sandbox": sandbox_json });

        let enforced = meta
            .get("sandbox")
            .and_then(|s| s.get("enforced"))
            .and_then(|e| e.as_bool())
            .unwrap_or(false);
        assert!(enforced, "should read enforced from metadata path");

        let level = meta
            .get("sandbox")
            .and_then(|s| s.get("enforcement_level"))
            .and_then(|l| l.as_str())
            .map(String::from);
        assert_eq!(level, Some("kernel".to_string()));
    }

    #[test]
    fn test_dropped_events_degrade_attestation() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = CapabilitySet::new()
            .allow_path(tmp.path(), AccessMode::Read)
            .unwrap();

        let mut attestation =
            build_attestation(&caps, SandboxRuntimeState::static_mode(true, None));
        attestation.runtime.set_dropped_event_count(3);
        attestation.recompute_status();

        assert_eq!(attestation.enforcement_level, EnforcementLevel::Degraded);
        assert!(!attestation.enforced);
        assert_eq!(attestation.runtime.dropped_event_count, 3);
    }

    #[test]
    fn test_inactive_supervision_degrades_even_without_explicit_reason() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = CapabilitySet::new()
            .allow_path(tmp.path(), AccessMode::Read)
            .unwrap();
        let runtime = SandboxRuntimeState {
            supported: true,
            applied: true,
            supervised_requested: true,
            supervised_active: false,
            contract: supervised_contract_name().to_string(),
            authorization_model: supervised_authorization_model().to_string(),
            fd_injection_equivalent: cfg!(target_os = "linux"),
            fail_open_possible: cfg!(target_os = "macos"),
            deadline_miss_count: 0,
            dropped_event_count: 0,
            degraded_reasons: Vec::new(),
            provider_states: default_provider_states(true),
            failure_reason: None,
        };

        let attestation = build_attestation(&caps, runtime);

        assert_eq!(attestation.enforcement_level, EnforcementLevel::Degraded);
        assert!(!attestation.enforced);
    }

    #[test]
    fn test_macos_supervised_contract_is_not_fd_injection_equivalent() {
        let runtime = SandboxRuntimeState::supervised_mode(true, false, None);

        if cfg!(target_os = "macos") {
            assert_eq!(runtime.contract, "macos_endpoint_security_auth_contract");
            assert_eq!(runtime.authorization_model, "auth_open_point_in_time");
            assert!(!runtime.fd_injection_equivalent);
            assert!(runtime.fail_open_possible);
            assert!(runtime
                .degraded_reasons
                .iter()
                .any(|reason| reason == "macos_authorization_contract_unavailable"));
        }
    }

    #[test]
    fn test_legacy_attestation_shape_still_deserializes() {
        let legacy = serde_json::json!({
            "enforced": true,
            "enforcement_level": "kernel",
            "platform": {
                "name": "macos",
                "mechanism": "seatbelt",
                "abi_version": null,
                "details": "legacy seatbelt sandbox"
            },
            "runtime": {
                "supported": true,
                "applied": true,
                "supervised_requested": false,
                "supervised_active": false,
                "failure_reason": null
            },
            "capabilities": {
                "fs": [],
                "network_mode": "blocked",
                "proxy_port": null,
                "signal_mode": "Isolated",
                "blocked_commands": [],
                "extensions_enabled": false
            }
        });

        let parsed: SandboxAttestation =
            serde_json::from_value(legacy).expect("legacy attestation should deserialize");

        assert_eq!(parsed.platform.mechanisms, vec!["seatbelt".to_string()]);
        assert_eq!(parsed.runtime.contract, "legacy_attestation");
        assert_eq!(parsed.runtime.authorization_model, "unknown");
        assert_eq!(parsed.runtime.deadline_miss_count, 0);
        assert_eq!(parsed.runtime.dropped_event_count, 0);
    }

    #[test]
    fn test_platform_mechanisms_only_include_active_supervised_contracts() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = CapabilitySet::new()
            .allow_path(tmp.path(), AccessMode::Read)
            .unwrap();
        let runtime =
            SandboxRuntimeState::supervised_mode(true, true, None).with_provider_states(vec![
                ProviderState::active_without_approval("seatbelt"),
                ProviderState::active("endpoint_security"),
                ProviderState::unknown("network_extension", "provider_state_unknown"),
            ]);

        let attestation = build_attestation(&caps, runtime);
        let mechanisms = &attestation.platform.mechanisms;

        if cfg!(target_os = "macos") {
            assert!(mechanisms.iter().any(|value| value == "seatbelt"));
            assert_eq!(
                mechanisms
                    .iter()
                    .filter(|value| *value == "seatbelt")
                    .count(),
                1
            );
            assert!(mechanisms
                .iter()
                .any(|value| value == "endpoint_security_contract"));
            assert!(!mechanisms
                .iter()
                .any(|value| value == "network_extension_contract"));
        }
    }
}
