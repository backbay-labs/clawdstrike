//! Sandbox attestation types for receipt integration.
//!
//! These types capture the sandbox enforcement state for inclusion in
//! signed receipts. They are ClawdStrike-owned serializable types built
//! from nono's CapabilitySet accessors.

use serde::{Deserialize, Serialize};

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
}

impl std::fmt::Display for EnforcementLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnforcementLevel::None => write!(f, "none"),
            EnforcementLevel::Kernel => write!(f, "kernel"),
            EnforcementLevel::KernelSupervised => write!(f, "kernel_supervised"),
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
            _ => Err(format!("unknown enforcement level: {}", s)),
        }
    }
}

/// Platform sandbox information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    pub name: String,
    pub mechanism: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abi_version: Option<u32>,
    pub details: String,
}

/// Runtime enforcement state captured after execution completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxRuntimeState {
    pub supported: bool,
    pub applied: bool,
    pub supervised_requested: bool,
    pub supervised_active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl SandboxRuntimeState {
    #[must_use]
    pub fn static_mode(applied: bool, failure_reason: Option<String>) -> Self {
        let support = nono::Sandbox::support_info();
        Self {
            supported: support.is_supported,
            applied,
            supervised_requested: false,
            supervised_active: false,
            failure_reason,
        }
    }

    #[must_use]
    pub fn supervised_mode(
        applied: bool,
        supervised_active: bool,
        failure_reason: Option<String>,
    ) -> Self {
        let support = nono::Sandbox::support_info();
        Self {
            supported: support.is_supported,
            applied,
            supervised_requested: true,
            supervised_active,
            failure_reason,
        }
    }
}

/// Snapshot of filesystem and network capabilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySnapshot {
    pub fs: Vec<FsCapSnapshot>,
    pub network_mode: String,
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

    let proxy_port = match caps.network_mode() {
        nono::NetworkMode::ProxyOnly { port, .. } => Some(*port),
        _ => None,
    };

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
        network_mode: format!("{}", caps.network_mode()),
        proxy_port,
        signal_mode: format!("{:?}", caps.signal_mode()),
        blocked_commands: caps.blocked_commands().to_vec(),
        extensions_enabled: caps.extensions_enabled(),
    };

    let mechanism = if cfg!(target_os = "macos") {
        "seatbelt"
    } else if cfg!(target_os = "linux") {
        "landlock"
    } else {
        "none"
    };

    let enforced = runtime.applied && (!runtime.supervised_requested || runtime.supervised_active);
    let enforcement_level = if !enforced {
        EnforcementLevel::None
    } else if runtime.supervised_active {
        EnforcementLevel::KernelSupervised
    } else {
        EnforcementLevel::Kernel
    };

    SandboxAttestation {
        enforced,
        enforcement_level,
        platform: PlatformInfo {
            name: support.platform.to_string(),
            mechanism: mechanism.to_string(),
            abi_version: None,
            details: support.details,
        },
        runtime,
        capabilities: cap_snapshot,
        supervisor: None,
        denials: vec![],
        audit: vec![],
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

        assert!(json["enforced"].is_boolean());
        assert!(json["runtime"]["applied"].is_boolean());
        assert!(json["capabilities"]["proxy_port"].as_u64().is_some());
        assert_eq!(json["capabilities"]["proxy_port"].as_u64().unwrap(), 8080);
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
}
