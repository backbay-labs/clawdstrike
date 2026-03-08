//! Sandbox integration module.
//!
//! Translates ClawdStrike guard policies into nono `CapabilitySet` operations
//! for kernel-level enforcement.

pub mod attestation;
pub mod capability_builder;
pub mod preflight;

pub use attestation::{
    build_attestation, AuditEntry, CapabilitySnapshot, EnforcementLevel, FsCapSnapshot,
    PlatformInfo, SandboxAttestation, SandboxRuntimeState, SupervisorStats, TimestampedDenial,
};
pub mod never_grant;
pub mod supervisor;

pub use capability_builder::{CapabilityBuilder, TranslationWarning, WarningSeverity};
pub use never_grant::build_never_grant_list;
pub use preflight::{preflight_check, PreflightResult};
pub use supervisor::GuardSupervisorBackend;
