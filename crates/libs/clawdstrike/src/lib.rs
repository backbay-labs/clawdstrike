#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! # Clawdstrike - Security Guards and Policy Engine
//!
//! This crate provides security guards for AI agent execution:
//! - `ForbiddenPathGuard`: Blocks access to sensitive paths
//! - `EgressAllowlistGuard`: Controls network egress
//! - `SecretLeakGuard`: Detects potential secret exposure
//! - `PatchIntegrityGuard`: Validates patch safety
//! - `McpToolGuard`: Restricts MCP tool invocations
//! - `PromptInjectionGuard`: Detects prompt-injection in untrusted text
//! - `JailbreakGuard`: Detects jailbreak attempts in user input
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use clawdstrike::{ForbiddenPathGuard, SecretLeakGuard};
//!
//! // Check if a path is forbidden
//! let guard = ForbiddenPathGuard::new();
//! assert!(guard.is_forbidden("/home/user/.ssh/id_rsa"));
//! assert!(!guard.is_forbidden("/app/src/main.rs"));
//!
//! // Scan content for secrets
//! let secret_guard = SecretLeakGuard::new();
//! let matches = secret_guard.scan(b"api_key = sk-1234567890abcdef");
//! // Would detect potential API key
//! ```
//!
//! ## Policy Configuration
//!
//! ```rust,ignore
//! use clawdstrike::Policy;
//!
//! let yaml = r#"
//! version: "1.1.0"
//! name: "example"
//! settings:
//!   fail_fast: true
//! "#;
//!
//! let policy = Policy::from_yaml(yaml).unwrap();
//! assert_eq!(policy.version, "1.1.0");
//! ```

// ============================================================================
// Always compiled: detection modules (WASM-compatible)
// ============================================================================

pub mod hygiene;
pub mod instruction_hierarchy;
pub mod jailbreak;
pub mod origin;
pub mod output_sanitizer;
pub mod spider_sense;
pub mod text_utils;

pub use hygiene::{
    detect_prompt_injection, detect_prompt_injection_with_limit, wrap_user_content, DedupeStatus,
    FingerprintDeduper, PromptInjectionLevel, PromptInjectionReport, USER_CONTENT_END,
    USER_CONTENT_START,
};
pub use instruction_hierarchy::{
    ConflictAction, ConflictSeverity, ContentModification, CustomMarkers, EnforcementAction,
    EnforcementActionType, HierarchyConflict, HierarchyEnforcementResult, HierarchyEnforcerConfig,
    HierarchyError, HierarchyMessage, HierarchyState, HierarchyStats, InstructionHierarchyEnforcer,
    InstructionLevel, MarkerFormat, MessageMetadata, MessageRole, MessageSource,
    ProcessingStats as HierarchyProcessingStats, RulesConfig, SourceType,
};
pub use jailbreak::{
    JailbreakCanonicalizationStats, JailbreakCategory, JailbreakDetectionResult, JailbreakDetector,
    JailbreakGuardConfig, JailbreakSeverity, JailbreakSignal, LayerResult, LayerResults,
    LinearModelConfig, SessionAggPersisted, SessionRiskSnapshot,
};
pub use origin::{
    ActorType, OriginContext, OriginProvider, ProvenanceConfidence, SpaceType, Visibility,
};
pub use output_sanitizer::{
    AllowlistConfig, DenylistConfig, DetectorType, EntityFinding, EntityRecognizer,
    OutputSanitizer, OutputSanitizerConfig, ProcessingStats, Redaction, RedactionStrategy,
    SanitizationResult, SanitizationStream, SensitiveCategory, SensitiveDataFinding, Span,
    StreamingConfig,
};
pub use spider_sense::{
    PatternDb, PatternEntry, PatternMatch, ScreeningResult, ScreeningVerdict, SpiderSenseDetector,
    SpiderSenseDetectorConfig,
};

// ============================================================================
// Full feature: guards, policy engine, infrastructure (requires tokio, etc.)
// ============================================================================

#[cfg(feature = "full")]
pub mod async_guards;
#[cfg(feature = "full")]
pub mod curator_config;
#[cfg(feature = "full")]
pub mod decision_taxonomy;
#[cfg(feature = "full")]
pub mod enclave;
#[cfg(feature = "full")]
pub mod engine;
#[cfg(any(feature = "full", feature = "policy-event"))]
pub mod error;
#[cfg(any(feature = "full", feature = "policy-event"))]
pub mod guards;
#[cfg(any(feature = "full", feature = "policy-event"))]
pub mod hushspec_compiler;
#[cfg(any(feature = "full", feature = "policy-event"))]
pub mod identity;
#[cfg(feature = "full")]
pub mod irm;
#[cfg(feature = "full")]
pub mod marketplace_feed;
#[cfg(feature = "full")]
pub mod origin_runtime;
#[cfg(feature = "full")]
pub mod pipeline;
#[cfg(feature = "full")]
pub mod pkg;
#[cfg(any(feature = "full", feature = "policy-event"))]
mod placeholders;
#[cfg(feature = "full")]
pub mod plugins;
#[cfg(any(feature = "full", feature = "policy-event"))]
pub mod policy;
#[cfg(feature = "full")]
pub mod policy_bundle;
#[cfg(any(feature = "full", feature = "policy-event"))]
pub mod posture;
#[cfg(all(feature = "full", unix))]
pub mod sandbox;
#[cfg(feature = "full")]
mod semver_utils;
#[cfg(all(feature = "full", feature = "spine"))]
pub mod spine_bridge;
#[cfg(feature = "full")]
pub mod watermarking;

#[cfg(feature = "full")]
pub use curator_config::{
    default_config_path, CuratorConfig, CuratorConfigFile, CuratorEntry, CuratorTrustSet,
    RichCuratorConfigFile, TrustLevel, ValidatedCurator,
};
#[cfg(feature = "full")]
pub use enclave::{EnclaveResolver, ResolvedEnclave};
#[cfg(feature = "full")]
pub use engine::{GuardReport, HushEngine, PostureAwareReport};
#[cfg(any(feature = "full", feature = "policy-event"))]
pub use error::{Error, Result};
#[cfg(any(feature = "full", feature = "policy-event"))]
pub use guards::{
    CustomGuardFactory, CustomGuardRegistry, EgressAllowlistGuard, ForbiddenPathGuard, Guard,
    GuardContext, GuardResult, JailbreakConfig, JailbreakGuard, McpToolGuard, PatchIntegrityGuard,
    PathAllowlistGuard, PromptInjectionGuard, SecretLeakGuard, Severity,
};
#[cfg(any(feature = "full", feature = "policy-event"))]
pub use identity::{
    AuthMethod, GeoLocation, IdentityPrincipal, IdentityProvider, OrganizationContext,
    OrganizationTier, RequestContext, SessionContext, SessionMetadata,
};
#[cfg(feature = "full")]
pub use jailbreak::{LlmJudge, SessionStore};
#[cfg(feature = "full")]
pub use marketplace_feed::{
    ContentIds, InclusionProofBundle, MarketplaceEntry, MarketplaceFeed, MarketplaceProvenance,
    SignedMarketplaceFeed, WitnessSignatureRef, MARKETPLACE_FEED_SCHEMA_VERSION,
};

#[cfg(feature = "ipfs")]
pub mod ipfs;

#[cfg(any(feature = "full", feature = "policy-event"))]
pub use hushspec_compiler::{compile_hushspec, is_hushspec};
#[cfg(feature = "full")]
pub use pipeline::{EvaluationPath, EvaluationStage};
#[cfg(feature = "full")]
pub use pkg::PackagePolicyResolver;
#[cfg(feature = "wasm-plugin-runtime")]
pub use plugins::{
    execute_wasm_guard_bytes, execute_wasm_guard_module, validate_wasm_guard_module,
    WasmGuardExecution, WasmGuardInputEnvelope, WasmGuardRuntimeOptions, WasmRuntimeAuditRecord,
};
#[cfg(feature = "full")]
pub use plugins::{
    parse_plugin_manifest_toml, resolve_plugin_root, PluginExecutionMode, PluginInspectResult,
    PluginLoadPlan, PluginLoader, PluginLoaderOptions, PluginManifest,
};
#[cfg(any(feature = "full", feature = "policy-event"))]
pub use policy::{Policy, RuleSet};
#[cfg(feature = "full")]
pub use policy_bundle::{PolicyBundle, SignedPolicyBundle, POLICY_BUNDLE_SCHEMA_VERSION};
#[cfg(any(feature = "full", feature = "policy-event"))]
pub use posture::{
    PostureBudgetCounter, PostureConfig, PostureProgram, PostureRuntimeState, PostureState,
    PostureTransition, PostureTransitionRecord, RuntimeTransitionTrigger, TransitionRequirement,
    TransitionTrigger,
};
#[cfg(all(feature = "full", feature = "spine"))]
pub use spine_bridge::{
    extract_spine_envelope_hash, policy_bundle_to_spine_envelope, POLICY_BUNDLE_FACT_TYPE,
};
#[cfg(feature = "full")]
pub use watermarking::{
    EncodedWatermark, PromptWatermarker, WatermarkConfig, WatermarkEncoding, WatermarkError,
    WatermarkExtractionResult, WatermarkExtractor, WatermarkPayload, WatermarkVerifierConfig,
    WatermarkedPrompt,
};

#[cfg(feature = "full")]
pub use irm::{
    Decision, EventType, ExecOperation, ExecutionIrm, FilesystemIrm, FsOperation, HostCall,
    HostCallMetadata, IrmEvent, IrmRouter, Monitor, NetOperation, NetworkIrm, Sandbox,
    SandboxConfig, SandboxStats,
};
#[cfg(feature = "full")]
pub use origin_runtime::{OriginFingerprint, OriginRuntimeState};

pub mod crypto {
    pub use hush_core::*;
}

/// Preserves the historical `hush_core::*` re-export while adding the
/// pure decision core (`CoreSeverity`, `CoreVerdict`, etc.).
pub mod core;

#[cfg(test)]
mod tests {
    #[test]
    fn core_namespace_preserves_hush_core_and_decision_core_exports() {
        let _ = crate::core::sha256(b"clawdstrike");
        let _ = crate::core::CoreSeverity::Info;
        let _ = std::mem::size_of::<crate::core::Error>();
        let _: crate::core::Result<()> = Ok(());
    }
}
