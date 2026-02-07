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
//! ```rust
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
//! ```rust
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

pub mod async_guards;
pub mod curator_config;
pub mod engine;
pub mod error;
pub mod guards;
pub mod hygiene;
pub mod identity;
pub mod instruction_hierarchy;
pub mod irm;
pub mod jailbreak;
pub mod marketplace_feed;
pub mod output_sanitizer;
pub mod pipeline;
mod placeholders;
pub mod plugins;
pub mod policy;
pub mod policy_bundle;
pub mod posture;
pub mod spine_bridge;
pub mod watermarking;

pub use curator_config::{
    default_config_path, CuratorConfig, CuratorConfigFile, CuratorEntry, CuratorTrustSet,
    RichCuratorConfigFile, TrustLevel, ValidatedCurator,
};
pub use engine::{GuardReport, HushEngine, PostureAwareReport};
pub use error::{Error, Result};
pub use guards::{
    CustomGuardFactory, CustomGuardRegistry, EgressAllowlistGuard, ForbiddenPathGuard, Guard,
    GuardContext, GuardResult, JailbreakConfig, JailbreakGuard, McpToolGuard, PatchIntegrityGuard,
    PathAllowlistGuard, PromptInjectionGuard, SecretLeakGuard, Severity,
};
pub use hygiene::{
    detect_prompt_injection, detect_prompt_injection_with_limit, wrap_user_content, DedupeStatus,
    FingerprintDeduper, PromptInjectionLevel, PromptInjectionReport, USER_CONTENT_END,
    USER_CONTENT_START,
};
pub use identity::{
    AuthMethod, GeoLocation, IdentityPrincipal, IdentityProvider, OrganizationContext,
    OrganizationTier, RequestContext, SessionContext, SessionMetadata,
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
    LinearModelConfig, LlmJudge, SessionAggPersisted, SessionRiskSnapshot, SessionStore,
};
pub use marketplace_feed::{
    ContentIds, InclusionProofBundle, MarketplaceEntry, MarketplaceFeed, MarketplaceProvenance,
    SignedMarketplaceFeed, WitnessSignatureRef, MARKETPLACE_FEED_SCHEMA_VERSION,
};

#[cfg(feature = "ipfs")]
pub mod ipfs;
pub use output_sanitizer::{
    AllowlistConfig, DenylistConfig, DetectorType, EntityFinding, EntityRecognizer,
    OutputSanitizer, OutputSanitizerConfig, ProcessingStats, Redaction, RedactionStrategy,
    SanitizationResult, SanitizationStream, SensitiveCategory, SensitiveDataFinding, Span,
    StreamingConfig,
};
pub use pipeline::{EvaluationPath, EvaluationStage};
#[cfg(feature = "wasm-plugin-runtime")]
pub use plugins::{
    execute_wasm_guard_bytes, execute_wasm_guard_module, validate_wasm_guard_module,
    WasmGuardExecution, WasmGuardInputEnvelope, WasmGuardRuntimeOptions, WasmRuntimeAuditRecord,
};
pub use plugins::{
    parse_plugin_manifest_toml, resolve_plugin_root, PluginExecutionMode, PluginInspectResult,
    PluginLoadPlan, PluginLoader, PluginLoaderOptions, PluginManifest,
};
pub use policy::{Policy, RuleSet};
pub use policy_bundle::{PolicyBundle, SignedPolicyBundle, POLICY_BUNDLE_SCHEMA_VERSION};
pub use posture::{
    PostureBudgetCounter, PostureConfig, PostureProgram, PostureRuntimeState, PostureState,
    PostureTransition, PostureTransitionRecord, RuntimeTransitionTrigger, TransitionRequirement,
    TransitionTrigger,
};
pub use spine_bridge::{
    extract_spine_envelope_hash, policy_bundle_to_spine_envelope, POLICY_BUNDLE_FACT_TYPE,
};
pub use watermarking::{
    EncodedWatermark, PromptWatermarker, WatermarkConfig, WatermarkEncoding, WatermarkError,
    WatermarkExtractionResult, WatermarkExtractor, WatermarkPayload, WatermarkVerifierConfig,
    WatermarkedPrompt,
};

// IRM exports
pub use irm::{
    Decision, EventType, ExecOperation, ExecutionIrm, FilesystemIrm, FsOperation, HostCall,
    HostCallMetadata, IrmEvent, IrmRouter, Monitor, NetOperation, NetworkIrm, Sandbox,
    SandboxConfig, SandboxStats,
};

/// Re-export core types
pub mod core {
    pub use hush_core::*;
}
