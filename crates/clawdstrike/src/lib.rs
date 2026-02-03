#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! # Clawdstrike - Security Guards and Policy Engine
//!
//! This crate provides security guards for AI agent execution:
//! - `ForbiddenPathGuard`: Blocks access to sensitive paths
//! - `EgressAllowlistGuard`: Controls network egress
//! - `SecretLeakGuard`: Detects potential secret exposure
//! - `PatchIntegrityGuard`: Validates patch safety
//! - `McpToolGuard`: Restricts MCP tool invocations
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
//! version: "1.0.0"
//! name: "example"
//! settings:
//!   fail_fast: true
//! "#;
//!
//! let policy = Policy::from_yaml(yaml).unwrap();
//! assert_eq!(policy.version, "1.0.0");
//! ```

pub mod engine;
pub mod error;
pub mod guards;
pub mod hygiene;
pub mod instruction_hierarchy;
pub mod irm;
pub mod jailbreak;
pub mod output_sanitizer;
pub mod policy;
pub mod watermarking;

pub use engine::{GuardReport, HushEngine};
pub use error::{Error, Result};
pub use guards::{
    EgressAllowlistGuard, ForbiddenPathGuard, Guard, GuardContext, GuardResult, JailbreakConfig,
    JailbreakGuard, McpToolGuard, PatchIntegrityGuard, PromptInjectionGuard, SecretLeakGuard,
    Severity,
};
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
    SessionRiskSnapshot,
};
pub use output_sanitizer::{
    DetectorType, OutputSanitizer, OutputSanitizerConfig, ProcessingStats, Redaction,
    RedactionStrategy, SanitizationResult, SensitiveCategory, SensitiveDataFinding, Span,
};
pub use policy::{Policy, RuleSet};
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
