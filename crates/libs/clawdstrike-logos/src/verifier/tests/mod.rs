//! Unit tests for the verifier, split into theme files and reunified here.
//!
//! Declared `#[cfg(test)] mod tests;` from `verifier.rs`. The theme files are
//! `include!`d (not `mod`-declared) so they share this single module's
//! `use super::*` import surface and the fixtures below, exactly as when they
//! lived in one inline `mod tests` block.
#![allow(
    clippy::expect_used,
    clippy::field_reassign_with_default,
    clippy::unwrap_used
)]

    use super::*;
    use crate::atoms::ActionKind;
    use clawdstrike::guards::{
        EgressAllowlistConfig, ForbiddenPathConfig, McpToolConfig, PathAllowlistConfig,
        PromptInjectionConfig, SecretLeakConfig, ShellCommandConfig,
    };
    use clawdstrike::policy::{GuardConfigs, Policy, RuleSet, VerificationSettings};
    use hush_proxy::policy::PolicyAction;
    use logos_ffi::AgentId;

    fn agent() -> AgentId {
        AgentId::new("test-agent")
    }

    fn formula_verifier() -> PolicyVerifier {
        PolicyVerifier::new()
    }

    fn simple_forbidden_path(path: &str) -> ForbiddenPathConfig {
        ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec![path.to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        }
    }

include!("core.rs");
include!("inheritance.rs");
include!("witness_synthesis.rs");
include!("load_time.rs");
include!("z3.rs");
