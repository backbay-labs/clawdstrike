//! HushEngine - Main entry point for security enforcement

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use hush_core::receipt::ViolationRef;
use hush_core::{sha256, Hash, Keypair};

use crate::async_guards::{AsyncGuard, AsyncGuardRuntime};
use crate::error::Result;
use crate::guards::{Guard, GuardContext};
use crate::pipeline::EvaluationPath;
use crate::policy::{Policy, PolicyGuards};
use crate::posture::PostureProgram;

mod aggregate;
mod bridge;
mod check_api;
mod construct;
mod evaluate;
mod posture;
mod prechecks;
mod receipts;
mod types;

pub(crate) use aggregate::aggregate_overall;
pub use construct::HushEngineBuilder;
#[cfg(test)]
pub(crate) use prechecks::tool_matches;
pub use types::{
    EngineStats, GuardEvaluationMetadata, GuardReport, GuardResolvedEnclave, PostureAwareReport,
};

pub(crate) struct PreparedContext {
    pub(crate) context: GuardContext,
    pub(crate) metadata: Option<GuardEvaluationMetadata>,
}

pub(crate) enum PreparedEvaluation {
    Continue(Box<PreparedContext>),
    Complete(Box<GuardReport>),
}

/// The main security enforcement engine
pub struct HushEngine {
    /// Active policy
    pub(crate) policy: Policy,
    /// Instantiated guards
    pub(crate) guards: PolicyGuards,
    /// Policy-driven custom guards (evaluated after built-ins)
    pub(crate) custom_guards: Vec<Box<dyn Guard>>,
    /// Additional guards appended at runtime (evaluated after built-ins)
    pub(crate) extra_guards: Vec<Box<dyn Guard>>,
    /// Signing keypair (optional)
    pub(crate) keypair: Option<Keypair>,
    /// Session state
    pub(crate) state: Arc<RwLock<EngineState>>,
    /// Sticky configuration error (fail-closed).
    pub(crate) config_error: Option<String>,
    /// Async guard runtime
    pub(crate) async_runtime: Arc<AsyncGuardRuntime>,
    /// Async guards instantiated from policy
    pub(crate) async_guards: Vec<Arc<dyn AsyncGuard>>,
    /// Async guard initialization error (fail closed)
    pub(crate) async_guard_init_error: Option<String>,
    /// Compiled posture program (if policy posture is configured)
    pub(crate) posture_program: Option<PostureProgram>,
}

/// Engine session state
#[derive(Default)]
pub(crate) struct EngineState {
    /// Number of actions checked
    pub(crate) action_count: u64,
    /// Number of violations
    pub(crate) violation_count: u64,
    /// Recent violations
    pub(crate) violations: Vec<ViolationRef>,
    /// Last internal evaluation path observed for a check.
    pub(crate) last_evaluation_path: Option<EvaluationPath>,
    /// Aggregate count of observed stage paths (for receipt summary).
    pub(crate) evaluation_path_counts: HashMap<String, u64>,
}

impl HushEngine {
    /// Get the policy hash (derived from the policy YAML).
    ///
    /// Note: this does not include any runtime `extra_guards`.
    pub fn policy_hash(&self) -> Result<Hash> {
        let yaml = self.policy.to_yaml()?;
        Ok(sha256(yaml.as_bytes()))
    }

    /// Get the active policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Get the active policy YAML.
    pub fn policy_yaml(&self) -> Result<String> {
        self.policy.to_yaml()
    }

    /// Get the signing keypair, if configured.
    pub fn keypair(&self) -> Option<&Keypair> {
        self.keypair.as_ref()
    }
}

#[cfg(test)]
mod tests;
