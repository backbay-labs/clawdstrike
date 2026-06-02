//! HushEngine - Main entry point for security enforcement

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use hush_core::receipt::ViolationRef;
use hush_core::{sha256, Hash, Keypair};

use crate::async_guards::{AsyncGuard, AsyncGuardRuntime};
use crate::enclave::EnclaveResolver;
use crate::error::Result;
use crate::guards::{Guard, GuardAction, GuardContext, GuardResult, Severity};
use crate::origin::OriginContext;
use crate::origin_runtime::{
    normalize_origin_budgets, origin_budget_counters, OriginFingerprint, OriginRuntimeState,
};
use crate::pipeline::{builtin_stage_for_guard_name, EvaluationPath, EvaluationStage};
use crate::policy::{OriginDefaultBehavior, Policy, PolicyGuards};
use crate::posture::PostureProgram;

mod aggregate;
mod bridge;
mod check_api;
mod construct;
mod posture;
mod prechecks;
mod receipts;
mod types;

pub(crate) use aggregate::aggregate_overall;
use bridge::{check_bridge_policy, format_origin_brief, BridgeCheckResult};
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

    /// Record a one-result evaluation and return a single-guard report.
    pub(crate) async fn single_result_report(
        &self,
        result: GuardResult,
        metadata: Option<GuardEvaluationMetadata>,
    ) -> GuardReport {
        let mut state = self.state.write().await;
        state.action_count += 1;
        state.last_evaluation_path = None;
        if !result.allowed {
            state.violation_count += 1;
            state.violations.push(ViolationRef {
                guard: result.guard.clone(),
                severity: format!("{:?}", result.severity).to_ascii_lowercase(),
                message: result.message.clone(),
                action: None,
            });
        }
        GuardReport {
            overall: result.clone(),
            per_guard: vec![result],
            evaluation_path: None,
            metadata,
        }
    }

    pub(crate) fn build_report_metadata(
        origin: Option<&OriginContext>,
        enclave: Option<&crate::enclave::ResolvedEnclave>,
    ) -> Option<GuardEvaluationMetadata> {
        let origin = origin.cloned();
        let enclave = enclave.map(|value| GuardResolvedEnclave {
            profile_id: value.profile_id.clone(),
            resolution_path: value.resolution_path.clone(),
        });
        if origin.is_none() && enclave.is_none() {
            return None;
        }
        Some(GuardEvaluationMetadata { origin, enclave })
    }

    pub(crate) fn report_metadata_for_context(
        context: &GuardContext,
    ) -> Option<GuardEvaluationMetadata> {
        Self::build_report_metadata(context.origin.as_ref(), context.enclave.as_ref())
    }

    pub(crate) async fn prepare_origin_context(
        &self,
        context: &GuardContext,
        origin_state: Option<&mut Option<OriginRuntimeState>>,
    ) -> Result<PreparedEvaluation> {
        let mut effective_context = context.clone();

        if let Some(origins_config) = self.policy.origins.as_ref() {
            match effective_context.origin.as_ref() {
                Some(origin) => {
                    if effective_context.enclave.is_none() {
                        match EnclaveResolver::resolve(origin, origins_config) {
                            Ok(resolved) => {
                                debug!(
                                    profile_id = ?resolved.profile_id,
                                    resolution_path = ?resolved.resolution_path,
                                    "Enclave resolved for origin"
                                );
                                effective_context.enclave = Some(resolved);
                            }
                            Err(err) => {
                                warn!(error = %err, "Enclave resolution failed — denying action");
                                let report = self
                                    .single_result_report(
                                        GuardResult::block(
                                            "enclave",
                                            Severity::Error,
                                            format!("enclave resolution failed: {err}"),
                                        ),
                                        Self::build_report_metadata(
                                            effective_context.origin.as_ref(),
                                            None,
                                        ),
                                    )
                                    .await;
                                return Ok(PreparedEvaluation::Complete(Box::new(report)));
                            }
                        }
                    }
                }
                None => {
                    let established_origin = origin_state
                        .as_ref()
                        .and_then(|state| state.as_ref())
                        .is_some();
                    if established_origin {
                        let report = self
                            .single_result_report(
                                GuardResult::block(
                                    "cross_origin",
                                    Severity::Error,
                                    "origin context required: session has an established origin but this check omits it".to_string(),
                                ),
                                None,
                            )
                            .await;
                        return Ok(PreparedEvaluation::Complete(Box::new(report)));
                    }
                    match origins_config.effective_default_behavior() {
                        OriginDefaultBehavior::Deny => {
                            let report = self
                                .single_result_report(
                                    GuardResult::block(
                                        "origin_required",
                                        Severity::Error,
                                        "origin context required: policy has origins block but no origin was provided".to_string(),
                                    ),
                                    None,
                                )
                                .await;
                            return Ok(PreparedEvaluation::Complete(Box::new(report)));
                        }
                        OriginDefaultBehavior::MinimalProfile => {
                            debug!(
                                "Origins policy present but no origin context — applying minimal_profile fallback"
                            );
                            if effective_context.enclave.is_none() {
                                if let Ok(fallback) = EnclaveResolver::apply_default_behavior(
                                    &OriginDefaultBehavior::MinimalProfile,
                                ) {
                                    effective_context.enclave = Some(fallback);
                                }
                            }
                        }
                    }
                }
            }
        }

        let metadata = Self::report_metadata_for_context(&effective_context);

        if self.policy.origins.is_some() {
            if let Some(origin_state) = origin_state {
                if let Some(origin) = effective_context.origin.clone() {
                    if let Some(current_enclave) = effective_context.enclave.clone() {
                        let current_fingerprint = OriginFingerprint::from(&origin);
                        if let Some(existing) = origin_state.as_ref() {
                            if existing.current_origin_fingerprint != current_fingerprint {
                                match check_bridge_policy(&existing.current_enclave, &origin) {
                                    BridgeCheckResult::Allow => {
                                        debug!("Cross-origin bridge allowed");
                                    }
                                    BridgeCheckResult::RequireApproval => {
                                        let report = self
                                            .single_result_report(
                                                GuardResult::block(
                                                    "cross_origin",
                                                    Severity::Warning,
                                                    format!(
                                                        "cross-origin transition requires approval (from {} to {})",
                                                        format_origin_brief(&existing.current_origin),
                                                        format_origin_brief(&origin),
                                                    ),
                                                ),
                                                metadata.clone(),
                                            )
                                            .await;
                                        return Ok(PreparedEvaluation::Complete(Box::new(report)));
                                    }
                                    BridgeCheckResult::Deny(reason) => {
                                        let report = self
                                            .single_result_report(
                                                GuardResult::block(
                                                    "cross_origin",
                                                    Severity::Error,
                                                    format!(
                                                        "cross-origin transition denied: {reason}"
                                                    ),
                                                ),
                                                metadata.clone(),
                                            )
                                            .await;
                                        return Ok(PreparedEvaluation::Complete(Box::new(report)));
                                    }
                                }
                                let budget_counters =
                                    origin_budget_counters(current_enclave.budgets.as_ref());
                                *origin_state = Some(OriginRuntimeState::new(
                                    origin,
                                    current_enclave,
                                    budget_counters,
                                ));
                            } else if let Some(existing) = origin_state.as_mut() {
                                existing.current_origin = origin;
                                existing.current_origin_fingerprint = current_fingerprint;
                                existing.current_enclave = current_enclave;
                                normalize_origin_budgets(existing);
                            }
                        } else {
                            let budget_counters =
                                origin_budget_counters(current_enclave.budgets.as_ref());
                            *origin_state = Some(OriginRuntimeState::new(
                                origin,
                                current_enclave,
                                budget_counters,
                            ));
                        }
                    }
                }
            }
        }

        Ok(PreparedEvaluation::Continue(Box::new(PreparedContext {
            context: effective_context,
            metadata,
        })))
    }

    pub(crate) async fn check_action_report_prepared(
        &self,
        action: &GuardAction<'_>,
        prepared: PreparedContext,
        origin_state: Option<&mut Option<OriginRuntimeState>>,
    ) -> Result<GuardReport> {
        let PreparedContext { context, metadata } = prepared;

        let mut pre_guard: Vec<GuardResult> = Vec::new();

        if let Some(result) = self.enclave_mcp_precheck(action, &context).await {
            if !result.allowed {
                return Ok(self.single_result_report(result, metadata).await);
            }
            pre_guard.push(result);
        }

        if let Some(result) = self.origin_data_precheck(action, &context).await {
            if !result.allowed {
                return Ok(self.single_result_report(result, metadata).await);
            }
            pre_guard.push(result);
        }

        if let Some(result) = self
            .origin_budget_precheck(action, &context, origin_state.as_deref())
            .await
        {
            if !result.allowed {
                return Ok(self.single_result_report(result, metadata).await);
            }
            pre_guard.push(result);
        }

        for result in &pre_guard {
            self.observe_guard_result(result).await;
        }

        let mut fast_guards: Vec<&dyn Guard> = Vec::new();
        let mut std_guards: Vec<&dyn Guard> = Vec::new();

        for guard in self.guards.builtin_guards_in_order() {
            match builtin_stage_for_guard_name(guard.name()) {
                EvaluationStage::FastPath => fast_guards.push(guard),
                EvaluationStage::StdPath | EvaluationStage::DeepPath => std_guards.push(guard),
            }
        }
        std_guards.extend(self.custom_guards.iter().map(|g| g.as_ref()));
        std_guards.extend(self.extra_guards.iter().map(|g| g.as_ref()));

        let mut per_guard: Vec<GuardResult> = Vec::with_capacity(
            pre_guard.len() + fast_guards.len() + std_guards.len() + self.async_guards.len(),
        );
        per_guard.extend(pre_guard);
        let mut evaluation_path = EvaluationPath::default();
        let fail_fast = self.policy.settings.effective_fail_fast();

        let fast_terminated = self
            .evaluate_guard_stage(
                EvaluationStage::FastPath,
                &fast_guards,
                action,
                &context,
                &mut per_guard,
                &mut evaluation_path,
            )
            .await;

        if !(fast_terminated && fail_fast) {
            let _ = self
                .evaluate_guard_stage(
                    EvaluationStage::StdPath,
                    &std_guards,
                    action,
                    &context,
                    &mut per_guard,
                    &mut evaluation_path,
                )
                .await;
        }

        if per_guard.iter().all(|r| r.allowed) && !self.async_guards.is_empty() {
            let deep_start = Instant::now();
            let async_results = self
                .async_runtime
                .evaluate_async_guards(&self.async_guards, action, &context, fail_fast)
                .await;
            let mut deep_stage_guards: Vec<String> = Vec::new();

            for result in async_results {
                deep_stage_guards.push(result.guard.clone());
                let denied = !result.allowed;
                self.observe_guard_result(&result).await;
                per_guard.push(result);

                if fail_fast && denied {
                    break;
                }
            }

            evaluation_path.record_stage(
                EvaluationStage::DeepPath,
                deep_stage_guards,
                deep_start.elapsed(),
            );
        }

        let overall = aggregate_overall(&per_guard);
        let evaluation_path = (!evaluation_path.is_empty()).then_some(evaluation_path);

        {
            let mut state = self.state.write().await;
            state.action_count += 1;
            state.last_evaluation_path = evaluation_path.clone();
            if let Some(path) = evaluation_path.as_ref() {
                let key = path.path_string();
                if !key.is_empty() {
                    *state.evaluation_path_counts.entry(key).or_insert(0) += 1;
                }
            }
        }

        if overall.allowed {
            self.consume_origin_budget(action, origin_state);
        }

        Ok(GuardReport {
            overall,
            per_guard,
            evaluation_path,
            metadata,
        })
    }

    async fn evaluate_guard_stage(
        &self,
        stage: EvaluationStage,
        guards: &[&dyn Guard],
        action: &GuardAction<'_>,
        context: &GuardContext,
        per_guard: &mut Vec<GuardResult>,
        evaluation_path: &mut EvaluationPath,
    ) -> bool {
        let fail_fast = self.policy.settings.effective_fail_fast();
        let stage_start = Instant::now();
        let mut stage_guards: Vec<String> = Vec::new();
        let mut terminated = false;

        for guard in guards {
            if !guard.handles(action) {
                continue;
            }

            let result = guard.check(action, context).await;
            stage_guards.push(result.guard.clone());
            let denied = !result.allowed;
            self.observe_guard_result(&result).await;
            per_guard.push(result);

            if fail_fast && denied {
                terminated = true;
                break;
            }
        }

        evaluation_path.record_stage(stage, stage_guards, stage_start.elapsed());
        terminated
    }

    async fn observe_guard_result(&self, result: &GuardResult) {
        if self.policy.settings.effective_verbose_logging() {
            debug!(
                guard = result.guard,
                allowed = result.allowed,
                severity = ?result.severity,
                "Guard check completed"
            );
        }

        if !result.allowed {
            let mut state = self.state.write().await;
            state.violation_count += 1;
            state.violations.push(ViolationRef {
                guard: result.guard.clone(),
                severity: format!("{:?}", result.severity).to_ascii_lowercase(),
                message: result.message.clone(),
                action: None,
            });

            warn!(
                guard = result.guard,
                message = result.message,
                "Security violation detected"
            );
        }
    }
}

#[cfg(test)]
mod tests;
