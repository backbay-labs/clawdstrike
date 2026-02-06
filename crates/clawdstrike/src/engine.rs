//! HushEngine - Main entry point for security enforcement

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use hush_core::receipt::{Provenance, Verdict, ViolationRef};
use hush_core::{sha256, Hash, Keypair, Receipt, SignedReceipt};
use serde::{Deserialize, Serialize};

use crate::async_guards::{AsyncGuard, AsyncGuardRuntime};
use crate::error::{Error, Result};
use crate::guards::{CustomGuardRegistry, Guard, GuardAction, GuardContext, GuardResult, Severity};
use crate::pipeline::{builtin_stage_for_guard_name, EvaluationPath, EvaluationStage};
use crate::policy::{Policy, PolicyGuards, RuleSet};
use crate::posture::{
    elapsed_since_timestamp, Capability, PostureBudgetCounter, PostureProgram, PostureRuntimeState,
    PostureTransitionRecord, RuntimeTransitionTrigger,
};

/// Per-guard evidence + an aggregated verdict.
#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardReport {
    pub overall: GuardResult,
    pub per_guard: Vec<GuardResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_path: Option<EvaluationPath>,
}

/// Guard report plus posture runtime updates.
#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PostureAwareReport {
    pub guard_report: GuardReport,
    pub posture_before: String,
    pub posture_after: String,
    pub budgets_before: HashMap<String, PostureBudgetCounter>,
    pub budgets_after: HashMap<String, PostureBudgetCounter>,
    pub budget_deltas: HashMap<String, i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transition: Option<PostureTransitionRecord>,
}

#[derive(Clone, Debug)]
struct PosturePrecheck {
    allowed: bool,
    guard: &'static str,
    severity: Severity,
    message: String,
    trigger: Option<RuntimeTransitionTrigger>,
}

impl PosturePrecheck {
    fn allow() -> Self {
        Self {
            allowed: true,
            guard: "posture",
            severity: Severity::Info,
            message: String::new(),
            trigger: None,
        }
    }

    fn deny(
        guard: &'static str,
        severity: Severity,
        message: String,
        trigger: Option<RuntimeTransitionTrigger>,
    ) -> Self {
        Self {
            allowed: false,
            guard,
            severity,
            message,
            trigger,
        }
    }
}

/// The main security enforcement engine
pub struct HushEngine {
    /// Active policy
    policy: Policy,
    /// Instantiated guards
    guards: PolicyGuards,
    /// Policy-driven custom guards (evaluated after built-ins)
    custom_guards: Vec<Box<dyn Guard>>,
    /// Additional guards appended at runtime (evaluated after built-ins)
    extra_guards: Vec<Box<dyn Guard>>,
    /// Signing keypair (optional)
    keypair: Option<Keypair>,
    /// Session state
    state: Arc<RwLock<EngineState>>,
    /// Sticky configuration error (fail-closed).
    config_error: Option<String>,
    /// Async guard runtime
    async_runtime: Arc<AsyncGuardRuntime>,
    /// Async guards instantiated from policy
    async_guards: Vec<Arc<dyn AsyncGuard>>,
    /// Async guard initialization error (fail closed)
    async_guard_init_error: Option<String>,
    /// Compiled posture program (if policy posture is configured)
    posture_program: Option<PostureProgram>,
}

/// Engine session state
#[derive(Default)]
struct EngineState {
    /// Number of actions checked
    action_count: u64,
    /// Number of violations
    violation_count: u64,
    /// Recent violations
    violations: Vec<ViolationRef>,
    /// Last internal evaluation path observed for a check.
    last_evaluation_path: Option<EvaluationPath>,
    /// Aggregate count of observed stage paths (for receipt summary).
    evaluation_path_counts: HashMap<String, u64>,
}

impl HushEngine {
    /// Create a new engine with default policy
    pub fn new() -> Self {
        Self::with_policy(Policy::default())
    }

    pub fn builder(policy: Policy) -> HushEngineBuilder {
        HushEngineBuilder {
            policy,
            custom_guard_registry: None,
            keypair: None,
        }
    }

    /// Create with a specific policy
    pub fn with_policy(policy: Policy) -> Self {
        let guards = policy.create_guards();
        let async_runtime = Arc::new(AsyncGuardRuntime::new());
        let (async_guards, async_guard_init_error) =
            match crate::async_guards::registry::build_async_guards(&policy) {
                Ok(v) => (v, None),
                Err(e) => (Vec::new(), Some(e.to_string())),
            };

        let (custom_guards, mut config_error) = match build_custom_guards_from_policy(&policy, None)
        {
            Ok(v) => (v, None),
            Err(e) => (Vec::new(), Some(e.to_string())),
        };

        let posture_program = match policy.posture.as_ref() {
            Some(config) => match PostureProgram::from_config(config) {
                Ok(program) => Some(program),
                Err(err) => {
                    config_error = Some(err);
                    None
                }
            },
            None => None,
        };

        Self {
            policy,
            guards,
            custom_guards,
            extra_guards: Vec::new(),
            keypair: None,
            state: Arc::new(RwLock::new(EngineState::default())),
            config_error,
            async_runtime,
            async_guards,
            async_guard_init_error,
            posture_program,
        }
    }

    /// Create from a named ruleset
    pub fn from_ruleset(name: &str) -> Result<Self> {
        let ruleset = RuleSet::by_name(name)?
            .ok_or_else(|| Error::ConfigError(format!("Unknown ruleset: {}", name)))?;
        Ok(Self::with_policy(ruleset.policy))
    }

    /// Set the signing keypair
    pub fn with_keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Generate a new signing keypair
    pub fn with_generated_keypair(mut self) -> Self {
        self.keypair = Some(Keypair::generate());
        self
    }

    /// Append an additional guard (evaluated after all built-in guards).
    ///
    /// Note: when `fail_fast` is enabled, guards after the first violation (including extras)
    /// will not run.
    pub fn with_extra_guard<G>(mut self, guard: G) -> Self
    where
        G: Guard + 'static,
    {
        self.extra_guards.push(Box::new(guard));
        self
    }

    /// Append an additional guard (evaluated after all built-in guards).
    ///
    /// Note: when `fail_fast` is enabled, guards after the first violation (including extras)
    /// will not run.
    pub fn with_extra_guard_box(mut self, guard: Box<dyn Guard>) -> Self {
        self.extra_guards.push(guard);
        self
    }

    /// Append an additional guard (evaluated after all built-in guards).
    ///
    /// Note: when `fail_fast` is enabled, guards after the first violation (including extras)
    /// will not run.
    pub fn add_extra_guard<G>(&mut self, guard: G) -> &mut Self
    where
        G: Guard + 'static,
    {
        self.extra_guards.push(Box::new(guard));
        self
    }

    /// Append an additional guard (evaluated after all built-in guards).
    ///
    /// Note: when `fail_fast` is enabled, guards after the first violation (including extras)
    /// will not run.
    pub fn add_extra_guard_box(&mut self, guard: Box<dyn Guard>) -> &mut Self {
        self.extra_guards.push(guard);
        self
    }

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

    /// Check a file access action
    pub async fn check_file_access(
        &self,
        path: &str,
        context: &GuardContext,
    ) -> Result<GuardResult> {
        self.check_action(&GuardAction::FileAccess(path), context)
            .await
    }

    /// Check a file write action
    pub async fn check_file_write(
        &self,
        path: &str,
        content: &[u8],
        context: &GuardContext,
    ) -> Result<GuardResult> {
        self.check_action(&GuardAction::FileWrite(path, content), context)
            .await
    }

    /// Check a network egress action
    pub async fn check_egress(
        &self,
        host: &str,
        port: u16,
        context: &GuardContext,
    ) -> Result<GuardResult> {
        self.check_action(&GuardAction::NetworkEgress(host, port), context)
            .await
    }

    /// Check a shell command action
    pub async fn check_shell(&self, command: &str, context: &GuardContext) -> Result<GuardResult> {
        self.check_action(&GuardAction::ShellCommand(command), context)
            .await
    }

    /// Check an MCP tool invocation
    pub async fn check_mcp_tool(
        &self,
        tool: &str,
        args: &serde_json::Value,
        context: &GuardContext,
    ) -> Result<GuardResult> {
        self.check_action(&GuardAction::McpTool(tool, args), context)
            .await
    }

    /// Check untrusted text (e.g. fetched web content) for prompt-injection signals.
    ///
    /// This uses `GuardAction::Custom("untrusted_text", ...)` and is evaluated by `PromptInjectionGuard`.
    pub async fn check_untrusted_text(
        &self,
        source: Option<&str>,
        text: &str,
        context: &GuardContext,
    ) -> Result<GuardResult> {
        let payload = match source {
            Some(source) => serde_json::json!({ "source": source, "text": text }),
            None => serde_json::json!({ "text": text }),
        };

        self.check_action(&GuardAction::Custom("untrusted_text", &payload), context)
            .await
    }

    /// Check a patch action
    pub async fn check_patch(
        &self,
        path: &str,
        diff: &str,
        context: &GuardContext,
    ) -> Result<GuardResult> {
        self.check_action(&GuardAction::Patch(path, diff), context)
            .await
    }

    /// Check any action against all applicable guards
    pub async fn check_action(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
    ) -> Result<GuardResult> {
        Ok(self.check_action_report(action, context).await?.overall)
    }

    /// Check any action and return per-guard evidence plus the aggregated verdict.
    pub async fn check_action_report(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
    ) -> Result<GuardReport> {
        if let Some(msg) = self.config_error.as_ref() {
            return Err(Error::ConfigError(msg.clone()));
        }
        if let Some(msg) = self.async_guard_init_error.as_ref() {
            return Err(Error::ConfigError(msg.clone()));
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

        let mut per_guard: Vec<GuardResult> =
            Vec::with_capacity(fast_guards.len() + std_guards.len() + self.async_guards.len());
        let mut evaluation_path = EvaluationPath::default();
        let fail_fast = self.policy.settings.effective_fail_fast();

        let fast_terminated = self
            .evaluate_guard_stage(
                EvaluationStage::FastPath,
                &fast_guards,
                action,
                context,
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
                    context,
                    &mut per_guard,
                    &mut evaluation_path,
                )
                .await;
        }

        // If we've already denied locally, don't run async guards (avoids unnecessary network calls).
        if per_guard.iter().all(|r| r.allowed) && !self.async_guards.is_empty() {
            let deep_start = Instant::now();
            let async_results = self
                .async_runtime
                .evaluate_async_guards(&self.async_guards, action, context, fail_fast)
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

        // Count the check and remember latest path even if we fail-fast.
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

        Ok(GuardReport {
            overall,
            per_guard,
            evaluation_path,
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
                severity: format!("{:?}", result.severity),
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

    /// Check an action and update posture runtime state (if posture is configured).
    pub async fn check_action_report_with_posture(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        posture_state: &mut Option<PostureRuntimeState>,
    ) -> Result<PostureAwareReport> {
        let Some(program) = self.posture_program.as_ref() else {
            let guard_report = self.check_action_report(action, context).await?;
            return Ok(PostureAwareReport {
                guard_report,
                posture_before: "default".to_string(),
                posture_after: "default".to_string(),
                budgets_before: HashMap::new(),
                budgets_after: HashMap::new(),
                budget_deltas: HashMap::new(),
                transition: None,
            });
        };

        self.ensure_posture_initialized(program, posture_state)?;
        let state = posture_state.as_mut().ok_or_else(|| {
            Error::ConfigError("failed to initialize posture runtime state".to_string())
        })?;
        self.normalize_state_budgets(program, state);

        let mut transition = self.apply_timeout_transitions(program, state);

        let posture_before = state.current_state.clone();
        let budgets_before = state.budgets.clone();

        let precheck = self.posture_precheck(action, state, program);
        if !precheck.allowed {
            if let Some(trigger) = precheck.trigger {
                if let Some(record) = self.apply_trigger_transition(program, state, trigger) {
                    transition = Some(record);
                }
            }

            let denied = GuardResult::block(precheck.guard, precheck.severity, precheck.message);
            self.observe_guard_result(&denied).await;
            let guard_report = GuardReport {
                overall: denied.clone(),
                per_guard: vec![denied],
                evaluation_path: None,
            };

            {
                let mut engine_state = self.state.write().await;
                engine_state.action_count += 1;
                // No guard pipeline ran for this check; avoid carrying stale path telemetry.
                engine_state.last_evaluation_path = None;
            }

            return Ok(PostureAwareReport {
                guard_report,
                posture_before,
                posture_after: state.current_state.clone(),
                budgets_before,
                budgets_after: state.budgets.clone(),
                budget_deltas: HashMap::new(),
                transition,
            });
        }

        let guard_report = self.check_action_report(action, context).await?;
        let mut budget_deltas: HashMap<String, i64> = HashMap::new();

        let mut trigger: Option<RuntimeTransitionTrigger> = None;
        if guard_report.overall.allowed {
            let capability = Capability::from_action(action);
            if let Some(budget_key) = capability.budget_key() {
                if let Some(counter) = state.budgets.get_mut(budget_key) {
                    if counter.try_consume() {
                        budget_deltas.insert(budget_key.to_string(), 1);
                    }
                    if counter.is_exhausted() {
                        trigger = Some(RuntimeTransitionTrigger::BudgetExhausted);
                    }
                }
            }
        } else {
            trigger = Some(if guard_report.overall.severity == Severity::Critical {
                RuntimeTransitionTrigger::CriticalViolation
            } else {
                RuntimeTransitionTrigger::AnyViolation
            });
        }

        if let Some(trigger) = trigger {
            if let Some(record) = self.apply_trigger_transition(program, state, trigger) {
                transition = Some(record);
            }
        }

        Ok(PostureAwareReport {
            guard_report,
            posture_before,
            posture_after: state.current_state.clone(),
            budgets_before,
            budgets_after: state.budgets.clone(),
            budget_deltas,
            transition,
        })
    }

    fn ensure_posture_initialized(
        &self,
        program: &PostureProgram,
        posture_state: &mut Option<PostureRuntimeState>,
    ) -> Result<()> {
        if posture_state.is_some() {
            return Ok(());
        }

        let initial = program.initial_runtime_state().ok_or_else(|| {
            Error::ConfigError(format!(
                "posture initial state '{}' is not defined",
                program.initial_state
            ))
        })?;

        *posture_state = Some(initial);
        Ok(())
    }

    fn normalize_state_budgets(&self, program: &PostureProgram, state: &mut PostureRuntimeState) {
        let Some(compiled) = program.state(&state.current_state) else {
            return;
        };

        state
            .budgets
            .retain(|name, _| compiled.budgets.contains_key(name));

        for (name, limit) in &compiled.budgets {
            let counter = state
                .budgets
                .entry(name.clone())
                .or_insert(PostureBudgetCounter {
                    used: 0,
                    limit: *limit,
                });
            counter.limit = *limit;
            if counter.used > counter.limit {
                counter.used = counter.limit;
            }
        }
    }

    fn apply_timeout_transitions(
        &self,
        program: &PostureProgram,
        state: &mut PostureRuntimeState,
    ) -> Option<PostureTransitionRecord> {
        let mut last_transition: Option<PostureTransitionRecord> = None;
        let max_hops = program.transitions.len().max(1);

        for _ in 0..max_hops {
            let now = chrono::Utc::now();
            let Some(elapsed) = elapsed_since_timestamp(&state.entered_at, now) else {
                break;
            };

            let Some(transition) =
                program.find_due_timeout_transition(&state.current_state, elapsed)
            else {
                break;
            };

            let trigger = transition.trigger_string();
            let record = self.apply_transition(program, state, &transition.to, trigger)?;
            last_transition = Some(record);
        }

        last_transition
    }

    fn posture_precheck(
        &self,
        action: &GuardAction<'_>,
        state: &PostureRuntimeState,
        program: &PostureProgram,
    ) -> PosturePrecheck {
        let Some(current_state) = program.state(&state.current_state) else {
            return PosturePrecheck::deny(
                "posture",
                Severity::Error,
                format!("unknown posture state '{}'", state.current_state),
                None,
            );
        };

        let capability = Capability::from_action(action);
        if !current_state.capabilities.contains(&capability) {
            return PosturePrecheck::deny(
                "posture",
                Severity::Error,
                format!(
                    "action '{}' is not allowed in posture state '{}'",
                    capability.as_str(),
                    state.current_state
                ),
                None,
            );
        }

        if let Some(budget_key) = capability.budget_key() {
            if let Some(counter) = state.budgets.get(budget_key) {
                if counter.is_exhausted() {
                    return PosturePrecheck::deny(
                        "posture_budget",
                        Severity::Error,
                        format!(
                            "budget '{}' exhausted ({}/{})",
                            budget_key, counter.used, counter.limit
                        ),
                        Some(RuntimeTransitionTrigger::BudgetExhausted),
                    );
                }
            }
        }

        PosturePrecheck::allow()
    }

    fn apply_trigger_transition(
        &self,
        program: &PostureProgram,
        state: &mut PostureRuntimeState,
        trigger: RuntimeTransitionTrigger,
    ) -> Option<PostureTransitionRecord> {
        let transition = program.find_transition(&state.current_state, trigger)?;
        self.apply_transition(program, state, &transition.to, trigger.as_str())
    }

    fn apply_transition(
        &self,
        program: &PostureProgram,
        state: &mut PostureRuntimeState,
        to_state: &str,
        trigger: &str,
    ) -> Option<PostureTransitionRecord> {
        let target = program.state(to_state)?;
        let from_state = state.current_state.clone();
        let now = chrono::Utc::now().to_rfc3339();

        state.current_state = to_state.to_string();
        state.entered_at = now.clone();
        state.budgets = target.initial_budgets();

        let record = PostureTransitionRecord {
            from: from_state,
            to: to_state.to_string(),
            trigger: trigger.to_string(),
            at: now,
        };
        state.transition_history.push(record.clone());

        Some(record)
    }

    /// Create a receipt for the current session
    pub async fn create_receipt(&self, content_hash: Hash) -> Result<Receipt> {
        let state = self.state.read().await;

        let verdict = if state.violation_count == 0 {
            Verdict::pass()
        } else {
            Verdict::fail()
        };

        let provenance = Provenance {
            clawdstrike_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            provider: None,
            policy_hash: Some(self.policy_hash()?),
            ruleset: Some(self.policy.name.clone()),
            violations: state.violations.clone(),
        };

        let mut receipt = Receipt::new(content_hash, verdict).with_provenance(provenance);

        if let Some(path) = state.last_evaluation_path.as_ref() {
            let observed_paths = state.evaluation_path_counts.clone();
            receipt = receipt.merge_metadata(serde_json::json!({
                "clawdstrike": {
                    "evaluation": {
                        "last_path": path.path_string(),
                        "last": path,
                        "observed_paths": observed_paths,
                    }
                }
            }));
        }

        if !self.extra_guards.is_empty() {
            let extra_guards: Vec<&str> = self.extra_guards.iter().map(|g| g.name()).collect();
            receipt = receipt.merge_metadata(serde_json::json!({
                "clawdstrike": {
                    "extra_guards": extra_guards,
                }
            }));
        }

        Ok(receipt)
    }

    /// Create and sign a receipt
    pub async fn create_signed_receipt(&self, content_hash: Hash) -> Result<SignedReceipt> {
        let keypair = self
            .keypair
            .as_ref()
            .ok_or_else(|| Error::ConfigError("No signing keypair configured".into()))?;

        let receipt = self.create_receipt(content_hash).await?;
        SignedReceipt::sign(receipt, keypair).map_err(Error::from)
    }

    /// Get session statistics
    pub async fn stats(&self) -> EngineStats {
        let state = self.state.read().await;
        EngineStats {
            action_count: state.action_count,
            violation_count: state.violation_count,
        }
    }

    /// Reset session state
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        *state = EngineState::default();
        info!("Engine state reset");
    }
}

pub struct HushEngineBuilder {
    policy: Policy,
    custom_guard_registry: Option<CustomGuardRegistry>,
    keypair: Option<Keypair>,
}

impl HushEngineBuilder {
    pub fn with_custom_guard_registry(mut self, registry: CustomGuardRegistry) -> Self {
        self.custom_guard_registry = Some(registry);
        self
    }

    pub fn with_keypair(mut self, keypair: Keypair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    pub fn with_generated_keypair(mut self) -> Self {
        self.keypair = Some(Keypair::generate());
        self
    }

    pub fn build(self) -> Result<HushEngine> {
        let guards = self.policy.create_guards();
        let async_runtime = Arc::new(AsyncGuardRuntime::new());
        let (async_guards, async_guard_init_error) =
            match crate::async_guards::registry::build_async_guards(&self.policy) {
                Ok(v) => (v, None),
                Err(e) => (Vec::new(), Some(e.to_string())),
            };
        let custom_guards =
            build_custom_guards_from_policy(&self.policy, self.custom_guard_registry.as_ref())?;
        let posture_program = self
            .policy
            .posture
            .as_ref()
            .map(PostureProgram::from_config)
            .transpose()
            .map_err(Error::ConfigError)?;

        Ok(HushEngine {
            policy: self.policy,
            guards,
            custom_guards,
            extra_guards: Vec::new(),
            keypair: self.keypair,
            state: Arc::new(RwLock::new(EngineState::default())),
            config_error: None,
            async_runtime,
            async_guards,
            async_guard_init_error,
            posture_program,
        })
    }
}

fn build_custom_guards_from_policy(
    policy: &Policy,
    registry: Option<&CustomGuardRegistry>,
) -> Result<Vec<Box<dyn Guard>>> {
    let mut out: Vec<Box<dyn Guard>> = Vec::new();

    for spec in &policy.custom_guards {
        if !spec.enabled {
            continue;
        }

        let Some(registry) = registry else {
            return Err(Error::ConfigError(format!(
                "Policy requires custom guard {} but no CustomGuardRegistry was provided",
                spec.id
            )));
        };

        let config = crate::placeholders::resolve_placeholders_in_json(spec.config.clone())?;
        let guard = registry.build(&spec.id, config)?;
        out.push(guard);
    }

    Ok(out)
}

impl Default for HushEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Session statistics
#[derive(Clone, Debug)]
pub struct EngineStats {
    pub action_count: u64,
    pub violation_count: u64,
}

/// Convert severity to ordinal for comparison
fn severity_ord(s: &Severity) -> u8 {
    match s {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

fn aggregate_overall(results: &[GuardResult]) -> GuardResult {
    if results.is_empty() {
        return GuardResult::allow("engine");
    }

    let mut best = &results[0];

    for r in &results[1..] {
        let best_blocks = !best.allowed;
        let r_blocks = !r.allowed;

        if r_blocks && !best_blocks {
            best = r;
            continue;
        }

        if r_blocks == best_blocks && severity_ord(&r.severity) > severity_ord(&best.severity) {
            best = r;
        }
    }

    best.clone()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use async_trait::async_trait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::async_guards::{http::HttpClient, AsyncGuard, AsyncGuardConfig, AsyncGuardError};
    use crate::policy::{AsyncExecutionMode, TimeoutBehavior};

    struct TestExtraGuard {
        name: &'static str,
        calls: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl Guard for TestExtraGuard {
        fn name(&self) -> &str {
            self.name
        }

        fn handles(&self, action: &GuardAction<'_>) -> bool {
            match action {
                GuardAction::Custom(kind, _) => *kind == "extra_guard_test",
                GuardAction::FileAccess(_) => self.name == "extra_guard_order",
                _ => false,
            }
        }

        async fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
            self.calls.fetch_add(1, Ordering::Relaxed);
            GuardResult::allow(self.name())
        }
    }

    struct TestAsyncAllowGuard {
        config: AsyncGuardConfig,
    }

    impl TestAsyncAllowGuard {
        fn new() -> Self {
            Self {
                config: AsyncGuardConfig {
                    timeout: Duration::from_millis(25),
                    on_timeout: TimeoutBehavior::Warn,
                    execution_mode: AsyncExecutionMode::Parallel,
                    cache_enabled: false,
                    cache_ttl: Duration::from_secs(60),
                    cache_max_size_bytes: 1_024,
                    rate_limit: None,
                    circuit_breaker: None,
                    retry: None,
                },
            }
        }
    }

    #[async_trait]
    impl AsyncGuard for TestAsyncAllowGuard {
        fn name(&self) -> &str {
            "test_async_allow"
        }

        fn handles(&self, _action: &GuardAction<'_>) -> bool {
            true
        }

        fn config(&self) -> &AsyncGuardConfig {
            &self.config
        }

        fn cache_key(&self, action: &GuardAction<'_>, _context: &GuardContext) -> Option<String> {
            Some(format!("test_async_allow:{:?}", action))
        }

        async fn check_uncached(
            &self,
            _action: &GuardAction<'_>,
            _context: &GuardContext,
            _http: &HttpClient,
        ) -> std::result::Result<GuardResult, AsyncGuardError> {
            Ok(GuardResult::allow(self.name()))
        }
    }

    #[tokio::test]
    async fn test_engine_new() {
        let engine = HushEngine::new();
        let stats = engine.stats().await;
        assert_eq!(stats.action_count, 0);
        assert_eq!(stats.violation_count, 0);
    }

    #[tokio::test]
    async fn test_check_file_access() {
        let engine = HushEngine::new();
        let context = GuardContext::new();

        // Normal file should be allowed
        let result = engine
            .check_file_access("/app/src/main.rs", &context)
            .await
            .unwrap();
        assert!(result.allowed);

        // SSH key should be blocked
        let result = engine
            .check_file_access("/home/user/.ssh/id_rsa", &context)
            .await
            .unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_extra_guard_executes_for_custom_action() {
        let calls = Arc::new(AtomicUsize::new(0));

        let engine = HushEngine::new().with_extra_guard(TestExtraGuard {
            name: "extra_guard_test",
            calls: calls.clone(),
        });
        let context = GuardContext::new();
        let payload = serde_json::json!({ "test": true });

        let report = engine
            .check_action_report(&GuardAction::Custom("extra_guard_test", &payload), &context)
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(report.per_guard.len(), 1);
        assert_eq!(report.per_guard[0].guard, "extra_guard_test");
    }

    #[tokio::test]
    async fn test_extra_guard_runs_after_builtins() {
        let calls = Arc::new(AtomicUsize::new(0));

        let engine = HushEngine::new().with_extra_guard(TestExtraGuard {
            name: "extra_guard_order",
            calls: calls.clone(),
        });
        let context = GuardContext::new();

        let report = engine
            .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await
            .unwrap();

        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert!(report.overall.allowed);
        assert!(report
            .per_guard
            .iter()
            .any(|r| r.guard != "extra_guard_order"));
        assert_eq!(
            report.per_guard.last().map(|r| r.guard.as_str()),
            Some("extra_guard_order")
        );
        assert_eq!(
            report
                .per_guard
                .iter()
                .filter(|r| r.guard == "extra_guard_order")
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn test_fail_fast_skips_extra_guards_after_deny() {
        let calls = Arc::new(AtomicUsize::new(0));

        let mut policy = Policy::new();
        policy.settings.fail_fast = Some(true);

        let engine = HushEngine::with_policy(policy).with_extra_guard(TestExtraGuard {
            name: "extra_guard_order",
            calls: calls.clone(),
        });
        let context = GuardContext::new();

        let report = engine
            .check_action_report(&GuardAction::FileAccess("/home/user/.ssh/id_rsa"), &context)
            .await
            .unwrap();

        assert!(!report.overall.allowed);
        assert_eq!(calls.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn test_check_egress() {
        let engine = HushEngine::new();
        let context = GuardContext::new();

        // Allowed API
        let result = engine
            .check_egress("api.openai.com", 443, &context)
            .await
            .unwrap();
        assert!(result.allowed);

        // Unknown domain blocked
        let result = engine
            .check_egress("evil.com", 443, &context)
            .await
            .unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_warn_aggregation_across_guards() {
        let engine = HushEngine::new();
        let context = GuardContext::new();

        let diff = r#"
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1 +1 @@
+api_key = "0123456789abcdef0123456789abcdef"
"#;

        let report = engine
            .check_action_report(&GuardAction::Patch("src/lib.rs", diff), &context)
            .await
            .unwrap();

        assert!(report.overall.allowed);
        assert_eq!(report.overall.severity, Severity::Warning);
        assert!(report.per_guard.iter().any(|r| r.guard == "secret_leak"));
    }

    #[tokio::test]
    async fn test_evaluation_path_records_fast_and_std_paths() {
        let engine = HushEngine::new();
        let context = GuardContext::new();

        let report = engine
            .check_action_report(
                &GuardAction::FileWrite("/app/src/main.rs", b"hello"),
                &context,
            )
            .await
            .unwrap();

        let path = report
            .evaluation_path
            .expect("evaluation path should be present");
        assert_eq!(
            path.stages,
            vec!["fast_path".to_string(), "std_path".to_string()]
        );
        assert!(path.stage_timings_us.contains_key("fast_path"));
        assert!(path.stage_timings_us.contains_key("std_path"));
        assert!(path.guard_sequence.iter().any(|g| g == "forbidden_path"));
        assert!(path.guard_sequence.iter().any(|g| g == "secret_leak"));
    }

    #[tokio::test]
    async fn test_evaluation_path_records_deep_path_with_async_guards() {
        let mut engine = HushEngine::new();
        engine.async_guards = vec![Arc::new(TestAsyncAllowGuard::new())];

        let context = GuardContext::new();
        let report = engine
            .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await
            .unwrap();

        let path = report
            .evaluation_path
            .expect("evaluation path should be present");
        assert_eq!(
            path.stages,
            vec!["fast_path".to_string(), "deep_path".to_string()]
        );
        assert!(path.stage_timings_us.contains_key("fast_path"));
        assert!(path.stage_timings_us.contains_key("deep_path"));
        assert!(path.guard_sequence.iter().any(|g| g == "test_async_allow"));
    }

    #[tokio::test]
    async fn test_violation_tracking() {
        let engine = HushEngine::new();
        let context = GuardContext::new();

        // Cause a violation
        let _ = engine
            .check_file_access("/home/user/.ssh/id_rsa", &context)
            .await
            .unwrap();

        let stats = engine.stats().await;
        assert_eq!(stats.action_count, 1);
        assert_eq!(stats.violation_count, 1);
    }

    #[tokio::test]
    async fn test_create_receipt() {
        let engine = HushEngine::new().with_generated_keypair();
        let context = GuardContext::new();

        // Normal action
        let _ = engine
            .check_file_access("/app/main.rs", &context)
            .await
            .unwrap();

        let content_hash = sha256(b"test content");
        let receipt = engine.create_receipt(content_hash).await.unwrap();

        assert!(receipt.verdict.passed);
        assert!(receipt.provenance.is_some());
    }

    #[tokio::test]
    async fn test_receipt_metadata_omitted_without_extra_guards() {
        let engine = HushEngine::new();
        let receipt = engine
            .create_receipt(sha256(b"test content"))
            .await
            .unwrap();
        assert!(receipt.metadata.is_none());
    }

    #[tokio::test]
    async fn test_receipt_metadata_includes_extra_guards() {
        let calls = Arc::new(AtomicUsize::new(0));

        let engine = HushEngine::new().with_extra_guard(TestExtraGuard {
            name: "extra_guard_metadata",
            calls: calls.clone(),
        });
        let receipt = engine
            .create_receipt(sha256(b"test content"))
            .await
            .unwrap();

        let metadata = receipt.metadata.expect("expected receipt metadata");
        assert_eq!(
            metadata["clawdstrike"]["extra_guards"],
            serde_json::json!(["extra_guard_metadata"])
        );
    }

    #[tokio::test]
    async fn test_receipt_metadata_includes_evaluation_path() {
        let engine = HushEngine::new();
        let context = GuardContext::new();

        let _ = engine
            .check_action_report(
                &GuardAction::FileWrite("/app/src/main.rs", b"hello"),
                &context,
            )
            .await
            .unwrap();

        let receipt = engine
            .create_receipt(sha256(b"test content"))
            .await
            .unwrap();
        let metadata = receipt.metadata.expect("expected receipt metadata");
        assert_eq!(
            metadata.pointer("/clawdstrike/evaluation/last_path"),
            Some(&serde_json::json!("fast_path -> std_path"))
        );
        assert!(metadata
            .pointer("/clawdstrike/evaluation/last/stage_timings_us/fast_path")
            .is_some());
        let observed = metadata
            .pointer("/clawdstrike/evaluation/observed_paths")
            .and_then(|v| v.as_object())
            .expect("observed path map");
        assert_eq!(
            observed.get("fast_path -> std_path"),
            Some(&serde_json::json!(1))
        );
    }

    #[tokio::test]
    async fn test_pipeline_perf_measurement_metadata_present() {
        let engine = HushEngine::new();
        let context = GuardContext::new();

        for _ in 0..32 {
            let _ = engine
                .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
                .await
                .unwrap();
        }

        let receipt = engine
            .create_receipt(sha256(b"pipeline-perf"))
            .await
            .unwrap();
        let metadata = receipt.metadata.expect("expected receipt metadata");
        let timings = metadata
            .pointer("/clawdstrike/evaluation/last/stage_timings_us")
            .and_then(|v| v.as_object())
            .expect("expected stage timings");
        assert!(!timings.is_empty());
    }

    #[tokio::test]
    async fn test_create_signed_receipt() {
        let engine = HushEngine::new().with_generated_keypair();
        let context = GuardContext::new();

        let _ = engine
            .check_file_access("/app/main.rs", &context)
            .await
            .unwrap();

        let content_hash = sha256(b"test content");
        let signed = engine.create_signed_receipt(content_hash).await.unwrap();

        assert!(signed.receipt.verdict.passed);
    }

    #[tokio::test]
    async fn test_from_ruleset() {
        let engine = HushEngine::from_ruleset("strict").unwrap();
        let context = GuardContext::new();

        // Strict ruleset blocks unknown egress
        let result = engine
            .check_egress("random.com", 443, &context)
            .await
            .unwrap();
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_reset() {
        let engine = HushEngine::new();
        let context = GuardContext::new();

        let _ = engine
            .check_file_access("/home/user/.ssh/id_rsa", &context)
            .await
            .unwrap();
        assert_eq!(engine.stats().await.violation_count, 1);

        engine.reset().await;
        assert_eq!(engine.stats().await.violation_count, 0);
    }

    struct AlwaysWarnGuard;

    #[async_trait]
    impl Guard for AlwaysWarnGuard {
        fn name(&self) -> &str {
            "acme.always_warn"
        }

        fn handles(&self, _action: &GuardAction<'_>) -> bool {
            true
        }

        async fn check(&self, _action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
            GuardResult::warn(self.name(), "Policy-driven custom guard warning")
        }
    }

    struct AlwaysWarnFactory;

    impl crate::guards::CustomGuardFactory for AlwaysWarnFactory {
        fn id(&self) -> &str {
            "acme.always_warn"
        }

        fn build(&self, _config: serde_json::Value) -> Result<Box<dyn Guard>> {
            Ok(Box::new(AlwaysWarnGuard))
        }
    }

    struct ExpectTokenFactory;

    impl crate::guards::CustomGuardFactory for ExpectTokenFactory {
        fn id(&self) -> &str {
            "acme.expect_token"
        }

        fn build(&self, config: serde_json::Value) -> Result<Box<dyn Guard>> {
            let token = config
                .get("token")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if token != "sekret" {
                return Err(Error::ConfigError(format!(
                    "expected token 'sekret' but got {:?}",
                    token
                )));
            }
            Ok(Box::new(AlwaysWarnGuard))
        }
    }

    #[tokio::test]
    async fn test_policy_custom_guards_run_after_builtins_when_registry_provided() {
        let yaml = r#"
version: "1.1.0"
name: Custom
custom_guards:
  - id: "acme.always_warn"
    enabled: true
    config: {}
"#;
        let policy = Policy::from_yaml(yaml).unwrap();

        let mut registry = CustomGuardRegistry::new();
        registry.register(AlwaysWarnFactory);

        let engine = HushEngine::builder(policy)
            .with_custom_guard_registry(registry)
            .build()
            .unwrap();

        let context = GuardContext::new();
        let report = engine
            .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await
            .unwrap();

        assert!(report.overall.allowed);
        assert_eq!(report.overall.severity, Severity::Warning);
        assert_eq!(
            report.per_guard.last().map(|r| r.guard.as_str()),
            Some("acme.always_warn")
        );
    }

    #[tokio::test]
    async fn test_policy_custom_guards_resolve_placeholders_in_config_before_build() {
        let key = "HC_TEST_CUSTOM_GUARD_TOKEN";
        let prev = std::env::var(key).ok();
        std::env::set_var(key, "sekret");

        let yaml = format!(
            r#"
version: "1.1.0"
name: Custom
custom_guards:
  - id: "acme.expect_token"
    enabled: true
    config:
      token: "${{{}}}"
"#,
            key
        );
        let policy = Policy::from_yaml(&yaml).unwrap();

        let mut registry = CustomGuardRegistry::new();
        registry.register(ExpectTokenFactory);

        let engine = HushEngine::builder(policy)
            .with_custom_guard_registry(registry)
            .build()
            .unwrap();

        let context = GuardContext::new();
        let report = engine
            .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await
            .unwrap();
        assert!(report.overall.allowed);

        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[test]
    fn test_policy_custom_guards_missing_env_placeholder_fails_closed() {
        let key = "HC_TEST_MISSING_CUSTOM_GUARD_ENV";
        let prev = std::env::var(key).ok();
        std::env::remove_var(key);

        let yaml = format!(
            r#"
version: "1.1.0"
name: Custom
custom_guards:
  - id: "acme.expect_token"
    enabled: true
    config:
      token: "${{{}}}"
"#,
            key
        );

        let err = Policy::from_yaml(&yaml).unwrap_err();
        assert!(err.to_string().contains(key));

        match prev {
            Some(v) => std::env::set_var(key, v),
            None => std::env::remove_var(key),
        }
    }

    #[tokio::test]
    async fn test_policy_custom_guards_fail_closed_when_registry_missing() {
        let yaml = r#"
version: "1.1.0"
name: Custom
custom_guards:
  - id: "acme.always_warn"
    enabled: true
    config: {}
"#;
        let policy = Policy::from_yaml(yaml).unwrap();

        // Builder should fail closed.
        let err = match HushEngine::builder(policy.clone()).build() {
            Ok(_) => panic!("Expected builder to fail without CustomGuardRegistry"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("CustomGuardRegistry"));

        // Legacy constructor should also fail closed at evaluation time.
        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new();
        let err = engine
            .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("CustomGuardRegistry"));
    }

    #[tokio::test]
    async fn test_posture_precheck_denies_missing_capability() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: "posture-precheck"
posture:
  initial: work
  states:
    work:
      capabilities: [file_access]
      budgets: {}
"#,
        )
        .unwrap();

        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new();
        let mut posture = None;

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::FileWrite("/tmp/out.txt", b"ok"),
                &context,
                &mut posture,
            )
            .await
            .unwrap();

        assert!(!report.guard_report.overall.allowed);
        assert_eq!(report.guard_report.overall.guard, "posture");
        assert_eq!(report.posture_after, "work");
    }

    #[tokio::test]
    async fn test_posture_precheck_denial_counts_as_violation_and_fails_receipt() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: "posture-precheck-receipt"
posture:
  initial: work
  states:
    work:
      capabilities: [file_access]
      budgets: {}
"#,
        )
        .unwrap();

        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new();
        let mut posture = None;

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::ShellCommand("echo hi"),
                &context,
                &mut posture,
            )
            .await
            .unwrap();
        assert!(!report.guard_report.overall.allowed);

        let stats = engine.stats().await;
        assert_eq!(stats.action_count, 1);
        assert_eq!(stats.violation_count, 1);

        let receipt = engine
            .create_receipt(sha256(b"posture-precheck-denial"))
            .await
            .unwrap();
        assert!(!receipt.verdict.passed);
        let provenance = receipt
            .provenance
            .expect("receipt should include provenance");
        assert_eq!(provenance.violations.len(), 1);
        assert_eq!(provenance.violations[0].guard, "posture");
    }

    #[tokio::test]
    async fn test_posture_budget_exhaustion_triggers_transition() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: "posture-budget"
posture:
  initial: work
  states:
    work:
      capabilities: [file_write]
      budgets:
        file_writes: 1
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: budget_exhausted }
"#,
        )
        .unwrap();

        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new();
        let mut posture = None;

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::FileWrite("/tmp/out.txt", b"ok"),
                &context,
                &mut posture,
            )
            .await
            .unwrap();

        assert!(report.guard_report.overall.allowed);
        assert_eq!(report.posture_after, "quarantine");
        assert_eq!(
            report.transition.as_ref().map(|t| t.trigger.as_str()),
            Some("budget_exhausted")
        );
    }

    #[tokio::test]
    async fn test_posture_any_violation_transition() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: "posture-any-violation"
posture:
  initial: work
  states:
    work:
      capabilities: [egress]
      budgets: {}
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: any_violation }
"#,
        )
        .unwrap();

        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new();
        let mut posture = None;

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::NetworkEgress("evil.example", 443),
                &context,
                &mut posture,
            )
            .await
            .unwrap();

        assert!(!report.guard_report.overall.allowed);
        assert_eq!(report.posture_after, "quarantine");
        assert_eq!(
            report.transition.as_ref().map(|t| t.trigger.as_str()),
            Some("any_violation")
        );
    }

    #[tokio::test]
    async fn test_posture_critical_violation_transition() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: "posture-critical-violation"
posture:
  initial: work
  states:
    work:
      capabilities: [file_write]
      budgets: {}
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: critical_violation }
"#,
        )
        .unwrap();

        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new();
        let mut posture = None;

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::FileWrite("/tmp/output.txt", b"AKIAABCDEFGHIJKLMNOP"),
                &context,
                &mut posture,
            )
            .await
            .unwrap();

        assert!(!report.guard_report.overall.allowed);
        assert_eq!(report.guard_report.overall.severity, Severity::Critical);
        assert_eq!(report.posture_after, "quarantine");
        assert_eq!(
            report.transition.as_ref().map(|t| t.trigger.as_str()),
            Some("critical_violation")
        );
    }

    #[tokio::test]
    async fn test_posture_timeout_transition_applied_on_request() {
        let policy = Policy::from_yaml(
            r#"
version: "1.2.0"
name: "posture-timeout"
posture:
  initial: elevated
  states:
    elevated:
      capabilities: [file_access]
      budgets: {}
    work:
      capabilities: [file_access]
      budgets: {}
  transitions:
    - { from: elevated, to: work, on: timeout, after: 1s }
"#,
        )
        .unwrap();

        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new();
        let mut posture = Some(PostureRuntimeState {
            current_state: "elevated".to_string(),
            entered_at: "2026-01-01T00:00:00Z".to_string(),
            transition_history: Vec::new(),
            budgets: HashMap::new(),
        });

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::FileAccess("/tmp/readme.md"),
                &context,
                &mut posture,
            )
            .await
            .unwrap();

        assert!(report.guard_report.overall.allowed);
        assert_eq!(report.posture_after, "work");
        assert_eq!(
            report.transition.as_ref().map(|t| t.trigger.as_str()),
            Some("timeout")
        );
    }
}
