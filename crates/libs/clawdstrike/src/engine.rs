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
use crate::enclave::EnclaveResolver;
use crate::error::{Error, Result};
use crate::guards::{
    CustomGuardRegistry, Guard, GuardAction, GuardContext, GuardResult, McpDefaultAction, Severity,
};
use crate::origin::OriginContext;
use crate::origin_runtime::{
    normalize_origin_budgets, origin_budget_counters, OriginFingerprint, OriginRuntimeState,
};
use crate::output_sanitizer::OutputSanitizer;
use crate::pipeline::{builtin_stage_for_guard_name, EvaluationPath, EvaluationStage};
use crate::policy::{OriginDefaultBehavior, Policy, PolicyGuards, RuleSet};
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<GuardEvaluationMetadata>,
}

#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardEvaluationMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<OriginContext>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enclave: Option<GuardResolvedEnclave>,
}

#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardResolvedEnclave {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolution_path: Vec<String>,
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

struct PreparedContext {
    context: GuardContext,
    metadata: Option<GuardEvaluationMetadata>,
}

enum PreparedEvaluation {
    Continue(Box<PreparedContext>),
    Complete(Box<GuardReport>),
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

    /// Record a one-result evaluation and return a single-guard report.
    async fn single_result_report(
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

    fn build_report_metadata(
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

    fn report_metadata_for_context(context: &GuardContext) -> Option<GuardEvaluationMetadata> {
        Self::build_report_metadata(context.origin.as_ref(), context.enclave.as_ref())
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
        let prepared = match self.prepare_origin_context(context, None).await? {
            PreparedEvaluation::Continue(prepared) => *prepared,
            PreparedEvaluation::Complete(report) => return Ok(*report),
        };

        self.check_action_report_prepared(action, prepared, None)
            .await
    }

    async fn prepare_origin_context(
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

    async fn check_action_report_prepared(
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

    async fn enclave_mcp_precheck(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
    ) -> Option<GuardResult> {
        let GuardAction::McpTool(tool_name, _) = action else {
            return None;
        };
        let enclave = context.enclave.as_ref()?;
        let enclave_mcp = enclave.mcp.as_ref()?;
        if !enclave_mcp.enabled {
            debug!("Enclave MCP pre-check skipped: enabled=false");
            return None;
        }

        let profile_label = enclave.profile_id.as_deref().unwrap_or("unknown");

        if enclave_mcp.block.iter().any(|b| tool_matches(tool_name, b)) {
            return Some(GuardResult::block(
                "enclave",
                Severity::Error,
                format!(
                    "tool '{}' blocked by enclave profile '{}'",
                    tool_name, profile_label
                ),
            ));
        }

        // A non-empty allow list is the primary gate. Once a tool is
        // explicitly allowed, only block-list and confirmation checks still
        // apply; `default_action` is only consulted when no allow list exists.
        if !enclave_mcp.allow.is_empty()
            && !enclave_mcp.allow.iter().any(|a| tool_matches(tool_name, a))
        {
            return Some(GuardResult::block(
                "enclave",
                Severity::Error,
                format!(
                    "tool '{}' not in enclave allow list for profile '{}'",
                    tool_name, profile_label
                ),
            ));
        }

        if enclave_mcp.allow.is_empty()
            && matches!(enclave_mcp.default_action, Some(McpDefaultAction::Block))
        {
            return Some(GuardResult::block(
                "enclave",
                Severity::Error,
                format!(
                    "tool '{}' blocked by default_action for profile '{}'",
                    tool_name, profile_label
                ),
            ));
        }

        if enclave_mcp
            .require_confirmation
            .iter()
            .any(|r| tool_matches(tool_name, r))
        {
            return Some(GuardResult::block(
                "enclave",
                Severity::Warning,
                format!(
                    "tool '{}' requires confirmation per enclave profile '{}'",
                    tool_name, profile_label
                ),
            ));
        }

        None
    }

    async fn origin_data_precheck(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
    ) -> Option<GuardResult> {
        let payload = output_send_payload(action);
        if matches!(payload, OutputSendPayload::NotOutputSend) {
            return None;
        }

        let enclave = context.enclave.as_ref()?;
        let data_policy = enclave.data.as_ref()?;
        let profile_label = enclave.profile_id.as_deref().unwrap_or("unknown");
        let payload = match payload {
            OutputSendPayload::Invalid(message) => {
                return Some(GuardResult::block("origin_data", Severity::Error, message));
            }
            OutputSendPayload::Valid(payload) => payload,
            OutputSendPayload::NotOutputSend => return None,
        };

        if !data_policy.allow_external_sharing && is_external_origin(context.origin.as_ref()) {
            return Some(GuardResult::block(
                "origin_data",
                Severity::Error,
                format!(
                    "output blocked by origin data policy for profile '{}' on external origin",
                    profile_label
                ),
            ));
        }

        let sanitizer = OutputSanitizer::new();
        let sanitized = sanitizer.sanitize_sync(payload.text);

        if data_policy.block_sensitive_outputs && !sanitized.findings.is_empty() {
            return Some(
                GuardResult::block(
                    "origin_data",
                    Severity::Error,
                    format!(
                        "output blocked by origin data policy for profile '{}' due to sensitive content",
                        profile_label
                    ),
                )
                .with_details(serde_json::json!({
                    "action": "blocked_sensitive_output",
                    "findings_count": sanitized.findings.len(),
                    "redactions_count": sanitized.redactions.len(),
                })),
            );
        }

        if data_policy.redact_before_send && sanitized.was_redacted {
            return Some(
                GuardResult::warn(
                    "origin_data",
                    format!(
                        "output sanitized by origin data policy for profile '{}'",
                        profile_label
                    ),
                )
                .with_details(serde_json::json!({
                    "action": "sanitized",
                    "sanitized": sanitized.sanitized,
                    "findings_count": sanitized.findings.len(),
                    "redactions_count": sanitized.redactions.len(),
                })),
            );
        }

        None
    }

    async fn origin_budget_precheck(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        origin_state: Option<&Option<OriginRuntimeState>>,
    ) -> Option<GuardResult> {
        let capability = Capability::from_action(action);
        let budget_key = capability.budget_key()?;
        let enclave = context.enclave.as_ref()?;
        let configured = enclave
            .budgets
            .as_ref()
            .and_then(|budgets| origin_budget_limit(budgets, budget_key));
        let limit = configured?;

        let Some(origin_state) = origin_state else {
            return Some(GuardResult::block(
                "origin_budget",
                Severity::Error,
                format!(
                    "origin budget '{}' requires session runtime state (limit={limit})",
                    budget_key
                ),
            ));
        };

        let Some(runtime) = origin_state.as_ref() else {
            return Some(GuardResult::block(
                "origin_budget",
                Severity::Error,
                format!(
                    "origin budget '{}' requires session runtime state (limit={limit})",
                    budget_key
                ),
            ));
        };

        if let Some(counter) = runtime.budgets.get(budget_key) {
            if counter.is_exhausted() {
                return Some(GuardResult::block(
                    "origin_budget",
                    Severity::Error,
                    format!(
                        "origin budget '{}' exhausted ({}/{})",
                        budget_key, counter.used, counter.limit
                    ),
                ));
            }
        }

        None
    }

    fn consume_origin_budget(
        &self,
        action: &GuardAction<'_>,
        origin_state: Option<&mut Option<OriginRuntimeState>>,
    ) {
        let Some(budget_key) = Capability::from_action(action).budget_key() else {
            return;
        };
        let Some(origin_state) = origin_state else {
            return;
        };
        let Some(runtime) = origin_state.as_mut() else {
            return;
        };
        if let Some(counter) = runtime.budgets.get_mut(budget_key) {
            let _ = counter.try_consume();
        }
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

    /// Check an action and update posture runtime state (if posture is configured).
    pub async fn check_action_report_with_posture(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        posture_state: &mut Option<PostureRuntimeState>,
    ) -> Result<PostureAwareReport> {
        let mut origin_state = posture_state
            .as_ref()
            .and_then(|state| state.origin_runtime.clone());
        let report = self
            .check_action_report_with_runtime(action, context, posture_state, &mut origin_state)
            .await?;
        if let Some(origin_state) = origin_state {
            let state = posture_state
                .get_or_insert_with(|| PostureRuntimeState::new("default", HashMap::new()));
            state.origin_runtime = Some(origin_state);
        }
        Ok(report)
    }

    pub async fn check_action_report_with_runtime(
        &self,
        action: &GuardAction<'_>,
        context: &GuardContext,
        posture_state: &mut Option<PostureRuntimeState>,
        origin_state: &mut Option<OriginRuntimeState>,
    ) -> Result<PostureAwareReport> {
        let Some(program) = self.posture_program.as_ref() else {
            let prepared = match self
                .prepare_origin_context(context, Some(origin_state))
                .await?
            {
                PreparedEvaluation::Continue(prepared) => *prepared,
                PreparedEvaluation::Complete(report) => {
                    return Ok(PostureAwareReport {
                        guard_report: *report,
                        posture_before: "default".to_string(),
                        posture_after: "default".to_string(),
                        budgets_before: HashMap::new(),
                        budgets_after: HashMap::new(),
                        budget_deltas: HashMap::new(),
                        transition: None,
                    });
                }
            };
            let guard_report = self
                .check_action_report_prepared(action, prepared, Some(origin_state))
                .await?;
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
        let prepared = match self
            .prepare_origin_context(context, Some(origin_state))
            .await?
        {
            PreparedEvaluation::Continue(prepared) => *prepared,
            PreparedEvaluation::Complete(report) => {
                let state = posture_state.as_ref().ok_or_else(|| {
                    Error::ConfigError("failed to initialize posture runtime state".to_string())
                })?;
                return Ok(PostureAwareReport {
                    guard_report: *report,
                    posture_before: state.current_state.clone(),
                    posture_after: state.current_state.clone(),
                    budgets_before: state.budgets.clone(),
                    budgets_after: state.budgets.clone(),
                    budget_deltas: HashMap::new(),
                    transition: None,
                });
            }
        };
        let posture_context = prepared.context.clone();

        // Apply enclave posture override regardless of how the enclave was
        // obtained (pre-set or freshly resolved).
        if let Some(ref enclave) = posture_context.enclave {
            if let Some(ref enclave_posture) = enclave.posture {
                let state = posture_state.as_mut().ok_or_else(|| {
                    Error::ConfigError("posture state not initialized".to_string())
                })?;

                // Only override if the session is still in its initial state
                // (hasn't transitioned yet) — don't override mid-session.
                if state.transition_history.is_empty() {
                    // Validate that the enclave's posture state exists in the program.
                    if program.state(enclave_posture).is_some() {
                        if state.current_state != *enclave_posture {
                            let from = state.current_state.clone();
                            debug!(
                                from = %from,
                                to = %enclave_posture,
                                "Enclave overriding initial posture"
                            );
                            state.current_state = enclave_posture.clone();
                            state.entered_at = chrono::Utc::now().to_rfc3339();
                            // Re-initialize budgets for the new state.
                            if let Some(compiled) = program.state(enclave_posture) {
                                state.budgets = compiled.initial_budgets();
                            }
                            // Record synthetic transition so subsequent
                            // calls cannot re-override the posture.
                            state.transition_history.push(
                                crate::posture::PostureTransitionRecord {
                                    from,
                                    to: enclave_posture.clone(),
                                    trigger: "enclave_init".to_string(),
                                    at: state.entered_at.clone(),
                                },
                            );
                        }
                    } else {
                        // Fail-closed: enclave references nonexistent posture state.
                        let available: Vec<&String> = program.states.keys().collect();
                        return Err(Error::ConfigError(format!(
                            "enclave profile references unknown posture state \
                             '{}' (available: {:?})",
                            enclave_posture, available
                        )));
                    }
                }
            }
        }

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
            let guard_report = self
                .single_result_report(denied, prepared.metadata.clone())
                .await;

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

        let guard_report = self
            .check_action_report_prepared(
                action,
                PreparedContext {
                    context: posture_context,
                    metadata: prepared.metadata.clone(),
                },
                Some(origin_state),
            )
            .await?;
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

    /// Create a receipt enriched with the origin/enclave metadata from a guard report.
    pub async fn create_receipt_for_report(
        &self,
        content_hash: Hash,
        report: &GuardReport,
    ) -> Result<Receipt> {
        let receipt = self.create_receipt(content_hash).await?;
        Ok(merge_report_metadata_into_receipt(
            receipt,
            report.metadata.as_ref(),
        ))
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

    /// Create and sign a receipt enriched with per-report origin metadata.
    pub async fn create_signed_receipt_for_report(
        &self,
        content_hash: Hash,
        report: &GuardReport,
    ) -> Result<SignedReceipt> {
        let keypair = self
            .keypair
            .as_ref()
            .ok_or_else(|| Error::ConfigError("No signing keypair configured".into()))?;

        let receipt = self.create_receipt_for_report(content_hash, report).await?;
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

/// Simple tool name matching (supports trailing `*` wildcard).
fn tool_matches(tool_name: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        tool_name.starts_with(prefix)
    } else {
        tool_name == pattern
    }
}

fn origin_budget_limit(budgets: &crate::policy::OriginBudgets, key: &str) -> Option<u64> {
    match key {
        "mcp_tool_calls" => budgets.mcp_tool_calls,
        "egress_calls" => budgets.egress_calls,
        "shell_commands" => budgets.shell_commands,
        _ => None,
    }
}

fn is_external_origin(origin: Option<&OriginContext>) -> bool {
    origin.is_some_and(|origin| {
        origin.external_participants == Some(true)
            || matches!(
                origin.visibility,
                Some(crate::origin::Visibility::Public | crate::origin::Visibility::ExternalShared)
            )
    })
}

enum OutputSendPayload<'a> {
    NotOutputSend,
    Invalid(String),
    Valid(OutputSendValue<'a>),
}

struct OutputSendValue<'a> {
    text: &'a str,
}

fn output_send_payload<'a>(action: &'a GuardAction<'a>) -> OutputSendPayload<'a> {
    let GuardAction::Custom(kind, payload) = action else {
        return OutputSendPayload::NotOutputSend;
    };
    if *kind != "origin.output_send" {
        return OutputSendPayload::NotOutputSend;
    }
    let Some(text) = payload.get("text").and_then(|value| value.as_str()) else {
        return OutputSendPayload::Invalid(
            "origin.output_send requires payload.text to be a string".to_string(),
        );
    };
    OutputSendPayload::Valid(OutputSendValue { text })
}

fn merge_report_metadata_into_receipt(
    mut receipt: Receipt,
    metadata: Option<&GuardEvaluationMetadata>,
) -> Receipt {
    let Some(metadata) = metadata else {
        return receipt;
    };

    if let Some(origin) = metadata.origin.as_ref() {
        if let Ok(origin_json) = serde_json::to_value(origin) {
            receipt = receipt.merge_metadata(serde_json::json!({
                "clawdstrike": {
                    "origin": origin_json,
                }
            }));
        }
    }

    if let Some(enclave) = metadata.enclave.as_ref() {
        receipt = receipt.merge_metadata(serde_json::json!({
            "clawdstrike": {
                "enclave": {
                    "profile_id": enclave.profile_id,
                    "resolution_path": enclave.resolution_path,
                }
            }
        }));
    }

    receipt
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

// ---------------------------------------------------------------------------
// Cross-Origin Bridge Helpers (Phase 1b)
// ---------------------------------------------------------------------------

/// Result of checking a bridge policy for a cross-origin transition.
enum BridgeCheckResult {
    /// The transition is allowed.
    Allow,
    /// The transition requires approval (denied with Warning severity).
    RequireApproval,
    /// The transition is denied with the given reason.
    Deny(String),
}

/// Check the bridge policy on the **session's** enclave (source) to determine
/// whether bridging to the given target origin is allowed.
fn check_bridge_policy(
    source_enclave: &crate::enclave::ResolvedEnclave,
    target_origin: &OriginContext,
) -> BridgeCheckResult {
    let Some(ref bridge) = source_enclave.bridge_policy else {
        return BridgeCheckResult::Deny("no bridge policy configured".to_string());
    };

    if !bridge.allow_cross_origin {
        return BridgeCheckResult::Deny("cross-origin transitions disabled".to_string());
    }

    // Check if target matches any allowed target.
    // An empty allowed_targets list means "all targets are allowed".
    let target_matches = bridge.allowed_targets.is_empty()
        || bridge.allowed_targets.iter().any(|t| {
            // Use to_string() comparison to match EnclaveResolver behavior
            // and avoid Custom("slack") != Slack inconsistency.
            let provider_ok = t
                .provider
                .as_ref()
                .is_none_or(|p| p.to_string() == target_origin.provider.to_string());
            let space_type_ok = t.space_type.as_ref().is_none_or(|st| {
                target_origin
                    .space_type
                    .as_ref()
                    .is_some_and(|tst| tst.to_string() == st.to_string())
            });
            let tags_ok =
                t.tags.is_empty() || t.tags.iter().all(|tag| target_origin.tags.contains(tag));
            let visibility_ok = t.visibility.as_ref().is_none_or(|v| {
                target_origin
                    .visibility
                    .as_ref()
                    .is_some_and(|tv| tv.to_string() == v.to_string())
            });
            provider_ok && space_type_ok && tags_ok && visibility_ok
        });

    if !target_matches {
        return BridgeCheckResult::Deny(
            "target origin does not match any allowed bridge target".to_string(),
        );
    }

    if bridge.require_approval {
        return BridgeCheckResult::RequireApproval;
    }

    BridgeCheckResult::Allow
}

/// Format an origin context briefly for error messages.
fn format_origin_brief(origin: &OriginContext) -> String {
    let mut parts = vec![format!("provider={}", origin.provider)];
    if let Some(ref id) = origin.space_id {
        parts.push(format!("space_id={}", id));
    }
    parts.join(",")
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
            continue;
        }

        if r_blocks == best_blocks
            && severity_ord(&r.severity) == severity_ord(&best.severity)
            && !r_blocks
            && r.is_sanitized()
            && !best.is_sanitized()
        {
            // Preserve sanitize payloads over plain warnings when severities tie.
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

    #[test]
    fn aggregate_overall_prefers_sanitize_over_plain_warning_on_tie() {
        let plain_warning = GuardResult::warn("warn_guard", "warning only");
        let sanitize_warning = GuardResult::sanitize(
            "sanitize_guard",
            "sanitized content",
            "dangerous input",
            "safe input",
        );

        let overall = aggregate_overall(&[plain_warning, sanitize_warning.clone()]);

        assert!(overall.allowed);
        assert_eq!(overall.severity, Severity::Warning);
        assert_eq!(overall.guard, "sanitize_guard");
        assert!(overall.is_sanitized());
        assert_eq!(
            overall.details.as_ref().and_then(|d| d.get("sanitized")),
            sanitize_warning
                .details
                .as_ref()
                .and_then(|d| d.get("sanitized"))
        );
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
            origin_runtime: None,
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

    // -----------------------------------------------------------------------
    // Origin Enclave Tests (Phase 1.1)
    // -----------------------------------------------------------------------

    use crate::guards::McpDefaultAction;
    use crate::origin::{OriginContext, OriginProvider, SpaceType, Visibility};
    use crate::policy::{
        BridgePolicy, BridgeTarget, OriginDefaultBehavior, OriginMatch, OriginProfile,
        OriginsConfig,
    };

    /// Helper: create a v1.4.0 policy with an origins block.
    fn policy_with_origins(origins: OriginsConfig) -> Policy {
        let mut policy = Policy::new();
        policy.version = "1.4.0".to_string();
        policy.name = "enclave-test".to_string();
        policy.origins = Some(origins);
        policy
    }

    /// Helper: create a simple Slack origin context.
    fn test_slack_origin() -> OriginContext {
        OriginContext {
            provider: OriginProvider::Slack,
            space_id: Some("C-test-123".into()),
            ..OriginContext::default()
        }
    }

    /// Helper: create a profile that matches Slack with given MCP config.
    fn slack_profile_with_mcp(id: &str, mcp: crate::guards::McpToolConfig) -> OriginProfile {
        OriginProfile {
            id: id.to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
            mcp: Some(mcp),
            posture: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        }
    }

    #[tokio::test]
    async fn test_enclave_blocks_mcp_tool() {
        let mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec!["dangerous_tool".to_string()],
            allow: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Allow),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-restricted", mcp)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        let report = engine
            .check_action_report(&GuardAction::McpTool("dangerous_tool", &args), &context)
            .await
            .unwrap();

        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "enclave");
        assert!(report
            .overall
            .message
            .contains("blocked by enclave profile"));
        assert!(report.overall.message.contains("slack-restricted"));
    }

    #[tokio::test]
    async fn test_enclave_allows_mcp_tool_passes_to_guard_pipeline() {
        let mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec!["other_tool".to_string()],
            allow: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Allow),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-open", mcp)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        // "safe_tool" is NOT in the enclave block list, and default_action=Allow
        // It should pass through the enclave check to the guard pipeline.
        let report = engine
            .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
            .await
            .unwrap();

        // The guard pipeline (McpToolGuard) runs — default policy allows most tools
        assert!(report.overall.allowed);
        // Verify enclave is NOT the denying guard
        assert_ne!(report.overall.guard, "enclave");
    }

    #[tokio::test]
    async fn test_policy_blocks_tool_even_if_enclave_allows() {
        // Enclave allows all tools
        let enclave_mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec![],
            allow: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Allow),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-permissive", enclave_mcp)],
        };

        // But the main policy blocks "shell_exec" by default
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        // "shell_exec" is in the default MCP block list for the policy
        let report = engine
            .check_action_report(&GuardAction::McpTool("shell_exec", &args), &context)
            .await
            .unwrap();

        // Policy guards should still block it even though enclave allows
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "mcp_tool");
    }

    #[tokio::test]
    async fn test_no_origin_normal_flow() {
        let engine = HushEngine::new();
        let context = GuardContext::new(); // No origin set

        let args = serde_json::json!({});
        let report = engine
            .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
            .await
            .unwrap();

        // Normal flow: no enclave resolution, just guard pipeline
        assert!(report.overall.allowed);
    }

    #[tokio::test]
    async fn test_posture_origin_resolution_failure_returns_deny_report() {
        let policy = Policy::from_yaml(
            r#"
version: "1.4.0"
name: "posture-origin-resolution-failure"
posture:
  initial: work
  states:
    work:
      capabilities: [mcp_tool]
      budgets: {}
origins:
  default_behavior: deny
  profiles:
    - id: github-only
      match_rules:
        provider: github
"#,
        )
        .unwrap();

        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new().with_origin(test_slack_origin());
        let mut posture = None;
        let args = serde_json::json!({});

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::McpTool("safe_tool", &args),
                &context,
                &mut posture,
            )
            .await
            .expect("resolution failure should return a deny report, not an error");

        assert!(!report.guard_report.overall.allowed);
        assert_eq!(report.guard_report.overall.guard, "enclave");
        assert!(report
            .guard_report
            .overall
            .message
            .contains("enclave resolution failed"));
    }

    #[tokio::test]
    async fn test_origin_egress_profile_intersects_with_base_policy() {
        use hush_proxy::policy::PolicyAction;

        let mut policy = policy_with_origins(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "slack-egress".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: Some(crate::guards::EgressAllowlistConfig {
                    enabled: true,
                    allow: vec!["api.github.com".to_string()],
                    block: vec![],
                    default_action: Some(PolicyAction::Block),
                    additional_allow: vec![],
                    remove_allow: vec![],
                    additional_block: vec![],
                    remove_block: vec![],
                }),
                data: None,
                budgets: None,
                bridge_policy: None,
                explanation: None,
            }],
        });
        policy.guards.egress_allowlist = Some(crate::guards::EgressAllowlistConfig {
            enabled: true,
            allow: vec!["api.openai.com".to_string(), "api.github.com".to_string()],
            block: vec![],
            default_action: Some(PolicyAction::Block),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new().with_origin(test_slack_origin());

        let allowed = engine
            .check_egress("api.github.com", 443, &context)
            .await
            .unwrap();
        assert!(allowed.allowed);

        let blocked = engine
            .check_egress("api.openai.com", 443, &context)
            .await
            .unwrap();
        assert!(!blocked.allowed);
        assert_eq!(blocked.guard, "egress_allowlist");
    }

    #[tokio::test]
    async fn test_origin_output_send_blocks_external_sharing() {
        let policy = policy_with_origins(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "slack-data".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: Some(crate::policy::OriginDataPolicy {
                    allow_external_sharing: false,
                    redact_before_send: false,
                    block_sensitive_outputs: false,
                }),
                budgets: None,
                bridge_policy: None,
                explanation: None,
            }],
        });
        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new().with_origin(OriginContext {
            provider: OriginProvider::Slack,
            space_id: Some("C-external".into()),
            visibility: Some(Visibility::ExternalShared),
            tags: vec!["provider:slack".to_string()],
            ..OriginContext::default()
        });
        let payload = serde_json::json!({
            "text": "share this status update",
            "target": "external-room"
        });

        let report = engine
            .check_action_report(
                &GuardAction::Custom("origin.output_send", &payload),
                &context,
            )
            .await
            .unwrap();

        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "origin_data");
        assert!(report.overall.message.contains("external origin"));
    }

    #[tokio::test]
    async fn test_origin_output_send_invalid_payload_is_ignored_without_data_policy() {
        let engine = HushEngine::new();
        let payload = serde_json::json!({
            "target": "external-room"
        });

        let report = engine
            .check_action_report(
                &GuardAction::Custom("origin.output_send", &payload),
                &GuardContext::new(),
            )
            .await
            .unwrap();

        assert!(report.overall.allowed);
        assert!(!report
            .per_guard
            .iter()
            .any(|result| result.guard == "origin_data"));
    }

    #[tokio::test]
    async fn test_origin_output_send_sanitizes_without_leaking_raw_content() {
        let policy = policy_with_origins(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "slack-redact".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: Some(crate::policy::OriginDataPolicy {
                    allow_external_sharing: true,
                    redact_before_send: true,
                    block_sensitive_outputs: false,
                }),
                budgets: None,
                bridge_policy: None,
                explanation: None,
            }],
        });
        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new().with_origin(test_slack_origin());
        let raw_email = "alice@example.com";
        let payload = serde_json::json!({
            "text": format!("Contact {raw_email} for incident updates."),
            "target": "slack-channel"
        });

        let report = engine
            .check_action_report(
                &GuardAction::Custom("origin.output_send", &payload),
                &context,
            )
            .await
            .unwrap();

        assert!(report.overall.allowed);
        assert_eq!(report.overall.guard, "origin_data");
        let details = report.overall.details.as_ref().expect("details");
        let sanitized = details
            .get("sanitized")
            .and_then(|value| value.as_str())
            .expect("sanitized text");
        assert!(!sanitized.contains(raw_email));
        assert!(sanitized.contains("***"));
        let serialized_report = serde_json::to_string(&report).unwrap();
        assert!(!serialized_report.contains(raw_email));
    }

    #[tokio::test]
    async fn test_origin_budget_exhaustion_blocks_followup_action() {
        let policy = policy_with_origins(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "slack-budgeted".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: Some(crate::policy::OriginBudgets {
                    mcp_tool_calls: Some(1),
                    ..Default::default()
                }),
                bridge_policy: None,
                explanation: None,
            }],
        });
        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new().with_origin(test_slack_origin());
        let mut posture_state = None;
        let mut origin_state = None;
        let args = serde_json::json!({});

        let allowed = engine
            .check_action_report_with_runtime(
                &GuardAction::McpTool("safe_tool", &args),
                &context,
                &mut posture_state,
                &mut origin_state,
            )
            .await
            .unwrap();
        assert!(allowed.guard_report.overall.allowed);

        let denied = engine
            .check_action_report_with_runtime(
                &GuardAction::McpTool("safe_tool", &args),
                &context,
                &mut posture_state,
                &mut origin_state,
            )
            .await
            .unwrap();
        assert!(!denied.guard_report.overall.allowed);
        assert_eq!(denied.guard_report.overall.guard, "origin_budget");
        assert!(denied.guard_report.overall.message.contains("exhausted"));
    }

    #[tokio::test]
    async fn test_origin_budget_blocks_on_stateless_api_path() {
        let policy = policy_with_origins(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "slack-budgeted".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: Some(crate::policy::OriginBudgets {
                    mcp_tool_calls: Some(1),
                    ..Default::default()
                }),
                bridge_policy: None,
                explanation: None,
            }],
        });
        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        let report = engine
            .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
            .await
            .unwrap();
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "origin_budget");
        assert!(report
            .overall
            .message
            .contains("requires session runtime state"));
    }

    #[tokio::test]
    async fn test_pre_resolved_enclave_is_preserved_without_origin_for_minimal_profile() {
        let policy = policy_with_origins(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![],
        });
        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new().with_enclave(manual_enclave("manual-pre-set", None));

        let report = engine
            .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await
            .unwrap();

        assert!(report.overall.allowed);
        let metadata = report.metadata.as_ref().expect("metadata");
        let enclave = metadata.enclave.as_ref().expect("enclave metadata");
        assert_eq!(enclave.profile_id.as_deref(), Some("manual-pre-set"));
    }

    #[tokio::test]
    async fn test_origin_required_still_denies_without_origin_even_with_pre_resolved_enclave() {
        let policy = policy_with_origins(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![],
        });
        let engine = HushEngine::with_policy(policy);
        let context = GuardContext::new().with_enclave(manual_enclave("manual-pre-set", None));

        let report = engine
            .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await
            .unwrap();

        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "origin_required");
    }

    #[tokio::test]
    async fn test_receipt_contains_origin_metadata() {
        let mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec![],
            allow: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Allow),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-meta", mcp)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        let report = engine
            .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
            .await
            .unwrap();

        let receipt = engine
            .create_receipt_for_report(sha256(b"origin-test"), &report)
            .await
            .unwrap();
        let metadata = receipt.metadata.expect("expected receipt metadata");

        // Verify origin metadata is present
        let origin_val = metadata
            .pointer("/clawdstrike/origin")
            .expect("origin metadata missing");
        assert_eq!(
            origin_val.get("provider").and_then(|v| v.as_str()),
            Some("slack")
        );
        assert_eq!(
            origin_val.get("space_id").and_then(|v| v.as_str()),
            Some("C-test-123")
        );

        // Verify enclave metadata is present
        let enclave_val = metadata
            .pointer("/clawdstrike/enclave")
            .expect("enclave metadata missing");
        assert_eq!(
            enclave_val.get("profile_id").and_then(|v| v.as_str()),
            Some("slack-meta")
        );
        assert!(enclave_val.get("resolution_path").is_some());
    }

    #[tokio::test]
    async fn test_enclave_resolution_failure_deny() {
        // Origins config has deny default and no matching profile for Slack
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "github-only".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::GitHub),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: None,
                bridge_policy: None,
                explanation: None,
            }],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        // Slack origin + deny default + no Slack profile → resolution fails → deny report
        let report = engine
            .check_action_report(&GuardAction::McpTool("any_tool", &args), &context)
            .await
            .unwrap();

        assert!(!report.overall.allowed);
        assert!(report.overall.message.contains("enclave resolution failed"));
    }

    #[tokio::test]
    async fn test_enclave_default_action_block_without_allow_list() {
        // Enclave has default_action=Block and empty allow list → blocks all tools
        let mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec![],
            allow: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Block),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-locked", mcp)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        let report = engine
            .check_action_report(&GuardAction::McpTool("any_tool", &args), &context)
            .await
            .unwrap();

        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "enclave");
        assert!(report.overall.message.contains("blocked by default_action"));
    }

    #[tokio::test]
    async fn test_enclave_default_action_block_beats_confirmation_without_allow_list() {
        let mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec![],
            allow: vec![],
            require_confirmation: vec!["any_tool".to_string()],
            default_action: Some(McpDefaultAction::Block),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-locked", mcp)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        let report = engine
            .check_action_report(&GuardAction::McpTool("any_tool", &args), &context)
            .await
            .unwrap();

        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "enclave");
        assert_eq!(report.overall.severity, Severity::Error);
        assert!(report.overall.message.contains("blocked by default_action"));
    }

    #[tokio::test]
    async fn test_enclave_default_action_block_with_allow_list() {
        // Enclave has default_action=Block but "read_file" is in allow list
        let mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec![],
            allow: vec!["read_file".to_string()],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Block),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-allowlist", mcp)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        // "read_file" is in allow list → passes enclave check
        let report = engine
            .check_action_report(&GuardAction::McpTool("read_file", &args), &context)
            .await
            .unwrap();
        assert!(report.overall.allowed);

        // "write_file" is NOT in allow list → blocked by enclave
        let report = engine
            .check_action_report(&GuardAction::McpTool("write_file", &args), &context)
            .await
            .unwrap();
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "enclave");
    }

    #[tokio::test]
    async fn test_enclave_allow_list_can_still_require_confirmation() {
        let mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec![],
            allow: vec!["read_file".to_string()],
            require_confirmation: vec!["read_file".to_string()],
            default_action: Some(McpDefaultAction::Block),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-confirm", mcp)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        let report = engine
            .check_action_report(&GuardAction::McpTool("read_file", &args), &context)
            .await
            .unwrap();

        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "enclave");
        assert_eq!(report.overall.severity, Severity::Warning);
        assert!(report.overall.message.contains("requires confirmation"));
    }

    #[tokio::test]
    async fn test_enclave_wildcard_block() {
        // Enclave blocks "dangerous_*" pattern
        let mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec!["dangerous_*".to_string()],
            allow: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Allow),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-wildcard", mcp)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let args = serde_json::json!({});

        // "dangerous_exec" matches "dangerous_*" → blocked
        let report = engine
            .check_action_report(&GuardAction::McpTool("dangerous_exec", &args), &context)
            .await
            .unwrap();
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "enclave");

        // "safe_tool" does NOT match "dangerous_*" → passes enclave
        let report = engine
            .check_action_report(&GuardAction::McpTool("safe_tool", &args), &context)
            .await
            .unwrap();
        assert!(report.overall.allowed);
    }

    #[test]
    fn test_tool_matches_helper() {
        // Exact match
        assert!(tool_matches("read_file", "read_file"));
        assert!(!tool_matches("read_file", "write_file"));

        // Wildcard
        assert!(tool_matches("read_file", "*"));
        assert!(tool_matches("dangerous_exec", "dangerous_*"));
        assert!(tool_matches("dangerous_", "dangerous_*"));
        assert!(!tool_matches("safe_tool", "dangerous_*"));

        // Prefix only (no wildcard)
        assert!(!tool_matches("read_file_extra", "read_file"));
    }

    #[tokio::test]
    async fn test_enclave_non_mcp_action_not_affected() {
        // Enclave with MCP restrictions should not affect file access checks
        let mcp = crate::guards::McpToolConfig {
            enabled: true,
            block: vec!["*".to_string()],
            allow: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Block),
            ..Default::default()
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_mcp("slack-lockdown", mcp)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());

        // File access should not be affected by enclave MCP restrictions
        let report = engine
            .check_action_report(&GuardAction::FileAccess("/app/src/main.rs"), &context)
            .await
            .unwrap();
        assert!(report.overall.allowed);
    }

    // -----------------------------------------------------------------------
    // Origin Enclave + Posture Integration Tests (Phase 1.3)
    // -----------------------------------------------------------------------

    /// Helper: create a policy with both posture and origins configured.
    fn policy_with_posture_and_origins(posture_yaml: &str, origins: OriginsConfig) -> Policy {
        let mut policy = Policy::from_yaml(posture_yaml).unwrap();
        policy.version = "1.4.0".to_string();
        policy.origins = Some(origins);
        policy
    }

    /// Helper: create an origin profile that matches Slack and specifies a posture.
    fn slack_profile_with_posture(id: &str, posture: &str) -> OriginProfile {
        OriginProfile {
            id: id.to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
            posture: Some(posture.to_string()),
            mcp: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        }
    }

    #[tokio::test]
    async fn test_enclave_sets_initial_posture() {
        // Policy has initial="standard", enclave specifies posture="elevated".
        // First check should run with elevated posture and elevated budgets.
        let posture_yaml = r#"
version: "1.2.0"
name: "enclave-posture"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access]
      budgets:
        file_writes: 5
    elevated:
      capabilities: [file_access, file_write, egress]
      budgets:
        file_writes: 100
        egress_calls: 50
"#;

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![slack_profile_with_posture("slack-elevated", "elevated")],
        };
        let policy = policy_with_posture_and_origins(posture_yaml, origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let mut posture = None;

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::FileAccess("/app/src/main.rs"),
                &context,
                &mut posture,
            )
            .await
            .unwrap();

        // Enclave should have overridden the initial posture to "elevated".
        assert!(report.guard_report.overall.allowed);
        assert_eq!(report.posture_before, "elevated");
        assert_eq!(report.posture_after, "elevated");

        // Budgets should reflect the elevated state.
        let state = posture.as_ref().unwrap();
        assert_eq!(state.current_state, "elevated");
        assert_eq!(state.budgets.get("file_writes").map(|b| b.limit), Some(100));
        assert_eq!(state.budgets.get("egress_calls").map(|b| b.limit), Some(50));
    }

    #[tokio::test]
    async fn test_enclave_posture_does_not_override_mid_session() {
        // After a transition has occurred (transition_history not empty),
        // enclave posture is ignored.
        let posture_yaml = r#"
version: "1.2.0"
name: "enclave-posture-mid-session"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access, egress]
      budgets: {}
    elevated:
      capabilities: [file_access, file_write, egress]
      budgets: {}
    quarantine:
      capabilities: []
      budgets: {}
  transitions:
    - { from: "*", to: quarantine, on: any_violation }
"#;

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![slack_profile_with_posture("slack-elevated", "elevated")],
        };
        let policy = policy_with_posture_and_origins(posture_yaml, origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());

        // Pre-populate posture state with a non-empty transition history,
        // simulating a session that has already transitioned.
        let mut posture = Some(PostureRuntimeState {
            current_state: "quarantine".to_string(),
            entered_at: chrono::Utc::now().to_rfc3339(),
            transition_history: vec![PostureTransitionRecord {
                from: "standard".to_string(),
                to: "quarantine".to_string(),
                trigger: "any_violation".to_string(),
                at: chrono::Utc::now().to_rfc3339(),
            }],
            budgets: HashMap::new(),
            origin_runtime: None,
        });

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::FileAccess("/app/src/main.rs"),
                &context,
                &mut posture,
            )
            .await
            .unwrap();

        // Posture should remain quarantine — enclave must not override mid-session.
        assert_eq!(report.posture_before, "quarantine");
        let state = posture.as_ref().unwrap();
        assert_eq!(state.current_state, "quarantine");
    }

    #[tokio::test]
    async fn test_posture_path_uses_pre_resolved_enclave() {
        let posture_yaml = r#"
version: "1.2.0"
name: "enclave-pre-resolved"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access]
      budgets: {}
    elevated:
      capabilities: [file_access, file_write]
      budgets: {}
"#;

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_posture("slack-elevated", "elevated")],
        };
        let policy = policy_with_posture_and_origins(posture_yaml, origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new()
            .with_origin(test_github_origin())
            .with_enclave(manual_enclave("manual-pre-resolved", Some("elevated")));
        let mut posture = None;

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::FileAccess("/app/src/main.rs"),
                &context,
                &mut posture,
            )
            .await
            .unwrap();

        assert!(report.guard_report.overall.allowed);
        assert_eq!(report.posture_before, "elevated");
        assert_eq!(report.posture_after, "elevated");
        assert_eq!(
            posture.as_ref().map(|state| state.current_state.as_str()),
            Some("elevated")
        );
    }

    #[tokio::test]
    async fn test_enclave_references_nonexistent_posture_state() {
        // Enclave specifies posture="nonexistent" which doesn't exist in the program.
        // Should return an error (fail-closed).
        let posture_yaml = r#"
version: "1.2.0"
name: "enclave-posture-bad-state"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access]
      budgets: {}
"#;

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![slack_profile_with_posture("slack-bad", "nonexistent")],
        };
        let policy = policy_with_posture_and_origins(posture_yaml, origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let mut posture = None;

        let err = engine
            .check_action_report_with_posture(
                &GuardAction::FileAccess("/app/src/main.rs"),
                &context,
                &mut posture,
            )
            .await
            .unwrap_err();

        let msg = err.to_string();
        assert!(
            msg.contains("unknown posture state 'nonexistent'"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn test_no_enclave_posture_normal_flow() {
        // Enclave resolved but has no posture field — posture uses policy default.
        let posture_yaml = r#"
version: "1.2.0"
name: "enclave-posture-no-override"
posture:
  initial: standard
  states:
    standard:
      capabilities: [file_access]
      budgets:
        file_writes: 10
"#;

        // Profile matches Slack but has NO posture field.
        let profile = OriginProfile {
            id: "slack-no-posture".to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
            posture: None,
            mcp: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        };

        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::MinimalProfile),
            profiles: vec![profile],
        };
        let policy = policy_with_posture_and_origins(posture_yaml, origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let mut posture = None;

        let report = engine
            .check_action_report_with_posture(
                &GuardAction::FileAccess("/app/src/main.rs"),
                &context,
                &mut posture,
            )
            .await
            .unwrap();

        // Should use the policy's default initial posture "standard".
        assert!(report.guard_report.overall.allowed);
        assert_eq!(report.posture_before, "standard");
        assert_eq!(report.posture_after, "standard");

        let state = posture.as_ref().unwrap();
        assert_eq!(state.current_state, "standard");
        assert_eq!(state.budgets.get("file_writes").map(|b| b.limit), Some(10));
    }

    // -----------------------------------------------------------------------
    // Cross-Origin Isolation Tests (Phase 1b)
    // -----------------------------------------------------------------------

    /// Helper: create a GitHub origin context.
    fn test_github_origin() -> OriginContext {
        OriginContext {
            provider: OriginProvider::GitHub,
            space_id: Some("PR-42".into()),
            space_type: Some(SpaceType::PullRequest),
            ..OriginContext::default()
        }
    }

    /// Helper: create a Teams origin context.
    fn test_teams_origin() -> OriginContext {
        OriginContext {
            provider: OriginProvider::Teams,
            space_id: Some("T-channel-1".into()),
            ..OriginContext::default()
        }
    }

    /// Helper: create a Slack profile with a bridge policy.
    fn slack_profile_with_bridge(id: &str, bridge: Option<BridgePolicy>) -> OriginProfile {
        OriginProfile {
            id: id.to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                ..Default::default()
            },
            mcp: None,
            posture: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: bridge,
            explanation: None,
        }
    }

    /// Helper: create a GitHub profile (so cross-origin resolves for target).
    fn github_profile() -> OriginProfile {
        OriginProfile {
            id: "github-default".to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::GitHub),
                ..Default::default()
            },
            mcp: None,
            posture: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        }
    }

    /// Helper: create a Teams profile.
    fn teams_profile() -> OriginProfile {
        OriginProfile {
            id: "teams-default".to_string(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Teams),
                ..Default::default()
            },
            mcp: None,
            posture: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        }
    }

    async fn check_with_origin_runtime(
        engine: &HushEngine,
        context: &GuardContext,
        origin_state: &mut Option<OriginRuntimeState>,
    ) -> GuardReport {
        let mut posture_state = None;
        engine
            .check_action_report_with_runtime(
                &GuardAction::FileAccess("/app/src/main.rs"),
                context,
                &mut posture_state,
                origin_state,
            )
            .await
            .unwrap()
            .guard_report
    }

    fn manual_enclave(profile_id: &str, posture: Option<&str>) -> crate::enclave::ResolvedEnclave {
        crate::enclave::ResolvedEnclave {
            profile_id: Some(profile_id.to_string()),
            mcp: None,
            posture: posture.map(str::to_string),
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: Some("manual test enclave".to_string()),
            resolution_path: vec!["manual:test".to_string()],
        }
    }

    #[tokio::test]
    async fn test_cross_origin_same_origin_passes() {
        // Two checks from the same origin (same provider + same space_id)
        // should both succeed without any cross-origin denial.
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![slack_profile_with_bridge("slack-base", None)],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);

        let context = GuardContext::new().with_origin(test_slack_origin());
        let mut origin_state = None;

        // First check establishes session origin
        let report = check_with_origin_runtime(&engine, &context, &mut origin_state).await;
        assert!(report.overall.allowed);

        // Second check with same origin should pass
        let report = check_with_origin_runtime(&engine, &context, &mut origin_state).await;
        assert!(report.overall.allowed);
    }

    #[tokio::test]
    async fn test_origin_runtime_is_ignored_without_origins_policy() {
        let mut policy = Policy::new();
        policy.version = "1.4.0".to_string();
        policy.name = "origin-runtime-opt-in".to_string();
        let engine = HushEngine::with_policy(policy);
        let mut origin_state = None;

        let slack_ctx = GuardContext::new()
            .with_origin(test_slack_origin())
            .with_enclave(manual_enclave("manual-slack", None));
        let slack_report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
        assert!(slack_report.overall.allowed);
        assert!(origin_state.is_none());

        let github_ctx = GuardContext::new()
            .with_origin(test_github_origin())
            .with_enclave(manual_enclave("manual-github", None));
        let github_report =
            check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
        assert!(github_report.overall.allowed);
        assert!(origin_state.is_none());
    }

    #[tokio::test]
    async fn test_cross_origin_different_origin_no_bridge_denied() {
        // First check from Slack, second from GitHub, no bridge policy -> denied
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                slack_profile_with_bridge("slack-no-bridge", None),
                github_profile(),
            ],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);
        let mut origin_state = None;

        // First check from Slack establishes session origin
        let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
        let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
        assert!(report.overall.allowed);

        // Second check from GitHub: cross-origin, no bridge policy -> denied
        let github_ctx = GuardContext::new().with_origin(test_github_origin());
        let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "cross_origin");
        assert_eq!(report.overall.severity, Severity::Error);
        assert!(report
            .overall
            .message
            .contains("no bridge policy configured"));
    }

    #[tokio::test]
    async fn test_cross_origin_bridge_allowed() {
        // Bridge policy allows cross-origin to GitHub -> second check passes
        let bridge = BridgePolicy {
            allow_cross_origin: true,
            allowed_targets: vec![BridgeTarget {
                provider: Some(OriginProvider::GitHub),
                space_type: None,
                tags: vec![],
                visibility: None,
            }],
            require_approval: false,
        };
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                slack_profile_with_bridge("slack-bridged", Some(bridge)),
                github_profile(),
            ],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);
        let mut origin_state = None;

        // First check from Slack establishes session origin
        let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
        let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
        assert!(report.overall.allowed);

        // Second check from GitHub: bridge allows it
        let github_ctx = GuardContext::new().with_origin(test_github_origin());
        let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
        assert!(report.overall.allowed);
    }

    #[tokio::test]
    async fn test_cross_origin_bridge_reinitializes_budgets_from_target_enclave() {
        let bridge = BridgePolicy {
            allow_cross_origin: true,
            allowed_targets: vec![BridgeTarget {
                provider: Some(OriginProvider::GitHub),
                space_type: None,
                tags: vec![],
                visibility: None,
            }],
            require_approval: false,
        };
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                OriginProfile {
                    id: "slack-source".to_string(),
                    match_rules: OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        ..Default::default()
                    },
                    mcp: None,
                    posture: None,
                    egress: None,
                    data: None,
                    budgets: Some(crate::policy::OriginBudgets {
                        mcp_tool_calls: Some(5),
                        ..Default::default()
                    }),
                    bridge_policy: Some(bridge),
                    explanation: None,
                },
                OriginProfile {
                    id: "github-target".to_string(),
                    match_rules: OriginMatch {
                        provider: Some(OriginProvider::GitHub),
                        ..Default::default()
                    },
                    mcp: None,
                    posture: None,
                    egress: None,
                    data: None,
                    budgets: Some(crate::policy::OriginBudgets {
                        mcp_tool_calls: Some(1),
                        ..Default::default()
                    }),
                    bridge_policy: None,
                    explanation: None,
                },
            ],
        };
        let engine = HushEngine::with_policy(policy_with_origins(origins));
        let args = serde_json::json!({});
        let mut posture_state = None;
        let mut origin_state = None;

        let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
        let slack = engine
            .check_action_report_with_runtime(
                &GuardAction::McpTool("safe_tool", &args),
                &slack_ctx,
                &mut posture_state,
                &mut origin_state,
            )
            .await
            .unwrap();
        assert!(slack.guard_report.overall.allowed);
        assert_eq!(
            origin_state
                .as_ref()
                .and_then(|state| state.budgets.get("mcp_tool_calls"))
                .map(|counter| counter.limit),
            Some(5)
        );

        let github_ctx = GuardContext::new().with_origin(test_github_origin());
        let github = engine
            .check_action_report_with_runtime(
                &GuardAction::McpTool("safe_tool", &args),
                &github_ctx,
                &mut posture_state,
                &mut origin_state,
            )
            .await
            .unwrap();
        assert!(github.guard_report.overall.allowed);
        assert_eq!(
            origin_state
                .as_ref()
                .and_then(|state| state.current_enclave.profile_id.as_deref()),
            Some("github-target")
        );
        assert_eq!(
            origin_state
                .as_ref()
                .and_then(|state| state.budgets.get("mcp_tool_calls"))
                .map(|counter| counter.limit),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_posture_wrapper_persists_origin_runtime_between_calls() {
        let posture_yaml = r#"
version: "1.2.0"
name: "posture-origin-wrapper"
posture:
  initial: standard
  states:
    standard:
      capabilities: [mcp_tool]
"#;
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "slack-budgeted".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: Some(crate::policy::OriginBudgets {
                    mcp_tool_calls: Some(1),
                    ..Default::default()
                }),
                bridge_policy: None,
                explanation: None,
            }],
        };
        let engine =
            HushEngine::with_policy(policy_with_posture_and_origins(posture_yaml, origins));
        let args = serde_json::json!({});
        let context = GuardContext::new().with_origin(test_slack_origin());
        let mut posture = None;

        let first = engine
            .check_action_report_with_posture(
                &GuardAction::McpTool("safe_tool", &args),
                &context,
                &mut posture,
            )
            .await
            .unwrap();
        assert!(first.guard_report.overall.allowed);
        assert!(posture
            .as_ref()
            .and_then(|state| state.origin_runtime.as_ref())
            .is_some());

        let second = engine
            .check_action_report_with_posture(
                &GuardAction::McpTool("safe_tool", &args),
                &context,
                &mut posture,
            )
            .await
            .unwrap();
        assert!(!second.guard_report.overall.allowed);
        assert_eq!(second.guard_report.overall.guard, "origin_budget");
        assert!(second.guard_report.overall.message.contains("exhausted"));
    }

    #[tokio::test]
    async fn test_posture_wrapper_persists_origin_runtime_without_posture_program() {
        let engine = HushEngine::with_policy(policy_with_origins(OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![OriginProfile {
                id: "slack-budgeted".to_string(),
                match_rules: OriginMatch {
                    provider: Some(OriginProvider::Slack),
                    ..Default::default()
                },
                mcp: None,
                posture: None,
                egress: None,
                data: None,
                budgets: Some(crate::policy::OriginBudgets {
                    mcp_tool_calls: Some(1),
                    ..Default::default()
                }),
                bridge_policy: None,
                explanation: None,
            }],
        }));
        let args = serde_json::json!({});
        let context = GuardContext::new().with_origin(test_slack_origin());
        let mut posture = None;

        let first = engine
            .check_action_report_with_posture(
                &GuardAction::McpTool("safe_tool", &args),
                &context,
                &mut posture,
            )
            .await
            .unwrap();
        assert!(first.guard_report.overall.allowed);
        assert_eq!(
            posture.as_ref().map(|state| state.current_state.as_str()),
            Some("default")
        );
        assert!(posture
            .as_ref()
            .and_then(|state| state.origin_runtime.as_ref())
            .is_some());

        let second = engine
            .check_action_report_with_posture(
                &GuardAction::McpTool("safe_tool", &args),
                &context,
                &mut posture,
            )
            .await
            .unwrap();
        assert!(!second.guard_report.overall.allowed);
        assert_eq!(second.guard_report.overall.guard, "origin_budget");
        assert!(second.guard_report.overall.message.contains("exhausted"));
    }

    #[tokio::test]
    async fn test_cross_origin_bridge_require_approval() {
        // Bridge policy requires approval -> denied with Warning severity
        let bridge = BridgePolicy {
            allow_cross_origin: true,
            allowed_targets: vec![], // empty = all targets allowed
            require_approval: true,
        };
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                slack_profile_with_bridge("slack-approval", Some(bridge)),
                github_profile(),
            ],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);
        let mut origin_state = None;

        // First check from Slack establishes session origin
        let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
        let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
        assert!(report.overall.allowed);

        // Second check from GitHub: requires approval -> denied with Warning
        let github_ctx = GuardContext::new().with_origin(test_github_origin());
        let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "cross_origin");
        assert_eq!(report.overall.severity, Severity::Warning);
        assert!(report.overall.message.contains("requires approval"));
    }

    #[tokio::test]
    async fn test_cross_origin_target_not_in_allowed_targets() {
        // Bridge allows cross-origin but only to GitHub; target is Teams -> denied
        let bridge = BridgePolicy {
            allow_cross_origin: true,
            allowed_targets: vec![BridgeTarget {
                provider: Some(OriginProvider::GitHub),
                space_type: None,
                tags: vec![],
                visibility: None,
            }],
            require_approval: false,
        };
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                slack_profile_with_bridge("slack-github-only", Some(bridge)),
                github_profile(),
                teams_profile(),
            ],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);
        let mut origin_state = None;

        // First check from Slack establishes session origin
        let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
        let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
        assert!(report.overall.allowed);

        // Second check from Teams: not in allowed targets -> denied
        let teams_ctx = GuardContext::new().with_origin(test_teams_origin());
        let report = check_with_origin_runtime(&engine, &teams_ctx, &mut origin_state).await;
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "cross_origin");
        assert_eq!(report.overall.severity, Severity::Error);
        assert!(report
            .overall
            .message
            .contains("does not match any allowed bridge target"));
    }

    #[tokio::test]
    async fn test_cross_origin_first_origin_establishes_session() {
        // First check sets session_origin; verify by checking that a different
        // origin is detected as cross-origin on the second check.
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                slack_profile_with_bridge("slack-no-bridge", None),
                github_profile(),
            ],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);
        let mut origin_state = None;

        // First check from Slack establishes session origin
        let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
        let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
        assert!(report.overall.allowed);

        // Verify session_origin was set: different origin triggers cross-origin detection
        let github_ctx = GuardContext::new().with_origin(test_github_origin());
        let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "cross_origin");
        // No bridge policy configured, so it should say so
        assert!(report
            .overall
            .message
            .contains("no bridge policy configured"));
    }

    #[tokio::test]
    async fn test_cross_origin_disabled_bridge() {
        // Bridge policy exists but allow_cross_origin=false -> denied
        let bridge = BridgePolicy {
            allow_cross_origin: false,
            allowed_targets: vec![],
            require_approval: false,
        };
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                slack_profile_with_bridge("slack-disabled-bridge", Some(bridge)),
                github_profile(),
            ],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);
        let mut origin_state = None;

        let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
        let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
        assert!(report.overall.allowed);

        let github_ctx = GuardContext::new().with_origin(test_github_origin());
        let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "cross_origin");
        assert!(report
            .overall
            .message
            .contains("cross-origin transitions disabled"));
    }

    #[tokio::test]
    async fn test_cross_origin_bridge_target_with_space_type_filter() {
        // Bridge allows cross-origin to GitHub issues only; target is PR -> denied
        let bridge = BridgePolicy {
            allow_cross_origin: true,
            allowed_targets: vec![BridgeTarget {
                provider: Some(OriginProvider::GitHub),
                space_type: Some(SpaceType::Issue),
                tags: vec![],
                visibility: None,
            }],
            require_approval: false,
        };
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                slack_profile_with_bridge("slack-github-issues", Some(bridge)),
                github_profile(),
            ],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);
        let mut origin_state = None;

        let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
        let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
        assert!(report.overall.allowed);

        // GitHub origin with space_type=PullRequest but bridge only allows Issue -> denied
        let github_ctx = GuardContext::new().with_origin(test_github_origin());
        let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "cross_origin");
        assert!(report
            .overall
            .message
            .contains("does not match any allowed bridge target"));
    }

    #[tokio::test]
    async fn test_cross_origin_bridge_target_with_visibility_filter() {
        // Bridge allows cross-origin only to public GitHub spaces
        let bridge = BridgePolicy {
            allow_cross_origin: true,
            allowed_targets: vec![BridgeTarget {
                provider: Some(OriginProvider::GitHub),
                space_type: None,
                tags: vec![],
                visibility: Some(Visibility::Public),
            }],
            require_approval: false,
        };
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                slack_profile_with_bridge("slack-public-github", Some(bridge)),
                github_profile(),
            ],
        };
        let policy = policy_with_origins(origins);
        let engine = HushEngine::with_policy(policy);
        let mut origin_state = None;

        let slack_ctx = GuardContext::new().with_origin(test_slack_origin());
        let report = check_with_origin_runtime(&engine, &slack_ctx, &mut origin_state).await;
        assert!(report.overall.allowed);

        // GitHub origin without visibility does not match Public filter -> denied
        let github_ctx = GuardContext::new().with_origin(test_github_origin());
        let report = check_with_origin_runtime(&engine, &github_ctx, &mut origin_state).await;
        assert!(!report.overall.allowed);
        assert_eq!(report.overall.guard, "cross_origin");

        // Now test with a public GitHub origin (new engine instance)
        let bridge2 = BridgePolicy {
            allow_cross_origin: true,
            allowed_targets: vec![BridgeTarget {
                provider: Some(OriginProvider::GitHub),
                space_type: None,
                tags: vec![],
                visibility: Some(Visibility::Public),
            }],
            require_approval: false,
        };
        let origins2 = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                slack_profile_with_bridge("slack-public-github", Some(bridge2)),
                github_profile(),
            ],
        };
        let engine2 = HushEngine::with_policy(policy_with_origins(origins2));
        let mut origin_state2 = None;

        let slack_ctx2 = GuardContext::new().with_origin(test_slack_origin());
        let _ = check_with_origin_runtime(&engine2, &slack_ctx2, &mut origin_state2).await;

        let public_github = OriginContext {
            provider: OriginProvider::GitHub,
            space_id: Some("repo-1".into()),
            visibility: Some(Visibility::Public),
            ..OriginContext::default()
        };
        let github_ctx2 = GuardContext::new().with_origin(public_github);
        let report = check_with_origin_runtime(&engine2, &github_ctx2, &mut origin_state2).await;
        assert!(report.overall.allowed);
    }

    #[tokio::test]
    async fn test_cross_origin_same_space_trust_downgrade_denied_without_bridge() {
        let origins = OriginsConfig {
            default_behavior: Some(OriginDefaultBehavior::Deny),
            profiles: vec![
                OriginProfile {
                    id: "slack-internal".to_string(),
                    match_rules: OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        external_participants: Some(false),
                        ..Default::default()
                    },
                    mcp: None,
                    posture: None,
                    egress: None,
                    data: None,
                    budgets: None,
                    bridge_policy: None,
                    explanation: None,
                },
                OriginProfile {
                    id: "slack-external".to_string(),
                    match_rules: OriginMatch {
                        provider: Some(OriginProvider::Slack),
                        external_participants: Some(true),
                        ..Default::default()
                    },
                    mcp: None,
                    posture: None,
                    egress: None,
                    data: None,
                    budgets: None,
                    bridge_policy: None,
                    explanation: None,
                },
            ],
        };
        let engine = HushEngine::with_policy(policy_with_origins(origins));
        let mut origin_state = None;

        let internal_origin = OriginContext {
            provider: OriginProvider::Slack,
            space_id: Some("C-test-123".into()),
            external_participants: Some(false),
            ..OriginContext::default()
        };
        let external_origin = OriginContext {
            provider: OriginProvider::Slack,
            space_id: Some("C-test-123".into()),
            external_participants: Some(true),
            ..OriginContext::default()
        };

        let internal_report = check_with_origin_runtime(
            &engine,
            &GuardContext::new().with_origin(internal_origin),
            &mut origin_state,
        )
        .await;
        assert!(internal_report.overall.allowed);

        let external_report = check_with_origin_runtime(
            &engine,
            &GuardContext::new().with_origin(external_origin),
            &mut origin_state,
        )
        .await;
        assert!(!external_report.overall.allowed);
        assert_eq!(external_report.overall.guard, "cross_origin");
        assert!(external_report
            .overall
            .message
            .contains("no bridge policy configured"));
    }
}
