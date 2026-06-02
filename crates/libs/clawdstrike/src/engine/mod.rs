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

fn severity_to_core(s: &Severity) -> crate::core::CoreSeverity {
    match s {
        Severity::Info => crate::core::CoreSeverity::Info,
        Severity::Warning => crate::core::CoreSeverity::Warning,
        Severity::Error => crate::core::CoreSeverity::Error,
        Severity::Critical => crate::core::CoreSeverity::Critical,
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
    let tuples: Vec<(bool, crate::core::CoreSeverity, bool)> = results
        .iter()
        .map(|r| (r.allowed, severity_to_core(&r.severity), r.is_sanitized()))
        .collect();

    match crate::core::aggregate::aggregate_index(&tuples) {
        Some(idx) => results[idx].clone(),
        None => GuardResult::allow("engine"),
    }
}

#[cfg(test)]
mod tests;
