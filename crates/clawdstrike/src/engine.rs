//! HushEngine - Main entry point for security enforcement

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use hush_core::receipt::{Provenance, Verdict, ViolationRef};
use hush_core::{sha256, Hash, Keypair, Receipt, SignedReceipt};
use serde::{Deserialize, Serialize};

use crate::async_guards::{AsyncGuard, AsyncGuardRuntime};
use crate::error::{Error, Result};
use crate::guards::{Guard, GuardAction, GuardContext, GuardResult, Severity};
use crate::policy::{Policy, PolicyGuards, RuleSet};

/// Per-guard evidence + an aggregated verdict.
#[must_use]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GuardReport {
    pub overall: GuardResult,
    pub per_guard: Vec<GuardResult>,
}

/// The main security enforcement engine
pub struct HushEngine {
    /// Active policy
    policy: Policy,
    /// Instantiated guards
    guards: PolicyGuards,
    /// Additional guards appended at runtime (evaluated after built-ins)
    extra_guards: Vec<Box<dyn Guard>>,
    /// Signing keypair (optional)
    keypair: Option<Keypair>,
    /// Session state
    state: Arc<RwLock<EngineState>>,
    /// Async guard runtime
    async_runtime: Arc<AsyncGuardRuntime>,
    /// Async guards instantiated from policy
    async_guards: Vec<Arc<dyn AsyncGuard>>,
    /// Async guard initialization error (fail closed)
    async_guard_init_error: Option<String>,
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
}

impl HushEngine {
    /// Create a new engine with default policy
    pub fn new() -> Self {
        Self::with_policy(Policy::default())
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

        Self {
            policy,
            guards,
            extra_guards: Vec::new(),
            keypair: None,
            state: Arc::new(RwLock::new(EngineState::default())),
            async_runtime,
            async_guards,
            async_guard_init_error,
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
        if let Some(msg) = self.async_guard_init_error.as_ref() {
            return Err(Error::ConfigError(msg.clone()));
        }

        let builtins = self.guards.builtin_guards_in_order();
        let mut per_guard: Vec<GuardResult> =
            Vec::with_capacity(builtins.len() + self.extra_guards.len());

        for guard in builtins.chain(self.extra_guards.iter().map(|g| g.as_ref())) {
            if !guard.handles(action) {
                continue;
            }

            let result = guard.check(action, context).await;

            if self.policy.settings.effective_verbose_logging() {
                debug!(
                    guard = guard.name(),
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

            per_guard.push(result);

            if self.policy.settings.effective_fail_fast()
                && per_guard.last().is_some_and(|r| !r.allowed)
            {
                break;
            }
        }

        // If we've already denied locally, don't run async guards (avoids unnecessary network calls).
        if per_guard.iter().all(|r| r.allowed) && !self.async_guards.is_empty() {
            let async_results = self
                .async_runtime
                .evaluate_async_guards(
                    &self.async_guards,
                    action,
                    context,
                    self.policy.settings.effective_fail_fast(),
                )
                .await;

            for result in async_results {
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

                per_guard.push(result);

                if self.policy.settings.effective_fail_fast()
                    && per_guard.last().is_some_and(|r| !r.allowed)
                {
                    break;
                }
            }
        }

        // Count the check even if we fail-fast.
        {
            let mut state = self.state.write().await;
            state.action_count += 1;
        }

        let overall = aggregate_overall(&per_guard);

        Ok(GuardReport { overall, per_guard })
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

        if !self.extra_guards.is_empty() {
            let extra_guards: Vec<&str> = self.extra_guards.iter().map(|g| g.name()).collect();
            receipt = receipt.with_metadata(serde_json::json!({
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
}
