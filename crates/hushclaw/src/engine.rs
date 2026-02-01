//! HushEngine - Main entry point for security enforcement

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use hush_core::receipt::{Provenance, Verdict, ViolationRef};
use hush_core::{sha256, Hash, Keypair, Receipt, SignedReceipt};

use crate::error::{Error, Result};
use crate::guards::{Guard, GuardAction, GuardContext, GuardResult, Severity};
use crate::policy::{Policy, PolicyGuards, RuleSet};

/// The main security enforcement engine
pub struct HushEngine {
    /// Active policy
    policy: Policy,
    /// Instantiated guards
    guards: PolicyGuards,
    /// Signing keypair (optional)
    keypair: Option<Keypair>,
    /// Session state
    state: Arc<RwLock<EngineState>>,
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
        Self {
            policy,
            guards,
            keypair: None,
            state: Arc::new(RwLock::new(EngineState::default())),
        }
    }

    /// Create from a named ruleset
    pub fn from_ruleset(name: &str) -> Result<Self> {
        let ruleset = RuleSet::by_name(name)
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

    /// Get the policy hash
    pub fn policy_hash(&self) -> Result<Hash> {
        let yaml = self.policy.to_yaml()?;
        Ok(sha256(yaml.as_bytes()))
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
        let guards: Vec<&dyn Guard> = vec![
            &self.guards.forbidden_path,
            &self.guards.egress_allowlist,
            &self.guards.secret_leak,
            &self.guards.patch_integrity,
            &self.guards.mcp_tool,
        ];

        let mut final_result: Option<GuardResult> = None;

        for guard in guards {
            if !guard.handles(action) {
                continue;
            }

            let result = guard.check(action, context).await;

            if self.policy.settings.verbose_logging {
                debug!(
                    guard = guard.name(),
                    allowed = result.allowed,
                    severity = ?result.severity,
                    "Guard check completed"
                );
            }

            // Record violations
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

                if self.policy.settings.fail_fast {
                    return Ok(result);
                }
            }

            // Keep the most severe result
            match (&final_result, &result) {
                (None, _) => final_result = Some(result),
                (Some(prev), curr) if !curr.allowed && prev.allowed => {
                    final_result = Some(result);
                }
                (Some(prev), curr) if !curr.allowed && !prev.allowed => {
                    // Keep the more severe one
                    if severity_ord(&curr.severity) > severity_ord(&prev.severity) {
                        final_result = Some(result);
                    }
                }
                _ => {}
            }
        }

        // Update action count
        {
            let mut state = self.state.write().await;
            state.action_count += 1;
        }

        Ok(final_result.unwrap_or_else(|| GuardResult::allow("engine")))
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
            hushclaw_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            provider: None,
            policy_hash: Some(self.policy_hash()?),
            ruleset: Some(self.policy.name.clone()),
            violations: state.violations.clone(),
        };

        Ok(Receipt::new(content_hash, verdict).with_provenance(provenance))
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

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn test_violation_tracking() {
        let engine = HushEngine::new();
        let context = GuardContext::new();

        // Cause a violation
        engine
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
        engine
            .check_file_access("/app/main.rs", &context)
            .await
            .unwrap();

        let content_hash = sha256(b"test content");
        let receipt = engine.create_receipt(content_hash).await.unwrap();

        assert!(receipt.verdict.passed);
        assert!(receipt.provenance.is_some());
    }

    #[tokio::test]
    async fn test_create_signed_receipt() {
        let engine = HushEngine::new().with_generated_keypair();
        let context = GuardContext::new();

        engine
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

        engine
            .check_file_access("/home/user/.ssh/id_rsa", &context)
            .await
            .unwrap();
        assert_eq!(engine.stats().await.violation_count, 1);

        engine.reset().await;
        assert_eq!(engine.stats().await.violation_count, 0);
    }
}
