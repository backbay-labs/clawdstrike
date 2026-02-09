//! Inline Reference Monitors (IRM)
//!
//! IRMs intercept host calls from sandboxed modules and enforce policy at runtime.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │  Sandboxed Module                                           │
//! └──────────────────────────┬──────────────────────────────────┘
//!                            │ host call
//!                            ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │  IRM Router                                                 │
//! │  - Dispatches to specialized monitors                       │
//! │  - Aggregates decisions                                     │
//! │  - Emits telemetry                                          │
//! └──────────────────────────┬──────────────────────────────────┘
//!                            │
//!         ┌──────────────────┼──────────────────┐
//!         │                  │                  │
//!         ▼                  ▼                  ▼
//! ┌───────────────┐  ┌───────────────┐  ┌───────────────┐
//! │ Filesystem    │  │ Network       │  │ Execution     │
//! │ Monitor       │  │ Monitor       │  │ Monitor       │
//! └───────────────┘  └───────────────┘  └───────────────┘
//! ```

mod exec;
mod fs;
mod net;
mod sandbox;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::policy::Policy;

pub use exec::ExecutionIrm;
pub use fs::FilesystemIrm;
pub use net::NetworkIrm;
pub use sandbox::{Sandbox, SandboxConfig, SandboxStats};

/// Event types emitted by IRMs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventType {
    /// Module loaded
    ModuleStart,
    /// Generic host call
    HostCall,
    /// Filesystem read
    FsRead,
    /// Filesystem write
    FsWrite,
    /// Network connection
    NetConnect,
    /// DNS resolution
    DnsResolve,
    /// Command execution
    CommandExec,
    /// Artifact produced
    ArtifactEmit,
    /// Policy violation
    PolicyViolation,
    /// Module exit
    ModuleExit,
}

impl EventType {
    /// Map a host function name to an event type
    pub fn from_function(function: &str) -> Self {
        match function {
            f if f.starts_with("fd_read") || f.starts_with("path_open") => EventType::FsRead,
            f if f.starts_with("fd_write") || f.starts_with("path_create") => EventType::FsWrite,
            f if f.starts_with("sock_") || f.starts_with("connect") => EventType::NetConnect,
            f if f == "command_exec" || f.starts_with("proc_") || f.starts_with("spawn") => {
                EventType::CommandExec
            }
            _ => EventType::HostCall,
        }
    }
}

/// Filesystem operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FsOperation {
    /// Read from a file
    Read { path: String },
    /// Write to a file
    Write {
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        content_hash: Option<String>,
    },
    /// Delete a file
    Delete { path: String },
    /// List directory contents
    List { path: String },
}

/// Network operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NetOperation {
    /// TCP/UDP connection
    Connect { host: String, port: u16 },
    /// DNS resolution
    Dns { domain: String },
    /// Listen on a port
    Listen { port: u16 },
}

/// Execution operation types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExecOperation {
    /// Spawn a process
    Spawn { command: String, args: Vec<String> },
    /// Send a signal
    Signal { pid: u32, signal: i32 },
}

/// Decision from an IRM check
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "lowercase")]
pub enum Decision {
    /// Allow the operation
    Allow,
    /// Deny the operation
    Deny { reason: String },
    /// Allow but audit/log
    Audit { message: String },
}

impl Decision {
    /// Check if the operation is allowed
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow | Decision::Audit { .. })
    }

    /// Create a deny decision
    pub fn deny(reason: impl Into<String>) -> Self {
        Decision::Deny {
            reason: reason.into(),
        }
    }

    /// Create an audit decision
    pub fn audit(message: impl Into<String>) -> Self {
        Decision::Audit {
            message: message.into(),
        }
    }
}

/// Host call intercepted by IRM
#[derive(Debug, Clone)]
pub struct HostCall {
    /// Host function name
    pub function: String,
    /// Arguments (serialized)
    pub args: Vec<serde_json::Value>,
    /// Call metadata
    pub metadata: HostCallMetadata,
}

impl HostCall {
    /// Create a new host call
    pub fn new(function: impl Into<String>, args: Vec<serde_json::Value>) -> Self {
        Self {
            function: function.into(),
            args,
            metadata: HostCallMetadata::default(),
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, metadata: HostCallMetadata) -> Self {
        self.metadata = metadata;
        self
    }
}

/// Metadata about a host call
#[derive(Debug, Clone)]
pub struct HostCallMetadata {
    /// Source location in module (if available)
    pub source_location: Option<String>,
    /// Call stack depth
    pub stack_depth: usize,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
}

impl Default for HostCallMetadata {
    fn default() -> Self {
        Self {
            source_location: None,
            stack_depth: 0,
            timestamp: Utc::now(),
        }
    }
}

impl HostCallMetadata {
    /// Create new metadata with current timestamp
    pub fn now() -> Self {
        Self {
            timestamp: Utc::now(),
            ..Default::default()
        }
    }
}

/// Event recorded by an IRM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IrmEvent {
    /// Unique event ID
    pub event_id: String,
    /// Event type
    pub event_type: EventType,
    /// Timestamp
    pub timestamp: DateTime<Utc>,
    /// Run/session ID
    pub run_id: String,
    /// Event-specific data
    pub data: serde_json::Value,
    /// Decision made
    pub decision: Decision,
}

impl IrmEvent {
    /// Create a new IRM event
    pub fn new(
        event_type: EventType,
        run_id: impl Into<String>,
        data: serde_json::Value,
        decision: Decision,
    ) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            event_type,
            timestamp: Utc::now(),
            run_id: run_id.into(),
            data,
            decision,
        }
    }
}

/// Inline Reference Monitor trait
#[async_trait]
pub trait Monitor: Send + Sync {
    /// Monitor name
    fn name(&self) -> &str;

    /// Check if this monitor handles the given event type
    fn handles(&self, event_type: EventType) -> bool;

    /// Evaluate a host call against policy
    async fn evaluate(&self, call: &HostCall, policy: &Policy) -> Decision;
}

/// IRM Router that dispatches to specialized monitors
pub struct IrmRouter {
    monitors: Vec<Arc<dyn Monitor>>,
    policy: Policy,
}

impl IrmRouter {
    /// Create a new IRM router with default monitors
    pub fn new(policy: Policy) -> Self {
        let monitors: Vec<Arc<dyn Monitor>> = vec![
            Arc::new(FilesystemIrm::new()),
            Arc::new(NetworkIrm::new()),
            Arc::new(ExecutionIrm::new()),
        ];

        Self { monitors, policy }
    }

    /// Create with custom monitors
    pub fn with_monitors(policy: Policy, monitors: Vec<Arc<dyn Monitor>>) -> Self {
        Self { monitors, policy }
    }

    /// Evaluate a host call through all applicable monitors
    pub async fn evaluate(&self, call: &HostCall) -> (Decision, Vec<String>) {
        let mut decisions = Vec::new();
        let mut applied_monitors = Vec::new();

        let event_type = EventType::from_function(&call.function);

        for monitor in &self.monitors {
            if monitor.handles(event_type) {
                let decision = monitor.evaluate(call, &self.policy).await;
                applied_monitors.push(monitor.name().to_string());

                match &decision {
                    Decision::Deny { .. } => {
                        // Deny takes precedence - return immediately
                        return (decision, applied_monitors);
                    }
                    Decision::Audit { .. } => {
                        decisions.push(decision);
                    }
                    Decision::Allow => {
                        decisions.push(decision);
                    }
                }
            }
        }

        // If any audits, return the first audit
        for decision in &decisions {
            if matches!(decision, Decision::Audit { .. }) {
                return (decision.clone(), applied_monitors);
            }
        }

        // All allowed
        (Decision::Allow, applied_monitors)
    }

    /// Create an IRM event from a host call evaluation
    pub fn create_event(&self, call: &HostCall, decision: Decision, run_id: &str) -> IrmEvent {
        let event_type = EventType::from_function(&call.function);

        IrmEvent::new(
            event_type,
            run_id,
            serde_json::json!({
                "function": call.function,
                "args": call.args,
            }),
            decision,
        )
    }

    /// Get the policy
    pub fn policy(&self) -> &Policy {
        &self.policy
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    #[test]
    fn test_fs_operation_serialization() {
        let op = FsOperation::Read {
            path: "/etc/passwd".to_string(),
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("read"));
        assert!(json.contains("/etc/passwd"));
    }

    #[test]
    fn test_net_operation_serialization() {
        let op = NetOperation::Connect {
            host: "api.github.com".to_string(),
            port: 443,
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("connect"));
        assert!(json.contains("api.github.com"));
    }

    #[test]
    fn test_exec_operation_serialization() {
        let op = ExecOperation::Spawn {
            command: "ls".to_string(),
            args: vec!["-la".to_string()],
        };
        let json = serde_json::to_string(&op).unwrap();
        assert!(json.contains("spawn"));
        assert!(json.contains("ls"));
    }

    #[test]
    fn test_decision_allow() {
        let decision = Decision::Allow;
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_decision_deny() {
        let decision = Decision::Deny {
            reason: "forbidden".to_string(),
        };
        assert!(!decision.is_allowed());
    }

    #[test]
    fn test_decision_audit() {
        let decision = Decision::Audit {
            message: "logged".to_string(),
        };
        assert!(decision.is_allowed());
    }

    #[test]
    fn test_event_type_mapping() {
        assert_eq!(EventType::from_function("fd_read"), EventType::FsRead);
        assert_eq!(EventType::from_function("fd_write"), EventType::FsWrite);
        assert_eq!(
            EventType::from_function("sock_connect"),
            EventType::NetConnect
        );
        assert_eq!(
            EventType::from_function("command_exec"),
            EventType::CommandExec
        );
        assert_eq!(EventType::from_function("unknown_fn"), EventType::HostCall);
    }

    #[test]
    fn test_host_call_creation() {
        let call = HostCall::new("fd_read", vec![serde_json::json!("/etc/passwd")]);
        assert_eq!(call.function, "fd_read");
        assert_eq!(call.args.len(), 1);
    }

    #[test]
    fn test_irm_event_creation() {
        let event = IrmEvent::new(
            EventType::FsRead,
            "run-123",
            serde_json::json!({"path": "/etc/passwd"}),
            Decision::Allow,
        );
        assert_eq!(event.run_id, "run-123");
        assert_eq!(event.event_type, EventType::FsRead);
        assert!(!event.event_id.is_empty());
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::policy::Policy;

    #[tokio::test]
    async fn test_irm_router_fs_evaluation() {
        let policy = Policy::default();
        let router = IrmRouter::new(policy);

        // Test forbidden path
        let call = HostCall::new("fd_read", vec![serde_json::json!("/etc/shadow")]);
        let (decision, monitors) = router.evaluate(&call).await;

        assert!(!decision.is_allowed());
        assert!(monitors.contains(&"filesystem_irm".to_string()));
    }

    #[tokio::test]
    async fn test_irm_router_net_evaluation() {
        let policy = Policy::default();
        let router = IrmRouter::new(policy);

        // Test unknown host
        let call = HostCall::new(
            "sock_connect",
            vec![serde_json::json!("https://unknown-host.com/api")],
        );
        let (decision, monitors) = router.evaluate(&call).await;

        assert!(!decision.is_allowed());
        assert!(monitors.contains(&"network_irm".to_string()));
    }

    #[tokio::test]
    async fn test_irm_router_exec_evaluation() {
        let policy = Policy::default();
        let router = IrmRouter::new(policy);

        // Test dangerous command
        let call = HostCall::new(
            "command_exec",
            vec![serde_json::json!("rm"), serde_json::json!(["-rf", "/"])],
        );
        let (decision, monitors) = router.evaluate(&call).await;

        assert!(!decision.is_allowed());
        assert!(monitors.contains(&"execution_irm".to_string()));
    }

    #[tokio::test]
    async fn test_irm_router_create_event() {
        let policy = Policy::default();
        let router = IrmRouter::new(policy);

        let call = HostCall::new("fd_read", vec![serde_json::json!("/app/main.rs")]);
        let event = router.create_event(&call, Decision::Allow, "test-run-123");

        assert_eq!(event.run_id, "test-run-123");
        assert_eq!(event.event_type, EventType::FsRead);
        assert!(event.decision.is_allowed());
    }

    #[tokio::test]
    async fn test_full_sandbox_workflow() {
        use super::sandbox::{Sandbox, SandboxConfig};

        let policy = Policy::default();
        let config = SandboxConfig {
            fail_fast: false,
            max_events: 100,
            emit_telemetry: true,
        };
        let sandbox = Sandbox::with_config(policy, config);

        // Initialize
        sandbox.init().await.unwrap();

        // Run various operations
        let _ = sandbox.check_fs("/workspace/src/main.rs", false).await;
        let _ = sandbox.check_fs("/workspace/output.txt", true).await;
        let _ = sandbox.check_net("api.github.com", 443).await;
        let _ = sandbox.check_exec("git", &["status".to_string()]).await;

        // Check stats
        let stats = sandbox.stats().await;
        assert!(stats.active);
        assert!(stats.allowed_count > 0);

        // Get events
        let events = sandbox.events().await;
        assert!(!events.is_empty());

        // Cleanup
        sandbox.cleanup().await.unwrap();
        assert!(!sandbox.stats().await.active);
    }
}
