//! WasmGuard and WasmGuardFactory — host-side wrappers that implement the Guard
//! trait by delegating to a sandboxed WASM plugin module.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

use crate::error::Result;
use crate::guards::{CustomGuardFactory, Guard, GuardAction, GuardContext, GuardResult, Severity};
use crate::plugins::manifest::{PluginCapabilities, PluginResourceLimits};
use crate::plugins::runtime::{
    execute_wasm_guard_bytes, WasmGuardInputEnvelope, WasmGuardRuntimeOptions,
};

/// A security guard backed by a sandboxed WASM module.
///
/// The compiled WASM bytes are cached via `Arc` so that cloning the guard (or
/// building multiple instances from the same factory) does not duplicate the
/// underlying allocation.
pub struct WasmGuard {
    /// Human-readable guard identifier (e.g. `acme.secret-scan`).
    guard_name: String,
    /// Raw WASM module bytes, shared across clones.
    wasm_bytes: Arc<Vec<u8>>,
    /// Declared action types this guard handles. Empty means "all".
    handles_actions: Vec<String>,
    /// Sandbox capabilities granted to the plugin.
    capabilities: PluginCapabilities,
    /// Resource limits for the WASM runtime.
    resources: PluginResourceLimits,
    /// Per-instance configuration forwarded into the WASM envelope.
    config: Value,
}

impl WasmGuard {
    /// Create a new WASM-backed guard.
    pub fn new(
        guard_name: String,
        wasm_bytes: Arc<Vec<u8>>,
        handles_actions: Vec<String>,
        capabilities: PluginCapabilities,
        resources: PluginResourceLimits,
        config: Value,
    ) -> Self {
        Self {
            guard_name,
            wasm_bytes,
            handles_actions,
            capabilities,
            resources,
            config,
        }
    }

    /// Map a `GuardAction` to its string action-type name.
    fn action_type_str(action: &GuardAction<'_>) -> &'static str {
        match action {
            GuardAction::FileAccess(_) => "file_access",
            GuardAction::FileWrite(_, _) => "file_write",
            GuardAction::NetworkEgress(_, _) => "network_egress",
            GuardAction::ShellCommand(_) => "shell_command",
            GuardAction::McpTool(_, _) => "mcp_tool",
            GuardAction::Patch(_, _) => "patch",
            GuardAction::Custom(_, _) => "custom",
        }
    }

    /// Serialize a `GuardAction` into the JSON payload expected by WASM guards.
    fn action_to_payload(action: &GuardAction<'_>, context: &GuardContext) -> Value {
        let data = match action {
            GuardAction::FileAccess(path) => serde_json::json!({
                "type": "file_access",
                "path": path,
            }),
            GuardAction::FileWrite(path, content) => serde_json::json!({
                "type": "file_write",
                "path": path,
                "content_length": content.len(),
                "content_utf8": String::from_utf8_lossy(content),
            }),
            GuardAction::NetworkEgress(host, port) => serde_json::json!({
                "type": "network_egress",
                "host": host,
                "port": port,
            }),
            GuardAction::ShellCommand(cmd) => serde_json::json!({
                "type": "shell_command",
                "command": cmd,
            }),
            GuardAction::McpTool(name, args) => serde_json::json!({
                "type": "mcp_tool",
                "toolName": name,
                "parameters": args,
            }),
            GuardAction::Patch(file, diff) => serde_json::json!({
                "type": "patch",
                "file": file,
                "diff": diff,
            }),
            GuardAction::Custom(kind, payload) => serde_json::json!({
                "type": kind,
                "data": payload,
            }),
        };

        serde_json::json!({
            "eventType": Self::action_type_str(action),
            "data": data,
            "context": {
                "cwd": context.cwd,
                "session_id": context.session_id,
                "agent_id": context.agent_id,
            },
        })
    }
}

#[async_trait]
impl Guard for WasmGuard {
    fn name(&self) -> &str {
        &self.guard_name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        if self.handles_actions.is_empty() {
            return true;
        }
        let action_str = Self::action_type_str(action);
        self.handles_actions.iter().any(|h| h == action_str)
    }

    async fn check(&self, action: &GuardAction<'_>, context: &GuardContext) -> GuardResult {
        let envelope = WasmGuardInputEnvelope {
            guard: self.guard_name.clone(),
            action_type: Some(Self::action_type_str(action).to_string()),
            payload: Self::action_to_payload(action, context),
            config: self.config.clone(),
        };

        let options = WasmGuardRuntimeOptions {
            capabilities: self.capabilities.clone(),
            resources: self.resources.clone(),
        };

        // Execute WASM in a blocking context since wasmtime is synchronous.
        let wasm_bytes = Arc::clone(&self.wasm_bytes);
        let result = tokio::task::spawn_blocking(move || {
            execute_wasm_guard_bytes(&wasm_bytes, &envelope, &options)
        })
        .await;

        match result {
            Ok(Ok(execution)) => execution.result,
            Ok(Err(e)) => {
                // WASM runtime error → fail-closed
                GuardResult {
                    allowed: false,
                    guard: self.guard_name.clone(),
                    severity: Severity::Error,
                    message: format!("WASM guard runtime error: {e}"),
                    details: Some(serde_json::json!({
                        "runtime_fault": "execution_error",
                    })),
                }
            }
            Err(e) => {
                // Tokio join error (panic in blocking task) → fail-closed
                GuardResult {
                    allowed: false,
                    guard: self.guard_name.clone(),
                    severity: Severity::Error,
                    message: format!("WASM guard task panicked: {e}"),
                    details: Some(serde_json::json!({
                        "runtime_fault": "task_panic",
                    })),
                }
            }
        }
    }
}

/// Factory that produces [`WasmGuard`] instances from cached WASM bytes.
///
/// Registered in the [`crate::guards::CustomGuardRegistry`] and invoked
/// when a policy references the guard by id.
pub struct WasmGuardFactory {
    /// Guard identifier (matches the `id` used in policy YAML).
    guard_id: String,
    /// Shared WASM module bytes.
    wasm_bytes: Arc<Vec<u8>>,
    /// Declared action types the guard handles.
    handles_actions: Vec<String>,
    /// Capabilities granted to the plugin sandbox.
    capabilities: PluginCapabilities,
    /// Resource limits for the WASM runtime.
    resources: PluginResourceLimits,
}

impl WasmGuardFactory {
    /// Create a new factory for a WASM guard plugin.
    pub fn new(
        guard_id: String,
        wasm_bytes: Vec<u8>,
        handles_actions: Vec<String>,
        capabilities: PluginCapabilities,
        resources: PluginResourceLimits,
    ) -> Self {
        Self {
            guard_id,
            wasm_bytes: Arc::new(wasm_bytes),
            handles_actions,
            capabilities,
            resources,
        }
    }
}

impl CustomGuardFactory for WasmGuardFactory {
    fn id(&self) -> &str {
        &self.guard_id
    }

    fn build(&self, config: Value) -> Result<Box<dyn Guard>> {
        Ok(Box::new(WasmGuard::new(
            self.guard_id.clone(),
            Arc::clone(&self.wasm_bytes),
            self.handles_actions.clone(),
            self.capabilities.clone(),
            self.resources.clone(),
            config,
        )))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guards::GuardContext;

    fn default_capabilities() -> PluginCapabilities {
        PluginCapabilities::default()
    }

    fn default_resources() -> PluginResourceLimits {
        PluginResourceLimits::default()
    }

    /// Compile a WAT string into WASM bytes for testing.
    fn compile_wat(wat_source: &str) -> Vec<u8> {
        wat::parse_str(wat_source).expect("valid WAT")
    }

    /// A minimal WASM guard that always allows.
    fn allow_guard_wat() -> &'static str {
        // Output: {"allowed":true,"severity":"low","message":"Allowed by wasm"} = 61 bytes
        r#"(module
            (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
            (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 64) "{\"allowed\":true,\"severity\":\"low\",\"message\":\"Allowed by wasm\"}")
            (func (export "clawdstrike_guard_init") (result i32)
              i32.const 1)
            (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
              i32.const 1)
            (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
              i32.const 64
              i32.const 61
              call $set_output
              drop
              i32.const 0)
        )"#
    }

    /// A minimal WASM guard that always denies.
    fn deny_guard_wat() -> &'static str {
        r#"(module
            (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
            (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
            (memory (export "memory") 1)
            (data (i32.const 64) "{\"allowed\":false,\"severity\":\"high\",\"message\":\"Denied by wasm\"}")
            (func (export "clawdstrike_guard_init") (result i32)
              i32.const 1)
            (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
              i32.const 1)
            (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
              i32.const 64
              i32.const 62
              call $set_output
              drop
              i32.const 0)
        )"#
    }

    /// A WASM guard that returns 0 from handles (does not handle the action).
    fn skip_guard_wat() -> &'static str {
        r#"(module
            (import "clawdstrike_host" "set_output" (func $set_output (param i32 i32) (result i32)))
            (import "clawdstrike_host" "request_capability" (func $cap (param i32) (result i32)))
            (memory (export "memory") 1)
            (func (export "clawdstrike_guard_init") (result i32)
              i32.const 1)
            (func (export "clawdstrike_guard_handles") (param i32 i32) (result i32)
              i32.const 0)
            (func (export "clawdstrike_guard_check") (param i32 i32) (result i32)
              i32.const 0)
        )"#
    }

    #[tokio::test]
    async fn wasm_guard_check_allow() {
        let wasm = compile_wat(allow_guard_wat());
        let guard = WasmGuard::new(
            "test.allow".to_string(),
            Arc::new(wasm),
            vec![],
            default_capabilities(),
            default_resources(),
            serde_json::json!({}),
        );

        let ctx = GuardContext::new();
        let result = guard
            .check(&GuardAction::FileAccess("/tmp/safe"), &ctx)
            .await;
        assert!(result.allowed);
        assert_eq!(result.guard, "test.allow");
    }

    #[tokio::test]
    async fn wasm_guard_check_deny() {
        let wasm = compile_wat(deny_guard_wat());
        let guard = WasmGuard::new(
            "test.deny".to_string(),
            Arc::new(wasm),
            vec![],
            default_capabilities(),
            default_resources(),
            serde_json::json!({}),
        );

        let ctx = GuardContext::new();
        let result = guard
            .check(&GuardAction::ShellCommand("rm -rf /"), &ctx)
            .await;
        assert!(!result.allowed);
        assert_eq!(result.guard, "test.deny");
        assert_eq!(result.severity, Severity::Error);
    }

    #[tokio::test]
    async fn wasm_guard_handles_delegates_to_action_list() {
        let wasm = compile_wat(allow_guard_wat());

        // Guard that only handles file_access
        let guard = WasmGuard::new(
            "test.file_only".to_string(),
            Arc::new(wasm),
            vec!["file_access".to_string()],
            default_capabilities(),
            default_resources(),
            serde_json::json!({}),
        );

        assert!(guard.handles(&GuardAction::FileAccess("/tmp/x")));
        assert!(!guard.handles(&GuardAction::ShellCommand("ls")));
    }

    #[tokio::test]
    async fn wasm_guard_handles_all_when_empty() {
        let wasm = compile_wat(allow_guard_wat());
        let guard = WasmGuard::new(
            "test.all".to_string(),
            Arc::new(wasm),
            vec![],
            default_capabilities(),
            default_resources(),
            serde_json::json!({}),
        );

        assert!(guard.handles(&GuardAction::FileAccess("/tmp/x")));
        assert!(guard.handles(&GuardAction::ShellCommand("ls")));
        assert!(guard.handles(&GuardAction::NetworkEgress("example.com", 443)));
    }

    #[tokio::test]
    async fn wasm_guard_skip_when_not_handled_returns_allow() {
        // When the WASM module's clawdstrike_guard_handles returns 0,
        // the runtime returns an allow result and skips check().
        let wasm = compile_wat(skip_guard_wat());
        let guard = WasmGuard::new(
            "test.skip".to_string(),
            Arc::new(wasm),
            vec![],
            default_capabilities(),
            default_resources(),
            serde_json::json!({}),
        );

        let ctx = GuardContext::new();
        let result = guard
            .check(&GuardAction::FileAccess("/tmp/safe"), &ctx)
            .await;
        // The runtime returns allow when handles() says no
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn wasm_guard_corrupted_bytes_fail_closed() {
        let guard = WasmGuard::new(
            "test.corrupt".to_string(),
            Arc::new(vec![0xFF, 0xFF, 0xFF]),
            vec![],
            default_capabilities(),
            default_resources(),
            serde_json::json!({}),
        );

        let ctx = GuardContext::new();
        let result = guard
            .check(&GuardAction::FileAccess("/tmp/safe"), &ctx)
            .await;
        assert!(!result.allowed, "corrupted WASM must fail-closed");
        assert!(result.message.contains("WASM guard runtime error"));
    }

    #[test]
    fn wasm_guard_factory_id() {
        let wasm = compile_wat(allow_guard_wat());
        let factory = WasmGuardFactory::new(
            "acme.guard".to_string(),
            wasm,
            vec![],
            default_capabilities(),
            default_resources(),
        );
        assert_eq!(factory.id(), "acme.guard");
    }

    #[tokio::test]
    async fn wasm_guard_factory_build_creates_working_guard() {
        let wasm = compile_wat(deny_guard_wat());
        let factory = WasmGuardFactory::new(
            "acme.deny".to_string(),
            wasm,
            vec![],
            default_capabilities(),
            default_resources(),
        );

        let guard = factory.build(serde_json::json!({})).expect("build");
        assert_eq!(guard.name(), "acme.deny");

        let ctx = GuardContext::new();
        let result = guard
            .check(&GuardAction::FileAccess("/tmp/test"), &ctx)
            .await;
        assert!(!result.allowed);
    }

    #[test]
    fn wasm_guard_factory_build_corrupted_still_creates_guard() {
        // Factory construction succeeds even with bad bytes;
        // the error surfaces at check() time (fail-closed).
        let factory = WasmGuardFactory::new(
            "acme.bad".to_string(),
            vec![0x00],
            vec![],
            default_capabilities(),
            default_resources(),
        );

        let guard = factory.build(serde_json::json!({})).expect("build");
        assert_eq!(guard.name(), "acme.bad");
    }
}
