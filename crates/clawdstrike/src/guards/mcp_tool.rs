//! MCP tool guard - restricts tool invocations

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::io;

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Default behavior when a tool is not explicitly allowed/blocked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum McpDefaultAction {
    #[default]
    Allow,
    Block,
}

/// Configuration for McpToolGuard
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpToolConfig {
    /// Allowed tool names (if empty, all are allowed except blocked)
    #[serde(default)]
    pub allow: Vec<String>,
    /// Blocked tool names (takes precedence)
    #[serde(default)]
    pub block: Vec<String>,
    /// Tools that require confirmation
    #[serde(default)]
    pub require_confirmation: Vec<String>,
    /// Default action when not explicitly matched
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_action: Option<McpDefaultAction>,
    /// Maximum arguments size (bytes)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_args_size: Option<usize>,
    /// Additional allowed tools when merging
    #[serde(default)]
    pub additional_allow: Vec<String>,
    /// Tools to remove from allow list when merging
    #[serde(default)]
    pub remove_allow: Vec<String>,
    /// Additional blocked tools when merging
    #[serde(default)]
    pub additional_block: Vec<String>,
    /// Tools to remove from block list when merging
    #[serde(default)]
    pub remove_block: Vec<String>,
}

fn default_max_args_size() -> usize {
    1024 * 1024 // 1MB
}

fn json_size_bytes(value: &serde_json::Value) -> std::result::Result<usize, serde_json::Error> {
    struct CountingWriter {
        count: usize,
    }

    impl io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.count += buf.len();
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut w = CountingWriter { count: 0 };
    serde_json::to_writer(&mut w, value)?;
    Ok(w.count)
}

impl McpToolConfig {
    /// Create config with default blocked tools
    pub fn with_defaults() -> Self {
        Self {
            allow: vec![],
            block: vec![
                // Dangerous shell operations
                "shell_exec".to_string(),
                "run_command".to_string(),
                // Direct file system access that bypasses guards
                "raw_file_write".to_string(),
                "raw_file_delete".to_string(),
            ],
            require_confirmation: vec![
                "file_write".to_string(),
                "file_delete".to_string(),
                "git_push".to_string(),
            ],
            default_action: Some(McpDefaultAction::Allow),
            max_args_size: Some(default_max_args_size()),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        }
    }

    /// Merge this config with a child config
    pub fn merge_with(&self, child: &Self) -> Self {
        let mut allow = self.allow.clone();
        let mut block = self.block.clone();
        let mut require_confirmation = self.require_confirmation.clone();

        // Add additional tools
        for t in &child.additional_allow {
            if !allow.contains(t) {
                allow.push(t.clone());
            }
        }
        for t in &child.additional_block {
            if !block.contains(t) {
                block.push(t.clone());
            }
        }

        // Remove specified tools
        allow.retain(|t| !child.remove_allow.contains(t));
        block.retain(|t| !child.remove_block.contains(t));

        // Use child's lists if non-empty
        if !child.allow.is_empty() {
            allow = child.allow.clone();
        }
        if !child.block.is_empty() {
            block = child.block.clone();
        }
        if !child.require_confirmation.is_empty() {
            require_confirmation = child.require_confirmation.clone();
        }

        Self {
            allow,
            block,
            require_confirmation,
            default_action: child.default_action.or(self.default_action),
            max_args_size: child.max_args_size.or(self.max_args_size),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        }
    }
}

/// Guard that controls MCP tool invocations
pub struct McpToolGuard {
    name: String,
    config: McpToolConfig,
    allow_set: HashSet<String>,
    block_set: HashSet<String>,
    confirm_set: HashSet<String>,
}

impl McpToolGuard {
    /// Create with default configuration
    pub fn new() -> Self {
        Self::with_config(McpToolConfig::with_defaults())
    }

    /// Create with custom configuration
    pub fn with_config(config: McpToolConfig) -> Self {
        let allow_set: HashSet<_> = config.allow.iter().cloned().collect();
        let block_set: HashSet<_> = config.block.iter().cloned().collect();
        let confirm_set: HashSet<_> = config.require_confirmation.iter().cloned().collect();

        Self {
            name: "mcp_tool".to_string(),
            config,
            allow_set,
            block_set,
            confirm_set,
        }
    }

    /// Check if a tool is allowed
    pub fn is_allowed(&self, tool_name: &str) -> ToolDecision {
        // Blocked takes precedence
        if self.block_set.contains(tool_name) {
            return ToolDecision::Block;
        }

        // Check if requires confirmation
        if self.confirm_set.contains(tool_name) {
            return ToolDecision::RequireConfirmation;
        }

        // Check allowlist mode
        if !self.allow_set.is_empty() {
            // Allowlist mode: only allowed tools pass
            if self.allow_set.contains(tool_name) {
                return ToolDecision::Allow;
            } else {
                return ToolDecision::Block;
            }
        }

        // Default action
        if self.config.default_action.unwrap_or_default() == McpDefaultAction::Block {
            ToolDecision::Block
        } else {
            ToolDecision::Allow
        }
    }
}

impl Default for McpToolGuard {
    fn default() -> Self {
        Self::new()
    }
}

/// Decision for a tool invocation
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ToolDecision {
    Allow,
    Block,
    RequireConfirmation,
}

#[async_trait]
impl Guard for McpToolGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        matches!(action, GuardAction::McpTool(_, _))
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        let (tool_name, args) = match action {
            GuardAction::McpTool(name, args) => (*name, *args),
            _ => return GuardResult::allow(&self.name),
        };

        // Check args size
        let args_size = match json_size_bytes(args) {
            Ok(bytes) => bytes,
            Err(e) => {
                return GuardResult::block(
                    &self.name,
                    Severity::Error,
                    format!("Failed to serialize tool args: {}", e),
                );
            }
        };

        let max_args_size = self.config.max_args_size.unwrap_or(default_max_args_size());
        if args_size > max_args_size {
            return GuardResult::block(
                &self.name,
                Severity::Error,
                format!(
                    "Tool arguments too large: {} bytes (max: {})",
                    args_size, max_args_size
                ),
            );
        }

        match self.is_allowed(tool_name) {
            ToolDecision::Allow => GuardResult::allow(&self.name),
            ToolDecision::Block => GuardResult::block(
                &self.name,
                Severity::Error,
                format!("Tool '{}' is blocked by policy", tool_name),
            )
            .with_details(serde_json::json!({
                "tool": tool_name,
                "reason": "blocked_by_policy",
            })),
            ToolDecision::RequireConfirmation => GuardResult::warn(
                &self.name,
                format!("Tool '{}' requires confirmation", tool_name),
            )
            .with_details(serde_json::json!({
                "tool": tool_name,
                "requires_confirmation": true,
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_blocked() {
        let guard = McpToolGuard::new();

        assert_eq!(guard.is_allowed("shell_exec"), ToolDecision::Block);
        assert_eq!(guard.is_allowed("run_command"), ToolDecision::Block);
    }

    #[test]
    fn test_default_allowed() {
        let guard = McpToolGuard::new();

        assert_eq!(guard.is_allowed("read_file"), ToolDecision::Allow);
        assert_eq!(guard.is_allowed("list_directory"), ToolDecision::Allow);
    }

    #[test]
    fn test_require_confirmation() {
        let guard = McpToolGuard::new();

        assert_eq!(
            guard.is_allowed("file_write"),
            ToolDecision::RequireConfirmation
        );
        assert_eq!(
            guard.is_allowed("git_push"),
            ToolDecision::RequireConfirmation
        );
    }

    #[test]
    fn test_allowlist_mode() {
        let config = McpToolConfig {
            allow: vec!["safe_tool".to_string()],
            block: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Block),
            max_args_size: Some(1024),
            ..Default::default()
        };
        let guard = McpToolGuard::with_config(config);

        assert_eq!(guard.is_allowed("safe_tool"), ToolDecision::Allow);
        assert_eq!(guard.is_allowed("other_tool"), ToolDecision::Block);
    }

    #[tokio::test]
    async fn test_guard_check() {
        let guard = McpToolGuard::new();
        let context = GuardContext::new();

        let args = serde_json::json!({"path": "/app/file.txt"});
        let result = guard
            .check(&GuardAction::McpTool("read_file", &args), &context)
            .await;
        assert!(result.allowed);

        let result = guard
            .check(&GuardAction::McpTool("shell_exec", &args), &context)
            .await;
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_args_size_limit() {
        let config = McpToolConfig {
            max_args_size: Some(100),
            ..Default::default()
        };
        let guard = McpToolGuard::with_config(config);
        let context = GuardContext::new();

        let large_args = serde_json::json!({"data": "x".repeat(200)});
        let result = guard
            .check(&GuardAction::McpTool("some_tool", &large_args), &context)
            .await;
        assert!(!result.allowed);
    }
}
