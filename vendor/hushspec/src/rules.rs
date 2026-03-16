use serde::{Deserialize, Serialize};

/// Container for all core security rules.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rules {
    /// Block access to sensitive filesystem paths by glob pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forbidden_paths: Option<ForbiddenPathsRule>,
    /// Allowlist-based path access control for read, write, and patch operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_allowlist: Option<PathAllowlistRule>,
    /// Network egress control by domain pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress: Option<EgressRule>,
    /// Detect secrets in file content using named regex patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_patterns: Option<SecretPatternsRule>,
    /// Validate patch/diff safety with size limits and forbidden patterns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub patch_integrity: Option<PatchIntegrityRule>,
    /// Block dangerous shell commands by regex pattern.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_commands: Option<ShellCommandsRule>,
    /// Control tool/MCP invocations with allow/block lists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_access: Option<ToolAccessRule>,
    /// Control computer use agent (CUA) actions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub computer_use: Option<ComputerUseRule>,
    /// Control remote desktop side channels.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_desktop_channels: Option<RemoteDesktopChannelsRule>,
    /// Control input injection capabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_injection: Option<InputInjectionRule>,
}

// --- Rule 1: Forbidden Paths ---

/// Block access to sensitive filesystem paths by glob pattern.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForbiddenPathsRule {
    /// Whether this rule is active. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Glob patterns that match forbidden paths (e.g. `~/.ssh/**`).
    #[serde(default)]
    pub patterns: Vec<String>,
    /// Glob patterns that override forbidden patterns.
    #[serde(default)]
    pub exceptions: Vec<String>,
}

// --- Rule 2: Path Allowlist ---

/// Allowlist-based path access control for read, write, and patch operations.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathAllowlistRule {
    /// Whether this rule is active.
    #[serde(default)]
    pub enabled: bool,
    /// Glob patterns allowed for read access.
    #[serde(default)]
    pub read: Vec<String>,
    /// Glob patterns allowed for write access.
    #[serde(default)]
    pub write: Vec<String>,
    /// Glob patterns allowed for patch/diff operations.
    #[serde(default)]
    pub patch: Vec<String>,
}

// --- Rule 3: Egress ---

/// Network egress control by domain pattern.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressRule {
    /// Whether this rule is active. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Domain patterns permitted for outbound requests.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Domain patterns blocked for outbound requests.
    #[serde(default)]
    pub block: Vec<String>,
    /// Action when no allow/block pattern matches. Defaults to `Block`.
    #[serde(default = "default_block")]
    pub default: DefaultAction,
}

// --- Rule 4: Secret Patterns ---

/// Detect secrets in file content using named regex patterns.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPatternsRule {
    /// Whether this rule is active. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Named regex patterns to scan for secrets.
    #[serde(default)]
    pub patterns: Vec<SecretPattern>,
    /// Glob patterns for paths exempt from scanning.
    #[serde(default)]
    pub skip_paths: Vec<String>,
}

/// A named regex pattern for secret detection.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretPattern {
    /// Unique name for this pattern (e.g. `"aws_access_key"`).
    pub name: String,
    /// Regex pattern to match against file content.
    pub pattern: String,
    /// Severity level when this pattern matches.
    pub severity: Severity,
    /// Optional human-readable description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

// --- Rule 5: Patch Integrity ---

/// Validate patch/diff safety with size limits and forbidden patterns.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchIntegrityRule {
    /// Whether this rule is active. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Maximum number of added lines allowed. Defaults to 1000.
    #[serde(default = "default_1000")]
    pub max_additions: usize,
    /// Maximum number of deleted lines allowed. Defaults to 500.
    #[serde(default = "default_500")]
    pub max_deletions: usize,
    /// Regex patterns that must not appear in the patch.
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
    /// Whether to enforce a balanced additions/deletions ratio.
    #[serde(default)]
    pub require_balance: bool,
    /// Maximum ratio of additions to deletions. Defaults to 10.0.
    #[serde(default = "default_imbalance_ratio")]
    pub max_imbalance_ratio: f64,
}

// --- Rule 6: Shell Commands ---

/// Block dangerous shell commands by regex pattern.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellCommandsRule {
    /// Whether this rule is active. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Regex patterns matching forbidden shell commands.
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
}

// --- Rule 7: Tool Access ---

/// Control tool/MCP invocations with allow/block lists.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAccessRule {
    /// Whether this rule is active. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Tool name patterns that are explicitly allowed.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Tool name patterns that are blocked.
    #[serde(default)]
    pub block: Vec<String>,
    /// Tool name patterns that require user confirmation before execution.
    #[serde(default)]
    pub require_confirmation: Vec<String>,
    /// Action when no allow/block pattern matches. Defaults to `Allow`.
    #[serde(default = "default_allow")]
    pub default: DefaultAction,
    /// Maximum byte size of serialized tool arguments.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_args_size: Option<usize>,
}

// --- Rule 8: Computer Use ---

/// Control computer use agent (CUA) actions.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputerUseRule {
    /// Whether this rule is active.
    #[serde(default)]
    pub enabled: bool,
    /// Enforcement mode for CUA actions.
    #[serde(default)]
    pub mode: ComputerUseMode,
    /// Action types the CUA is allowed to perform.
    #[serde(default)]
    pub allowed_actions: Vec<String>,
}

/// CUA enforcement mode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerUseMode {
    /// Log actions without blocking.
    Observe,
    /// Block disallowed actions but allow permitted ones.
    #[default]
    Guardrail,
    /// Deny all actions not on the explicit allowlist.
    FailClosed,
}

// --- Rule 9: Remote Desktop Channels ---

/// Control remote desktop side channels.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteDesktopChannelsRule {
    /// Whether this rule is active.
    #[serde(default)]
    pub enabled: bool,
    /// Allow clipboard sharing.
    #[serde(default)]
    pub clipboard: bool,
    /// Allow file transfer.
    #[serde(default)]
    pub file_transfer: bool,
    /// Allow audio passthrough. Defaults to `true`.
    #[serde(default = "default_true")]
    pub audio: bool,
    /// Allow drive mapping.
    #[serde(default)]
    pub drive_mapping: bool,
}

// --- Rule 10: Input Injection ---

/// Control input injection capabilities.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputInjectionRule {
    /// Whether this rule is active.
    #[serde(default)]
    pub enabled: bool,
    /// Input injection types the agent may use (e.g. `"keyboard"`, `"mouse"`).
    #[serde(default)]
    pub allowed_types: Vec<String>,
    /// Require a postcondition probe after each injection.
    #[serde(default)]
    pub require_postcondition_probe: bool,
}

// --- Shared Types ---

/// Severity level for secret pattern matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Immediate policy violation; must block.
    Critical,
    /// Serious finding; should block by default.
    Error,
    /// Advisory finding; logged but may not block.
    Warn,
}

/// Default action when no allow/block rule matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DefaultAction {
    /// Permit the action.
    Allow,
    /// Deny the action.
    Block,
}

// --- Default value helpers ---

pub(crate) fn default_true() -> bool {
    true
}

pub(crate) fn default_block() -> DefaultAction {
    DefaultAction::Block
}

pub(crate) fn default_allow() -> DefaultAction {
    DefaultAction::Allow
}

pub(crate) fn default_1000() -> usize {
    1000
}

pub(crate) fn default_500() -> usize {
    500
}

pub(crate) fn default_imbalance_ratio() -> f64 {
    10.0
}
