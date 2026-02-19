//! Computer use guard - controls CUA (Computer Use Agent) actions

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::{Guard, GuardAction, GuardContext, GuardResult, Severity};

/// Enforcement mode for computer use actions.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerUseMode {
    /// Always allow but log the action.
    Observe,
    /// Allow if action is in the allowlist, warn otherwise.
    #[default]
    Guardrail,
    /// Deny if action is not in the allowlist.
    FailClosed,
}

/// Configuration for ComputerUseGuard
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComputerUseConfig {
    /// Enable/disable this guard.
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    /// Allowed CUA action types (e.g. "remote.session.connect", "input.inject").
    #[serde(default)]
    pub allowed_actions: Vec<String>,
    /// Enforcement mode.
    #[serde(default)]
    pub mode: ComputerUseMode,
}

fn default_enabled() -> bool {
    true
}

impl Default for ComputerUseConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowed_actions: vec![
                "remote.session.connect".to_string(),
                "remote.session.disconnect".to_string(),
                "remote.session.reconnect".to_string(),
                "input.inject".to_string(),
                "remote.clipboard".to_string(),
                "remote.file_transfer".to_string(),
                "remote.audio".to_string(),
                "remote.drive_mapping".to_string(),
                "remote.printing".to_string(),
                "remote.session_share".to_string(),
            ],
            mode: ComputerUseMode::Guardrail,
        }
    }
}

/// Guard that controls CUA (Computer Use Agent) actions.
///
/// Handles `GuardAction::Custom` where the custom type starts with `"remote."` or `"input."`.
pub struct ComputerUseGuard {
    name: String,
    enabled: bool,
    mode: ComputerUseMode,
    allowed_set: HashSet<String>,
}

impl ComputerUseGuard {
    /// Create with default configuration.
    pub fn new() -> Self {
        Self::with_config(ComputerUseConfig::default())
    }

    /// Create with custom configuration.
    pub fn with_config(config: ComputerUseConfig) -> Self {
        let enabled = config.enabled;
        let mode = config.mode.clone();
        let allowed_set: HashSet<_> = config.allowed_actions.into_iter().collect();

        Self {
            name: "computer_use".to_string(),
            enabled,
            mode,
            allowed_set,
        }
    }
}

impl Default for ComputerUseGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Guard for ComputerUseGuard {
    fn name(&self) -> &str {
        &self.name
    }

    fn handles(&self, action: &GuardAction<'_>) -> bool {
        if !self.enabled {
            return false;
        }

        matches!(action, GuardAction::Custom(ct, _) if ct.starts_with("remote.") || ct.starts_with("input."))
    }

    async fn check(&self, action: &GuardAction<'_>, _context: &GuardContext) -> GuardResult {
        if !self.enabled {
            return GuardResult::allow(&self.name);
        }

        let custom_type = match action {
            GuardAction::Custom(ct, _) => *ct,
            _ => return GuardResult::allow(&self.name),
        };

        let in_allowlist = self.allowed_set.contains(custom_type);

        match self.mode {
            ComputerUseMode::Observe => {
                // Always allow but log
                GuardResult::warn(
                    &self.name,
                    format!("Computer use action observed: {}", custom_type),
                )
                .with_details(serde_json::json!({
                    "action_type": custom_type,
                    "mode": "observe",
                    "in_allowlist": in_allowlist,
                }))
            }
            ComputerUseMode::Guardrail => {
                if in_allowlist {
                    GuardResult::allow(&self.name)
                } else {
                    GuardResult::warn(
                        &self.name,
                        format!(
                            "Computer use action '{}' is not in allowlist (guardrail mode)",
                            custom_type
                        ),
                    )
                    .with_details(serde_json::json!({
                        "action_type": custom_type,
                        "mode": "guardrail",
                    }))
                }
            }
            ComputerUseMode::FailClosed => {
                if in_allowlist {
                    GuardResult::allow(&self.name)
                } else {
                    GuardResult::block(
                        &self.name,
                        Severity::Error,
                        format!(
                            "Computer use action '{}' denied by policy (fail_closed mode)",
                            custom_type
                        ),
                    )
                    .with_details(serde_json::json!({
                        "action_type": custom_type,
                        "mode": "fail_closed",
                        "reason": "not_in_allowlist",
                    }))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handles_remote_actions() {
        let guard = ComputerUseGuard::new();
        let data = serde_json::json!({});

        assert!(guard.handles(&GuardAction::Custom("remote.session.connect", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.clipboard", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.file_transfer", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.audio", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.drive_mapping", &data)));
        assert!(guard.handles(&GuardAction::Custom("remote.printing", &data)));
        assert!(guard.handles(&GuardAction::Custom("input.inject", &data)));
    }

    #[test]
    fn test_default_allowlist_includes_all_remote_side_channels() {
        let config = ComputerUseConfig::default();
        let expected = [
            "remote.audio",
            "remote.drive_mapping",
            "remote.printing",
            "remote.session_share",
        ];

        for action in expected {
            assert!(
                config.allowed_actions.contains(&action.to_string()),
                "default allowed_actions should include {action}"
            );
        }
    }

    #[test]
    fn test_does_not_handle_non_cua_actions() {
        let guard = ComputerUseGuard::new();
        let data = serde_json::json!({});

        assert!(!guard.handles(&GuardAction::Custom("other.action", &data)));
        assert!(!guard.handles(&GuardAction::FileAccess("/tmp/file")));
    }

    #[test]
    fn test_disabled_guard_does_not_handle() {
        let config = ComputerUseConfig {
            enabled: false,
            ..Default::default()
        };
        let guard = ComputerUseGuard::with_config(config);
        let data = serde_json::json!({});

        assert!(!guard.handles(&GuardAction::Custom("remote.session.connect", &data)));
    }

    #[tokio::test]
    async fn test_guardrail_allows_known_action() {
        let guard = ComputerUseGuard::new();
        let context = GuardContext::new();
        let data = serde_json::json!({});

        let result = guard
            .check(
                &GuardAction::Custom("remote.session.connect", &data),
                &context,
            )
            .await;
        assert!(result.allowed);
    }

    #[tokio::test]
    async fn test_guardrail_warns_unknown_action() {
        let guard = ComputerUseGuard::new();
        let context = GuardContext::new();
        let data = serde_json::json!({});

        let result = guard
            .check(
                &GuardAction::Custom("remote.unknown_action", &data),
                &context,
            )
            .await;
        assert!(result.allowed); // guardrail mode allows
        assert_eq!(result.severity, Severity::Warning);
    }

    #[tokio::test]
    async fn test_fail_closed_denies_unknown_action() {
        let config = ComputerUseConfig {
            mode: ComputerUseMode::FailClosed,
            ..Default::default()
        };
        let guard = ComputerUseGuard::with_config(config);
        let context = GuardContext::new();
        let data = serde_json::json!({});

        let result = guard
            .check(
                &GuardAction::Custom("remote.unknown_action", &data),
                &context,
            )
            .await;
        assert!(!result.allowed);
    }

    #[tokio::test]
    async fn test_observe_always_allows() {
        let config = ComputerUseConfig {
            mode: ComputerUseMode::Observe,
            ..Default::default()
        };
        let guard = ComputerUseGuard::with_config(config);
        let context = GuardContext::new();
        let data = serde_json::json!({});

        let result = guard
            .check(
                &GuardAction::Custom("remote.unknown_action", &data),
                &context,
            )
            .await;
        assert!(result.allowed);
        assert_eq!(result.severity, Severity::Warning);
    }
}
