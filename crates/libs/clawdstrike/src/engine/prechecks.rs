//! Enclave / origin / budget prechecks that run before the guard pipeline.

use tracing::debug;

use crate::guards::{GuardAction, GuardContext, GuardResult, McpDefaultAction, Severity};
use crate::origin::OriginContext;
use crate::origin_runtime::OriginRuntimeState;
use crate::output_sanitizer::OutputSanitizer;
use crate::posture::Capability;

use super::HushEngine;

impl HushEngine {
    pub(crate) async fn enclave_mcp_precheck(
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

    pub(crate) async fn origin_data_precheck(
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

    pub(crate) async fn origin_budget_precheck(
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

    pub(crate) fn consume_origin_budget(
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
}

/// Simple tool name matching (supports trailing `*` wildcard).
pub(crate) fn tool_matches(tool_name: &str, pattern: &str) -> bool {
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
