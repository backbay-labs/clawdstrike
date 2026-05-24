use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;
use uuid::Uuid;

use crate::evaluate::{Decision, EvaluationAction, EvaluationResult, PostureResult, evaluate};
use crate::schema::HushSpec;
use crate::version::HUSHSPEC_VERSION;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionReceipt {
    pub receipt_id: String,
    pub timestamp: String,
    pub hushspec_version: String,
    pub action: ActionSummary,
    pub decision: Decision,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub rule_trace: Vec<RuleEvaluation>,
    pub policy: PolicySummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<PostureResult>,
    pub evaluation_duration_us: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSummary {
    #[serde(rename = "type")]
    pub action_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub content_redacted: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleEvaluation {
    pub rule_block: String,
    pub outcome: RuleOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub evaluated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleOutcome {
    Allow,
    Warn,
    Deny,
    Skip,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicySummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub version: String,
    /// SHA-256 hex digest of the canonical JSON serialization.
    pub content_hash: String,
}

#[derive(Clone, Debug)]
pub struct AuditConfig {
    pub enabled: bool,
    pub include_rule_trace: bool,
    pub redact_content: bool,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            include_rule_trace: true,
            redact_content: true,
        }
    }
}

/// Wrap `evaluate()` with timing, rule trace, and policy hashing.
///
/// When `config.enabled` is false, skips overhead but still returns a
/// correct decision.
pub fn evaluate_audited(
    spec: &HushSpec,
    action: &EvaluationAction,
    config: &AuditConfig,
) -> DecisionReceipt {
    let start = if config.enabled {
        Some(Instant::now())
    } else {
        None
    };

    let result = evaluate(spec, action);

    let duration_us = start.map(|s| s.elapsed().as_micros() as u64).unwrap_or(0);

    let rule_trace = if config.enabled && config.include_rule_trace {
        collect_rule_trace(spec, action, &result)
    } else {
        Vec::new()
    };

    let policy = if config.enabled {
        build_policy_summary(spec)
    } else {
        PolicySummary {
            name: spec.name.clone(),
            version: spec.hushspec.clone(),
            content_hash: String::new(),
        }
    };

    let action_summary = ActionSummary {
        action_type: action.action_type.clone(),
        target: action.target.clone(),
        content_redacted: config.redact_content && action.content.is_some(),
    };

    let timestamp = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);

    DecisionReceipt {
        receipt_id: Uuid::new_v4().to_string(),
        timestamp,
        hushspec_version: HUSHSPEC_VERSION.to_string(),
        action: action_summary,
        decision: result.decision,
        matched_rule: result.matched_rule,
        reason: result.reason,
        rule_trace,
        policy,
        origin_profile: result.origin_profile,
        posture: result.posture,
        evaluation_duration_us: duration_us,
    }
}

fn build_policy_summary(spec: &HushSpec) -> PolicySummary {
    let content_hash = compute_policy_hash(spec);
    PolicySummary {
        name: spec.name.clone(),
        version: spec.hushspec.clone(),
        content_hash,
    }
}

/// SHA-256 hex digest of the canonical JSON serialization. Deterministic.
pub fn compute_policy_hash(spec: &HushSpec) -> String {
    let json = serde_json::to_string(spec).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn collect_rule_trace(
    spec: &HushSpec,
    action: &EvaluationAction,
    result: &EvaluationResult,
) -> Vec<RuleEvaluation> {
    let mut trace = Vec::new();

    if result.posture.is_some() {
        let posture_denied = result
            .matched_rule
            .as_ref()
            .is_some_and(|r| r.starts_with("extensions.posture.states."));

        if posture_denied {
            trace.push(RuleEvaluation {
                rule_block: "posture_capability".to_string(),
                outcome: RuleOutcome::Deny,
                matched_rule: result.matched_rule.clone(),
                reason: result.reason.clone(),
                evaluated: true,
            });
            append_skipped_rules(spec, action, &mut trace, "short-circuited by posture deny");
            return trace;
        }

        trace.push(RuleEvaluation {
            rule_block: "posture_capability".to_string(),
            outcome: RuleOutcome::Allow,
            matched_rule: None,
            reason: Some("posture capabilities satisfied".to_string()),
            evaluated: true,
        });
    }

    match action.action_type.as_str() {
        "tool_call" => {
            trace_tool_access(spec, action, result, &mut trace);
        }
        "egress" => {
            trace_egress(spec, result, &mut trace);
        }
        "file_read" => {
            trace_path_guards(spec, result, &mut trace);
        }
        "file_write" => {
            trace_path_guards(spec, result, &mut trace);
            trace_secret_patterns(spec, result, &mut trace);
        }
        "patch_apply" => {
            trace_path_guards(spec, result, &mut trace);
            trace_patch_integrity(spec, result, &mut trace);
        }
        "shell_command" => {
            trace_shell_commands(spec, result, &mut trace);
        }
        "computer_use" => {
            trace_computer_use(spec, result, &mut trace);
        }
        _ => {
            // Unknown action type -- no specific rule blocks apply.
            trace.push(RuleEvaluation {
                rule_block: "default".to_string(),
                outcome: outcome_from_decision(result.decision),
                matched_rule: result.matched_rule.clone(),
                reason: result.reason.clone(),
                evaluated: true,
            });
        }
    }

    trace
}

fn trace_tool_access(
    spec: &HushSpec,
    action: &EvaluationAction,
    result: &EvaluationResult,
    trace: &mut Vec<RuleEvaluation>,
) {
    let has_origin_rule = result
        .matched_rule
        .as_ref()
        .is_some_and(|r| r.starts_with("extensions.origins.profiles."));

    let has_rule = has_origin_rule
        || spec
            .rules
            .as_ref()
            .and_then(|r| r.tool_access.as_ref())
            .is_some()
        || action.origin.is_some();

    if has_rule {
        trace.push(RuleEvaluation {
            rule_block: "tool_access".to_string(),
            outcome: outcome_from_decision(result.decision),
            matched_rule: result.matched_rule.clone(),
            reason: result.reason.clone(),
            evaluated: true,
        });
    } else {
        trace.push(RuleEvaluation {
            rule_block: "tool_access".to_string(),
            outcome: RuleOutcome::Skip,
            matched_rule: None,
            reason: Some("no tool_access rule configured".to_string()),
            evaluated: false,
        });
    }
}

fn trace_egress(spec: &HushSpec, result: &EvaluationResult, trace: &mut Vec<RuleEvaluation>) {
    let has_origin_rule = result
        .matched_rule
        .as_ref()
        .is_some_and(|r| r.contains("egress"));

    let has_rule = has_origin_rule
        || spec
            .rules
            .as_ref()
            .and_then(|r| r.egress.as_ref())
            .is_some();

    if has_rule {
        trace.push(RuleEvaluation {
            rule_block: "egress".to_string(),
            outcome: outcome_from_decision(result.decision),
            matched_rule: result.matched_rule.clone(),
            reason: result.reason.clone(),
            evaluated: true,
        });
    } else {
        trace.push(RuleEvaluation {
            rule_block: "egress".to_string(),
            outcome: RuleOutcome::Skip,
            matched_rule: None,
            reason: Some("no egress rule configured".to_string()),
            evaluated: false,
        });
    }
}

fn trace_path_guards(spec: &HushSpec, result: &EvaluationResult, trace: &mut Vec<RuleEvaluation>) {
    let rules = spec.rules.as_ref();
    let decided_by_forbidden = result
        .matched_rule
        .as_ref()
        .is_some_and(|r| r.contains("forbidden_paths"));
    let decided_by_allowlist = result
        .matched_rule
        .as_ref()
        .is_some_and(|r| r.contains("path_allowlist"));

    if let Some(fp) = rules.and_then(|r| r.forbidden_paths.as_ref()) {
        if fp.enabled {
            if decided_by_forbidden {
                trace.push(RuleEvaluation {
                    rule_block: "forbidden_paths".to_string(),
                    outcome: outcome_from_decision(result.decision),
                    matched_rule: result.matched_rule.clone(),
                    reason: result.reason.clone(),
                    evaluated: true,
                });
            } else {
                trace.push(RuleEvaluation {
                    rule_block: "forbidden_paths".to_string(),
                    outcome: RuleOutcome::Allow,
                    matched_rule: None,
                    reason: Some("path did not match any forbidden pattern".to_string()),
                    evaluated: true,
                });
            }
        } else {
            trace.push(RuleEvaluation {
                rule_block: "forbidden_paths".to_string(),
                outcome: RuleOutcome::Skip,
                matched_rule: None,
                reason: Some("rule disabled".to_string()),
                evaluated: false,
            });
        }
    }

    if let Some(pa) = rules.and_then(|r| r.path_allowlist.as_ref()) {
        if pa.enabled {
            let short_circuited = decided_by_forbidden && result.decision == Decision::Deny;
            if short_circuited {
                trace.push(RuleEvaluation {
                    rule_block: "path_allowlist".to_string(),
                    outcome: RuleOutcome::Skip,
                    matched_rule: None,
                    reason: Some("short-circuited by prior deny".to_string()),
                    evaluated: false,
                });
            } else if decided_by_allowlist {
                trace.push(RuleEvaluation {
                    rule_block: "path_allowlist".to_string(),
                    outcome: outcome_from_decision(result.decision),
                    matched_rule: result.matched_rule.clone(),
                    reason: result.reason.clone(),
                    evaluated: true,
                });
            } else {
                trace.push(RuleEvaluation {
                    rule_block: "path_allowlist".to_string(),
                    outcome: RuleOutcome::Allow,
                    matched_rule: None,
                    reason: Some("path matched allowlist".to_string()),
                    evaluated: true,
                });
            }
        } else {
            trace.push(RuleEvaluation {
                rule_block: "path_allowlist".to_string(),
                outcome: RuleOutcome::Skip,
                matched_rule: None,
                reason: Some("rule disabled".to_string()),
                evaluated: false,
            });
        }
    }
}

fn trace_secret_patterns(
    spec: &HushSpec,
    result: &EvaluationResult,
    trace: &mut Vec<RuleEvaluation>,
) {
    let rules = spec.rules.as_ref();
    let decided_by_secret = result
        .matched_rule
        .as_ref()
        .is_some_and(|r| r.contains("secret_patterns"));
    let prior_deny = !trace.is_empty()
        && trace
            .iter()
            .any(|t| t.outcome == RuleOutcome::Deny && t.evaluated);

    if let Some(sp) = rules.and_then(|r| r.secret_patterns.as_ref()) {
        if sp.enabled {
            if prior_deny {
                trace.push(RuleEvaluation {
                    rule_block: "secret_patterns".to_string(),
                    outcome: RuleOutcome::Skip,
                    matched_rule: None,
                    reason: Some("short-circuited by prior deny".to_string()),
                    evaluated: false,
                });
            } else if decided_by_secret {
                trace.push(RuleEvaluation {
                    rule_block: "secret_patterns".to_string(),
                    outcome: outcome_from_decision(result.decision),
                    matched_rule: result.matched_rule.clone(),
                    reason: result.reason.clone(),
                    evaluated: true,
                });
            } else {
                trace.push(RuleEvaluation {
                    rule_block: "secret_patterns".to_string(),
                    outcome: RuleOutcome::Allow,
                    matched_rule: None,
                    reason: Some("content did not match any secret pattern".to_string()),
                    evaluated: true,
                });
            }
        } else {
            trace.push(RuleEvaluation {
                rule_block: "secret_patterns".to_string(),
                outcome: RuleOutcome::Skip,
                matched_rule: None,
                reason: Some("rule disabled".to_string()),
                evaluated: false,
            });
        }
    }
}

fn trace_patch_integrity(
    spec: &HushSpec,
    result: &EvaluationResult,
    trace: &mut Vec<RuleEvaluation>,
) {
    let rules = spec.rules.as_ref();
    let decided_by_patch = result
        .matched_rule
        .as_ref()
        .is_some_and(|r| r.contains("patch_integrity"));
    let prior_deny = trace
        .iter()
        .any(|t| t.outcome == RuleOutcome::Deny && t.evaluated);

    if let Some(pi) = rules.and_then(|r| r.patch_integrity.as_ref()) {
        if pi.enabled {
            if prior_deny {
                trace.push(RuleEvaluation {
                    rule_block: "patch_integrity".to_string(),
                    outcome: RuleOutcome::Skip,
                    matched_rule: None,
                    reason: Some("short-circuited by prior deny".to_string()),
                    evaluated: false,
                });
            } else if decided_by_patch {
                trace.push(RuleEvaluation {
                    rule_block: "patch_integrity".to_string(),
                    outcome: outcome_from_decision(result.decision),
                    matched_rule: result.matched_rule.clone(),
                    reason: result.reason.clone(),
                    evaluated: true,
                });
            } else {
                trace.push(RuleEvaluation {
                    rule_block: "patch_integrity".to_string(),
                    outcome: RuleOutcome::Allow,
                    matched_rule: None,
                    reason: Some("patch passed integrity checks".to_string()),
                    evaluated: true,
                });
            }
        } else {
            trace.push(RuleEvaluation {
                rule_block: "patch_integrity".to_string(),
                outcome: RuleOutcome::Skip,
                matched_rule: None,
                reason: Some("rule disabled".to_string()),
                evaluated: false,
            });
        }
    }
}

fn trace_shell_commands(
    spec: &HushSpec,
    result: &EvaluationResult,
    trace: &mut Vec<RuleEvaluation>,
) {
    let rules = spec.rules.as_ref();
    let decided_by_shell = result
        .matched_rule
        .as_ref()
        .is_some_and(|r| r.contains("shell_commands"));

    if let Some(sc) = rules.and_then(|r| r.shell_commands.as_ref()) {
        if sc.enabled {
            if decided_by_shell {
                trace.push(RuleEvaluation {
                    rule_block: "shell_commands".to_string(),
                    outcome: outcome_from_decision(result.decision),
                    matched_rule: result.matched_rule.clone(),
                    reason: result.reason.clone(),
                    evaluated: true,
                });
            } else {
                trace.push(RuleEvaluation {
                    rule_block: "shell_commands".to_string(),
                    outcome: RuleOutcome::Allow,
                    matched_rule: None,
                    reason: Some("command did not match any forbidden pattern".to_string()),
                    evaluated: true,
                });
            }
        } else {
            trace.push(RuleEvaluation {
                rule_block: "shell_commands".to_string(),
                outcome: RuleOutcome::Skip,
                matched_rule: None,
                reason: Some("rule disabled".to_string()),
                evaluated: false,
            });
        }
    }
}

fn trace_computer_use(spec: &HushSpec, result: &EvaluationResult, trace: &mut Vec<RuleEvaluation>) {
    let rules = spec.rules.as_ref();
    let decided_by_computer = result
        .matched_rule
        .as_ref()
        .is_some_and(|r| r.contains("computer_use"));

    if let Some(cu) = rules.and_then(|r| r.computer_use.as_ref()) {
        if cu.enabled {
            if decided_by_computer {
                trace.push(RuleEvaluation {
                    rule_block: "computer_use".to_string(),
                    outcome: outcome_from_decision(result.decision),
                    matched_rule: result.matched_rule.clone(),
                    reason: result.reason.clone(),
                    evaluated: true,
                });
            } else {
                trace.push(RuleEvaluation {
                    rule_block: "computer_use".to_string(),
                    outcome: RuleOutcome::Allow,
                    matched_rule: None,
                    reason: Some("action allowed by computer_use rule".to_string()),
                    evaluated: true,
                });
            }
        } else {
            trace.push(RuleEvaluation {
                rule_block: "computer_use".to_string(),
                outcome: RuleOutcome::Skip,
                matched_rule: None,
                reason: Some("rule disabled".to_string()),
                evaluated: false,
            });
        }
    }
}

fn append_skipped_rules(
    _spec: &HushSpec,
    action: &EvaluationAction,
    trace: &mut Vec<RuleEvaluation>,
    reason: &str,
) {
    let blocks: Vec<&str> = match action.action_type.as_str() {
        "tool_call" => vec!["tool_access"],
        "egress" => vec!["egress"],
        "file_read" => vec!["forbidden_paths", "path_allowlist"],
        "file_write" => vec!["forbidden_paths", "path_allowlist", "secret_patterns"],
        "patch_apply" => vec!["forbidden_paths", "path_allowlist", "patch_integrity"],
        "shell_command" => vec!["shell_commands"],
        "computer_use" => vec!["computer_use"],
        _ => vec![],
    };

    for block in blocks {
        trace.push(RuleEvaluation {
            rule_block: block.to_string(),
            outcome: RuleOutcome::Skip,
            matched_rule: None,
            reason: Some(reason.to_string()),
            evaluated: false,
        });
    }
}

fn outcome_from_decision(decision: Decision) -> RuleOutcome {
    match decision {
        Decision::Allow => RuleOutcome::Allow,
        Decision::Warn => RuleOutcome::Warn,
        Decision::Deny => RuleOutcome::Deny,
    }
}
