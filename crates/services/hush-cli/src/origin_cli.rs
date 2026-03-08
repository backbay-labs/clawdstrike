//! Origin subcommands — resolve, explain, and list-profiles for origin-aware
//! policy enforcement.

use std::io::Write;

use clap::Subcommand;
use colored::Colorize;
use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};

use clawdstrike::policy::{OriginMatch, OriginProfile, OriginsConfig};
use clawdstrike::{
    EnclaveResolver, OriginContext, OriginProvider, Policy, ResolvedEnclave, SpaceType, Visibility,
};

use crate::remote_extends::{RemoteExtendsConfig, RemotePolicyResolver};
use crate::ui;
use crate::ExitCode;

// ---------------------------------------------------------------------------
// Clap definitions
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
pub enum OriginCommands {
    /// Resolve an origin context against a policy to find the matching enclave profile
    Resolve {
        /// Policy YAML file or ruleset name (default: "default")
        #[arg(default_value = "default")]
        policy_path: String,

        /// Origin provider (slack, github, teams, jira, etc.)
        #[arg(long)]
        provider: Option<String>,

        /// Space/channel identifier
        #[arg(long)]
        space_id: Option<String>,

        /// Space type (channel, dm, thread, issue, pull_request, etc.)
        #[arg(long)]
        space_type: Option<String>,

        /// Visibility (private, internal, public, external_shared)
        #[arg(long)]
        visibility: Option<String>,

        /// Comma-separated tags
        #[arg(long)]
        tags: Option<String>,

        /// Tenant identifier
        #[arg(long)]
        tenant_id: Option<String>,

        /// Thread identifier
        #[arg(long)]
        thread_id: Option<String>,

        /// Flag: external participants present (use --no-external-participants for false)
        #[arg(long, overrides_with = "no_external_participants")]
        external_participants: bool,

        /// Flag: no external participants (sets external_participants=false)
        #[arg(long, overrides_with = "external_participants", hide = true)]
        no_external_participants: bool,

        /// Sensitivity level
        #[arg(long)]
        sensitivity: Option<String>,

        /// Actor role used for profile matching
        #[arg(long)]
        actor_role: Option<String>,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// Explain the origin resolution process — show which profiles match and why
    Explain {
        /// Policy YAML file or ruleset name (default: "default")
        #[arg(default_value = "default")]
        policy_path: String,

        /// Origin provider (slack, github, teams, jira, etc.)
        #[arg(long)]
        provider: Option<String>,

        /// Space/channel identifier
        #[arg(long)]
        space_id: Option<String>,

        /// Space type (channel, dm, thread, issue, pull_request, etc.)
        #[arg(long)]
        space_type: Option<String>,

        /// Visibility (private, internal, public, external_shared)
        #[arg(long)]
        visibility: Option<String>,

        /// Comma-separated tags
        #[arg(long)]
        tags: Option<String>,

        /// Tenant identifier
        #[arg(long)]
        tenant_id: Option<String>,

        /// Thread identifier
        #[arg(long)]
        thread_id: Option<String>,

        /// Flag: external participants present (use --no-external-participants for false)
        #[arg(long, overrides_with = "no_external_participants")]
        external_participants: bool,

        /// Flag: no external participants (sets external_participants=false)
        #[arg(long, overrides_with = "external_participants", hide = true)]
        no_external_participants: bool,

        /// Sensitivity level
        #[arg(long)]
        sensitivity: Option<String>,

        /// Actor role used for profile matching
        #[arg(long)]
        actor_role: Option<String>,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },

    /// List all origin profiles defined in a policy
    #[command(name = "list-profiles")]
    ListProfiles {
        /// Policy YAML file or ruleset name (default: "default")
        #[arg(default_value = "default")]
        policy_path: String,

        /// Emit machine-readable JSON
        #[arg(long)]
        json: bool,
    },
}

// ---------------------------------------------------------------------------
// Shared argument struct for resolve/explain
// ---------------------------------------------------------------------------

struct OriginArgs {
    provider: Option<String>,
    space_id: Option<String>,
    space_type: Option<String>,
    visibility: Option<String>,
    tags: Option<String>,
    tenant_id: Option<String>,
    thread_id: Option<String>,
    external_participants: Option<bool>,
    sensitivity: Option<String>,
    actor_role: Option<String>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn cmd_origin(
    command: OriginCommands,
    remote_extends: &RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    match command {
        OriginCommands::Resolve {
            policy_path,
            provider,
            space_id,
            space_type,
            visibility,
            tags,
            tenant_id,
            thread_id,
            external_participants,
            no_external_participants,
            sensitivity,
            actor_role,
            json,
        } => cmd_resolve(
            &policy_path,
            OriginArgs {
                provider,
                space_id,
                space_type,
                visibility,
                tags,
                tenant_id,
                thread_id,
                external_participants: ext_participants_flag(
                    external_participants,
                    no_external_participants,
                ),
                sensitivity,
                actor_role,
            },
            json,
            remote_extends,
            stdout,
            stderr,
        ),

        OriginCommands::Explain {
            policy_path,
            provider,
            space_id,
            space_type,
            visibility,
            tags,
            tenant_id,
            thread_id,
            external_participants,
            no_external_participants,
            sensitivity,
            actor_role,
            json,
        } => cmd_explain(
            &policy_path,
            OriginArgs {
                provider,
                space_id,
                space_type,
                visibility,
                tags,
                tenant_id,
                thread_id,
                external_participants: ext_participants_flag(
                    external_participants,
                    no_external_participants,
                ),
                sensitivity,
                actor_role,
            },
            json,
            remote_extends,
            stdout,
            stderr,
        ),

        OriginCommands::ListProfiles { policy_path, json } => {
            cmd_list_profiles(&policy_path, json, remote_extends, stdout, stderr)
        }
    }
}

// ---------------------------------------------------------------------------
// Helper: convert --external-participants / --no-external-participants to Option<bool>
// ---------------------------------------------------------------------------

fn ext_participants_flag(yes: bool, no: bool) -> Option<bool> {
    match (yes, no) {
        (true, _) => Some(true),
        (_, true) => Some(false),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Helper: build OriginContext from CLI flags
// ---------------------------------------------------------------------------

fn build_origin_context(args: &OriginArgs) -> OriginContext {
    OriginContext {
        provider: args
            .provider
            .as_ref()
            .map(|p| parse_provider(p))
            .unwrap_or_else(|| OriginProvider::Custom("unknown".into())),
        space_id: args.space_id.clone(),
        space_type: args.space_type.as_ref().map(|s| parse_space_type(s)),
        visibility: args.visibility.as_ref().map(|v| parse_visibility(v)),
        tags: args
            .tags
            .as_ref()
            .map(|t| t.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default(),
        tenant_id: args.tenant_id.clone(),
        thread_id: args.thread_id.clone(),
        external_participants: args.external_participants,
        sensitivity: args.sensitivity.clone(),
        actor_role: args.actor_role.clone(),
        ..Default::default()
    }
}

fn parse_provider(s: &str) -> OriginProvider {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .unwrap_or(OriginProvider::Custom(s.to_string()))
}

fn parse_space_type(s: &str) -> SpaceType {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .unwrap_or(SpaceType::Custom(s.to_string()))
}

fn parse_visibility(s: &str) -> Visibility {
    serde_json::from_value(serde_json::Value::String(s.to_string())).unwrap_or(Visibility::Unknown)
}

// ---------------------------------------------------------------------------
// Helper: load policy and extract OriginsConfig
// ---------------------------------------------------------------------------

fn load_origins_config(
    policy_path: &str,
    remote_extends: &RemoteExtendsConfig,
    stderr: &mut dyn Write,
) -> Result<(Policy, OriginsConfig), ExitCode> {
    let policy = load_policy(policy_path, remote_extends, stderr)?;

    let origins = match &policy.origins {
        Some(origins) => origins.clone(),
        None => {
            let _ = writeln!(
                stderr,
                "{} Policy has no `origins` configuration",
                ui::Verdict::Error.icon()
            );
            return Err(ExitCode::ConfigError);
        }
    };

    Ok((policy, origins))
}

fn load_policy(
    policy_path: &str,
    remote_extends: &RemoteExtendsConfig,
    stderr: &mut dyn Write,
) -> Result<Policy, ExitCode> {
    let resolver = match RemotePolicyResolver::new(remote_extends.clone()) {
        Ok(r) => r,
        Err(e) => {
            let _ = writeln!(
                stderr,
                "{} Failed to initialize remote extends resolver: {}",
                ui::Verdict::Error.icon(),
                e
            );
            return Err(ExitCode::RuntimeError);
        }
    };

    // Try as a file path first, then as a ruleset name.
    let path = std::path::Path::new(policy_path);
    if path.exists() {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "{} Failed to read policy file: {}",
                    ui::Verdict::Error.icon(),
                    e
                );
                return Err(ExitCode::RuntimeError);
            }
        };

        match Policy::from_yaml_with_extends_resolver(&content, Some(path), &resolver) {
            Ok(p) => Ok(p),
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "{} Failed to load policy: {}",
                    ui::Verdict::Error.icon(),
                    e
                );
                Err(ExitCode::ConfigError)
            }
        }
    } else {
        match clawdstrike::RuleSet::by_name(policy_path) {
            Ok(Some(rs)) => Ok(rs.policy),
            Ok(None) => {
                let _ = writeln!(
                    stderr,
                    "{} Unknown ruleset or file not found: {}",
                    ui::Verdict::Error.icon(),
                    policy_path
                );
                Err(ExitCode::ConfigError)
            }
            Err(e) => {
                let _ = writeln!(
                    stderr,
                    "{} Failed to load ruleset: {}",
                    ui::Verdict::Error.icon(),
                    e
                );
                Err(ExitCode::ConfigError)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 2.1: clawdstrike origin resolve
// ---------------------------------------------------------------------------

fn cmd_resolve(
    policy_path: &str,
    args: OriginArgs,
    json: bool,
    remote_extends: &RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let (_policy, origins) = match load_origins_config(policy_path, remote_extends, stderr) {
        Ok(v) => v,
        Err(code) => return code,
    };

    let origin = build_origin_context(&args);

    match EnclaveResolver::resolve(&origin, &origins) {
        Ok(enclave) => {
            if json {
                emit_resolve_json(&enclave, stdout);
            } else {
                emit_resolve_human(&enclave, stdout);
            }
            ExitCode::Ok
        }
        Err(e) => {
            if json {
                let err_json = serde_json::json!({
                    "error": e.to_string(),
                    "resolved": false,
                });
                let _ = writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&err_json).unwrap_or_default()
                );
            } else {
                let _ = writeln!(
                    stderr,
                    "{} Resolution failed: {}",
                    ui::Verdict::Error.icon(),
                    e
                );
            }
            ExitCode::Fail
        }
    }
}

fn emit_resolve_json(enclave: &ResolvedEnclave, stdout: &mut dyn Write) {
    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(enclave).unwrap_or_else(|_| "{}".to_string())
    );
}

fn emit_resolve_human(enclave: &ResolvedEnclave, stdout: &mut dyn Write) {
    ui::section("Resolved Enclave", stdout);

    ui::kv(
        "Profile",
        enclave
            .profile_id
            .as_deref()
            .unwrap_or("(default behavior)"),
        stdout,
    );

    if let Some(ref posture) = enclave.posture {
        ui::kv("Posture", posture, stdout);
    }

    if !enclave.resolution_path.is_empty() {
        ui::kv(
            "Resolution path",
            &enclave.resolution_path.join("; "),
            stdout,
        );
    }

    if let Some(ref explanation) = enclave.explanation {
        ui::kv("Explanation", explanation, stdout);
    }

    // MCP summary
    if let Some(ref mcp) = enclave.mcp {
        let default_action = mcp
            .default_action
            .as_ref()
            .map(|a| format!("{a:?}"))
            .unwrap_or_else(|| "-".into());
        let blocked = if mcp.block.is_empty() {
            "-".into()
        } else {
            format!("[{}]", mcp.block.join(", "))
        };
        let allowed = if mcp.allow.is_empty() {
            "-".into()
        } else {
            format!("[{}]", mcp.allow.join(", "))
        };
        let _ = writeln!(stdout);
        ui::kv("MCP default_action", &default_action, stdout);
        ui::kv("MCP allow", &allowed, stdout);
        ui::kv("MCP block", &blocked, stdout);
    }

    // Egress summary
    if let Some(ref egress) = enclave.egress {
        let domains = if egress.allow.is_empty() {
            "-".into()
        } else {
            format!("[{}]", egress.allow.join(", "))
        };
        let _ = writeln!(stdout);
        ui::kv("Egress allowed_domains", &domains, stdout);
    }

    // Data policy
    if let Some(ref data) = enclave.data {
        let _ = writeln!(stdout);
        ui::kv(
            "Data allow_external_sharing",
            &data.allow_external_sharing.to_string(),
            stdout,
        );
        ui::kv(
            "Data redact_before_send",
            &data.redact_before_send.to_string(),
            stdout,
        );
        ui::kv(
            "Data block_sensitive_outputs",
            &data.block_sensitive_outputs.to_string(),
            stdout,
        );
    }

    // Budgets
    if let Some(ref budgets) = enclave.budgets {
        let _ = writeln!(stdout);
        if let Some(calls) = budgets.mcp_tool_calls {
            ui::kv("Budget mcp_tool_calls", &calls.to_string(), stdout);
        }
        if let Some(calls) = budgets.egress_calls {
            ui::kv("Budget egress_calls", &calls.to_string(), stdout);
        }
        if let Some(calls) = budgets.shell_commands {
            ui::kv("Budget shell_commands", &calls.to_string(), stdout);
        }
    }

    // Bridge policy
    if let Some(ref bridge) = enclave.bridge_policy {
        let _ = writeln!(stdout);
        ui::kv(
            "Bridge allow_cross_origin",
            &bridge.allow_cross_origin.to_string(),
            stdout,
        );
        ui::kv(
            "Bridge require_approval",
            &bridge.require_approval.to_string(),
            stdout,
        );
        if !bridge.allowed_targets.is_empty() {
            let targets: Vec<String> = bridge
                .allowed_targets
                .iter()
                .map(|t| {
                    let mut parts = Vec::new();
                    if let Some(ref p) = t.provider {
                        parts.push(format!("provider={p}"));
                    }
                    if let Some(ref st) = t.space_type {
                        parts.push(format!("space_type={st}"));
                    }
                    if !t.tags.is_empty() {
                        parts.push(format!("tags=[{}]", t.tags.join(",")));
                    }
                    if let Some(ref v) = t.visibility {
                        parts.push(format!("visibility={v}"));
                    }
                    parts.join(",")
                })
                .collect();
            ui::kv("Bridge targets", &targets.join("; "), stdout);
        }
    }
}

// ---------------------------------------------------------------------------
// 2.2: clawdstrike origin explain
// ---------------------------------------------------------------------------

fn cmd_explain(
    policy_path: &str,
    args: OriginArgs,
    json: bool,
    remote_extends: &RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let (_policy, origins) = match load_origins_config(policy_path, remote_extends, stderr) {
        Ok(v) => v,
        Err(code) => return code,
    };

    let origin = build_origin_context(&args);

    let evaluations = evaluate_profiles(&origin, &origins);

    // Also compute the actual winner via the resolver.
    let resolved = EnclaveResolver::resolve(&origin, &origins);

    if json {
        emit_explain_json(&origin, &evaluations, &resolved, &origins, stdout);
    } else {
        emit_explain_human(&origin, &evaluations, &resolved, &origins, stdout);
    }

    ExitCode::Ok
}

/// Per-profile evaluation result for explain output.
#[derive(Clone, Debug, serde::Serialize)]
struct ProfileEvaluation {
    profile_id: String,
    matched: bool,
    specificity: usize,
    field_results: Vec<FieldResult>,
}

#[derive(Clone, Debug, serde::Serialize)]
struct FieldResult {
    field: String,
    matched: bool,
    expected: String,
    actual: String,
}

/// Evaluate each profile against the origin and return detailed results.
fn evaluate_profiles(origin: &OriginContext, config: &OriginsConfig) -> Vec<ProfileEvaluation> {
    config
        .profiles
        .iter()
        .map(|profile| evaluate_single_profile(origin, profile))
        .collect()
}

fn evaluate_single_profile(origin: &OriginContext, profile: &OriginProfile) -> ProfileEvaluation {
    let rules = &profile.match_rules;
    let mut field_results = Vec::new();
    let mut all_matched = true;
    let mut specificity: usize = 0;

    // provider
    if let Some(ref rule_provider) = rules.provider {
        let origin_str = origin.provider.to_string();
        let rule_str = rule_provider.to_string();
        let matched = origin_str == rule_str;
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "provider".into(),
            matched,
            expected: rule_str,
            actual: origin_str,
        });
    }

    // tenant_id
    if let Some(ref rule_tenant) = rules.tenant_id {
        let actual = origin.tenant_id.as_deref().unwrap_or("(none)");
        let matched = origin.tenant_id.as_deref() == Some(rule_tenant.as_str());
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "tenant_id".into(),
            matched,
            expected: rule_tenant.clone(),
            actual: actual.into(),
        });
    }

    // space_id
    if let Some(ref rule_space) = rules.space_id {
        let actual = origin.space_id.as_deref().unwrap_or("(none)");
        let matched = origin.space_id.as_deref() == Some(rule_space.as_str());
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "space_id".into(),
            matched,
            expected: rule_space.clone(),
            actual: actual.into(),
        });
    }

    // space_type
    if let Some(ref rule_space_type) = rules.space_type {
        let actual = origin
            .space_type
            .as_ref()
            .map(|s| s.to_string())
            .unwrap_or("(none)".into());
        let matched =
            origin.space_type.as_ref().map(|s| s.to_string()) == Some(rule_space_type.to_string());
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "space_type".into(),
            matched,
            expected: rule_space_type.to_string(),
            actual,
        });
    }

    // thread_id
    if let Some(ref rule_thread) = rules.thread_id {
        let actual = origin.thread_id.as_deref().unwrap_or("(none)");
        let matched = origin.thread_id.as_deref() == Some(rule_thread.as_str());
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "thread_id".into(),
            matched,
            expected: rule_thread.clone(),
            actual: actual.into(),
        });
    }

    // visibility
    if let Some(ref rule_vis) = rules.visibility {
        let actual = origin
            .visibility
            .as_ref()
            .map(|v| v.to_string())
            .unwrap_or("(none)".into());
        let matched =
            origin.visibility.as_ref().map(|v| v.to_string()) == Some(rule_vis.to_string());
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "visibility".into(),
            matched,
            expected: rule_vis.to_string(),
            actual,
        });
    }

    // external_participants
    if let Some(rule_ext) = rules.external_participants {
        let actual = origin
            .external_participants
            .map(|b| b.to_string())
            .unwrap_or("(none)".into());
        let matched = origin.external_participants == Some(rule_ext);
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "external_participants".into(),
            matched,
            expected: rule_ext.to_string(),
            actual,
        });
    }

    // tags
    if !rules.tags.is_empty() {
        let origin_tags_str = if origin.tags.is_empty() {
            "[]".into()
        } else {
            format!("[{}]", origin.tags.join(","))
        };
        let rule_tags_str = format!("[{}]", rules.tags.join(","));
        let matched = rules.tags.iter().all(|t| origin.tags.contains(t));
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "tags".into(),
            matched,
            expected: rule_tags_str,
            actual: origin_tags_str,
        });
    }

    // sensitivity
    if let Some(ref rule_sens) = rules.sensitivity {
        let actual = origin.sensitivity.as_deref().unwrap_or("(none)");
        let matched = origin.sensitivity.as_deref() == Some(rule_sens.as_str());
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "sensitivity".into(),
            matched,
            expected: rule_sens.clone(),
            actual: actual.into(),
        });
    }

    if let Some(ref rule_role) = rules.actor_role {
        let actual = origin.actor_role.as_deref().unwrap_or("(none)");
        let matched = origin.actor_role.as_deref() == Some(rule_role.as_str());
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "actor_role".into(),
            matched,
            expected: rule_role.clone(),
            actual: actual.into(),
        });
    }

    // provenance_confidence
    if let Some(ref rule_pc) = rules.provenance_confidence {
        let actual = origin
            .provenance_confidence
            .as_ref()
            .map(|p| p.to_string())
            .unwrap_or("(none)".into());
        let matched = origin.provenance_confidence.as_ref() == Some(rule_pc);
        if matched {
            specificity += 1;
        } else {
            all_matched = false;
        }
        field_results.push(FieldResult {
            field: "provenance_confidence".into(),
            matched,
            expected: rule_pc.to_string(),
            actual,
        });
    }

    // A profile with no match rules is a default/fallback — always matches with specificity 0.
    let is_default_profile = field_results.is_empty();

    ProfileEvaluation {
        profile_id: profile.id.clone(),
        matched: all_matched && (is_default_profile || !field_results.is_empty()),
        specificity,
        field_results,
    }
}

fn emit_explain_json(
    origin: &OriginContext,
    evaluations: &[ProfileEvaluation],
    resolved: &Result<ResolvedEnclave, clawdstrike::Error>,
    config: &OriginsConfig,
    stdout: &mut dyn Write,
) {
    let winner = match resolved {
        Ok(ref enclave) => serde_json::to_value(enclave).ok(),
        Err(ref e) => Some(serde_json::json!({ "error": e.to_string() })),
    };

    let output = serde_json::json!({
        "origin": origin,
        "evaluations": evaluations,
        "winner": winner,
        "default_behavior": format!("{:?}", config.effective_default_behavior()),
    });

    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
    );
}

fn emit_explain_human(
    origin: &OriginContext,
    evaluations: &[ProfileEvaluation],
    resolved: &Result<ResolvedEnclave, clawdstrike::Error>,
    config: &OriginsConfig,
    stdout: &mut dyn Write,
) {
    // Print the origin being evaluated.
    let _ = writeln!(stdout, "{}", "Evaluating origin:".bold());
    let _ = writeln!(stdout, "  provider={}", origin.provider);
    if let Some(ref sid) = origin.space_id {
        let _ = writeln!(stdout, "  space_id={sid}");
    }
    if let Some(ref vis) = origin.visibility {
        let _ = writeln!(stdout, "  visibility={vis}");
    }
    if let Some(ref st) = origin.space_type {
        let _ = writeln!(stdout, "  space_type={st}");
    }
    if !origin.tags.is_empty() {
        let _ = writeln!(stdout, "  tags=[{}]", origin.tags.join(","));
    }
    if let Some(ref tid) = origin.tenant_id {
        let _ = writeln!(stdout, "  tenant_id={tid}");
    }
    if let Some(ref thid) = origin.thread_id {
        let _ = writeln!(stdout, "  thread_id={thid}");
    }
    if let Some(ext) = origin.external_participants {
        let _ = writeln!(stdout, "  external_participants={ext}");
    }
    if let Some(ref sens) = origin.sensitivity {
        let _ = writeln!(stdout, "  sensitivity={sens}");
    }
    if let Some(ref pc) = origin.provenance_confidence {
        let _ = writeln!(stdout, "  provenance_confidence={pc}");
    }
    let _ = writeln!(stdout);

    // Evaluate each profile.
    for eval in evaluations {
        let _ = writeln!(
            stdout,
            "{}",
            format!("Profile \"{}\":", eval.profile_id).bold()
        );

        if eval.field_results.is_empty() {
            let _ = writeln!(
                stdout,
                "  {} {}",
                "~".dimmed(),
                "(default profile, no match rules)".dimmed()
            );
        }

        for fr in &eval.field_results {
            let icon = if fr.matched {
                "✓".green().to_string()
            } else {
                "✗".red().to_string()
            };

            if fr.matched {
                let _ = writeln!(
                    stdout,
                    "  {icon} {}: {} = {}",
                    fr.field, fr.actual, fr.expected
                );
            } else {
                let _ = writeln!(
                    stdout,
                    "  {icon} {}: {} != {}",
                    fr.field,
                    fr.actual.red(),
                    fr.expected.green()
                );
            }
        }

        if eval.matched {
            let _ = writeln!(
                stdout,
                "  {} {}",
                "->".green().bold(),
                format!("MATCH (specificity: {})", eval.specificity)
                    .green()
                    .bold()
            );
        } else {
            let _ = writeln!(stdout, "  {} {}", "->".dimmed(), "NO MATCH".dimmed());
        }

        let _ = writeln!(stdout);
    }

    // Print the winner.
    match resolved {
        Ok(ref enclave) => {
            let profile_id = enclave
                .profile_id
                .as_deref()
                .unwrap_or("(default behavior)");
            let _ = writeln!(stdout, "{}", format!("Winner: {profile_id}").green().bold());
            if !enclave.resolution_path.is_empty() {
                let _ = writeln!(
                    stdout,
                    "  {}",
                    format!("Resolution: {}", enclave.resolution_path.join("; ")).dimmed()
                );
            }
            if let Some(ref explanation) = enclave.explanation {
                let _ = writeln!(stdout, "  {}", explanation.dimmed());
            }
        }
        Err(ref e) => {
            let _ = writeln!(
                stdout,
                "{} {}",
                "No winner:".red().bold(),
                e.to_string().red()
            );
            let _ = writeln!(
                stdout,
                "  default_behavior: {:?}",
                config.effective_default_behavior()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 2.3: clawdstrike origin list-profiles
// ---------------------------------------------------------------------------

fn cmd_list_profiles(
    policy_path: &str,
    json: bool,
    remote_extends: &RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let (_policy, origins) = match load_origins_config(policy_path, remote_extends, stderr) {
        Ok(v) => v,
        Err(code) => return code,
    };

    if json {
        emit_list_profiles_json(&origins, stdout);
    } else {
        emit_list_profiles_table(&origins, stdout);
    }

    ExitCode::Ok
}

fn emit_list_profiles_json(config: &OriginsConfig, stdout: &mut dyn Write) {
    #[derive(serde::Serialize)]
    struct ProfileSummary {
        id: String,
        match_criteria: OriginMatch,
        posture: Option<String>,
        explanation: Option<String>,
    }

    let profiles: Vec<ProfileSummary> = config
        .profiles
        .iter()
        .map(|p| ProfileSummary {
            id: p.id.clone(),
            match_criteria: p.match_rules.clone(),
            posture: p.posture.clone(),
            explanation: p.explanation.clone(),
        })
        .collect();

    let output = serde_json::json!({
        "default_behavior": format!("{:?}", config.effective_default_behavior()),
        "profile_count": profiles.len(),
        "profiles": profiles,
    });

    let _ = writeln!(
        stdout,
        "{}",
        serde_json::to_string_pretty(&output).unwrap_or_else(|_| "{}".to_string())
    );
}

fn emit_list_profiles_table(config: &OriginsConfig, stdout: &mut dyn Write) {
    let _ = writeln!(
        stdout,
        "{}",
        format!(
            "Origin profiles ({} total, default_behavior: {:?})",
            config.profiles.len(),
            config.effective_default_behavior()
        )
        .bold()
    );
    let _ = writeln!(stdout);

    let mut table = Table::new();
    table
        .load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["ID", "Match Criteria", "Posture", "Explanation"]);

    for profile in &config.profiles {
        let criteria = format_match_criteria(&profile.match_rules);
        let posture = profile.posture.as_deref().unwrap_or("-");
        let explanation = profile.explanation.as_deref().unwrap_or("-");

        table.add_row(vec![&profile.id, &criteria, posture, explanation]);
    }

    let _ = writeln!(stdout, "{table}");
}

/// Format match rules as a compact human-readable string.
fn format_match_criteria(rules: &OriginMatch) -> String {
    let mut parts = Vec::new();

    if let Some(ref provider) = rules.provider {
        parts.push(format!("provider={provider}"));
    }
    if let Some(ref tenant_id) = rules.tenant_id {
        parts.push(format!("tenant_id={tenant_id}"));
    }
    if let Some(ref space_id) = rules.space_id {
        parts.push(format!("space_id={space_id}"));
    }
    if let Some(ref space_type) = rules.space_type {
        parts.push(format!("space_type={space_type}"));
    }
    if let Some(ref thread_id) = rules.thread_id {
        parts.push(format!("thread_id={thread_id}"));
    }
    if let Some(ref visibility) = rules.visibility {
        parts.push(format!("visibility={visibility}"));
    }
    if let Some(ext) = rules.external_participants {
        parts.push(format!("external_participants={ext}"));
    }
    if !rules.tags.is_empty() {
        parts.push(format!("tags=[{}]", rules.tags.join(",")));
    }
    if let Some(ref sensitivity) = rules.sensitivity {
        parts.push(format!("sensitivity={sensitivity}"));
    }
    if let Some(ref actor_role) = rules.actor_role {
        parts.push(format!("actor_role={actor_role}"));
    }
    if let Some(ref pc) = rules.provenance_confidence {
        parts.push(format!("provenance_confidence={pc}"));
    }

    if parts.is_empty() {
        "(default/catch-all)".into()
    } else {
        parts.join(", ")
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_known_providers() {
        assert_eq!(parse_provider("slack"), OriginProvider::Slack);
        assert_eq!(parse_provider("github"), OriginProvider::GitHub);
        assert_eq!(parse_provider("teams"), OriginProvider::Teams);
        assert_eq!(parse_provider("jira"), OriginProvider::Jira);
        assert_eq!(
            parse_provider("custom_tool"),
            OriginProvider::Custom("custom_tool".into())
        );
    }

    #[test]
    fn parse_known_space_types() {
        assert_eq!(parse_space_type("channel"), SpaceType::Channel);
        assert_eq!(parse_space_type("pull_request"), SpaceType::PullRequest);
        assert_eq!(parse_space_type("dm"), SpaceType::Dm);
        assert_eq!(
            parse_space_type("wiki_page"),
            SpaceType::Custom("wiki_page".into())
        );
    }

    #[test]
    fn parse_known_visibility() {
        assert_eq!(parse_visibility("private"), Visibility::Private);
        assert_eq!(parse_visibility("internal"), Visibility::Internal);
        assert_eq!(parse_visibility("public"), Visibility::Public);
        assert_eq!(
            parse_visibility("external_shared"),
            Visibility::ExternalShared
        );
    }

    #[test]
    fn build_origin_context_all_flags() {
        let args = OriginArgs {
            provider: Some("slack".into()),
            space_id: Some("C123".into()),
            space_type: Some("channel".into()),
            visibility: Some("internal".into()),
            tags: Some("incident,pci".into()),
            tenant_id: Some("T001".into()),
            thread_id: Some("thread-42".into()),
            external_participants: Some(true),
            sensitivity: Some("high".into()),
            actor_role: Some("incident_commander".into()),
        };

        let ctx = build_origin_context(&args);
        assert_eq!(ctx.provider, OriginProvider::Slack);
        assert_eq!(ctx.space_id.as_deref(), Some("C123"));
        assert_eq!(ctx.space_type, Some(SpaceType::Channel));
        assert_eq!(ctx.visibility, Some(Visibility::Internal));
        assert_eq!(ctx.tags, vec!["incident", "pci"]);
        assert_eq!(ctx.tenant_id.as_deref(), Some("T001"));
        assert_eq!(ctx.thread_id.as_deref(), Some("thread-42"));
        assert_eq!(ctx.external_participants, Some(true));
        assert_eq!(ctx.sensitivity.as_deref(), Some("high"));
        assert_eq!(ctx.actor_role.as_deref(), Some("incident_commander"));
    }

    #[test]
    fn build_origin_context_minimal() {
        let args = OriginArgs {
            provider: None,
            space_id: None,
            space_type: None,
            visibility: None,
            tags: None,
            tenant_id: None,
            thread_id: None,
            external_participants: None,
            sensitivity: None,
            actor_role: None,
        };

        let ctx = build_origin_context(&args);
        assert_eq!(ctx.provider, OriginProvider::Custom("unknown".into()));
        assert_eq!(ctx.space_id, None);
        assert!(ctx.tags.is_empty());
        assert_eq!(ctx.external_participants, None);
    }

    #[test]
    fn build_origin_context_external_participants_false() {
        let args = OriginArgs {
            provider: Some("slack".into()),
            space_id: None,
            space_type: None,
            visibility: None,
            tags: None,
            tenant_id: None,
            thread_id: None,
            external_participants: Some(false),
            sensitivity: None,
            actor_role: None,
        };

        let ctx = build_origin_context(&args);
        assert_eq!(ctx.external_participants, Some(false));
    }

    #[test]
    fn format_match_criteria_all_fields() {
        let rules = OriginMatch {
            provider: Some(OriginProvider::Slack),
            visibility: Some(Visibility::Internal),
            tags: vec!["incident".into()],
            ..Default::default()
        };

        let formatted = format_match_criteria(&rules);
        assert!(formatted.contains("provider=slack"));
        assert!(formatted.contains("visibility=internal"));
        assert!(formatted.contains("tags=[incident]"));
    }

    #[test]
    fn format_match_criteria_empty() {
        let rules = OriginMatch::default();
        let formatted = format_match_criteria(&rules);
        assert_eq!(formatted, "(default/catch-all)");
    }

    #[test]
    fn evaluate_single_profile_match() {
        let origin = OriginContext {
            provider: OriginProvider::Slack,
            visibility: Some(Visibility::Internal),
            tags: vec!["incident".into()],
            actor_role: Some("incident_commander".into()),
            ..Default::default()
        };

        let profile = OriginProfile {
            id: "test".into(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                visibility: Some(Visibility::Internal),
                tags: vec!["incident".into()],
                actor_role: Some("incident_commander".into()),
                ..Default::default()
            },
            posture: None,
            mcp: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        };

        let eval = evaluate_single_profile(&origin, &profile);
        assert!(eval.matched);
        assert_eq!(eval.specificity, 4);
        assert_eq!(eval.field_results.len(), 4);
        assert!(eval.field_results.iter().all(|r| r.matched));
    }

    #[test]
    fn evaluate_single_profile_actor_role_mismatch() {
        let origin = OriginContext {
            provider: OriginProvider::Slack,
            actor_role: Some("viewer".into()),
            ..Default::default()
        };

        let profile = OriginProfile {
            id: "test".into(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::Slack),
                actor_role: Some("approver".into()),
                ..Default::default()
            },
            posture: None,
            mcp: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        };

        let eval = evaluate_single_profile(&origin, &profile);
        assert!(!eval.matched);
        assert_eq!(eval.field_results.len(), 2);
        assert_eq!(eval.field_results[1].field, "actor_role");
        assert!(!eval.field_results[1].matched);
        assert_eq!(eval.field_results[1].actual, "viewer");
    }

    #[test]
    fn evaluate_single_profile_mismatch() {
        let origin = OriginContext {
            provider: OriginProvider::Slack,
            ..Default::default()
        };

        let profile = OriginProfile {
            id: "test".into(),
            match_rules: OriginMatch {
                provider: Some(OriginProvider::GitHub),
                ..Default::default()
            },
            posture: None,
            mcp: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        };

        let eval = evaluate_single_profile(&origin, &profile);
        assert!(!eval.matched);
        assert_eq!(eval.field_results.len(), 1);
        assert!(!eval.field_results[0].matched);
    }

    #[test]
    fn evaluate_default_profile() {
        let origin = OriginContext {
            provider: OriginProvider::Slack,
            ..Default::default()
        };

        let profile = OriginProfile {
            id: "fallback".into(),
            match_rules: OriginMatch::default(),
            posture: None,
            mcp: None,
            egress: None,
            data: None,
            budgets: None,
            bridge_policy: None,
            explanation: None,
        };

        let eval = evaluate_single_profile(&origin, &profile);
        assert!(eval.matched);
        assert_eq!(eval.specificity, 0);
        assert!(eval.field_results.is_empty());
    }
}
