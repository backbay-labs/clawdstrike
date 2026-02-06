use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::{BufRead, Write};
use std::path::PathBuf;

use hush_proxy::policy::PolicyAction;

use clawdstrike::guards::{normalize_path_for_policy, EgressAllowlistConfig, ForbiddenPathConfig};
use clawdstrike::guards::{PathAllowlistConfig, SecretLeakConfig};
use clawdstrike::policy::POLICY_SCHEMA_VERSION;
use clawdstrike::{Policy, PostureConfig, PostureState, PostureTransition, TransitionTrigger};

use crate::policy_event::{PolicyEvent, PolicyEventData, PolicyEventType};
use crate::remote_extends::RemoteExtendsConfig;
use crate::ExitCode;

#[derive(Debug, Clone)]
pub struct PolicySynthCommand {
    pub events: PathBuf,
    pub extends: Option<String>,
    pub out: PathBuf,
    pub diff_out: Option<PathBuf>,
    pub risk_out: PathBuf,
    pub with_posture: bool,
    pub json: bool,
}

#[derive(Default)]
struct ObservedStats {
    total_events: u64,
    earliest_ts: Option<String>,
    latest_ts: Option<String>,
    capabilities: BTreeSet<String>,
    hosts: BTreeSet<String>,
    file_access_paths: BTreeSet<String>,
    file_write_paths: BTreeSet<String>,
    patch_paths: BTreeSet<String>,
    file_writes: u64,
    egress_calls: u64,
    shell_commands: u64,
    mcp_tool_calls: u64,
    patches: u64,
    custom_calls: u64,
}

pub fn cmd_policy_synth(
    args: PolicySynthCommand,
    remote_extends: &RemoteExtendsConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> ExitCode {
    let events = match load_events(&args.events) {
        Ok(events) => events,
        Err(err) => {
            let _ = writeln!(stderr, "Error: {}", err);
            return ExitCode::RuntimeError;
        }
    };

    let stats = collect_stats(&events);

    let policy = build_candidate_policy(&stats, args.extends.clone(), args.with_posture);
    if let Err(err) = policy.validate() {
        let _ = writeln!(
            stderr,
            "Error: synthesized policy failed validation: {}",
            err
        );
        return ExitCode::ConfigError;
    }

    if let Some(parent) = args.out.parent() {
        if !parent.as_os_str().is_empty() {
            if let Err(err) = std::fs::create_dir_all(parent) {
                let _ = writeln!(stderr, "Error: failed to create output directory: {}", err);
                return ExitCode::RuntimeError;
            }
        }
    }

    let yaml = match policy.to_yaml() {
        Ok(yaml) => yaml,
        Err(err) => {
            let _ = writeln!(
                stderr,
                "Error: failed to serialize synthesized policy: {}",
                err
            );
            return ExitCode::RuntimeError;
        }
    };

    if let Err(err) = std::fs::write(&args.out, yaml) {
        let _ = writeln!(
            stderr,
            "Error: failed to write policy output {}: {}",
            args.out.display(),
            err
        );
        return ExitCode::RuntimeError;
    }

    if let Some(diff_out) = &args.diff_out {
        if let Some(base_ref) = args.extends.as_ref() {
            let base =
                match crate::policy_diff::load_policy_from_arg(base_ref, true, remote_extends) {
                    Ok(loaded) => loaded.policy,
                    Err(err) => {
                        let _ = writeln!(
                            stderr,
                            "Error: failed to load base policy {}: {}",
                            base_ref, err.message
                        );
                        return crate::policy_error_exit_code(&err.source);
                    }
                };

            if let Err(err) = write_diff(&base, &policy, diff_out) {
                let _ = writeln!(stderr, "Error: failed to write diff output: {}", err);
                return ExitCode::RuntimeError;
            }
        } else {
            let _ = writeln!(stderr, "Warning: --diff-out ignored without --extends");
        }
    }

    if let Err(err) = write_risk_report(&args.risk_out, &stats, args.with_posture, &policy) {
        let _ = writeln!(stderr, "Error: failed to write risk report: {}", err);
        return ExitCode::RuntimeError;
    }

    if args.json {
        let payload = serde_json::json!({
            "events": stats.total_events,
            "output": args.out,
            "diff": args.diff_out,
            "risk": args.risk_out,
            "with_posture": args.with_posture,
        });
        let _ = writeln!(
            stdout,
            "{}",
            serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        let _ = writeln!(
            stdout,
            "Synthesized policy from {} event(s): {}",
            stats.total_events,
            args.out.display()
        );
        if let Some(diff_out) = args.diff_out {
            let _ = writeln!(stdout, "Diff output: {}", diff_out.display());
        }
        let _ = writeln!(stdout, "Risk report: {}", args.risk_out.display());
    }

    ExitCode::Ok
}

fn load_events(path: &PathBuf) -> anyhow::Result<Vec<PolicyEvent>> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let mut events = Vec::new();

    for (line_idx, line) in reader.lines().enumerate() {
        let line = line?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let event: PolicyEvent = serde_json::from_str(trimmed).map_err(|err| {
            anyhow::anyhow!(
                "invalid PolicyEvent JSONL at line {}: {}",
                line_idx + 1,
                err
            )
        })?;
        events.push(event);
    }

    Ok(events)
}

fn collect_stats(events: &[PolicyEvent]) -> ObservedStats {
    let mut stats = ObservedStats::default();

    for event in events {
        stats.total_events += 1;

        let ts = event.timestamp.to_rfc3339();
        if stats
            .earliest_ts
            .as_ref()
            .is_none_or(|existing| ts < *existing)
        {
            stats.earliest_ts = Some(ts.clone());
        }
        if stats
            .latest_ts
            .as_ref()
            .is_none_or(|existing| ts > *existing)
        {
            stats.latest_ts = Some(ts.clone());
        }

        match (&event.event_type, &event.data) {
            (PolicyEventType::FileRead, PolicyEventData::File(file)) => {
                stats.capabilities.insert("file_access".to_string());
                stats.file_access_paths.insert(file.path.clone());
            }
            (PolicyEventType::FileWrite, PolicyEventData::File(file)) => {
                stats.capabilities.insert("file_access".to_string());
                stats.capabilities.insert("file_write".to_string());
                stats.file_access_paths.insert(file.path.clone());
                stats.file_write_paths.insert(file.path.clone());
                stats.file_writes += 1;
            }
            (PolicyEventType::NetworkEgress, PolicyEventData::Network(network)) => {
                stats.capabilities.insert("egress".to_string());
                stats.hosts.insert(network.host.clone());
                stats.egress_calls += 1;
            }
            (PolicyEventType::CommandExec, PolicyEventData::Command(_)) => {
                stats.capabilities.insert("shell".to_string());
                stats.shell_commands += 1;
            }
            (PolicyEventType::PatchApply, PolicyEventData::Patch(patch)) => {
                stats.capabilities.insert("patch".to_string());
                stats.capabilities.insert("file_write".to_string());
                stats.patch_paths.insert(patch.file_path.clone());
                stats.patches += 1;
            }
            (PolicyEventType::ToolCall, PolicyEventData::Tool(_)) => {
                stats.capabilities.insert("mcp_tool".to_string());
                stats.mcp_tool_calls += 1;
            }
            (PolicyEventType::Custom, _) => {
                stats.capabilities.insert("custom".to_string());
                stats.custom_calls += 1;
            }
            _ => {}
        }
    }

    stats
}

fn build_candidate_policy(
    stats: &ObservedStats,
    extends: Option<String>,
    with_posture: bool,
) -> Policy {
    let mut policy = Policy::default();
    policy.version = POLICY_SCHEMA_VERSION.to_string();
    policy.name = "Synthesized Policy".to_string();
    policy.description = "Auto-generated from observed policy events".to_string();
    policy.extends = extends;

    policy.guards.forbidden_path = Some(ForbiddenPathConfig::with_defaults());
    policy.guards.secret_leak = Some(SecretLeakConfig::default());

    let file_access_allow = derive_path_patterns(&stats.file_access_paths);
    let file_write_allow = derive_path_patterns(&stats.file_write_paths);
    let patch_allow = derive_path_patterns(&stats.patch_paths);

    if !file_access_allow.is_empty() || !file_write_allow.is_empty() || !patch_allow.is_empty() {
        policy.guards.path_allowlist = Some(PathAllowlistConfig {
            enabled: true,
            file_access_allow,
            file_write_allow,
            patch_allow,
        });
    }

    if !stats.hosts.is_empty() {
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: stats.hosts.iter().cloned().collect(),
            block: Vec::new(),
            default_action: Some(PolicyAction::Block),
            additional_allow: Vec::new(),
            remove_allow: Vec::new(),
            additional_block: Vec::new(),
            remove_block: Vec::new(),
        });
    }

    if with_posture {
        let mut states = BTreeMap::new();
        let capabilities = ordered_capabilities(&stats.capabilities);

        let mut budgets: HashMap<String, i64> = HashMap::new();
        maybe_insert_budget(&mut budgets, "file_writes", stats.file_writes);
        maybe_insert_budget(&mut budgets, "egress_calls", stats.egress_calls);
        maybe_insert_budget(&mut budgets, "shell_commands", stats.shell_commands);
        maybe_insert_budget(&mut budgets, "mcp_tool_calls", stats.mcp_tool_calls);
        maybe_insert_budget(&mut budgets, "patches", stats.patches);
        maybe_insert_budget(&mut budgets, "custom_calls", stats.custom_calls);

        states.insert(
            "work".to_string(),
            PostureState {
                description: Some("Synthesized working state".to_string()),
                capabilities,
                budgets,
            },
        );

        states.insert(
            "quarantine".to_string(),
            PostureState {
                description: Some("Lockdown state on critical violations".to_string()),
                capabilities: Vec::new(),
                budgets: HashMap::new(),
            },
        );

        policy.posture = Some(PostureConfig {
            initial: "work".to_string(),
            states,
            transitions: vec![PostureTransition {
                from: "*".to_string(),
                to: "quarantine".to_string(),
                on: TransitionTrigger::CriticalViolation,
                after: None,
                requires: Vec::new(),
            }],
        });
    }

    policy
}

fn maybe_insert_budget(budgets: &mut HashMap<String, i64>, key: &str, observed: u64) {
    if observed == 0 {
        return;
    }

    let margin = std::cmp::max(5, ((observed as f64) * 0.2).ceil() as u64);
    let value = observed.saturating_add(margin);
    budgets.insert(key.to_string(), value as i64);
}

fn ordered_capabilities(capabilities: &BTreeSet<String>) -> Vec<String> {
    const ORDER: &[&str] = &[
        "file_access",
        "file_write",
        "egress",
        "mcp_tool",
        "patch",
        "shell",
        "custom",
    ];

    ORDER
        .iter()
        .filter(|capability| capabilities.contains(**capability))
        .map(|capability| capability.to_string())
        .collect()
}

fn derive_path_patterns(paths: &BTreeSet<String>) -> Vec<String> {
    let mut patterns = BTreeSet::new();

    for path in paths {
        let normalized = normalize_path_for_policy(path);
        if normalized.is_empty() {
            continue;
        }

        let dir = normalized
            .rsplit_once('/')
            .map(|(parent, _)| parent)
            .unwrap_or(normalized.as_str());

        let pattern = if normalized.starts_with('/') {
            if dir.is_empty() {
                "/**".to_string()
            } else {
                format!("{}/**", dir)
            }
        } else {
            let trimmed = dir.trim_start_matches("./").trim_start_matches('/');
            if trimmed.is_empty() {
                "**".to_string()
            } else {
                format!("**/{}/**", trimmed)
            }
        };

        patterns.insert(pattern);
    }

    patterns.into_iter().collect()
}

fn write_diff(base: &Policy, candidate: &Policy, out: &PathBuf) -> anyhow::Result<()> {
    let left = serde_json::to_value(base)?;
    let right = serde_json::to_value(candidate)?;
    let diff = crate::policy_diff::diff_values(&left, &right);

    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let payload = serde_json::to_string_pretty(&diff)?;
    std::fs::write(out, payload)?;
    Ok(())
}

fn write_risk_report(
    path: &PathBuf,
    stats: &ObservedStats,
    with_posture: bool,
    policy: &Policy,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    let mut lines = Vec::new();
    lines.push("# Synth Risk Notes".to_string());
    lines.push(String::new());
    lines.push(format!("- Events analyzed: {}", stats.total_events));
    if let Some(start) = stats.earliest_ts.as_ref() {
        lines.push(format!("- First event: {}", start));
    }
    if let Some(end) = stats.latest_ts.as_ref() {
        lines.push(format!("- Last event: {}", end));
    }

    lines.push(String::new());
    lines.push("## Generated Controls".to_string());
    lines.push("- Safety defaults retained: forbidden_path + secret_leak".to_string());

    if let Some(path_allowlist) = policy.guards.path_allowlist.as_ref() {
        lines.push(format!(
            "- Path allowlist generated: file_access={} file_write={} patch={}",
            path_allowlist.file_access_allow.len(),
            path_allowlist.file_write_allow.len(),
            path_allowlist.patch_allow.len()
        ));
    } else {
        lines.push("- Path allowlist not generated (no observed file paths)".to_string());
    }

    if let Some(egress) = policy.guards.egress_allowlist.as_ref() {
        lines.push(format!(
            "- Egress allowlist generated with {} host(s)",
            egress.allow.len()
        ));
    } else {
        lines.push("- Egress allowlist not generated (no observed egress)".to_string());
    }

    lines.push(String::new());
    lines.push("## Review Checklist".to_string());
    lines.push("- Validate generated allowlists against expected workload paths/hosts".to_string());
    lines.push("- Confirm no production workflows rely on unobserved actions".to_string());
    lines.push("- Roll out in staged mode before enforcing broadly".to_string());

    if with_posture {
        lines.push(String::new());
        lines.push("## Posture Notes".to_string());
        lines.push("- Generated posture includes work + quarantine states".to_string());
        lines.push("- Budgets use observed counts plus margin".to_string());
    }

    std::fs::write(path, lines.join("\n"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    use crate::policy_event::{FileEventData, NetworkEventData, ToolEventData};

    fn sample_events() -> Vec<PolicyEvent> {
        vec![
            PolicyEvent {
                event_id: "evt-1".to_string(),
                event_type: PolicyEventType::FileRead,
                timestamp: Utc::now(),
                session_id: Some("sess-1".to_string()),
                data: PolicyEventData::File(FileEventData {
                    path: "/workspace/project/src/lib.rs".to_string(),
                    operation: Some("read".to_string()),
                    content_base64: None,
                    content: None,
                    content_hash: None,
                }),
                metadata: None,
                context: None,
            },
            PolicyEvent {
                event_id: "evt-2".to_string(),
                event_type: PolicyEventType::FileWrite,
                timestamp: Utc::now(),
                session_id: Some("sess-1".to_string()),
                data: PolicyEventData::File(FileEventData {
                    path: "/workspace/project/src/lib.rs".to_string(),
                    operation: Some("write".to_string()),
                    content_base64: None,
                    content: None,
                    content_hash: None,
                }),
                metadata: None,
                context: None,
            },
            PolicyEvent {
                event_id: "evt-3".to_string(),
                event_type: PolicyEventType::NetworkEgress,
                timestamp: Utc::now(),
                session_id: Some("sess-1".to_string()),
                data: PolicyEventData::Network(NetworkEventData {
                    host: "api.github.com".to_string(),
                    port: 443,
                    protocol: Some("tcp".to_string()),
                    url: None,
                }),
                metadata: None,
                context: None,
            },
            PolicyEvent {
                event_id: "evt-4".to_string(),
                event_type: PolicyEventType::ToolCall,
                timestamp: Utc::now(),
                session_id: Some("sess-1".to_string()),
                data: PolicyEventData::Tool(ToolEventData {
                    tool_name: "fs_read".to_string(),
                    parameters: serde_json::json!({}),
                }),
                metadata: None,
                context: None,
            },
        ]
    }

    fn unique_temp_dir(prefix: &str) -> PathBuf {
        let millis = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock should be monotonic")
            .as_millis();
        let dir =
            std::env::temp_dir().join(format!("{}_{}_{}", prefix, std::process::id(), millis));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }

    #[test]
    fn synth_builds_valid_policy_with_safety_defaults() {
        let stats = collect_stats(&sample_events());
        let policy = build_candidate_policy(&stats, None, false);
        policy
            .validate()
            .expect("synthesized policy should validate");

        assert!(policy.guards.forbidden_path.is_some());
        assert!(policy.guards.secret_leak.is_some());
        assert!(policy.guards.path_allowlist.is_some());
        assert!(policy.guards.egress_allowlist.is_some());
        assert!(policy.posture.is_none());
    }

    #[test]
    fn synth_with_posture_adds_states_and_transition() {
        let stats = collect_stats(&sample_events());
        let policy = build_candidate_policy(&stats, None, true);
        policy
            .validate()
            .expect("synthesized policy should validate");

        let posture = policy.posture.expect("posture should be generated");
        assert_eq!(posture.initial, "work");
        assert!(posture.states.contains_key("work"));
        assert!(posture.states.contains_key("quarantine"));
        assert_eq!(posture.transitions.len(), 1);
        assert_eq!(posture.transitions[0].from, "*");
        assert_eq!(posture.transitions[0].to, "quarantine");
    }

    #[test]
    fn synth_writes_diff_and_risk_report() {
        let stats = collect_stats(&sample_events());
        let candidate =
            build_candidate_policy(&stats, Some("clawdstrike:default".to_string()), true);
        let base = Policy::default();
        let dir = unique_temp_dir("hush_cli_synth");
        let diff_path = dir.join("candidate.diff.json");
        let risk_path = dir.join("candidate.risks.md");

        write_diff(&base, &candidate, &diff_path).expect("diff write should succeed");
        write_risk_report(&risk_path, &stats, true, &candidate).expect("risk write should succeed");

        let diff_raw = std::fs::read_to_string(&diff_path).expect("diff file should exist");
        let _parsed: serde_json::Value =
            serde_json::from_str(&diff_raw).expect("diff should be valid json");
        let risk_raw = std::fs::read_to_string(&risk_path).expect("risk file should exist");
        assert!(risk_raw.contains("Safety defaults retained"));
        assert!(risk_raw.contains("Posture Notes"));
    }

    #[test]
    fn cmd_policy_synth_generates_outputs() {
        let dir = unique_temp_dir("hush_cli_synth_cmd");
        let events_path = dir.join("events.jsonl");
        let out_path = dir.join("candidate.yaml");
        let diff_path = dir.join("candidate.diff.json");
        let risk_path = dir.join("candidate.risks.md");

        let lines = sample_events()
            .into_iter()
            .map(|event| serde_json::to_string(&event).expect("event should serialize"))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(&events_path, format!("{}\n", lines))
            .expect("events file should be written");

        let args = PolicySynthCommand {
            events: events_path,
            extends: Some("clawdstrike:default".to_string()),
            out: out_path.clone(),
            diff_out: Some(diff_path.clone()),
            risk_out: risk_path.clone(),
            with_posture: true,
            json: false,
        };

        let mut stdout = Vec::<u8>::new();
        let mut stderr = Vec::<u8>::new();
        let code = cmd_policy_synth(
            args,
            &RemoteExtendsConfig::disabled(),
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(
            code,
            ExitCode::Ok,
            "stderr: {}",
            String::from_utf8_lossy(&stderr)
        );
        assert!(out_path.exists());
        assert!(diff_path.exists());
        assert!(risk_path.exists());
    }
}
