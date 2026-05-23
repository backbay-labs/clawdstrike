//! Workflow management commands

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::RwLock;

use crate::state::AppState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Workflow {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub trigger: WorkflowTrigger,
    pub actions: Vec<WorkflowAction>,
    pub last_run: Option<String>,
    pub run_count: u64,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WorkflowTrigger {
    #[serde(rename = "event_match")]
    EventMatch { conditions: Vec<TriggerCondition> },
    #[serde(rename = "schedule")]
    Schedule { cron: String },
    #[serde(rename = "aggregation")]
    Aggregation {
        conditions: Vec<TriggerCondition>,
        threshold: u32,
        window: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerCondition {
    pub field: String,
    pub operator: String,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum WorkflowAction {
    #[serde(rename = "slack_webhook")]
    SlackWebhook {
        url: String,
        channel: String,
        template: String,
    },
    #[serde(rename = "pagerduty")]
    PagerDuty {
        routing_key: String,
        severity: String,
    },
    #[serde(rename = "email")]
    Email {
        to: Vec<String>,
        subject: String,
        template: String,
    },
    #[serde(rename = "webhook")]
    Webhook {
        url: String,
        method: String,
        headers: HashMap<String, String>,
        body: String,
    },
    #[serde(rename = "log")]
    Log { path: String, format: String },
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestResult {
    pub success: bool,
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<WorkflowDryRunReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDryRunReport {
    pub workflow_id: String,
    pub workflow_name: String,
    pub context: serde_json::Value,
    pub actions: Vec<WorkflowDryRunAction>,
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowDryRunAction {
    pub index: usize,
    pub action_type: String,
    pub ok: bool,
    pub preview: serde_json::Value,
    pub errors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

// In-memory workflow storage (persisted to file)
static WORKFLOWS: OnceLock<RwLock<HashMap<String, Workflow>>> = OnceLock::new();

const APP_DATA_DIR: &str = "clawdstrike-desktop";
const LEGACY_APP_DATA_DIR: &str = "sdr-desktop";
const WORKFLOWS_FILENAME: &str = "workflows.json";

fn get_workflows() -> &'static RwLock<HashMap<String, Workflow>> {
    WORKFLOWS.get_or_init(|| {
        let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
        let workflows = load_workflows_from_dir(&base).unwrap_or_default();
        RwLock::new(workflows)
    })
}

fn workflows_path_in(base: &std::path::Path) -> PathBuf {
    base.join(APP_DATA_DIR).join(WORKFLOWS_FILENAME)
}

fn legacy_workflows_path_in(base: &std::path::Path) -> PathBuf {
    base.join(LEGACY_APP_DATA_DIR).join(WORKFLOWS_FILENAME)
}

/// Moves `<data_local>/sdr-desktop/workflows.json` to the new
/// `clawdstrike-desktop/` location on first startup after the rename.
fn migrate_legacy_workflows_dir(base: &std::path::Path) {
    let new_path = workflows_path_in(base);
    if new_path.exists() {
        return;
    }
    let legacy_path = legacy_workflows_path_in(base);
    if !legacy_path.exists() {
        return;
    }

    let Some(new_parent) = new_path.parent() else {
        return;
    };
    if let Err(e) = std::fs::create_dir_all(new_parent) {
        tracing::warn!(
            error = %e,
            target = ?new_parent,
            "failed to create workflows directory during legacy migration"
        );
        return;
    }

    if let Err(rename_err) = std::fs::rename(&legacy_path, &new_path) {
        // Cross-filesystem moves return EXDEV; fall back to copy + remove.
        match std::fs::copy(&legacy_path, &new_path) {
            Ok(_) => {
                if let Err(e) = std::fs::remove_file(&legacy_path) {
                    tracing::warn!(
                        error = %e,
                        path = ?legacy_path,
                        "copied legacy workflows.json but failed to remove the source"
                    );
                }
            }
            Err(copy_err) => {
                tracing::warn!(
                    rename_error = %rename_err,
                    copy_error = %copy_err,
                    from = ?legacy_path,
                    to = ?new_path,
                    "failed to migrate legacy workflows.json"
                );
                return;
            }
        }
    }

    if let Some(legacy_dir) = legacy_path.parent() {
        // Remove the legacy directory if it's empty after the move.
        let _ = std::fs::remove_dir(legacy_dir);
    }
}

fn load_workflows_from_dir(base: &std::path::Path) -> Option<HashMap<String, Workflow>> {
    migrate_legacy_workflows_dir(base);
    let path = workflows_path_in(base);
    if !path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

fn save_workflows_to_file(workflows: &HashMap<String, Workflow>) -> Result<(), String> {
    let base = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    let path = workflows_path_in(&base);

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    let content = serde_json::to_string_pretty(workflows)
        .map_err(|e| format!("Failed to serialize: {}", e))?;

    std::fs::write(&path, content).map_err(|e| format!("Failed to write file: {}", e))
}

#[derive(Debug, Default)]
struct TemplateDiagnostics {
    missing_keys: Vec<String>,
    errors: Vec<String>,
}

fn render_template(template: &str, data: &serde_json::Value) -> (String, TemplateDiagnostics) {
    // Minimal handlebars-ish replacement: {{a.b.c}}
    let mut diag = TemplateDiagnostics::default();
    let mut out = String::with_capacity(template.len());
    let chars: Vec<char> = template.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if chars[i] == '{' && i + 1 < chars.len() && chars[i + 1] == '{' {
            let mut j = i + 2;
            while j + 1 < chars.len() && !(chars[j] == '}' && chars[j + 1] == '}') {
                j += 1;
            }
            if j + 1 >= chars.len() {
                // Unclosed, append remainder.
                diag.errors.push("unclosed {{...}} placeholder".to_string());
                out.extend(chars[i..].iter());
                break;
            }

            let key: String = chars[i + 2..j]
                .iter()
                .collect::<String>()
                .trim()
                .to_string();
            if key.is_empty() {
                diag.errors.push("empty {{...}} placeholder".to_string());
            } else if let Some(val) = get_by_path(data, &key) {
                out.push_str(&val);
            } else {
                diag.missing_keys.push(key);
            }
            i = j + 2;
            continue;
        }

        out.push(chars[i]);
        i += 1;
    }

    diag.missing_keys.sort();
    diag.missing_keys.dedup();
    diag.errors.sort();
    diag.errors.dedup();

    (out, diag)
}

fn get_by_path(root: &serde_json::Value, path: &str) -> Option<String> {
    let mut cur = root;
    for part in path.split('.').filter(|p| !p.is_empty()) {
        cur = cur.get(part)?;
    }

    match cur {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Number(n) => Some(n.to_string()),
        serde_json::Value::Bool(b) => Some(b.to_string()),
        serde_json::Value::Null => Some(String::new()),
        other => serde_json::to_string(other).ok(),
    }
}

fn validate_trigger(trigger: &WorkflowTrigger) -> Vec<String> {
    let mut errors = Vec::new();

    fn validate_conditions(conditions: &[TriggerCondition]) -> Vec<String> {
        let mut errors = Vec::new();
        for (idx, c) in conditions.iter().enumerate() {
            if c.field.trim().is_empty() {
                errors.push(format!("trigger.conditions[{idx}].field is empty"));
            } else if !matches!(
                c.field.as_str(),
                "verdict" | "guard" | "agent" | "severity" | "action_type"
            ) {
                errors.push(format!(
                    "trigger.conditions[{idx}].field {field:?} is not supported",
                    field = c.field
                ));
            }

            if c.operator.trim().is_empty() {
                errors.push(format!("trigger.conditions[{idx}].operator is empty"));
            } else if !matches!(
                c.operator.as_str(),
                "equals" | "not_equals" | "contains" | "greater_than"
            ) {
                errors.push(format!(
                    "trigger.conditions[{idx}].operator {op:?} is not supported",
                    op = c.operator
                ));
            }

            if c.operator == "greater_than" && !c.value.is_number() {
                errors.push(format!(
                    "trigger.conditions[{idx}].value must be a number for operator greater_than"
                ));
            }
        }
        errors
    }

    match trigger {
        WorkflowTrigger::EventMatch { conditions } => {
            errors.extend(validate_conditions(conditions));
        }
        WorkflowTrigger::Schedule { cron } => {
            let cron = cron.trim();
            if cron.is_empty() {
                errors.push("trigger.cron is empty".to_string());
            } else {
                let parts: Vec<&str> = cron.split_whitespace().collect();
                if parts.len() != 5 {
                    errors.push(format!(
                        "trigger.cron must have 5 fields (got {}): {cron:?}",
                        parts.len()
                    ));
                }
            }
        }
        WorkflowTrigger::Aggregation {
            conditions,
            threshold,
            window,
        } => {
            errors.extend(validate_conditions(conditions));
            if *threshold == 0 {
                errors.push("trigger.threshold must be > 0".to_string());
            }
            if let Err(e) = parse_window(window) {
                errors.push(e);
            }
        }
    }

    errors
}

fn parse_window(window: &str) -> Result<(u64, char), String> {
    let w = window.trim();
    if w.len() < 2 {
        return Err(format!("trigger.window is invalid: {window:?}"));
    }

    let (num_str, unit_str) = w.split_at(w.len() - 1);
    let unit = unit_str.chars().next().unwrap_or(' ');
    if !matches!(unit, 's' | 'm' | 'h' | 'd') {
        return Err(format!(
            "trigger.window must end with one of s|m|h|d (got {unit:?}): {window:?}"
        ));
    }

    let n: u64 = num_str
        .parse()
        .map_err(|_| format!("trigger.window must start with an integer: {window:?}"))?;
    if n == 0 {
        return Err(format!("trigger.window must be > 0: {window:?}"));
    }

    Ok((n, unit))
}

fn synthetic_event() -> serde_json::Value {
    serde_json::json!({
        "id": "evt_synthetic",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "event_type": "check",
        "action_type": "egress",
        "target": "example.com:443",
        "decision": "allowed",
        "guard": "synthetic",
        "severity": "info",
        "message": "Synthetic event for workflow dry run",
        "session_id": "sess_synthetic",
        "agent_id": "agent_synthetic",
        "metadata": {},
    })
}

fn build_context(event: serde_json::Value) -> serde_json::Value {
    let target = event
        .get("target")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let action_type = event
        .get("action_type")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let decision = event
        .get("decision")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let severity = event
        .get("severity")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let guard = event
        .get("guard")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let session_id = event
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let agent_id = event
        .get("agent_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let timestamp = event
        .get("timestamp")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    serde_json::json!({
        "target": target,
        "action_type": action_type,
        "decision": decision,
        "severity": severity,
        "guard": guard,
        "session_id": session_id,
        "agent_id": agent_id,
        "timestamp": timestamp,
        "event": event,
    })
}

fn validate_email_recipient(addr: &str) -> bool {
    let addr = addr.trim();
    if addr.is_empty() {
        return false;
    }
    if addr.contains(' ') {
        return false;
    }
    addr.contains('@')
}

fn validate_http_method(method: &str) -> bool {
    matches!(
        method.trim().to_uppercase().as_str(),
        "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "HEAD"
    )
}

fn simulate_actions(
    actions: &[WorkflowAction],
    context: &serde_json::Value,
) -> (Vec<WorkflowDryRunAction>, Vec<String>, Vec<String>) {
    let mut out = Vec::new();
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    for (idx, action) in actions.iter().enumerate() {
        let mut action_errors: Vec<String> = Vec::new();
        let mut action_warnings: Vec<String> = Vec::new();
        let preview = match action {
            WorkflowAction::SlackWebhook {
                url,
                channel,
                template,
            } => {
                if reqwest::Url::parse(url).is_err() {
                    action_errors.push(format!("actions[{idx}].url is not a valid URL"));
                }
                if channel.trim().is_empty() {
                    action_errors.push(format!("actions[{idx}].channel is empty"));
                }
                let (text, diag) = render_template(template, context);
                for k in diag.missing_keys {
                    action_warnings.push(format!(
                        "actions[{idx}].template references missing key {k:?}"
                    ));
                }
                for e in diag.errors {
                    action_errors.push(format!("actions[{idx}].template: {e}"));
                }
                serde_json::json!({
                    "kind": "slack_webhook",
                    "url": url,
                    "payload": { "channel": channel, "text": text },
                })
            }
            WorkflowAction::PagerDuty {
                routing_key,
                severity,
            } => {
                if routing_key.trim().is_empty() {
                    action_errors.push(format!("actions[{idx}].routing_key is empty"));
                }
                let sev = severity.trim().to_lowercase();
                if !matches!(sev.as_str(), "critical" | "error" | "warning" | "info") {
                    action_errors.push(format!(
                        "actions[{idx}].severity must be one of critical|error|warning|info"
                    ));
                }
                serde_json::json!({
                    "kind": "pagerduty",
                    "payload": { "routing_key": routing_key, "severity": sev, "event_action": "trigger" },
                })
            }
            WorkflowAction::Email {
                to,
                subject,
                template,
            } => {
                if to.is_empty() {
                    action_errors.push(format!("actions[{idx}].to is empty"));
                } else {
                    for (j, addr) in to.iter().enumerate() {
                        if !validate_email_recipient(addr) {
                            action_errors.push(format!("actions[{idx}].to[{j}] is invalid"));
                        }
                    }
                }
                if subject.trim().is_empty() {
                    action_errors.push(format!("actions[{idx}].subject is empty"));
                }
                let (body, diag) = render_template(template, context);
                for k in diag.missing_keys {
                    action_warnings.push(format!(
                        "actions[{idx}].template references missing key {k:?}"
                    ));
                }
                for e in diag.errors {
                    action_errors.push(format!("actions[{idx}].template: {e}"));
                }
                serde_json::json!({
                    "kind": "email",
                    "to": to,
                    "subject": subject,
                    "body": body,
                })
            }
            WorkflowAction::Webhook {
                url,
                method,
                headers,
                body,
            } => {
                if reqwest::Url::parse(url).is_err() {
                    action_errors.push(format!("actions[{idx}].url is not a valid URL"));
                }
                if !validate_http_method(method) {
                    action_errors.push(format!(
                        "actions[{idx}].method is invalid (expected GET|POST|PUT|PATCH|DELETE|HEAD)"
                    ));
                }
                for (k, v) in headers.iter() {
                    if k.trim().is_empty() {
                        action_errors.push(format!("actions[{idx}].headers has an empty key"));
                        break;
                    }
                    if v.contains('\n') || v.contains('\r') {
                        action_errors
                            .push(format!("actions[{idx}].headers[{k:?}] contains a newline"));
                        break;
                    }
                }
                let (rendered_body, diag) = render_template(body, context);
                for k in diag.missing_keys {
                    action_warnings
                        .push(format!("actions[{idx}].body references missing key {k:?}"));
                }
                for e in diag.errors {
                    action_errors.push(format!("actions[{idx}].body: {e}"));
                }
                serde_json::json!({
                    "kind": "webhook",
                    "url": url,
                    "method": method,
                    "headers": headers,
                    "body": rendered_body,
                })
            }
            WorkflowAction::Log { path, format } => {
                if path.trim().is_empty() {
                    action_errors.push(format!("actions[{idx}].path is empty"));
                }
                let (line, diag) = render_template(format, context);
                for k in diag.missing_keys {
                    action_warnings.push(format!(
                        "actions[{idx}].format references missing key {k:?}"
                    ));
                }
                for e in diag.errors {
                    action_errors.push(format!("actions[{idx}].format: {e}"));
                }
                serde_json::json!({
                    "kind": "log",
                    "path": path,
                    "line": line,
                })
            }
        };

        let ok = action_errors.is_empty();
        if !ok {
            errors.extend(action_errors.clone());
        }
        if !action_warnings.is_empty() {
            warnings.extend(action_warnings.clone());
        }

        out.push(WorkflowDryRunAction {
            index: idx,
            action_type: match action {
                WorkflowAction::SlackWebhook { .. } => "slack_webhook",
                WorkflowAction::PagerDuty { .. } => "pagerduty",
                WorkflowAction::Email { .. } => "email",
                WorkflowAction::Webhook { .. } => "webhook",
                WorkflowAction::Log { .. } => "log",
            }
            .to_string(),
            ok,
            preview,
            errors: action_errors,
            warnings: action_warnings,
        });
    }

    (out, errors, warnings)
}

/// List all workflows
#[tauri::command]
pub async fn list_workflows() -> Result<Vec<Workflow>, String> {
    let workflows = get_workflows().read().await;
    Ok(workflows.values().cloned().collect())
}

/// Save a workflow (create or update)
#[tauri::command]
pub async fn save_workflow(workflow: Workflow) -> Result<(), String> {
    let mut workflows = get_workflows().write().await;
    workflows.insert(workflow.id.clone(), workflow);
    save_workflows_to_file(&workflows)
}

/// Delete a workflow
#[tauri::command]
pub async fn delete_workflow(workflow_id: String) -> Result<(), String> {
    let mut workflows = get_workflows().write().await;
    workflows.remove(&workflow_id);
    save_workflows_to_file(&workflows)
}

/// Test a workflow (dry run)
#[tauri::command]
pub async fn test_workflow(
    workflow_id: String,
    _state: State<'_, AppState>,
) -> Result<TestResult, String> {
    let workflows = get_workflows().read().await;

    let workflow = workflows
        .get(&workflow_id)
        .ok_or_else(|| format!("Workflow not found: {}", workflow_id))?;

    let event = synthetic_event();
    let context = build_context(event);

    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    errors.extend(validate_trigger(&workflow.trigger));

    if workflow.actions.is_empty() {
        errors.push("Workflow has no actions configured".to_string());
    }

    let (action_reports, action_errors, action_warnings) =
        simulate_actions(&workflow.actions, &context);
    errors.extend(action_errors);
    warnings.extend(action_warnings);

    let success = errors.is_empty();
    let message = if success {
        if warnings.is_empty() {
            Some(format!(
                "Dry run OK: workflow '{}' with {} action(s)",
                workflow.name,
                workflow.actions.len()
            ))
        } else {
            let max = 5usize;
            let summary: Vec<String> = warnings.iter().take(max).cloned().collect();
            Some(format!(
                "Dry run OK with {} warning(s): {}{}",
                warnings.len(),
                summary.join("; "),
                if warnings.len() > max { "; ..." } else { "" }
            ))
        }
    } else {
        let max = 5usize;
        let summary: Vec<String> = errors.iter().take(max).cloned().collect();
        Some(format!(
            "Dry run failed ({} error(s)): {}{}",
            errors.len(),
            summary.join("; "),
            if errors.len() > max { "; ..." } else { "" }
        ))
    };

    Ok(TestResult {
        success,
        message,
        report: Some(WorkflowDryRunReport {
            workflow_id: workflow.id.clone(),
            workflow_name: workflow.name.clone(),
            context,
            actions: action_reports,
            errors,
            warnings,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_template_replaces_nested_paths() {
        let data = serde_json::json!({ "a": { "b": "c" }, "n": 1 });
        let (out, diag) = render_template("x={{a.b}} n={{n}} missing={{nope}}", &data);
        assert_eq!(out, "x=c n=1 missing=");
        assert_eq!(diag.missing_keys, vec!["nope"]);
        assert!(diag.errors.is_empty());
    }

    #[test]
    fn parse_window_accepts_units() {
        assert_eq!(parse_window("5m").unwrap(), (5, 'm'));
        assert_eq!(parse_window("1h").unwrap(), (1, 'h'));
        assert!(parse_window("0m").is_err());
        assert!(parse_window("5w").is_err());
        assert!(parse_window("m").is_err());
    }

    #[test]
    fn migrate_legacy_workflows_dir_moves_file_and_cleans_up() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let base = tmp.path();
        let legacy_dir = base.join(LEGACY_APP_DATA_DIR);
        std::fs::create_dir_all(&legacy_dir).expect("create legacy dir");
        let legacy_file = legacy_dir.join(WORKFLOWS_FILENAME);
        let payload = r#"{"wf1":{"id":"wf1","name":"n","enabled":true,"trigger":{"type":"event_match","conditions":[]},"actions":[],"last_run":null,"run_count":0,"created_at":"2026-05-23T00:00:00Z"}}"#;
        std::fs::write(&legacy_file, payload).expect("write legacy payload");

        let loaded = load_workflows_from_dir(base).expect("loaded workflows");
        assert!(loaded.contains_key("wf1"));

        let new_file = base.join(APP_DATA_DIR).join(WORKFLOWS_FILENAME);
        assert!(new_file.exists(), "new path should hold the migrated file");
        assert!(!legacy_file.exists(), "legacy file should be gone");
        assert!(
            !legacy_dir.exists(),
            "empty legacy directory should be removed"
        );
    }

    #[test]
    fn migrate_legacy_workflows_dir_skips_when_new_path_exists() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        let base = tmp.path();
        let legacy_dir = base.join(LEGACY_APP_DATA_DIR);
        let new_dir = base.join(APP_DATA_DIR);
        std::fs::create_dir_all(&legacy_dir).expect("legacy dir");
        std::fs::create_dir_all(&new_dir).expect("new dir");
        std::fs::write(legacy_dir.join(WORKFLOWS_FILENAME), "{\"legacy\":true}")
            .expect("legacy file");
        std::fs::write(new_dir.join(WORKFLOWS_FILENAME), "{}").expect("new file");

        migrate_legacy_workflows_dir(base);

        assert!(
            legacy_dir.join(WORKFLOWS_FILENAME).exists(),
            "legacy file must not be touched once the new path is populated"
        );
        let contents =
            std::fs::read_to_string(new_dir.join(WORKFLOWS_FILENAME)).expect("read new");
        assert_eq!(contents, "{}", "existing new file must not be overwritten");
    }

    #[test]
    fn migrate_legacy_workflows_dir_is_noop_without_legacy() {
        let tmp = tempfile::tempdir().expect("create tempdir");
        migrate_legacy_workflows_dir(tmp.path());
        assert!(!tmp.path().join(APP_DATA_DIR).exists());
        assert!(!tmp.path().join(LEGACY_APP_DATA_DIR).exists());
    }

    #[test]
    fn simulate_actions_validates_urls_and_methods() {
        let ctx = serde_json::json!({ "target": "t", "event": {} });
        let actions = vec![
            WorkflowAction::SlackWebhook {
                url: "not-a-url".to_string(),
                channel: "".to_string(),
                template: "hi {{target}}".to_string(),
            },
            WorkflowAction::Webhook {
                url: "http://example.com".to_string(),
                method: "NOPE".to_string(),
                headers: HashMap::new(),
                body: "x".to_string(),
            },
        ];

        let (_reports, errors, warnings) = simulate_actions(&actions, &ctx);
        assert!(!errors.is_empty());
        assert!(warnings.is_empty());
        assert!(errors.iter().any(|e| e.contains("url")));
        assert!(errors.iter().any(|e| e.contains("method")));
    }
}
