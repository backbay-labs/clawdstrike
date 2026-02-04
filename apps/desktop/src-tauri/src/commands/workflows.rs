//! Workflow management commands

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

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
    PagerDuty { routing_key: String, severity: String },
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
}

// In-memory workflow storage (persisted to file)
static WORKFLOWS: OnceLock<RwLock<HashMap<String, Workflow>>> = OnceLock::new();

fn get_workflows() -> &'static RwLock<HashMap<String, Workflow>> {
    WORKFLOWS.get_or_init(|| {
        let workflows = load_workflows_from_file().unwrap_or_default();
        RwLock::new(workflows)
    })
}

fn get_workflows_file_path() -> PathBuf {
    let app_data = dirs::data_local_dir().unwrap_or_else(|| PathBuf::from("."));
    app_data.join("sdr-desktop").join("workflows.json")
}

fn load_workflows_from_file() -> Option<HashMap<String, Workflow>> {
    let path = get_workflows_file_path();
    if !path.exists() {
        return None;
    }

    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str(&content).ok()
}

fn save_workflows_to_file(workflows: &HashMap<String, Workflow>) -> Result<(), String> {
    let path = get_workflows_file_path();

    // Ensure parent directory exists
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory: {}", e))?;
    }

    let content =
        serde_json::to_string_pretty(workflows).map_err(|e| format!("Failed to serialize: {}", e))?;

    std::fs::write(&path, content).map_err(|e| format!("Failed to write file: {}", e))
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
pub async fn test_workflow(workflow_id: String) -> Result<TestResult, String> {
    let workflows = get_workflows().read().await;

    let workflow = workflows
        .get(&workflow_id)
        .ok_or_else(|| format!("Workflow not found: {}", workflow_id))?;

    // TODO: Implement actual workflow testing
    // For now, just validate the workflow structure

    if workflow.actions.is_empty() {
        return Ok(TestResult {
            success: false,
            message: Some("Workflow has no actions configured".to_string()),
        });
    }

    Ok(TestResult {
        success: true,
        message: Some(format!(
            "Workflow '{}' validated successfully with {} action(s)",
            workflow.name,
            workflow.actions.len()
        )),
    })
}
