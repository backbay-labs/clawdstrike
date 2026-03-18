//! Workspace-shell command adapters for trusted roots and filesystem contracts.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use huntronomer_workspace_core::{
    search::SearchEventPayload, CreatePathKind, DeleteResult, FsService, MoveResult,
    SearchService, WorkspaceEntry, WorkspaceEntryKind, WorkspaceFile, WorkspaceRoot,
    WorkspaceService, WorkspaceSettingsStore, WriteResult,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::RwLock;

pub struct WorkspaceCommandState {
    workspace: RwLock<WorkspaceService>,
    fs: FsService,
    search: SearchService,
}

impl WorkspaceCommandState {
    pub fn new(settings_path: impl Into<PathBuf>) -> Result<Self, String> {
        let workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            workspace: RwLock::new(workspace),
            fs: FsService,
            search: SearchService::default(),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePathRequest {
    pub root_id: String,
    pub relative_path: String,
    pub kind: CreatePathKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MovePathRequest {
    pub root_id: String,
    pub from_relative_path: String,
    pub to_relative_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspacePathSearchMatchPayload {
    pub root_id: String,
    pub relative_path: String,
    pub name: String,
    pub kind: WorkspaceEntryKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceContentSearchMatchPayload {
    pub root_id: String,
    pub relative_path: String,
    pub line_number: u64,
    pub column: u64,
    pub line_text: String,
    pub preview: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceGitFileStatusPayload {
    pub root_id: String,
    pub relative_path: String,
    pub staged_status: String,
    pub unstaged_status: String,
    pub additions: u64,
    pub deletions: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceGitStatusSummaryPayload {
    pub root_id: String,
    pub branch: String,
    pub ahead: u64,
    pub behind: u64,
    pub staged_count: usize,
    pub unstaged_count: usize,
    pub untracked_count: usize,
    pub changed_files: Vec<WorkspaceGitFileStatusPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceGitDiffSummaryPayload {
    pub root_id: String,
    pub relative_path: Option<String>,
    pub file_count: usize,
    pub additions: u64,
    pub deletions: u64,
    pub preview_lines: Vec<String>,
}

#[tauri::command]
pub async fn workspace_register_root(
    state: State<'_, WorkspaceCommandState>,
    path: String,
) -> Result<WorkspaceRoot, String> {
    state
        .workspace
        .write()
        .await
        .register_root(path)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn workspace_remove_root(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
) -> Result<Option<WorkspaceRoot>, String> {
    state
        .workspace
        .write()
        .await
        .remove_root(&root_id)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn workspace_list_recent_roots(
    state: State<'_, WorkspaceCommandState>,
) -> Result<Vec<WorkspaceRoot>, String> {
    Ok(state.workspace.read().await.list_recent_roots())
}

#[tauri::command]
pub async fn workspace_list_dir(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
    relative_path: String,
) -> Result<Vec<WorkspaceEntry>, String> {
    let workspace = state.workspace.read().await;
    state
        .fs
        .list_dir(&workspace, &root_id, &relative_path)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn workspace_stat_path(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
    relative_path: String,
) -> Result<WorkspaceEntry, String> {
    let workspace = state.workspace.read().await;
    state
        .fs
        .stat_path(&workspace, &root_id, &relative_path)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn workspace_read_file(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
    relative_path: String,
) -> Result<WorkspaceFile, String> {
    let workspace = state.workspace.read().await;
    state
        .fs
        .read_file(&workspace, &root_id, &relative_path)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn workspace_write_file(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
    relative_path: String,
    contents: String,
) -> Result<WriteResult, String> {
    let workspace = state.workspace.read().await;
    state
        .fs
        .write_file(&workspace, &root_id, &relative_path, &contents)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn workspace_create_path(
    state: State<'_, WorkspaceCommandState>,
    request: CreatePathRequest,
) -> Result<WorkspaceEntry, String> {
    let workspace = state.workspace.read().await;
    state
        .fs
        .create_path(
            &workspace,
            &request.root_id,
            &request.relative_path,
            request.kind,
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn workspace_move_path(
    state: State<'_, WorkspaceCommandState>,
    request: MovePathRequest,
) -> Result<MoveResult, String> {
    let workspace = state.workspace.read().await;
    state
        .fs
        .move_path(
            &workspace,
            &request.root_id,
            &request.from_relative_path,
            &request.to_relative_path,
        )
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn workspace_delete_path(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
    relative_path: String,
) -> Result<DeleteResult, String> {
    let workspace = state.workspace.read().await;
    state
        .fs
        .delete_path(&workspace, &root_id, &relative_path)
        .map_err(|error| error.to_string())
}

#[tauri::command]
pub async fn workspace_search_paths(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
    query: String,
) -> Result<Vec<WorkspacePathSearchMatchPayload>, String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let job = {
        let workspace = state.workspace.read().await;
        state
            .search
            .start_path_search(&workspace, &root_id, trimmed)
            .map_err(|error| error.to_string())?
    };
    let events = state
        .search
        .wait_for_job(&job.job_id)
        .map_err(|error| error.to_string())?;
    let workspace = state.workspace.read().await;

    events
        .into_iter()
        .filter_map(|event| match event.payload {
            SearchEventPayload::PathMatch(found) => Some(found),
            _ => None,
        })
        .map(|found| {
            let canonical = workspace
                .resolve_existing_path(&root_id, &found.relative_path)
                .map_err(|error| error.to_string())?;
            let metadata = std::fs::metadata(&canonical).map_err(|error| error.to_string())?;
            let name = Path::new(&found.relative_path)
                .file_name()
                .map(|segment| segment.to_string_lossy().to_string())
                .unwrap_or_else(|| found.relative_path.clone());

            Ok(WorkspacePathSearchMatchPayload {
                root_id: root_id.clone(),
                relative_path: found.relative_path,
                name,
                kind: if metadata.is_dir() {
                    WorkspaceEntryKind::Directory
                } else {
                    WorkspaceEntryKind::File
                },
            })
        })
        .collect()
}

#[tauri::command]
pub async fn workspace_search_content(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
    query: String,
) -> Result<Vec<WorkspaceContentSearchMatchPayload>, String> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }

    let job = {
        let workspace = state.workspace.read().await;
        state
            .search
            .start_content_search(&workspace, &root_id, trimmed, &[])
            .map_err(|error| error.to_string())?
    };
    let events = state
        .search
        .wait_for_job(&job.job_id)
        .map_err(|error| error.to_string())?;

    Ok(events
        .into_iter()
        .filter_map(|event| match event.payload {
            SearchEventPayload::ContentMatch(found) => Some(found),
            _ => None,
        })
        .map(|found| WorkspaceContentSearchMatchPayload {
            root_id: root_id.clone(),
            relative_path: found.relative_path,
            line_number: found.line_number,
            column: found.column,
            line_text: found.preview.clone(),
            preview: found.preview,
        })
        .collect())
}

#[tauri::command]
pub async fn workspace_git_status(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
) -> Result<WorkspaceGitStatusSummaryPayload, String> {
    let root_path = {
        let workspace = state.workspace.read().await;
        root_path_for(&workspace, &root_id)?
    };

    build_git_status_summary(&root_id, &root_path)
}

#[tauri::command]
pub async fn workspace_git_diff_summary(
    state: State<'_, WorkspaceCommandState>,
    root_id: String,
    relative_path: Option<String>,
) -> Result<WorkspaceGitDiffSummaryPayload, String> {
    let root_path = {
        let workspace = state.workspace.read().await;
        root_path_for(&workspace, &root_id)?
    };
    let status = build_git_status_summary(&root_id, &root_path)?;
    let target_path = relative_path.filter(|value| !value.trim().is_empty());
    let changed_files: Vec<_> = match target_path.as_deref() {
        Some(path) => status
            .changed_files
            .iter()
            .filter(|file| file.relative_path == path)
            .cloned()
            .collect(),
        None => status.changed_files.clone(),
    };

    let additions = changed_files.iter().map(|file| file.additions).sum();
    let deletions = changed_files.iter().map(|file| file.deletions).sum();
    let preview_lines = changed_files
        .iter()
        .map(|file| {
            format!(
                "{} | {} / {} | +{} -{}",
                file.relative_path,
                display_git_status(&file.staged_status),
                display_git_status(&file.unstaged_status),
                file.additions,
                file.deletions
            )
        })
        .collect();

    Ok(WorkspaceGitDiffSummaryPayload {
        root_id,
        relative_path: target_path,
        file_count: changed_files.len(),
        additions,
        deletions,
        preview_lines,
    })
}

fn root_path_for(workspace: &WorkspaceService, root_id: &str) -> Result<PathBuf, String> {
    workspace
        .root_metadata(root_id)
        .map(|root| PathBuf::from(root.canonical_path))
        .map_err(|error| error.to_string())
}

fn build_git_status_summary(
    root_id: &str,
    root_path: &Path,
) -> Result<WorkspaceGitStatusSummaryPayload, String> {
    let status_output = run_git(root_path, &["status", "--porcelain=1", "--branch"])?;
    let numstats = collect_git_numstats(root_path)?;
    let mut lines = status_output.lines();
    let branch_line = lines.next().unwrap_or("## detached");
    let (branch, ahead, behind) = parse_branch_summary(branch_line);
    let mut changed_files = Vec::new();
    let mut staged_count = 0usize;
    let mut unstaged_count = 0usize;
    let mut untracked_count = 0usize;

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let Some((staged_status, unstaged_status, relative_path)) = parse_git_status_line(line) else {
            continue;
        };
        if staged_status != ' ' && staged_status != '?' {
            staged_count += 1;
        }
        if unstaged_status != ' ' && unstaged_status != '?' {
            unstaged_count += 1;
        }
        if staged_status == '?' && unstaged_status == '?' {
            untracked_count += 1;
        }
        let (additions, deletions) = numstats
            .get(&relative_path)
            .copied()
            .unwrap_or((0, 0));
        changed_files.push(WorkspaceGitFileStatusPayload {
            root_id: root_id.to_string(),
            relative_path,
            staged_status: staged_status.to_string(),
            unstaged_status: unstaged_status.to_string(),
            additions,
            deletions,
        });
    }

    Ok(WorkspaceGitStatusSummaryPayload {
        root_id: root_id.to_string(),
        branch,
        ahead,
        behind,
        staged_count,
        unstaged_count,
        untracked_count,
        changed_files,
    })
}

fn run_git(root_path: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(root_path)
        .args(args)
        .output()
        .map_err(|error| format!("git {} failed: {error}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(if stderr.is_empty() {
            if stdout.is_empty() {
                format!("git {} failed with status {:?}", args.join(" "), output.status.code())
            } else {
                stdout
            }
        } else {
            stderr
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn collect_git_numstats(root_path: &Path) -> Result<BTreeMap<String, (u64, u64)>, String> {
    let mut by_path = BTreeMap::new();
    for args in [
        vec!["diff", "--numstat"],
        vec!["diff", "--numstat", "--cached"],
    ] {
        let output = run_git(root_path, &args)?;
        for line in output.lines() {
            let Some((relative_path, additions, deletions)) = parse_git_numstat_line(line) else {
                continue;
            };
            let entry = by_path.entry(relative_path).or_insert((0, 0));
            entry.0 += additions;
            entry.1 += deletions;
        }
    }
    Ok(by_path)
}

fn parse_git_numstat_line(line: &str) -> Option<(String, u64, u64)> {
    let mut parts = line.split('\t');
    let additions = parts.next()?;
    let deletions = parts.next()?;
    let relative_path = parts.next()?.trim();
    if relative_path.is_empty() {
        return None;
    }
    Some((
        relative_path
            .rsplit_once(" -> ")
            .map(|(_, target)| target.to_string())
            .unwrap_or_else(|| relative_path.to_string()),
        additions.parse().unwrap_or(0),
        deletions.parse().unwrap_or(0),
    ))
}

fn parse_branch_summary(line: &str) -> (String, u64, u64) {
    let body = line.strip_prefix("## ").unwrap_or(line).trim();
    let branch = body
        .split(" [")
        .next()
        .unwrap_or(body)
        .split("...")
        .next()
        .unwrap_or(body)
        .trim()
        .to_string();
    let mut ahead = 0;
    let mut behind = 0;
    if let Some(summary) = body
        .split(" [")
        .nth(1)
        .and_then(|value| value.strip_suffix(']'))
    {
        for part in summary.split(',') {
            let candidate = part.trim();
            if let Some(value) = candidate.strip_prefix("ahead ") {
                ahead = value.parse().unwrap_or(0);
            } else if let Some(value) = candidate.strip_prefix("behind ") {
                behind = value.parse().unwrap_or(0);
            }
        }
    }
    (branch, ahead, behind)
}

fn parse_git_status_line(line: &str) -> Option<(char, char, String)> {
    let mut chars = line.chars();
    let staged_status = chars.next()?;
    let unstaged_status = chars.next()?;
    let relative_path = line
        .get(3..)?
        .trim()
        .rsplit_once(" -> ")
        .map(|(_, target)| target.to_string())
        .unwrap_or_else(|| line.get(3..).unwrap_or_default().trim().to_string());
    if relative_path.is_empty() {
        return None;
    }
    Some((staged_status, unstaged_status, relative_path))
}

fn display_git_status(status: &str) -> &str {
    if status.trim().is_empty() { "·" } else { status }
}
