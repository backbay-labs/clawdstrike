//! Workspace-shell command adapters for trusted roots and filesystem contracts.

use huntronomer_workspace_core::{
    CreatePathKind, DeleteResult, FsService, MoveResult, WorkspaceEntry, WorkspaceFile,
    WorkspaceRoot, WorkspaceService, WorkspaceSettingsStore, WriteResult,
};
use serde::{Deserialize, Serialize};
use tauri::State;
use tokio::sync::RwLock;

pub struct WorkspaceCommandState {
    workspace: RwLock<WorkspaceService>,
    fs: FsService,
}

impl WorkspaceCommandState {
    pub fn new(settings_path: impl Into<std::path::PathBuf>) -> Result<Self, String> {
        let workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))
            .map_err(|error| error.to_string())?;
        Ok(Self {
            workspace: RwLock::new(workspace),
            fs: FsService,
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
