use std::fs;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Runtime};
use tauri_plugin_opener::OpenerExt;

use super::persistence::persistence_root;
use super::workspace_registry::{PersistedWorkspaceRegistry, WORKSPACE_REGISTRY_FILE};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceEntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceCommandErrorCode {
    UnknownRoot,
    PathEscape,
    NotFound,
    SymlinkDenied,
    UnsupportedKind,
    IoError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTreeEntry {
    pub path: String,
    pub kind: WorkspaceEntryKind,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceCommandError {
    pub code: WorkspaceCommandErrorCode,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceCommandSuccess<T> {
    pub ok: bool,
    pub data: T,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceCommandFailure {
    pub ok: bool,
    pub error: WorkspaceCommandError,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum WorkspaceCommandResult<T> {
    Success(WorkspaceCommandSuccess<T>),
    Failure(WorkspaceCommandFailure),
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReadWorkspaceTreeResponse {
    pub entries: Vec<WorkspaceTreeEntry>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkspaceDirectoryResponse {
    pub relative_path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RenameWorkspaceEntryResponse {
    pub old_relative_path: String,
    pub new_relative_path: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DeleteWorkspaceEntryResponse {
    pub relative_path: String,
    pub kind: WorkspaceEntryKind,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RevealWorkspaceEntryResponse {
    pub relative_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReadWorkspaceTreeRequest {
    pub root_id: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkspaceDirectoryRequest {
    pub root_id: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RenameWorkspaceEntryRequest {
    pub root_id: String,
    pub old_relative_path: String,
    pub new_relative_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteWorkspaceEntryRequest {
    pub root_id: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealWorkspaceEntryRequest {
    pub root_id: String,
    pub relative_path: String,
}

fn ok<T>(data: T) -> WorkspaceCommandResult<T> {
    WorkspaceCommandResult::Success(WorkspaceCommandSuccess { ok: true, data })
}

fn fail<T>(
    code: WorkspaceCommandErrorCode,
    message: impl Into<String>,
    path: Option<String>,
) -> WorkspaceCommandResult<T> {
    WorkspaceCommandResult::Failure(WorkspaceCommandFailure {
        ok: false,
        error: WorkspaceCommandError {
            code,
            message: message.into(),
            path,
        },
    })
}

fn make_error(
    code: WorkspaceCommandErrorCode,
    message: impl Into<String>,
    path: Option<String>,
) -> WorkspaceCommandError {
    WorkspaceCommandError {
        code,
        message: message.into(),
        path,
    }
}

fn emit_workspace_fs_diagnostic(event: &str, payload: serde_json::Value) {
    eprintln!(
        "[workspace-fs] {}",
        json!({
            "event": event,
            "payload": payload,
        })
    );
}

fn workspace_result_payload<T>(result: &WorkspaceCommandResult<T>) -> serde_json::Value {
    match result {
        WorkspaceCommandResult::Success(_) => json!({
            "ok": true,
        }),
        WorkspaceCommandResult::Failure(failure) => json!({
            "ok": false,
            "error": failure.error,
        }),
    }
}

fn workspace_registry_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    Ok(persistence_root(app)?.join(WORKSPACE_REGISTRY_FILE))
}

fn load_workspace_registry(path: &Path) -> Result<PersistedWorkspaceRegistry, String> {
    if !path.exists() {
        return Ok(PersistedWorkspaceRegistry::default());
    }

    let raw = fs::read_to_string(path)
        .map_err(|e| format!("Failed to read workspace registry {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("Failed to parse workspace registry {}: {e}", path.display()))
}

fn sanitize_display_path(path: &Path) -> String {
    let raw = path.to_string_lossy().replace('\\', "/");
    raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_string()
}

fn sanitize_relative_path(path: &Path) -> String {
    sanitize_display_path(path)
        .trim_start_matches('/')
        .to_string()
}

fn resolve_workspace_root_path(
    registry_file: &Path,
    root_id: &str,
) -> Result<PathBuf, WorkspaceCommandError> {
    let registry = load_workspace_registry(registry_file)
        .map_err(|message| make_error(WorkspaceCommandErrorCode::IoError, message, None))?;

    let Some(root) = registry.roots.iter().find(|root| root.root_id == root_id) else {
        return Err(make_error(
            WorkspaceCommandErrorCode::UnknownRoot,
            format!("Unknown workspace root: {root_id}"),
            None,
        ));
    };

    let root_path = PathBuf::from(&root.canonical_path);
    let metadata = fs::symlink_metadata(&root_path).map_err(|_| {
        make_error(
            WorkspaceCommandErrorCode::NotFound,
            format!("Workspace root is missing: {}", root_path.display()),
            Some(root.canonical_path.clone()),
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(make_error(
            WorkspaceCommandErrorCode::SymlinkDenied,
            format!("Workspace root is symlinked: {}", root_path.display()),
            Some(root.canonical_path.clone()),
        ));
    }
    if !metadata.is_dir() {
        return Err(make_error(
            WorkspaceCommandErrorCode::UnsupportedKind,
            format!("Workspace root is not a directory: {}", root_path.display()),
            Some(root.canonical_path.clone()),
        ));
    }

    Ok(root_path)
}

fn validate_relative_path(path: &str, allow_empty: bool) -> Result<PathBuf, WorkspaceCommandError> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        if allow_empty {
            return Ok(PathBuf::new());
        }
        return Err(make_error(
            WorkspaceCommandErrorCode::PathEscape,
            "Workspace relative path must not be empty",
            Some(path.to_string()),
        ));
    }

    let candidate = Path::new(trimmed);
    if candidate.is_absolute() {
        return Err(make_error(
            WorkspaceCommandErrorCode::PathEscape,
            "Workspace relative path must not be absolute",
            Some(trimmed.to_string()),
        ));
    }

    let mut normalized = PathBuf::new();
    for component in candidate.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => continue,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(make_error(
                    WorkspaceCommandErrorCode::PathEscape,
                    "Workspace relative path cannot escape the mounted root",
                    Some(trimmed.to_string()),
                ));
            }
        }
    }

    if normalized.as_os_str().is_empty() && !allow_empty {
        return Err(make_error(
            WorkspaceCommandErrorCode::PathEscape,
            "Workspace relative path must not be empty",
            Some(trimmed.to_string()),
        ));
    }

    Ok(normalized)
}

fn resolve_workspace_entry_path(
    root_path: &Path,
    relative_path: &str,
    allow_missing_leaf: bool,
) -> Result<PathBuf, WorkspaceCommandError> {
    let normalized_relative = validate_relative_path(relative_path, false)?;
    let mut current = root_path.to_path_buf();
    let components: Vec<_> = normalized_relative.components().collect();

    for (index, component) in components.iter().enumerate() {
        let Component::Normal(part) = component else {
            return Err(make_error(
                WorkspaceCommandErrorCode::PathEscape,
                "Workspace relative path cannot escape the mounted root",
                Some(relative_path.to_string()),
            ));
        };

        let next = current.join(part);
        let is_last = index == components.len() - 1;

        match fs::symlink_metadata(&next) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(make_error(
                        WorkspaceCommandErrorCode::SymlinkDenied,
                        format!(
                            "Refusing to access symlinked workspace entry {}",
                            next.display()
                        ),
                        Some(relative_path.to_string()),
                    ));
                }
                if is_last {
                    return Ok(next);
                }
                if !metadata.is_dir() {
                    return Err(make_error(
                        WorkspaceCommandErrorCode::UnsupportedKind,
                        format!(
                            "Intermediate workspace path is not a directory: {}",
                            next.display()
                        ),
                        Some(relative_path.to_string()),
                    ));
                }
                current = next;
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound && allow_missing_leaf && is_last =>
            {
                return Ok(next);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(make_error(
                    WorkspaceCommandErrorCode::NotFound,
                    format!("Workspace entry not found: {}", next.display()),
                    Some(relative_path.to_string()),
                ));
            }
            Err(err) => {
                return Err(make_error(
                    WorkspaceCommandErrorCode::IoError,
                    format!(
                        "Failed to inspect workspace entry {}: {err}",
                        next.display()
                    ),
                    Some(relative_path.to_string()),
                ));
            }
        }
    }

    Ok(current)
}

fn classify_entry(path: &Path) -> Result<WorkspaceEntryKind, WorkspaceCommandError> {
    let metadata = fs::symlink_metadata(path).map_err(|e| {
        make_error(
            WorkspaceCommandErrorCode::IoError,
            format!("Failed to inspect workspace entry {}: {e}", path.display()),
            Some(sanitize_display_path(path)),
        )
    })?;

    if metadata.file_type().is_symlink() {
        return Err(make_error(
            WorkspaceCommandErrorCode::SymlinkDenied,
            format!(
                "Refusing to access symlinked workspace entry {}",
                path.display()
            ),
            Some(sanitize_display_path(path)),
        ));
    }

    if metadata.is_dir() {
        return Ok(WorkspaceEntryKind::Directory);
    }
    if metadata.is_file() {
        return Ok(WorkspaceEntryKind::File);
    }

    Err(make_error(
        WorkspaceCommandErrorCode::UnsupportedKind,
        format!("Unsupported workspace entry kind {}", path.display()),
        Some(sanitize_display_path(path)),
    ))
}

fn collect_workspace_tree_entries(
    root_path: &Path,
    current_dir: &Path,
    entries: &mut Vec<WorkspaceTreeEntry>,
) -> Result<(), WorkspaceCommandError> {
    let dir_entries = fs::read_dir(current_dir).map_err(|e| {
        make_error(
            WorkspaceCommandErrorCode::IoError,
            format!(
                "Failed to read workspace directory {}: {e}",
                current_dir.display()
            ),
            Some(sanitize_display_path(current_dir)),
        )
    })?;

    for entry in dir_entries {
        let entry = entry.map_err(|e| {
            make_error(
                WorkspaceCommandErrorCode::IoError,
                format!(
                    "Failed to enumerate workspace directory {}: {e}",
                    current_dir.display()
                ),
                Some(sanitize_display_path(current_dir)),
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|e| {
            make_error(
                WorkspaceCommandErrorCode::IoError,
                format!("Failed to inspect workspace entry {}: {e}", path.display()),
                Some(sanitize_display_path(&path)),
            )
        })?;

        if file_type.is_symlink() {
            continue;
        }

        let relative_path = path
            .strip_prefix(root_path)
            .map(sanitize_relative_path)
            .map_err(|_| {
                make_error(
                    WorkspaceCommandErrorCode::IoError,
                    format!("Failed to relativize workspace entry {}", path.display()),
                    Some(sanitize_display_path(&path)),
                )
            })?;

        if file_type.is_dir() {
            if path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".swarm"))
            {
                entries.push(WorkspaceTreeEntry {
                    path: relative_path,
                    kind: WorkspaceEntryKind::File,
                });
                continue;
            }

            entries.push(WorkspaceTreeEntry {
                path: relative_path,
                kind: WorkspaceEntryKind::Directory,
            });
            collect_workspace_tree_entries(root_path, &path, entries)?;
        } else if file_type.is_file() {
            entries.push(WorkspaceTreeEntry {
                path: relative_path,
                kind: WorkspaceEntryKind::File,
            });
        }
    }

    Ok(())
}

fn read_workspace_tree_at(
    registry_file: &Path,
    root_id: &str,
) -> WorkspaceCommandResult<ReadWorkspaceTreeResponse> {
    let root_path = match resolve_workspace_root_path(registry_file, root_id) {
        Ok(root_path) => root_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };

    let mut entries = Vec::new();
    if let Err(error) = collect_workspace_tree_entries(&root_path, &root_path, &mut entries) {
        return fail(error.code, error.message, error.path);
    }

    ok(ReadWorkspaceTreeResponse { entries })
}

fn create_workspace_directory_at(
    registry_file: &Path,
    root_id: &str,
    relative_path: &str,
) -> WorkspaceCommandResult<CreateWorkspaceDirectoryResponse> {
    let root_path = match resolve_workspace_root_path(registry_file, root_id) {
        Ok(root_path) => root_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    let target_path = match resolve_workspace_entry_path(&root_path, relative_path, true) {
        Ok(target_path) => target_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };

    if let Err(err) = fs::create_dir_all(&target_path) {
        return fail(
            WorkspaceCommandErrorCode::IoError,
            format!(
                "Failed to create workspace directory {}: {err}",
                target_path.display()
            ),
            Some(relative_path.to_string()),
        );
    }

    ok(CreateWorkspaceDirectoryResponse {
        relative_path: relative_path.replace('\\', "/"),
    })
}

fn rename_workspace_entry_at(
    registry_file: &Path,
    root_id: &str,
    old_relative_path: &str,
    new_relative_path: &str,
) -> WorkspaceCommandResult<RenameWorkspaceEntryResponse> {
    let root_path = match resolve_workspace_root_path(registry_file, root_id) {
        Ok(root_path) => root_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    let source_path = match resolve_workspace_entry_path(&root_path, old_relative_path, false) {
        Ok(source_path) => source_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    let target_path = match resolve_workspace_entry_path(&root_path, new_relative_path, true) {
        Ok(target_path) => target_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };

    if let Some(parent) = target_path.parent() {
        if !parent.exists() {
            return fail(
                WorkspaceCommandErrorCode::NotFound,
                format!(
                    "Workspace destination parent is missing: {}",
                    parent.display()
                ),
                Some(new_relative_path.to_string()),
            );
        }
    }

    if let Err(err) = fs::rename(&source_path, &target_path) {
        return fail(
            WorkspaceCommandErrorCode::IoError,
            format!(
                "Failed to rename workspace entry {} -> {}: {err}",
                source_path.display(),
                target_path.display()
            ),
            Some(old_relative_path.to_string()),
        );
    }

    ok(RenameWorkspaceEntryResponse {
        old_relative_path: old_relative_path.replace('\\', "/"),
        new_relative_path: new_relative_path.replace('\\', "/"),
    })
}

fn delete_workspace_entry_at(
    registry_file: &Path,
    root_id: &str,
    relative_path: &str,
) -> WorkspaceCommandResult<DeleteWorkspaceEntryResponse> {
    let root_path = match resolve_workspace_root_path(registry_file, root_id) {
        Ok(root_path) => root_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    let target_path = match resolve_workspace_entry_path(&root_path, relative_path, false) {
        Ok(target_path) => target_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    let kind = match classify_entry(&target_path) {
        Ok(kind) => kind,
        Err(error) => return fail(error.code, error.message, error.path),
    };

    let removal_result = match kind {
        WorkspaceEntryKind::File => fs::remove_file(&target_path),
        WorkspaceEntryKind::Directory => fs::remove_dir_all(&target_path),
    };
    if let Err(err) = removal_result {
        return fail(
            WorkspaceCommandErrorCode::IoError,
            format!(
                "Failed to delete workspace entry {}: {err}",
                target_path.display()
            ),
            Some(relative_path.to_string()),
        );
    }

    ok(DeleteWorkspaceEntryResponse {
        relative_path: relative_path.replace('\\', "/"),
        kind,
    })
}

fn resolve_workspace_entry_for_reveal_at(
    registry_file: &Path,
    root_id: &str,
    relative_path: &str,
) -> Result<PathBuf, WorkspaceCommandError> {
    let root_path = resolve_workspace_root_path(registry_file, root_id)?;
    resolve_workspace_entry_path(&root_path, relative_path, false)
}

#[tauri::command]
pub async fn read_workspace_tree<R: Runtime>(
    app: AppHandle<R>,
    request: ReadWorkspaceTreeRequest,
) -> Result<WorkspaceCommandResult<ReadWorkspaceTreeResponse>, String> {
    let registry_file = workspace_registry_path(&app)?;
    let root_id = request.root_id.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        read_workspace_tree_at(&registry_file, &root_id)
    })
    .await
    .map_err(|e| format!("Workspace tree read task failed: {e}"))?;
    emit_workspace_fs_diagnostic(
        "read_workspace_tree",
        json!({
            "rootId": request.root_id,
            "result": workspace_result_payload(&result),
        }),
    );
    Ok(result)
}

#[tauri::command]
pub async fn create_workspace_directory<R: Runtime>(
    app: AppHandle<R>,
    request: CreateWorkspaceDirectoryRequest,
) -> Result<WorkspaceCommandResult<CreateWorkspaceDirectoryResponse>, String> {
    let registry_file = workspace_registry_path(&app)?;
    let root_id = request.root_id.clone();
    let relative_path = request.relative_path.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        create_workspace_directory_at(&registry_file, &root_id, &relative_path)
    })
    .await
    .map_err(|e| format!("Workspace directory creation task failed: {e}"))?;
    emit_workspace_fs_diagnostic(
        "create_workspace_directory",
        json!({
            "rootId": request.root_id,
            "relativePath": request.relative_path,
            "result": workspace_result_payload(&result),
        }),
    );
    Ok(result)
}

#[tauri::command]
pub async fn rename_workspace_entry<R: Runtime>(
    app: AppHandle<R>,
    request: RenameWorkspaceEntryRequest,
) -> Result<WorkspaceCommandResult<RenameWorkspaceEntryResponse>, String> {
    let registry_file = workspace_registry_path(&app)?;
    let root_id = request.root_id.clone();
    let old_relative_path = request.old_relative_path.clone();
    let new_relative_path = request.new_relative_path.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        rename_workspace_entry_at(
            &registry_file,
            &root_id,
            &old_relative_path,
            &new_relative_path,
        )
    })
    .await
    .map_err(|e| format!("Workspace rename task failed: {e}"))?;
    emit_workspace_fs_diagnostic(
        "rename_workspace_entry",
        json!({
            "rootId": request.root_id,
            "oldRelativePath": request.old_relative_path,
            "newRelativePath": request.new_relative_path,
            "result": workspace_result_payload(&result),
        }),
    );
    Ok(result)
}

#[tauri::command]
pub async fn delete_workspace_entry<R: Runtime>(
    app: AppHandle<R>,
    request: DeleteWorkspaceEntryRequest,
) -> Result<WorkspaceCommandResult<DeleteWorkspaceEntryResponse>, String> {
    let registry_file = workspace_registry_path(&app)?;
    let root_id = request.root_id.clone();
    let relative_path = request.relative_path.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        delete_workspace_entry_at(&registry_file, &root_id, &relative_path)
    })
    .await
    .map_err(|e| format!("Workspace delete task failed: {e}"))?;
    emit_workspace_fs_diagnostic(
        "delete_workspace_entry",
        json!({
            "rootId": request.root_id,
            "relativePath": request.relative_path,
            "result": workspace_result_payload(&result),
        }),
    );
    Ok(result)
}

#[tauri::command]
pub async fn reveal_workspace_entry<R: Runtime>(
    app: AppHandle<R>,
    request: RevealWorkspaceEntryRequest,
) -> Result<WorkspaceCommandResult<RevealWorkspaceEntryResponse>, String> {
    let registry_file = workspace_registry_path(&app)?;
    let root_id = request.root_id.clone();
    let relative_path = request.relative_path.clone();
    let target = tauri::async_runtime::spawn_blocking(move || {
        resolve_workspace_entry_for_reveal_at(&registry_file, &root_id, &relative_path)
    })
    .await
    .map_err(|e| format!("Workspace reveal task failed: {e}"))?;

    let target = match target {
        Ok(target) => target,
        Err(error) => {
            let failure = fail(error.code, error.message, error.path);
            emit_workspace_fs_diagnostic(
                "reveal_workspace_entry",
                json!({
                    "rootId": request.root_id,
                    "relativePath": request.relative_path,
                    "result": workspace_result_payload(&failure),
                }),
            );
            return Ok(failure);
        }
    };

    let result = match app.opener().reveal_item_in_dir(&target) {
        Ok(()) => ok(RevealWorkspaceEntryResponse {
            relative_path: request.relative_path.replace('\\', "/"),
        }),
        Err(err) => fail(
            WorkspaceCommandErrorCode::IoError,
            format!(
                "Failed to reveal workspace entry {}: {err}",
                target.display()
            ),
            Some(request.relative_path.clone()),
        ),
    };
    emit_workspace_fs_diagnostic(
        "reveal_workspace_entry",
        json!({
            "rootId": request.root_id,
            "relativePath": request.relative_path,
            "result": workspace_result_payload(&result),
        }),
    );
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use tempfile::tempdir;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    fn write_registry_fixture(registry_file: &Path, root_id: &str, root_path: &Path) {
        let registry = PersistedWorkspaceRegistry {
            version: 1,
            default_root_id: Some(root_id.to_string()),
            ordered_root_ids: vec![root_id.to_string()],
            roots: vec![super::super::workspace_registry::WorkspaceRootRecord {
                root_id: root_id.to_string(),
                canonical_path: root_path.to_string_lossy().to_string(),
                display_path: root_path.to_string_lossy().to_string(),
                label: "root".to_string(),
                kind: super::super::workspace_registry::WorkspaceRootKind::DefaultHome,
                provenance: super::super::workspace_registry::WorkspaceRootProvenance::Bootstrap,
                is_default: true,
                aliases: Vec::new(),
            }],
        };
        fs::write(
            registry_file,
            serde_json::to_string_pretty(&registry).expect("serialize registry"),
        )
        .expect("write registry");
    }

    #[test]
    fn workspace_fs_rejects_unknown_root() {
        let dir = tempdir().unwrap();
        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        fs::write(
            &registry_file,
            serde_json::to_string(&PersistedWorkspaceRegistry::default()).unwrap(),
        )
        .unwrap();

        let result = read_workspace_tree_at(&registry_file, "missing-root");
        match result {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::UnknownRoot);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected failure"),
        }
    }

    #[test]
    fn workspace_fs_rejects_path_traversal() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let result = delete_workspace_entry_at(&registry_file, "root-default", "../escape.txt");
        match result {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::PathEscape);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected failure"),
        }
    }

    #[test]
    fn workspace_fs_reads_tree_and_treats_swarm_dirs_as_files() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(root.join("policies")).unwrap();
        fs::create_dir_all(root.join("cases/demo.swarm")).unwrap();
        fs::write(root.join("policies/default.yaml"), "name: test\n").unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let result = read_workspace_tree_at(&registry_file, "root-default");
        let WorkspaceCommandResult::Success(success) = result else {
            panic!("expected success");
        };
        let entries = success.data.entries;
        assert!(entries.iter().any(|entry| {
            entry.path == "policies" && entry.kind == WorkspaceEntryKind::Directory
        }));
        assert!(entries.iter().any(|entry| {
            entry.path == "policies/default.yaml" && entry.kind == WorkspaceEntryKind::File
        }));
        assert!(entries.iter().any(|entry| {
            entry.path == "cases/demo.swarm" && entry.kind == WorkspaceEntryKind::File
        }));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_fs_skips_symlinked_entries_in_tree() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("real.txt"), "ok").unwrap();

        let external = dir.path().join("external");
        fs::create_dir_all(&external).unwrap();
        fs::write(external.join("secret.txt"), "secret").unwrap();
        symlink(&external, root.join("linked")).unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let result = read_workspace_tree_at(&registry_file, "root-default");
        let WorkspaceCommandResult::Success(success) = result else {
            panic!("expected success");
        };
        assert!(success
            .data
            .entries
            .iter()
            .all(|entry| !entry.path.starts_with("linked")));
    }

    #[cfg(unix)]
    #[test]
    fn workspace_fs_denies_symlinked_mutations() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(&root).unwrap();

        let external_file = dir.path().join("outside.txt");
        let mut file = File::create(&external_file).unwrap();
        writeln!(file, "outside").unwrap();
        symlink(&external_file, root.join("linked.txt")).unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let result = delete_workspace_entry_at(&registry_file, "root-default", "linked.txt");
        match result {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::SymlinkDenied);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected symlink denial"),
        }
    }
}
