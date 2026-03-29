use std::borrow::Cow;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;
use tauri::{AppHandle, Runtime};
use tauri_plugin_opener::OpenerExt;

use super::persistence::persistence_root;
use super::workspace_registry::{
    PersistedWorkspaceRegistry, WorkspaceRootKind, WorkspaceRootRecord, WORKSPACE_REGISTRY_FILE,
};

#[cfg(unix)]
use std::ffi::CString;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;

const WORKSPACE_CONTENT_DIR_NAME: &str = "workspace";

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
    AlreadyExists,
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
pub struct CreateWorkspaceFileResponse {
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
    #[serde(default)]
    pub include_internal_entries: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkspaceDirectoryRequest {
    pub root_id: String,
    pub relative_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateWorkspaceFileRequest {
    pub root_id: String,
    pub relative_path: String,
    #[serde(default)]
    pub content: Option<String>,
    #[serde(default)]
    pub default_content_file_type: Option<String>,
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

const POLICY_DEFAULT_CONTENT: &str = r#"version: "1.2.0"
name: Untitled Policy
description: ""

guards:
  forbidden_path:
    enabled: true
  egress_allowlist:
    enabled: true
    default_action: block
  secret_leak:
    enabled: true
  shell_command:
    enabled: true

settings:
  fail_fast: false
  verbose_logging: false
"#;

const SIGMA_DEFAULT_CONTENT: &str = r#"title: Untitled Detection Rule
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: |
    Detects ...
author: ""
date: 2026/03/14
tags:
    - attack.execution
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'suspicious'
    condition: selection
falsepositives:
    - Unknown
level: medium
"#;

const YARA_DEFAULT_CONTENT: &str = r#"rule untitled_rule {
    meta:
        author = ""
        description = ""
        date = "2026-03-14"

    strings:
        $s1 = "pattern"

    condition:
        any of them
}
"#;

const OCSF_DEFAULT_CONTENT: &str = r#"{
  "class_uid": 2004,
  "category_uid": 2,
  "activity_id": 1,
  "severity_id": 1,
  "status_id": 1,
  "time": 0,
  "message": "",
  "metadata": {
    "version": "1.4.0",
    "product": {
      "name": "ClawdStrike",
      "uid": "clawdstrike",
      "vendor_name": "Backbay Labs"
    }
  },
  "finding_info": {
    "uid": "",
    "title": ""
  }
}
"#;

#[derive(Debug, Clone)]
struct WorkspaceRootContext {
    record: WorkspaceRootRecord,
    path: PathBuf,
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

fn workspace_default_file_content(file_type: &str) -> Option<&'static str> {
    match file_type {
        "clawdstrike_policy" => Some(POLICY_DEFAULT_CONTENT),
        "sigma_rule" => Some(SIGMA_DEFAULT_CONTENT),
        "yara_rule" => Some(YARA_DEFAULT_CONTENT),
        "ocsf_event" => Some(OCSF_DEFAULT_CONTENT),
        _ => None,
    }
}

fn resolve_workspace_root_context(
    registry_file: &Path,
    root_id: &str,
) -> Result<WorkspaceRootContext, WorkspaceCommandError> {
    let registry = load_workspace_registry(registry_file)
        .map_err(|message| make_error(WorkspaceCommandErrorCode::IoError, message, None))?;

    let Some(root) = registry
        .roots
        .iter()
        .find(|root| root.root_id == root_id)
        .cloned()
    else {
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

    Ok(WorkspaceRootContext {
        record: root,
        path: root_path,
    })
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

fn resolve_workspace_creation_path(
    root_path: &Path,
    relative_path: &str,
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
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let mut target_path = next;
                for remaining_component in components.iter().skip(index + 1) {
                    let Component::Normal(remaining_part) = remaining_component else {
                        return Err(make_error(
                            WorkspaceCommandErrorCode::PathEscape,
                            "Workspace relative path cannot escape the mounted root",
                            Some(relative_path.to_string()),
                        ));
                    };
                    target_path.push(remaining_part);
                }
                return Ok(target_path);
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

fn is_internal_workspace_entry(
    root_context: &WorkspaceRootContext,
    relative_path: &str,
    _path: &Path,
) -> bool {
    if root_context.record.kind != WorkspaceRootKind::DefaultHome {
        return false;
    }

    relative_path != WORKSPACE_CONTENT_DIR_NAME
        && !relative_path.starts_with(&format!("{WORKSPACE_CONTENT_DIR_NAME}/"))
}

#[derive(Debug, Clone, Copy)]
enum DefaultHomeAccessScope {
    VisibleEntry,
    CreateDirectory,
    MutableEntry,
}

fn allows_default_home_access(relative_path: &str, scope: DefaultHomeAccessScope) -> bool {
    match scope {
        DefaultHomeAccessScope::VisibleEntry | DefaultHomeAccessScope::CreateDirectory => {
            relative_path == WORKSPACE_CONTENT_DIR_NAME
                || relative_path.starts_with(&format!("{WORKSPACE_CONTENT_DIR_NAME}/"))
        }
        DefaultHomeAccessScope::MutableEntry => {
            relative_path.starts_with(&format!("{WORKSPACE_CONTENT_DIR_NAME}/"))
        }
    }
}

fn ensure_default_home_access(
    root_context: &WorkspaceRootContext,
    relative_path: &str,
    scope: DefaultHomeAccessScope,
) -> Result<(), WorkspaceCommandError> {
    let normalized_relative = validate_relative_path(relative_path, false)?;
    let normalized_relative = sanitize_relative_path(&normalized_relative);
    if root_context.record.kind != WorkspaceRootKind::DefaultHome
        || allows_default_home_access(&normalized_relative, scope)
    {
        return Ok(());
    }
    Err(make_error(
        WorkspaceCommandErrorCode::NotFound,
        "Workspace entry not found",
        Some(normalized_relative),
    ))
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
    root_context: &WorkspaceRootContext,
    root_path: &Path,
    current_dir: &Path,
    entries: &mut Vec<WorkspaceTreeEntry>,
    include_internal_entries: bool,
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

        if !include_internal_entries
            && is_internal_workspace_entry(root_context, &relative_path, &path)
        {
            continue;
        }

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
            collect_workspace_tree_entries(
                root_context,
                root_path,
                &path,
                entries,
                include_internal_entries,
            )?;
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
    include_internal_entries: bool,
) -> WorkspaceCommandResult<ReadWorkspaceTreeResponse> {
    let root_context = match resolve_workspace_root_context(registry_file, root_id) {
        Ok(root_context) => root_context,
        Err(error) => return fail(error.code, error.message, error.path),
    };

    let mut entries = Vec::new();
    if let Err(error) = collect_workspace_tree_entries(
        &root_context,
        &root_context.path,
        &root_context.path,
        &mut entries,
        include_internal_entries,
    ) {
        return fail(error.code, error.message, error.path);
    }

    ok(ReadWorkspaceTreeResponse { entries })
}

fn create_workspace_directory_at(
    registry_file: &Path,
    root_id: &str,
    relative_path: &str,
) -> WorkspaceCommandResult<CreateWorkspaceDirectoryResponse> {
    let root_context = match resolve_workspace_root_context(registry_file, root_id) {
        Ok(root_context) => root_context,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    if let Err(error) = ensure_default_home_access(
        &root_context,
        relative_path,
        DefaultHomeAccessScope::CreateDirectory,
    ) {
        return fail(error.code, error.message, error.path);
    }
    let target_path = match resolve_workspace_creation_path(&root_context.path, relative_path) {
        Ok(target_path) => target_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };

    if target_path.exists() {
        return fail(
            WorkspaceCommandErrorCode::AlreadyExists,
            format!(
                "Workspace directory already exists: {}",
                target_path.display()
            ),
            Some(relative_path.to_string()),
        );
    }

    if let Some(parent) = target_path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            return fail(
                WorkspaceCommandErrorCode::IoError,
                format!(
                    "Failed to create workspace directory parent {}: {err}",
                    parent.display()
                ),
                Some(relative_path.to_string()),
            );
        }
    }

    if let Err(err) = fs::create_dir(&target_path) {
        let code = if err.kind() == std::io::ErrorKind::AlreadyExists {
            WorkspaceCommandErrorCode::AlreadyExists
        } else {
            WorkspaceCommandErrorCode::IoError
        };
        return fail(
            code,
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

fn create_workspace_file_at(
    registry_file: &Path,
    root_id: &str,
    relative_path: &str,
    content: Option<&str>,
    default_content_file_type: Option<&str>,
) -> WorkspaceCommandResult<CreateWorkspaceFileResponse> {
    let root_context = match resolve_workspace_root_context(registry_file, root_id) {
        Ok(root_context) => root_context,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    if let Err(error) = ensure_default_home_access(
        &root_context,
        relative_path,
        DefaultHomeAccessScope::MutableEntry,
    ) {
        return fail(error.code, error.message, error.path);
    }
    let target_path = match resolve_workspace_creation_path(&root_context.path, relative_path) {
        Ok(target_path) => target_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    let content = match (content, default_content_file_type) {
        (Some(content), _) => Cow::Borrowed(content),
        (None, Some(file_type)) => match workspace_default_file_content(file_type) {
            Some(content) => Cow::Borrowed(content),
            None => {
                return fail(
                    WorkspaceCommandErrorCode::UnsupportedKind,
                    format!("Unsupported workspace file template: {file_type}"),
                    Some(relative_path.to_string()),
                );
            }
        },
        (None, None) => Cow::Borrowed(""),
    };

    if target_path.exists() {
        return fail(
            WorkspaceCommandErrorCode::AlreadyExists,
            format!("Workspace file already exists: {}", target_path.display()),
            Some(relative_path.to_string()),
        );
    }

    if let Some(parent) = target_path.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            return fail(
                WorkspaceCommandErrorCode::IoError,
                format!(
                    "Failed to create workspace file parent {}: {err}",
                    parent.display()
                ),
                Some(relative_path.to_string()),
            );
        }
    }

    let mut file = match OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target_path)
    {
        Ok(file) => file,
        Err(err) => {
            let code = if err.kind() == std::io::ErrorKind::AlreadyExists {
                WorkspaceCommandErrorCode::AlreadyExists
            } else {
                WorkspaceCommandErrorCode::IoError
            };
            return fail(
                code,
                format!(
                    "Failed to create workspace file {}: {err}",
                    target_path.display()
                ),
                Some(relative_path.to_string()),
            );
        }
    };

    if let Err(err) = file.write_all(content.as_bytes()) {
        let _ = fs::remove_file(&target_path);
        return fail(
            WorkspaceCommandErrorCode::IoError,
            format!(
                "Failed to write workspace file {}: {err}",
                target_path.display()
            ),
            Some(relative_path.to_string()),
        );
    }
    if let Err(err) = file.sync_all() {
        let _ = fs::remove_file(&target_path);
        return fail(
            WorkspaceCommandErrorCode::IoError,
            format!(
                "Failed to sync workspace file {}: {err}",
                target_path.display()
            ),
            Some(relative_path.to_string()),
        );
    }

    ok(CreateWorkspaceFileResponse {
        relative_path: relative_path.replace('\\', "/"),
    })
}

#[cfg(unix)]
fn path_to_c_string(path: &Path) -> std::io::Result<CString> {
    CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains NUL"))
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn rename_without_replace(source_path: &Path, target_path: &Path) -> std::io::Result<()> {
    let source = path_to_c_string(source_path)?;
    let target = path_to_c_string(target_path)?;
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
fn rename_without_replace(source_path: &Path, target_path: &Path) -> std::io::Result<()> {
    let source = path_to_c_string(source_path)?;
    let target = path_to_c_string(target_path)?;
    let rc = unsafe { libc::renamex_np(source.as_ptr(), target.as_ptr(), libc::RENAME_EXCL) };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios"
    ))
))]
fn rename_without_replace(source_path: &Path, target_path: &Path) -> std::io::Result<()> {
    fs::rename(source_path, target_path)
}

#[cfg(windows)]
fn rename_without_replace(source_path: &Path, target_path: &Path) -> std::io::Result<()> {
    fs::rename(source_path, target_path)
}

fn rename_workspace_entry_at(
    registry_file: &Path,
    root_id: &str,
    old_relative_path: &str,
    new_relative_path: &str,
) -> WorkspaceCommandResult<RenameWorkspaceEntryResponse> {
    let root_context = match resolve_workspace_root_context(registry_file, root_id) {
        Ok(root_context) => root_context,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    if let Err(error) = ensure_default_home_access(
        &root_context,
        old_relative_path,
        DefaultHomeAccessScope::MutableEntry,
    ) {
        return fail(error.code, error.message, error.path);
    }
    if let Err(error) = ensure_default_home_access(
        &root_context,
        new_relative_path,
        DefaultHomeAccessScope::MutableEntry,
    ) {
        return fail(error.code, error.message, error.path);
    }
    let source_path = match resolve_workspace_entry_path(&root_context.path, old_relative_path, false) {
        Ok(source_path) => source_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    let target_path = match resolve_workspace_entry_path(&root_context.path, new_relative_path, true) {
        Ok(target_path) => target_path,
        Err(error) => return fail(error.code, error.message, error.path),
    };

    if source_path == target_path {
        return ok(RenameWorkspaceEntryResponse {
            old_relative_path: old_relative_path.replace('\\', "/"),
            new_relative_path: new_relative_path.replace('\\', "/"),
        });
    }

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

    if target_path.exists() {
        return fail(
            WorkspaceCommandErrorCode::AlreadyExists,
            format!(
                "Workspace destination already exists: {}",
                target_path.display()
            ),
            Some(new_relative_path.to_string()),
        );
    }

    if let Err(err) = rename_without_replace(&source_path, &target_path) {
        if err.kind() == std::io::ErrorKind::AlreadyExists || target_path.exists() {
            return fail(
                WorkspaceCommandErrorCode::AlreadyExists,
                format!(
                    "Workspace destination already exists: {}",
                    target_path.display()
                ),
                Some(new_relative_path.to_string()),
            );
        }
        return fail(
            if err.kind() == std::io::ErrorKind::NotFound {
                WorkspaceCommandErrorCode::NotFound
            } else {
                WorkspaceCommandErrorCode::IoError
            },
            format!(
                "Failed to rename workspace entry {} -> {}: {err}",
                source_path.display(),
                target_path.display()
            ),
            Some(if err.kind() == std::io::ErrorKind::NotFound {
                old_relative_path.to_string()
            } else {
                new_relative_path.to_string()
            }),
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
    let root_context = match resolve_workspace_root_context(registry_file, root_id) {
        Ok(root_context) => root_context,
        Err(error) => return fail(error.code, error.message, error.path),
    };
    if let Err(error) = ensure_default_home_access(
        &root_context,
        relative_path,
        DefaultHomeAccessScope::MutableEntry,
    ) {
        return fail(error.code, error.message, error.path);
    }
    let target_path = match resolve_workspace_entry_path(&root_context.path, relative_path, false) {
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
    let root_context = resolve_workspace_root_context(registry_file, root_id)?;
    ensure_default_home_access(
        &root_context,
        relative_path,
        DefaultHomeAccessScope::VisibleEntry,
    )?;
    resolve_workspace_entry_path(&root_context.path, relative_path, false)
}

#[tauri::command]
pub async fn read_workspace_tree<R: Runtime>(
    app: AppHandle<R>,
    request: ReadWorkspaceTreeRequest,
) -> Result<WorkspaceCommandResult<ReadWorkspaceTreeResponse>, String> {
    let registry_file = workspace_registry_path(&app)?;
    let root_id = request.root_id.clone();
    let include_internal_entries = request.include_internal_entries;
    let result = tauri::async_runtime::spawn_blocking(move || {
        read_workspace_tree_at(&registry_file, &root_id, include_internal_entries)
    })
    .await
    .map_err(|e| format!("Workspace tree read task failed: {e}"))?;
    emit_workspace_fs_diagnostic(
        "read_workspace_tree",
        json!({
            "rootId": request.root_id,
            "includeInternalEntries": request.include_internal_entries,
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
pub async fn create_workspace_file<R: Runtime>(
    app: AppHandle<R>,
    request: CreateWorkspaceFileRequest,
) -> Result<WorkspaceCommandResult<CreateWorkspaceFileResponse>, String> {
    let registry_file = workspace_registry_path(&app)?;
    let root_id = request.root_id.clone();
    let relative_path = request.relative_path.clone();
    let content = request.content.clone();
    let default_content_file_type = request.default_content_file_type.clone();
    let result = tauri::async_runtime::spawn_blocking(move || {
        create_workspace_file_at(
            &registry_file,
            &root_id,
            &relative_path,
            content.as_deref(),
            default_content_file_type.as_deref(),
        )
    })
    .await
    .map_err(|e| format!("Workspace file creation task failed: {e}"))?;
    emit_workspace_fs_diagnostic(
        "create_workspace_file",
        json!({
            "rootId": request.root_id,
            "relativePath": request.relative_path,
            "contentLength": request.content.as_ref().map(String::len),
            "defaultContentFileType": request.default_content_file_type,
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

    fn write_registry_fixture_with_kind(
        registry_file: &Path,
        root_id: &str,
        root_path: &Path,
        kind: super::super::workspace_registry::WorkspaceRootKind,
    ) {
        let registry = PersistedWorkspaceRegistry {
            version: 1,
            default_root_id: Some(root_id.to_string()),
            ordered_root_ids: vec![root_id.to_string()],
            roots: vec![super::super::workspace_registry::WorkspaceRootRecord {
                root_id: root_id.to_string(),
                canonical_path: root_path.to_string_lossy().to_string(),
                display_path: root_path.to_string_lossy().to_string(),
                label: "root".to_string(),
                kind,
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

    fn write_registry_fixture(registry_file: &Path, root_id: &str, root_path: &Path) {
        write_registry_fixture_with_kind(
            registry_file,
            root_id,
            root_path,
            super::super::workspace_registry::WorkspaceRootKind::DefaultHome,
        );
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

        let result = read_workspace_tree_at(&registry_file, "missing-root", false);
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
        let root = dir.path().join(".clawdstrike");
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
        write_registry_fixture_with_kind(
            &registry_file,
            "root-mounted",
            &root,
            super::super::workspace_registry::WorkspaceRootKind::MountedFolder,
        );

        let result = read_workspace_tree_at(&registry_file, "root-mounted", false);
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

        let result = read_workspace_tree_at(&registry_file, "root-default", false);
        let WorkspaceCommandResult::Success(success) = result else {
            panic!("expected success");
        };
        assert!(success
            .data
            .entries
            .iter()
            .all(|entry| !entry.path.starts_with("linked")));
    }

    #[test]
    fn workspace_fs_hides_internal_entries_by_default() {
        let dir = tempdir().unwrap();
        let root = dir.path().join(".clawdstrike");
        fs::create_dir_all(root.join("workspace/policies")).unwrap();
        fs::create_dir_all(root.join("receipts")).unwrap();
        fs::write(root.join("workspace/policies/default.yaml"), "name: test\n").unwrap();
        fs::write(root.join("receipts/session.json"), "{}").unwrap();
        fs::write(root.join(WORKSPACE_REGISTRY_FILE), "{}").unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let default_result = read_workspace_tree_at(&registry_file, "root-default", false);
        let WorkspaceCommandResult::Success(default_success) = default_result else {
            panic!("expected success");
        };
        assert!(default_success
            .data
            .entries
            .iter()
            .any(|entry| entry.path == "workspace/policies/default.yaml"));
        assert!(default_success
            .data
            .entries
            .iter()
            .all(|entry| !entry.path.starts_with("receipts")));
        assert!(default_success
            .data
            .entries
            .iter()
            .all(|entry| entry.path != WORKSPACE_REGISTRY_FILE));

        let expanded_result = read_workspace_tree_at(&registry_file, "root-default", true);
        let WorkspaceCommandResult::Success(expanded_success) = expanded_result else {
            panic!("expected success");
        };
        assert!(expanded_success
            .data
            .entries
            .iter()
            .any(|entry| entry.path == "receipts"));
        assert!(expanded_success
            .data
            .entries
            .iter()
            .any(|entry| entry.path == "receipts/session.json"));
        assert!(expanded_success
            .data
            .entries
            .iter()
            .any(|entry| entry.path == WORKSPACE_REGISTRY_FILE));
    }

    #[test]
    fn workspace_fs_rejects_default_home_internal_mutations_and_reveal() {
        let dir = tempdir().unwrap();
        let root = dir.path().join(".clawdstrike");
        fs::create_dir_all(root.join("workspace")).unwrap();
        fs::create_dir_all(root.join("receipts")).unwrap();
        fs::write(root.join("receipts/session.json"), "{}").unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let create_dir = create_workspace_directory_at(&registry_file, "root-default", "receipts/new-dir");
        let create_file = create_workspace_file_at(
            &registry_file,
            "root-default",
            "receipts/new.json",
            Some("{}"),
            None,
        );
        let rename_out = rename_workspace_entry_at(
            &registry_file,
            "root-default",
            "workspace",
            "receipts/workspace-hidden",
        );
        let rename_in = rename_workspace_entry_at(
            &registry_file,
            "root-default",
            "receipts/session.json",
            "workspace/session.json",
        );
        let delete_internal = delete_workspace_entry_at(&registry_file, "root-default", "receipts/session.json");
        let reveal_internal =
            resolve_workspace_entry_for_reveal_at(&registry_file, "root-default", "receipts/session.json");

        match create_dir {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::NotFound);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected create dir rejection"),
        }
        match create_file {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::NotFound);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected create file rejection"),
        }
        match rename_out {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::NotFound);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected rename-out rejection"),
        }
        match rename_in {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::NotFound);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected rename-in rejection"),
        }
        match delete_internal {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::NotFound);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected delete rejection"),
        }
        match reveal_internal {
            Err(error) => assert_eq!(error.code, WorkspaceCommandErrorCode::NotFound),
            Ok(_) => panic!("expected reveal to reject internal default-home path"),
        }
    }

    #[test]
    fn workspace_fs_only_allows_directory_bootstrap_at_default_home_workspace_root() {
        let dir = tempdir().unwrap();
        let root = dir.path().join(".clawdstrike");
        fs::create_dir_all(&root).unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let create_workspace_dir =
            create_workspace_directory_at(&registry_file, "root-default", "workspace");
        let create_workspace_file = create_workspace_file_at(
            &registry_file,
            "root-default",
            "workspace",
            Some("name: bad\n"),
            None,
        );
        let delete_workspace_dir =
            delete_workspace_entry_at(&registry_file, "root-default", "workspace");

        let WorkspaceCommandResult::Success(success) = create_workspace_dir else {
            panic!("expected bootstrap workspace directory creation to succeed");
        };
        assert_eq!(success.data.relative_path, "workspace");

        match create_workspace_file {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::NotFound);
            }
            WorkspaceCommandResult::Success(_) => {
                panic!("expected file creation at workspace root to be rejected")
            }
        }

        match delete_workspace_dir {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::NotFound);
            }
            WorkspaceCommandResult::Success(_) => {
                panic!("expected deleting workspace root to be rejected")
            }
        }
    }

    #[test]
    fn workspace_fs_allows_mounted_folder_mutations_outside_default_home_workspace_dir() {
        let dir = tempdir().unwrap();
        let root = dir.path().join(".clawdstrike");
        fs::create_dir_all(root.join("receipts")).unwrap();
        fs::write(root.join("receipts/session.json"), "{}").unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture_with_kind(
            &registry_file,
            "root-mounted",
            &root,
            super::super::workspace_registry::WorkspaceRootKind::MountedFolder,
        );

        let create_file = create_workspace_file_at(
            &registry_file,
            "root-mounted",
            "receipts/new.json",
            Some("{}"),
            None,
        );
        let reveal_path =
            resolve_workspace_entry_for_reveal_at(&registry_file, "root-mounted", "receipts/session.json");

        let WorkspaceCommandResult::Success(success) = create_file else {
            panic!("expected mounted-folder create success");
        };
        assert_eq!(success.data.relative_path, "receipts/new.json");
        assert_eq!(reveal_path.expect("reveal path"), root.join("receipts/session.json"));
    }

    #[test]
    fn workspace_fs_keeps_registry_visible_for_mounted_folder_roots() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(WORKSPACE_REGISTRY_FILE), "{}").unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture_with_kind(
            &registry_file,
            "root-mounted",
            &root,
            super::super::workspace_registry::WorkspaceRootKind::MountedFolder,
        );

        let result = read_workspace_tree_at(&registry_file, "root-mounted", false);
        let WorkspaceCommandResult::Success(success) = result else {
            panic!("expected success");
        };
        assert!(success
            .data
            .entries
            .iter()
            .any(|entry| entry.path == WORKSPACE_REGISTRY_FILE));
    }

    #[test]
    fn workspace_fs_keeps_dotfiles_visible_for_mounted_folder_roots() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("repo");
        fs::create_dir_all(root.join(".github")).unwrap();
        fs::write(root.join(".github/workflows.yml"), "name: ci\n").unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture_with_kind(
            &registry_file,
            "root-mounted",
            &root,
            super::super::workspace_registry::WorkspaceRootKind::MountedFolder,
        );

        let result = read_workspace_tree_at(&registry_file, "root-mounted", false);
        let WorkspaceCommandResult::Success(success) = result else {
            panic!("expected success");
        };
        assert!(success
            .data
            .entries
            .iter()
            .any(|entry| entry.path == ".github"));
        assert!(success
            .data
            .entries
            .iter()
            .any(|entry| entry.path == ".github/workflows.yml"));
    }

    #[test]
    fn workspace_fs_creates_workspace_file_and_rejects_conflicts() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let result = create_workspace_file_at(
            &registry_file,
            "root-default",
            "workspace/policies/default.yaml",
            Some("name: created\n"),
            None,
        );
        let WorkspaceCommandResult::Success(success) = result else {
            panic!("expected success");
        };
        assert_eq!(
            success.data.relative_path,
            "workspace/policies/default.yaml"
        );
        assert_eq!(
            fs::read_to_string(root.join("workspace/policies/default.yaml")).unwrap(),
            "name: created\n"
        );

        let conflict = create_workspace_file_at(
            &registry_file,
            "root-default",
            "workspace/policies/default.yaml",
            Some("name: conflict\n"),
            None,
        );
        match conflict {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::AlreadyExists);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected conflict"),
        }
    }

    #[test]
    fn workspace_fs_creates_workspace_file_from_backend_default_content() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let result = create_workspace_file_at(
            &registry_file,
            "root-default",
            "workspace/policies/generated.yaml",
            None,
            Some("clawdstrike_policy"),
        );
        let WorkspaceCommandResult::Success(success) = result else {
            panic!("expected success");
        };
        assert_eq!(
            success.data.relative_path,
            "workspace/policies/generated.yaml"
        );
        let written = fs::read_to_string(root.join("workspace/policies/generated.yaml")).unwrap();
        assert!(written.contains("Untitled Policy"));
        assert!(written.contains("forbidden_path"));
    }

    #[test]
    fn workspace_fs_rejects_unknown_backend_default_content_type() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(&root).unwrap();
        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let result = create_workspace_file_at(
            &registry_file,
            "root-default",
            "workspace/unknown.txt",
            None,
            Some("totally_unknown"),
        );
        match result {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(
                    failure.error.code,
                    WorkspaceCommandErrorCode::UnsupportedKind
                );
            }
            WorkspaceCommandResult::Success(_) => panic!("expected unsupported file type"),
        }
    }

    #[test]
    fn workspace_fs_rejects_directory_and_rename_conflicts() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(root.join("workspace/policies")).unwrap();
        fs::write(root.join("workspace/existing.yaml"), "name: existing\n").unwrap();
        fs::write(root.join("workspace/source.yaml"), "name: source\n").unwrap();
        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let dir_conflict =
            create_workspace_directory_at(&registry_file, "root-default", "workspace/policies");
        match dir_conflict {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::AlreadyExists);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected directory conflict"),
        }

        let rename_conflict = rename_workspace_entry_at(
            &registry_file,
            "root-default",
            "workspace/source.yaml",
            "workspace/existing.yaml",
        );
        match rename_conflict {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::AlreadyExists);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected rename conflict"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn workspace_fs_denies_symlinked_mutations() {
        let dir = tempdir().unwrap();
        let root = dir.path().join("workspace");
        fs::create_dir_all(root.join("workspace")).unwrap();

        let external_file = dir.path().join("outside.txt");
        let mut file = File::create(&external_file).unwrap();
        writeln!(file, "outside").unwrap();
        symlink(&external_file, root.join("workspace/linked.txt")).unwrap();

        let registry_file = dir.path().join(WORKSPACE_REGISTRY_FILE);
        write_registry_fixture(&registry_file, "root-default", &root);

        let result = delete_workspace_entry_at(
            &registry_file,
            "root-default",
            "workspace/linked.txt",
        );
        match result {
            WorkspaceCommandResult::Failure(failure) => {
                assert_eq!(failure.error.code, WorkspaceCommandErrorCode::SymlinkDenied);
            }
            WorkspaceCommandResult::Success(_) => panic!("expected symlink denial"),
        }
    }
}
