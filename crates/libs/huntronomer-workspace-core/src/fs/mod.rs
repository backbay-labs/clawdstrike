use std::path::Path;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::workspace::{
    pathbuf_to_relative_string, WorkspaceError, WorkspaceRoot, WorkspaceService,
};

pub type Result<T> = std::result::Result<T, WorkspaceError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceEntryKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceEntry {
    pub root_id: String,
    pub relative_path: String,
    pub canonical_path: String,
    pub name: String,
    pub kind: WorkspaceEntryKind,
    pub size: u64,
    pub modified_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFile {
    pub root: WorkspaceRoot,
    pub entry: WorkspaceEntry,
    pub contents: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CreatePathKind {
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteResult {
    pub root: WorkspaceRoot,
    pub entry: WorkspaceEntry,
    pub bytes_written: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MoveResult {
    pub root: WorkspaceRoot,
    pub from_relative_path: String,
    pub entry: WorkspaceEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteResult {
    pub root: WorkspaceRoot,
    pub relative_path: String,
    pub deleted: bool,
}

#[derive(Debug, Default, Clone, Copy)]
pub struct FsService;

impl FsService {
    pub fn list_dir(
        &self,
        workspace: &WorkspaceService,
        root_id: &str,
        relative_path: &str,
    ) -> Result<Vec<WorkspaceEntry>> {
        let target = workspace.resolve_existing_path(root_id, relative_path)?;
        if !target.is_dir() {
            return Err(WorkspaceError::NotDirectory(target.display().to_string()));
        }

        let mut entries = Vec::new();
        for child in std::fs::read_dir(&target)? {
            let child = child?;
            let child_path = child.path();
            entries.push(entry_from_path(workspace, root_id, &child_path)?);
        }

        entries.sort_by(|left, right| right.kind.cmp(&left.kind).then(left.name.cmp(&right.name)));

        Ok(entries)
    }

    pub fn stat_path(
        &self,
        workspace: &WorkspaceService,
        root_id: &str,
        relative_path: &str,
    ) -> Result<WorkspaceEntry> {
        let target = workspace.resolve_existing_path(root_id, relative_path)?;
        entry_from_path(workspace, root_id, &target)
    }

    pub fn read_file(
        &self,
        workspace: &WorkspaceService,
        root_id: &str,
        relative_path: &str,
    ) -> Result<WorkspaceFile> {
        let target = workspace.resolve_existing_path(root_id, relative_path)?;
        if !target.is_file() {
            return Err(WorkspaceError::NotFile(target.display().to_string()));
        }

        let contents = std::fs::read_to_string(&target)?;
        Ok(WorkspaceFile {
            root: workspace.root_metadata(root_id)?,
            entry: entry_from_path(workspace, root_id, &target)?,
            contents,
        })
    }

    pub fn write_file(
        &self,
        workspace: &WorkspaceService,
        root_id: &str,
        relative_path: &str,
        contents: &str,
    ) -> Result<WriteResult> {
        let target = if workspace
            .resolve_existing_path(root_id, relative_path)
            .is_ok()
        {
            workspace.resolve_existing_path(root_id, relative_path)?
        } else {
            workspace.resolve_new_path(root_id, relative_path)?
        };

        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&target, contents)?;

        Ok(WriteResult {
            root: workspace.root_metadata(root_id)?,
            entry: entry_from_path(workspace, root_id, &target)?,
            bytes_written: contents.len(),
        })
    }

    pub fn create_path(
        &self,
        workspace: &WorkspaceService,
        root_id: &str,
        relative_path: &str,
        kind: CreatePathKind,
    ) -> Result<WorkspaceEntry> {
        let target = workspace.resolve_new_path(root_id, relative_path)?;
        match kind {
            CreatePathKind::File => {
                std::fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&target)?;
            }
            CreatePathKind::Directory => {
                std::fs::create_dir(&target)?;
            }
        }

        entry_from_path(workspace, root_id, &target)
    }

    pub fn move_path(
        &self,
        workspace: &WorkspaceService,
        root_id: &str,
        from_relative_path: &str,
        to_relative_path: &str,
    ) -> Result<MoveResult> {
        let source = workspace.resolve_existing_path(root_id, from_relative_path)?;
        let destination = workspace.resolve_new_path(root_id, to_relative_path)?;
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::rename(&source, &destination)?;

        Ok(MoveResult {
            root: workspace.root_metadata(root_id)?,
            from_relative_path: from_relative_path.to_string(),
            entry: entry_from_path(workspace, root_id, &destination)?,
        })
    }

    pub fn delete_path(
        &self,
        workspace: &WorkspaceService,
        root_id: &str,
        relative_path: &str,
    ) -> Result<DeleteResult> {
        let target = workspace.resolve_existing_path(root_id, relative_path)?;
        if target.is_dir() {
            std::fs::remove_dir_all(&target)?;
        } else {
            std::fs::remove_file(&target)?;
        }

        Ok(DeleteResult {
            root: workspace.root_metadata(root_id)?,
            relative_path: relative_path.to_string(),
            deleted: true,
        })
    }
}

fn entry_from_path(
    workspace: &WorkspaceService,
    root_id: &str,
    path: &Path,
) -> Result<WorkspaceEntry> {
    let metadata = std::fs::metadata(path)?;
    let kind = if metadata.is_dir() {
        WorkspaceEntryKind::Directory
    } else {
        WorkspaceEntryKind::File
    };

    let modified_at = metadata
        .modified()
        .ok()
        .map(DateTime::<Utc>::from)
        .map(|timestamp| timestamp.to_rfc3339());
    let relative_path = workspace.relative_path_for(root_id, path)?;
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| pathbuf_to_relative_string(path));

    Ok(WorkspaceEntry {
        root_id: root_id.to_string(),
        relative_path,
        canonical_path: path.display().to_string(),
        name,
        kind,
        size: metadata.len(),
        modified_at,
    })
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::settings::WorkspaceSettingsStore;
    use crate::workspace::WorkspaceService;

    use super::{CreatePathKind, FsService, WorkspaceEntryKind};

    fn unique_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "huntronomer-workspace-core-fs-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| {
            panic!("failed to create test directory {}: {error}", dir.display())
        });
        dir
    }

    #[test]
    fn lists_reads_writes_moves_and_deletes() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("lifecycle");
        let settings_path = root_dir.join("workspace-settings.json");
        let workspace_dir = root_dir.join("repo");
        std::fs::create_dir_all(&workspace_dir)?;

        let mut workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;
        let root = workspace.register_root(&workspace_dir)?;
        let fs = FsService;

        let created_dir = fs.create_path(&workspace, &root.id, "src", CreatePathKind::Directory)?;
        assert_eq!(created_dir.kind, WorkspaceEntryKind::Directory);

        let created_file =
            fs.create_path(&workspace, &root.id, "src/main.rs", CreatePathKind::File)?;
        assert_eq!(created_file.kind, WorkspaceEntryKind::File);

        let write_result = fs.write_file(&workspace, &root.id, "src/main.rs", "fn main() {}\n")?;
        assert_eq!(write_result.bytes_written, "fn main() {}\n".len());

        let file = fs.read_file(&workspace, &root.id, "src/main.rs")?;
        assert_eq!(file.contents, "fn main() {}\n");

        let entries = fs.list_dir(&workspace, &root.id, "src")?;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].relative_path, "src/main.rs");

        let moved = fs.move_path(&workspace, &root.id, "src/main.rs", "src/lib.rs")?;
        assert_eq!(moved.entry.relative_path, "src/lib.rs");

        let deleted = fs.delete_path(&workspace, &root.id, "src/lib.rs")?;
        assert!(deleted.deleted);

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }

    #[test]
    fn rejects_escape_attempts() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("escape");
        let settings_path = root_dir.join("workspace-settings.json");
        let workspace_dir = root_dir.join("repo");
        std::fs::create_dir_all(&workspace_dir)?;

        let mut workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;
        let root = workspace.register_root(&workspace_dir)?;
        let fs = FsService;

        let error = fs
            .read_file(&workspace, &root.id, "../secret.txt")
            .expect_err("escape should fail");
        assert!(matches!(
            error,
            crate::workspace::WorkspaceError::PathEscapesRoot
        ));

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }
}
