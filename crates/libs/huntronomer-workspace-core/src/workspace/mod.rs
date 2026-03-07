use std::collections::HashMap;
use std::ffi::OsStr;
use std::path::{Component, Path, PathBuf};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::settings::{WorkspaceSettings, WorkspaceSettingsStore};

#[derive(Debug, Error)]
pub enum WorkspaceError {
    #[error("workspace root is not registered: {0}")]
    UnknownRoot(String),
    #[error("workspace path must be relative")]
    AbsolutePathRejected,
    #[error("workspace path escapes the trusted root")]
    PathEscapesRoot,
    #[error("workspace path is missing a final name component")]
    MissingPathName,
    #[error("workspace root does not exist: {0}")]
    RootNotFound(String),
    #[error("workspace path does not exist: {0}")]
    PathNotFound(String),
    #[error("workspace path is not a directory: {0}")]
    NotDirectory(String),
    #[error("workspace path is not a file: {0}")]
    NotFile(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, WorkspaceError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRoot {
    pub id: String,
    pub name: String,
    pub canonical_path: String,
    pub created_at: String,
    pub last_opened_at: String,
}

#[derive(Debug, Clone)]
struct RegisteredRoot {
    root: WorkspaceRoot,
    canonical_path: PathBuf,
}

pub struct WorkspaceService {
    settings_store: WorkspaceSettingsStore,
    roots: HashMap<String, RegisteredRoot>,
    recent_root_ids: Vec<String>,
    active_root_id: Option<String>,
}

impl WorkspaceService {
    pub fn new(settings_store: WorkspaceSettingsStore) -> Result<Self> {
        let settings = settings_store.load()?;
        let mut roots = HashMap::new();

        for root in settings.trusted_roots.iter().cloned() {
            roots.insert(
                root.id.clone(),
                RegisteredRoot {
                    canonical_path: PathBuf::from(&root.canonical_path),
                    root,
                },
            );
        }

        Ok(Self {
            settings_store,
            roots,
            recent_root_ids: settings.recent_root_ids,
            active_root_id: settings.active_root_id,
        })
    }

    pub fn settings_store(&self) -> &WorkspaceSettingsStore {
        &self.settings_store
    }

    pub fn register_root(&mut self, path: impl AsRef<Path>) -> Result<WorkspaceRoot> {
        let canonical_path = std::fs::canonicalize(path.as_ref())?;
        if !canonical_path.is_dir() {
            return Err(WorkspaceError::NotDirectory(
                canonical_path.display().to_string(),
            ));
        }

        if let Some(existing) = self
            .roots
            .values_mut()
            .find(|candidate| candidate.canonical_path == canonical_path)
        {
            existing.root.last_opened_at = timestamp_now();
            let root = existing.root.clone();
            self.touch_recent_root(&root.id);
            self.active_root_id = Some(root.id.clone());
            self.persist()?;
            return Ok(root);
        }

        let name = canonical_path
            .file_name()
            .unwrap_or_else(|| OsStr::new("workspace"))
            .to_string_lossy()
            .to_string();
        let root = WorkspaceRoot {
            id: Uuid::now_v7().to_string(),
            name,
            canonical_path: canonical_path.display().to_string(),
            created_at: timestamp_now(),
            last_opened_at: timestamp_now(),
        };

        self.roots.insert(
            root.id.clone(),
            RegisteredRoot {
                root: root.clone(),
                canonical_path,
            },
        );
        self.touch_recent_root(&root.id);
        self.active_root_id = Some(root.id.clone());
        self.persist()?;

        Ok(root)
    }

    pub fn remove_root(&mut self, root_id: &str) -> Result<Option<WorkspaceRoot>> {
        let removed = self.roots.remove(root_id).map(|registered| registered.root);
        if removed.is_some() {
            self.recent_root_ids
                .retain(|candidate| candidate != root_id);
            if self.active_root_id.as_deref() == Some(root_id) {
                self.active_root_id = self.recent_root_ids.first().cloned();
            }
            self.persist()?;
        }

        Ok(removed)
    }

    pub fn list_roots(&self) -> Vec<WorkspaceRoot> {
        let mut roots: Vec<_> = self
            .roots
            .values()
            .map(|registered| registered.root.clone())
            .collect();
        roots.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.cmp(&right.id)));
        roots
    }

    pub fn list_recent_roots(&self) -> Vec<WorkspaceRoot> {
        self.recent_root_ids
            .iter()
            .filter_map(|root_id| {
                self.roots
                    .get(root_id)
                    .map(|registered| registered.root.clone())
            })
            .collect()
    }

    pub fn active_root(&self) -> Option<WorkspaceRoot> {
        self.active_root_id
            .as_ref()
            .and_then(|root_id| self.roots.get(root_id))
            .map(|registered| registered.root.clone())
    }

    pub fn set_active_root(&mut self, root_id: &str) -> Result<WorkspaceRoot> {
        let root = self.root(root_id)?.root.clone();
        self.active_root_id = Some(root_id.to_string());
        self.touch_recent_root(root_id);
        self.persist()?;
        Ok(root)
    }

    pub fn resolve_existing_path(&self, root_id: &str, relative_path: &str) -> Result<PathBuf> {
        let relative = normalize_relative_path(relative_path)?;
        let root = self.root(root_id)?;
        let joined = if relative.as_os_str().is_empty() {
            root.canonical_path.clone()
        } else {
            root.canonical_path.join(relative)
        };

        if !joined.exists() {
            return Err(WorkspaceError::PathNotFound(joined.display().to_string()));
        }

        let canonical = std::fs::canonicalize(&joined)?;
        if !canonical.starts_with(&root.canonical_path) {
            return Err(WorkspaceError::PathEscapesRoot);
        }

        Ok(canonical)
    }

    pub fn resolve_new_path(&self, root_id: &str, relative_path: &str) -> Result<PathBuf> {
        let relative = normalize_relative_path(relative_path)?;
        let root = self.root(root_id)?;
        let file_name = relative
            .file_name()
            .ok_or(WorkspaceError::MissingPathName)?;
        let parent = relative.parent().unwrap_or_else(|| Path::new(""));
        let parent_target = if parent.as_os_str().is_empty() {
            root.canonical_path.clone()
        } else {
            root.canonical_path.join(parent)
        };

        if !parent_target.exists() {
            return Err(WorkspaceError::PathNotFound(
                parent_target.display().to_string(),
            ));
        }

        let parent_canonical = std::fs::canonicalize(parent_target)?;
        if !parent_canonical.starts_with(&root.canonical_path) {
            return Err(WorkspaceError::PathEscapesRoot);
        }

        Ok(parent_canonical.join(file_name))
    }

    pub fn relative_path_for(&self, root_id: &str, path: &Path) -> Result<String> {
        let root = self.root(root_id)?;
        let relative = path
            .strip_prefix(&root.canonical_path)
            .map_err(|_| WorkspaceError::PathEscapesRoot)?;
        Ok(pathbuf_to_relative_string(relative))
    }

    pub fn root_metadata(&self, root_id: &str) -> Result<WorkspaceRoot> {
        Ok(self.root(root_id)?.root.clone())
    }

    fn root(&self, root_id: &str) -> Result<&RegisteredRoot> {
        self.roots
            .get(root_id)
            .ok_or_else(|| WorkspaceError::UnknownRoot(root_id.to_string()))
    }

    fn touch_recent_root(&mut self, root_id: &str) {
        self.recent_root_ids
            .retain(|candidate| candidate != root_id);
        self.recent_root_ids.insert(0, root_id.to_string());
    }

    fn persist(&self) -> Result<()> {
        let settings = WorkspaceSettings {
            trusted_roots: self.list_roots(),
            recent_root_ids: self.recent_root_ids.clone(),
            active_root_id: self.active_root_id.clone(),
        };
        self.settings_store.save(&settings)
    }
}

pub fn normalize_relative_path(relative_path: &str) -> Result<PathBuf> {
    let path = Path::new(relative_path);
    if path.is_absolute() {
        return Err(WorkspaceError::AbsolutePathRejected);
    }

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => return Err(WorkspaceError::PathEscapesRoot),
            Component::RootDir | Component::Prefix(_) => {
                return Err(WorkspaceError::AbsolutePathRejected)
            }
        }
    }

    Ok(normalized)
}

pub(crate) fn pathbuf_to_relative_string(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn timestamp_now() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{normalize_relative_path, WorkspaceError, WorkspaceService};
    use crate::settings::WorkspaceSettingsStore;

    fn unique_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "huntronomer-workspace-core-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| {
            panic!("failed to create test directory {}: {error}", dir.display())
        });
        dir
    }

    #[test]
    fn normalizes_safe_relative_paths() -> Result<(), Box<dyn std::error::Error>> {
        let normalized = normalize_relative_path("./src/lib.rs")?;
        assert_eq!(normalized, PathBuf::from("src/lib.rs"));
        Ok(())
    }

    #[test]
    fn rejects_escape_paths() {
        let error = normalize_relative_path("../secret").expect_err("path should fail");
        assert!(matches!(error, WorkspaceError::PathEscapesRoot));
    }

    #[test]
    fn registers_roots_and_persists_recent_state() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("workspace-root");
        let settings_path = root_dir.join("workspace-settings.json");
        let workspace_dir = root_dir.join("repo");
        std::fs::create_dir_all(&workspace_dir)?;

        let mut service =
            WorkspaceService::new(WorkspaceSettingsStore::new(settings_path.clone()))?;
        let registered = service.register_root(&workspace_dir)?;

        assert_eq!(
            service.active_root().as_ref().map(|root| root.id.as_str()),
            Some(registered.id.as_str())
        );
        assert_eq!(service.list_recent_roots(), vec![registered.clone()]);

        let reloaded = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;
        assert_eq!(reloaded.list_recent_roots(), vec![registered.clone()]);
        assert_eq!(reloaded.active_root(), Some(registered));

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }

    #[test]
    fn rejects_nonexistent_root_registration() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("missing-root");
        let settings_path = root_dir.join("workspace-settings.json");
        let missing = root_dir.join("does-not-exist");
        let mut service = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;

        let error = service
            .register_root(&missing)
            .expect_err("root should fail");
        assert!(matches!(error, WorkspaceError::Io(_)));

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }
}
