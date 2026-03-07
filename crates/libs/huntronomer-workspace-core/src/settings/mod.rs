use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::workspace::{Result, WorkspaceRoot};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSettings {
    #[serde(default)]
    pub trusted_roots: Vec<WorkspaceRoot>,
    #[serde(default)]
    pub recent_root_ids: Vec<String>,
    pub active_root_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct WorkspaceSettingsStore {
    path: PathBuf,
}

impl WorkspaceSettingsStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> Result<WorkspaceSettings> {
        if !self.path.exists() {
            return Ok(WorkspaceSettings::default());
        }

        let contents = std::fs::read_to_string(&self.path)?;
        let settings = serde_json::from_str(&contents)?;
        Ok(settings)
    }

    pub fn save(&self, settings: &WorkspaceSettings) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let contents = serde_json::to_string_pretty(settings)?;
        let temp_path = self.path.with_extension("tmp");
        std::fs::write(&temp_path, contents)?;
        std::fs::rename(temp_path, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::workspace::WorkspaceRoot;

    use super::{WorkspaceSettings, WorkspaceSettingsStore};

    fn unique_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "huntronomer-workspace-core-settings-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| {
            panic!("failed to create test directory {}: {error}", dir.display())
        });
        dir
    }

    #[test]
    fn round_trips_workspace_settings() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("roundtrip");
        let store = WorkspaceSettingsStore::new(root_dir.join("workspace-settings.json"));
        let settings = WorkspaceSettings {
            trusted_roots: vec![WorkspaceRoot {
                id: "root-1".to_string(),
                name: "repo".to_string(),
                canonical_path: "/tmp/repo".to_string(),
                created_at: "2026-01-01T00:00:00Z".to_string(),
                last_opened_at: "2026-01-01T00:00:00Z".to_string(),
            }],
            recent_root_ids: vec!["root-1".to_string()],
            active_root_id: Some("root-1".to_string()),
        };

        store.save(&settings)?;
        let loaded = store.load()?;

        assert_eq!(loaded, settings);

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }
}
