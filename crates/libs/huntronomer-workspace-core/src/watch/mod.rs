use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::workspace::{Result, WorkspaceService};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceFsEventKind {
    Created,
    Modified,
    Removed,
    Renamed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFsEvent {
    pub root_id: String,
    pub kind: WorkspaceFsEventKind,
    pub relative_path: String,
    pub previous_relative_path: Option<String>,
    pub at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SnapshotEntryKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SnapshotEntry {
    kind: SnapshotEntryKind,
    size: u64,
    modified_unix_nanos: Option<u128>,
}

#[derive(Debug, Default)]
pub struct WatchService {
    snapshots: Mutex<HashMap<String, BTreeMap<String, SnapshotEntry>>>,
}

impl WatchService {
    pub fn prime_root(&self, workspace: &WorkspaceService, root_id: &str) -> Result<()> {
        let root_path = root_path(workspace, root_id)?;
        let snapshot = build_snapshot(workspace, root_id, &root_path)?;
        let mut snapshots = self.snapshots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshots.insert(root_id.to_string(), snapshot);
        Ok(())
    }

    pub fn poll_changes(&self, workspace: &WorkspaceService, root_id: &str) -> Result<Vec<WorkspaceFsEvent>> {
        let root_path = root_path(workspace, root_id)?;
        let current = build_snapshot(workspace, root_id, &root_path)?;
        let mut snapshots = self.snapshots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = snapshots.insert(root_id.to_string(), current.clone());

        let Some(previous) = previous else {
            return Ok(Vec::new());
        };

        Ok(diff_snapshots(root_id, &previous, &current))
    }

    pub fn clear_root(&self, root_id: &str) {
        let mut snapshots = self.snapshots.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        snapshots.remove(root_id);
    }
}

fn root_path(workspace: &WorkspaceService, root_id: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(workspace.root_metadata(root_id)?.canonical_path))
}

fn build_snapshot(
    workspace: &WorkspaceService,
    root_id: &str,
    root_path: &Path,
) -> Result<BTreeMap<String, SnapshotEntry>> {
    let mut entries = BTreeMap::new();
    collect_snapshot_entries(workspace, root_id, root_path, root_path, &mut entries)?;
    Ok(entries)
}

fn collect_snapshot_entries(
    workspace: &WorkspaceService,
    root_id: &str,
    root_path: &Path,
    current_path: &Path,
    entries: &mut BTreeMap<String, SnapshotEntry>,
) -> Result<()> {
    for child in std::fs::read_dir(current_path)? {
        let child = child?;
        let child_path = child.path();
        let metadata = std::fs::symlink_metadata(&child_path)?;
        let file_type = metadata.file_type();
        let kind = if file_type.is_dir() {
            SnapshotEntryKind::Directory
        } else if file_type.is_symlink() {
            SnapshotEntryKind::Symlink
        } else {
            SnapshotEntryKind::File
        };

        let relative_path = workspace.relative_path_for(root_id, &child_path)?;
        entries.insert(
            relative_path,
            SnapshotEntry {
                kind,
                size: metadata.len(),
                modified_unix_nanos: metadata
                    .modified()
                    .ok()
                    .and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|duration| duration.as_nanos()),
            },
        );

        if file_type.is_dir() {
            collect_snapshot_entries(workspace, root_id, root_path, &child_path, entries)?;
        }
    }

    let _ = root_path;
    Ok(())
}

fn diff_snapshots(
    root_id: &str,
    previous: &BTreeMap<String, SnapshotEntry>,
    current: &BTreeMap<String, SnapshotEntry>,
) -> Vec<WorkspaceFsEvent> {
    let mut created = Vec::new();
    let mut removed = Vec::new();
    let mut modified = Vec::new();

    for (path, entry) in current {
        match previous.get(path) {
            None => created.push((path.clone(), entry.clone())),
            Some(old_entry) if old_entry != entry => modified.push(path.clone()),
            Some(_) => {}
        }
    }

    for (path, entry) in previous {
        if !current.contains_key(path) {
            removed.push((path.clone(), entry.clone()));
        }
    }

    let mut events = Vec::new();
    let mut matched_created = vec![false; created.len()];
    let mut matched_removed = vec![false; removed.len()];

    for (removed_index, (removed_path, removed_entry)) in removed.iter().enumerate() {
        if let Some((created_index, (created_path, _))) = created
            .iter()
            .enumerate()
            .find(|(created_index, (_, created_entry))| {
                !matched_created[*created_index] && *removed_entry == *created_entry
            })
        {
            matched_removed[removed_index] = true;
            matched_created[created_index] = true;
            events.push(WorkspaceFsEvent {
                root_id: root_id.to_string(),
                kind: WorkspaceFsEventKind::Renamed,
                relative_path: created_path.clone(),
                previous_relative_path: Some(removed_path.clone()),
                at: timestamp_now(),
            });
        }
    }

    for (index, (path, _)) in created.iter().enumerate() {
        if !matched_created[index] {
            events.push(WorkspaceFsEvent {
                root_id: root_id.to_string(),
                kind: WorkspaceFsEventKind::Created,
                relative_path: path.clone(),
                previous_relative_path: None,
                at: timestamp_now(),
            });
        }
    }

    for path in modified {
        events.push(WorkspaceFsEvent {
            root_id: root_id.to_string(),
            kind: WorkspaceFsEventKind::Modified,
            relative_path: path,
            previous_relative_path: None,
            at: timestamp_now(),
        });
    }

    for (index, (path, _)) in removed.iter().enumerate() {
        if !matched_removed[index] {
            events.push(WorkspaceFsEvent {
                root_id: root_id.to_string(),
                kind: WorkspaceFsEventKind::Removed,
                relative_path: path.clone(),
                previous_relative_path: None,
                at: timestamp_now(),
            });
        }
    }

    events.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    events
}

fn timestamp_now() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::thread;
    use std::time::Duration;

    use crate::settings::WorkspaceSettingsStore;
    use crate::workspace::WorkspaceService;

    use super::{WatchService, WorkspaceFsEventKind};

    fn unique_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "huntronomer-workspace-core-watch-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| {
            panic!("failed to create test directory {}: {error}", dir.display())
        });
        dir
    }

    #[test]
    fn emits_created_modified_renamed_and_removed_events() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("events");
        let settings_path = root_dir.join("workspace-settings.json");
        let workspace_dir = root_dir.join("repo");
        std::fs::create_dir_all(&workspace_dir)?;

        let mut workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;
        let root = workspace.register_root(&workspace_dir)?;
        let watch = WatchService::default();

        watch.prime_root(&workspace, &root.id)?;

        std::fs::write(workspace_dir.join("alpha.txt"), "alpha")?;
        let created = watch.poll_changes(&workspace, &root.id)?;
        assert_eq!(created.len(), 1);
        assert_eq!(created[0].kind, WorkspaceFsEventKind::Created);
        assert_eq!(created[0].relative_path, "alpha.txt");

        thread::sleep(Duration::from_millis(20));
        std::fs::write(workspace_dir.join("alpha.txt"), "alpha updated")?;
        let modified = watch.poll_changes(&workspace, &root.id)?;
        assert_eq!(modified.len(), 1);
        assert_eq!(modified[0].kind, WorkspaceFsEventKind::Modified);
        assert_eq!(modified[0].relative_path, "alpha.txt");

        std::fs::rename(workspace_dir.join("alpha.txt"), workspace_dir.join("beta.txt"))?;
        let renamed = watch.poll_changes(&workspace, &root.id)?;
        assert_eq!(renamed.len(), 1);
        assert_eq!(renamed[0].kind, WorkspaceFsEventKind::Renamed);
        assert_eq!(renamed[0].relative_path, "beta.txt");
        assert_eq!(renamed[0].previous_relative_path.as_deref(), Some("alpha.txt"));

        std::fs::remove_file(workspace_dir.join("beta.txt"))?;
        let removed = watch.poll_changes(&workspace, &root.id)?;
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].kind, WorkspaceFsEventKind::Removed);
        assert_eq!(removed[0].relative_path, "beta.txt");

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }
}
