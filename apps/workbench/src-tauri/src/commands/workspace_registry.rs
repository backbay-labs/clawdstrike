use std::collections::HashSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Runtime};
use uuid::Uuid;

use super::persistence::persistence_root;

const WORKSPACE_REGISTRY_VERSION: u32 = 1;
pub const WORKSPACE_REGISTRY_FILE: &str = "workspace-root-registry.v1.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRootKind {
    DefaultHome,
    MountedFolder,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceRootProvenance {
    Bootstrap,
    LocalStorageMigration,
    UserAdded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRootRecord {
    pub root_id: String,
    pub canonical_path: String,
    pub display_path: String,
    pub label: String,
    pub kind: WorkspaceRootKind,
    pub provenance: WorkspaceRootProvenance,
    pub is_default: bool,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PersistedWorkspaceRegistry {
    pub version: u32,
    pub default_root_id: Option<String>,
    pub ordered_root_ids: Vec<String>,
    pub roots: Vec<WorkspaceRootRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceRegistrySnapshot {
    pub version: u32,
    pub default_root_id: Option<String>,
    pub ordered_root_ids: Vec<String>,
    pub roots: Vec<WorkspaceRootRecord>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct BootstrapWorkspaceRegistryRequest {
    pub legacy_roots: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapWorkspaceRegistryResponse {
    pub snapshot: WorkspaceRegistrySnapshot,
    pub migrated_legacy_roots: Vec<String>,
    pub dropped_legacy_roots: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddWorkspaceRootRequest {
    pub path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoveWorkspaceRootRequest {
    pub root_id: String,
}

impl Default for PersistedWorkspaceRegistry {
    fn default() -> Self {
        Self {
            version: WORKSPACE_REGISTRY_VERSION,
            default_root_id: None,
            ordered_root_ids: Vec::new(),
            roots: Vec::new(),
        }
    }
}

impl From<PersistedWorkspaceRegistry> for WorkspaceRegistrySnapshot {
    fn from(value: PersistedWorkspaceRegistry) -> Self {
        Self {
            version: value.version,
            default_root_id: value.default_root_id,
            ordered_root_ids: value.ordered_root_ids,
            roots: value.roots,
        }
    }
}

fn resolve_default_workspace_root() -> Result<PathBuf, String> {
    let home =
        dirs_next::home_dir().ok_or_else(|| "Failed to resolve user home directory".to_string())?;
    Ok(home.join(".clawdstrike"))
}

fn ensure_default_root_exists(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path).map_err(|e| {
        format!(
            "Failed to create default workspace root {}: {e}",
            path.display()
        )
    })
}

fn canonicalize_workspace_root(path: &Path) -> Result<PathBuf, String> {
    std::fs::canonicalize(path).map_err(|e| {
        format!(
            "Failed to canonicalize workspace root {}: {e}",
            path.display()
        )
    })
}

fn sanitize_display_path(path: &Path) -> String {
    let raw = path.to_string_lossy().to_string();
    raw.strip_prefix(r"\\?\").unwrap_or(&raw).to_string()
}

fn normalize_path_string(path: &str) -> String {
    path.replace('\\', "/")
}

fn label_for_path(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or_else(|| sanitize_display_path(path))
}

fn registry_path<R: Runtime>(app: &AppHandle<R>) -> Result<PathBuf, String> {
    Ok(persistence_root(app)?.join(WORKSPACE_REGISTRY_FILE))
}

fn load_registry(path: &Path) -> Result<PersistedWorkspaceRegistry, String> {
    if !path.exists() {
        return Ok(PersistedWorkspaceRegistry::default());
    }

    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("Failed to read workspace registry {}: {e}", path.display()))?;
    serde_json::from_str(&raw)
        .map_err(|e| format!("Failed to parse workspace registry {}: {e}", path.display()))
}

fn ensure_not_symlink(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }

    let metadata = std::fs::symlink_metadata(path)
        .map_err(|e| format!("Failed to inspect {}: {e}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "Refusing to access symlinked workspace registry path {}",
            path.display()
        ));
    }

    Ok(())
}

fn cleanup_stale_temp(path: &Path) {
    if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

fn write_registry(path: &Path, registry: &PersistedWorkspaceRegistry) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create workspace registry directory {}: {e}",
                parent.display()
            )
        })?;
    }

    let temp = path.with_file_name(format!(".{}.tmp", WORKSPACE_REGISTRY_FILE));
    let backup = path.with_file_name(format!("{}.bak", WORKSPACE_REGISTRY_FILE));
    cleanup_stale_temp(&temp);

    ensure_not_symlink(path)?;
    ensure_not_symlink(&backup)?;

    let payload = serde_json::to_string_pretty(registry)
        .map_err(|e| format!("Failed to serialize workspace registry: {e}"))?;

    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temp)
            .map_err(|e| {
                format!(
                    "Failed to open temp workspace registry {}: {e}",
                    temp.display()
                )
            })?;
        file.write_all(payload.as_bytes()).map_err(|e| {
            format!(
                "Failed to write temp workspace registry {}: {e}",
                temp.display()
            )
        })?;
        file.sync_all().map_err(|e| {
            format!(
                "Failed to sync temp workspace registry {}: {e}",
                temp.display()
            )
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o600));
    }

    let had_existing_target = path.exists();
    if had_existing_target {
        if backup.exists() {
            std::fs::remove_file(&backup).map_err(|e| {
                format!(
                    "Failed to remove stale workspace registry backup {}: {e}",
                    backup.display()
                )
            })?;
        }

        std::fs::rename(path, &backup).map_err(|e| {
            format!(
                "Failed to move previous workspace registry {} to backup {}: {e}",
                path.display(),
                backup.display()
            )
        })?;
    }

    if let Err(error) = std::fs::rename(&temp, path) {
        cleanup_stale_temp(&temp);
        if had_existing_target {
            let _ = std::fs::rename(&backup, path);
        }
        return Err(format!(
            "Failed to finalize workspace registry {}: {error}",
            path.display()
        ));
    }

    Ok(())
}

fn find_root_index_by_root_id(
    registry: &PersistedWorkspaceRegistry,
    root_id: &str,
) -> Option<usize> {
    registry
        .roots
        .iter()
        .position(|root| root.root_id == root_id)
}

fn find_root_index_by_candidate(
    registry: &PersistedWorkspaceRegistry,
    canonical_path: &str,
    candidate_paths: &[String],
) -> Option<usize> {
    let normalized_candidates: HashSet<String> = candidate_paths
        .iter()
        .map(|path| normalize_path_string(path))
        .collect();

    registry.roots.iter().position(|root| {
        if normalize_path_string(&root.canonical_path) == canonical_path {
            return true;
        }
        if normalized_candidates.contains(&normalize_path_string(&root.display_path)) {
            return true;
        }

        root.aliases
            .iter()
            .any(|alias| normalized_candidates.contains(&normalize_path_string(alias)))
    })
}

fn push_unique_alias(aliases: &mut Vec<String>, alias: String) {
    if alias.trim().is_empty() {
        return;
    }
    let normalized_alias = normalize_path_string(&alias);
    if aliases
        .iter()
        .any(|existing| normalize_path_string(existing) == normalized_alias)
    {
        return;
    }
    aliases.push(alias);
}

fn remove_self_aliases(record: &mut WorkspaceRootRecord) {
    let display = normalize_path_string(&record.display_path);
    let canonical = normalize_path_string(&record.canonical_path);
    let mut seen = HashSet::new();
    record.aliases.retain(|alias| {
        let normalized = normalize_path_string(alias);
        if normalized == display || normalized == canonical || !seen.insert(normalized) {
            return false;
        }
        true
    });
}

fn path_is_same_or_descendant(candidate: &Path, ancestor: &Path) -> bool {
    candidate == ancestor || candidate.starts_with(ancestor)
}

fn admit_root(
    registry: &mut PersistedWorkspaceRegistry,
    canonical_path: &Path,
    display_path: &Path,
    kind: WorkspaceRootKind,
    provenance: WorkspaceRootProvenance,
    is_default: bool,
    alias_candidates: &[PathBuf],
    preferred_root_id: Option<String>,
) -> String {
    let canonical_string = sanitize_display_path(canonical_path);
    let display_string = sanitize_display_path(display_path);
    let alias_strings = alias_candidates
        .iter()
        .map(|path| sanitize_display_path(path))
        .collect::<Vec<_>>();

    if let Some(index) = preferred_root_id
        .as_deref()
        .and_then(|root_id| find_root_index_by_root_id(registry, root_id))
        .or_else(|| find_root_index_by_candidate(registry, &canonical_string, &alias_strings))
    {
        let root = registry
            .roots
            .get_mut(index)
            .expect("index already validated");
        let next_is_default = root.is_default || is_default;
        root.canonical_path = canonical_string.clone();
        if root.display_path.trim().is_empty() {
            root.display_path = display_string.clone();
        }
        if root.label.trim().is_empty() {
            root.label = label_for_path(display_path);
        }
        root.kind = if next_is_default {
            WorkspaceRootKind::DefaultHome
        } else {
            kind
        };
        root.provenance = if next_is_default {
            WorkspaceRootProvenance::Bootstrap
        } else {
            provenance
        };
        root.is_default = next_is_default;
        push_unique_alias(&mut root.aliases, display_string);
        for alias in alias_strings {
            push_unique_alias(&mut root.aliases, alias);
        }
        remove_self_aliases(root);
        if root.is_default {
            registry.default_root_id = Some(root.root_id.clone());
        }
        if !registry
            .ordered_root_ids
            .iter()
            .any(|id| id == &root.root_id)
        {
            registry.ordered_root_ids.push(root.root_id.clone());
        }
        return root.root_id.clone();
    }

    let root_id = preferred_root_id.unwrap_or_else(|| Uuid::new_v4().to_string());
    let mut aliases = Vec::new();
    for alias in alias_strings {
        push_unique_alias(&mut aliases, alias);
    }

    let mut record = WorkspaceRootRecord {
        root_id: root_id.clone(),
        canonical_path: canonical_string,
        display_path: display_string,
        label: label_for_path(display_path),
        kind: if is_default {
            WorkspaceRootKind::DefaultHome
        } else {
            kind
        },
        provenance: if is_default {
            WorkspaceRootProvenance::Bootstrap
        } else {
            provenance
        },
        is_default,
        aliases,
    };
    remove_self_aliases(&mut record);

    registry.roots.push(record);
    registry.ordered_root_ids.push(root_id.clone());
    if is_default {
        registry.default_root_id = Some(root_id.clone());
    }

    root_id
}

fn snapshot_from_registry(registry: &PersistedWorkspaceRegistry) -> WorkspaceRegistrySnapshot {
    registry.clone().into()
}

fn legacy_root_is_default_workspace_alias(candidate: &Path, default_root: &Path) -> bool {
    let normalized_candidate = normalize_path_string(&sanitize_display_path(candidate));
    let normalized_default_workspace =
        normalize_path_string(&sanitize_display_path(&default_root.join("workspace")));
    normalized_candidate == normalized_default_workspace
}

fn bootstrap_registry_at(
    registry_file: &Path,
    default_root: &Path,
    legacy_roots: &[String],
) -> Result<BootstrapWorkspaceRegistryResponse, String> {
    ensure_default_root_exists(default_root)?;
    let default_canonical = canonicalize_workspace_root(default_root)?;
    let default_workspace_alias = default_root.join("workspace");

    let mut registry = load_registry(registry_file)?;
    registry.version = WORKSPACE_REGISTRY_VERSION;

    let mut migrated_legacy_roots = Vec::new();
    let mut dropped_legacy_roots = Vec::new();
    let mut default_seen_in_input = false;

    if registry.roots.is_empty() {
        for legacy_root in legacy_roots {
            let trimmed = legacy_root.trim();
            if trimmed.is_empty() {
                continue;
            }
            let candidate = PathBuf::from(trimmed);
            if !candidate.exists() {
                dropped_legacy_roots.push(trimmed.to_string());
                continue;
            }

            if legacy_root_is_default_workspace_alias(&candidate, default_root) {
                default_seen_in_input = true;
                migrated_legacy_roots.push(trimmed.to_string());
                admit_root(
                    &mut registry,
                    &default_canonical,
                    default_root,
                    WorkspaceRootKind::DefaultHome,
                    WorkspaceRootProvenance::Bootstrap,
                    true,
                    &[candidate.clone(), default_workspace_alias.clone()],
                    None,
                );
                continue;
            }

            let canonical = match canonicalize_workspace_root(&candidate) {
                Ok(canonical) => canonical,
                Err(_) => {
                    dropped_legacy_roots.push(trimmed.to_string());
                    continue;
                }
            };

            if canonical == default_canonical {
                default_seen_in_input = true;
                migrated_legacy_roots.push(trimmed.to_string());
                admit_root(
                    &mut registry,
                    &default_canonical,
                    default_root,
                    WorkspaceRootKind::DefaultHome,
                    WorkspaceRootProvenance::Bootstrap,
                    true,
                    &[candidate.clone(), default_workspace_alias.clone()],
                    None,
                );
                continue;
            }

            if path_is_same_or_descendant(&canonical, &default_canonical) {
                dropped_legacy_roots.push(trimmed.to_string());
                continue;
            }

            migrated_legacy_roots.push(trimmed.to_string());
            admit_root(
                &mut registry,
                &canonical,
                &candidate,
                WorkspaceRootKind::MountedFolder,
                WorkspaceRootProvenance::LocalStorageMigration,
                false,
                &[candidate.clone()],
                None,
            );
        }
    } else {
        for legacy_root in legacy_roots {
            let trimmed = legacy_root.trim();
            if trimmed.is_empty() {
                continue;
            }
            let candidate = PathBuf::from(trimmed);
            if !candidate.exists() {
                dropped_legacy_roots.push(trimmed.to_string());
                continue;
            }

            if legacy_root_is_default_workspace_alias(&candidate, default_root) {
                default_seen_in_input = true;
                migrated_legacy_roots.push(trimmed.to_string());
                admit_root(
                    &mut registry,
                    &default_canonical,
                    default_root,
                    WorkspaceRootKind::DefaultHome,
                    WorkspaceRootProvenance::Bootstrap,
                    true,
                    &[candidate.clone(), default_workspace_alias.clone()],
                    None,
                );
                continue;
            }

            let canonical = match canonicalize_workspace_root(&candidate) {
                Ok(canonical) => canonical,
                Err(_) => {
                    dropped_legacy_roots.push(trimmed.to_string());
                    continue;
                }
            };

            if canonical == default_canonical {
                default_seen_in_input = true;
                migrated_legacy_roots.push(trimmed.to_string());
                admit_root(
                    &mut registry,
                    &default_canonical,
                    default_root,
                    WorkspaceRootKind::DefaultHome,
                    WorkspaceRootProvenance::Bootstrap,
                    true,
                    &[candidate.clone(), default_workspace_alias.clone()],
                    None,
                );
                continue;
            }

            if path_is_same_or_descendant(&canonical, &default_canonical) {
                dropped_legacy_roots.push(trimmed.to_string());
                continue;
            }

            migrated_legacy_roots.push(trimmed.to_string());
            admit_root(
                &mut registry,
                &canonical,
                &candidate,
                WorkspaceRootKind::MountedFolder,
                WorkspaceRootProvenance::LocalStorageMigration,
                false,
                &[candidate.clone()],
                None,
            );
        }
    }

    let default_root_id = admit_root(
        &mut registry,
        &default_canonical,
        default_root,
        WorkspaceRootKind::DefaultHome,
        WorkspaceRootProvenance::Bootstrap,
        true,
        &[default_workspace_alias],
        None,
    );

    if !default_seen_in_input
        && !registry
            .ordered_root_ids
            .iter()
            .any(|root_id| root_id == &default_root_id)
    {
        registry.ordered_root_ids.push(default_root_id.clone());
    }

    let ordered_root_ids = registry.ordered_root_ids.clone();
    registry
        .roots
        .retain(|root| ordered_root_ids.iter().any(|id| id == &root.root_id));
    registry
        .ordered_root_ids
        .retain(|root_id| registry.roots.iter().any(|root| &root.root_id == root_id));
    registry.version = WORKSPACE_REGISTRY_VERSION;
    registry.default_root_id = Some(default_root_id);

    write_registry(registry_file, &registry)?;

    Ok(BootstrapWorkspaceRegistryResponse {
        snapshot: snapshot_from_registry(&registry),
        migrated_legacy_roots,
        dropped_legacy_roots,
    })
}

fn add_workspace_root_at(
    registry_file: &Path,
    default_root: &Path,
    path: &str,
) -> Result<WorkspaceRegistrySnapshot, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Workspace root path must not be empty".to_string());
    }

    let bootstrap = bootstrap_registry_at(registry_file, default_root, &[])?;
    let mut registry = PersistedWorkspaceRegistry {
        version: bootstrap.snapshot.version,
        default_root_id: bootstrap.snapshot.default_root_id,
        ordered_root_ids: bootstrap.snapshot.ordered_root_ids,
        roots: bootstrap.snapshot.roots,
    };

    let candidate = PathBuf::from(trimmed);
    if !candidate.exists() || !candidate.is_dir() {
        return Err(format!(
            "Workspace root must reference an existing directory: {}",
            candidate.display()
        ));
    }

    let canonical = canonicalize_workspace_root(&candidate)?;
    let default_canonical = canonicalize_workspace_root(default_root)?;
    if canonical == default_canonical {
        return Ok(snapshot_from_registry(&registry));
    }
    if path_is_same_or_descendant(&canonical, &default_canonical) {
        return Err(format!(
            "Paths inside the managed default workspace cannot be mounted as separate roots: {}",
            candidate.display()
        ));
    }
    admit_root(
        &mut registry,
        &canonical,
        &candidate,
        WorkspaceRootKind::MountedFolder,
        WorkspaceRootProvenance::UserAdded,
        false,
        &[candidate.clone()],
        None,
    );

    write_registry(registry_file, &registry)?;
    Ok(snapshot_from_registry(&registry))
}

fn remove_workspace_root_at(
    registry_file: &Path,
    default_root: &Path,
    root_id: &str,
) -> Result<WorkspaceRegistrySnapshot, String> {
    let bootstrap = bootstrap_registry_at(registry_file, default_root, &[])?;
    let mut registry = PersistedWorkspaceRegistry {
        version: bootstrap.snapshot.version,
        default_root_id: bootstrap.snapshot.default_root_id,
        ordered_root_ids: bootstrap.snapshot.ordered_root_ids,
        roots: bootstrap.snapshot.roots,
    };

    if registry.default_root_id.as_deref() == Some(root_id) {
        return Err("Cannot remove the default workspace root".to_string());
    }

    let before_len = registry.roots.len();
    registry.roots.retain(|root| root.root_id != root_id);
    if registry.roots.len() == before_len {
        return Ok(snapshot_from_registry(&registry));
    }

    registry.ordered_root_ids.retain(|id| id != root_id);
    write_registry(registry_file, &registry)?;
    Ok(snapshot_from_registry(&registry))
}

#[tauri::command]
pub async fn bootstrap_workspace_registry<R: Runtime>(
    app: AppHandle<R>,
    request: BootstrapWorkspaceRegistryRequest,
) -> Result<BootstrapWorkspaceRegistryResponse, String> {
    let registry_file = registry_path(&app)?;
    let default_root = resolve_default_workspace_root()?;
    tauri::async_runtime::spawn_blocking(move || {
        bootstrap_registry_at(&registry_file, &default_root, &request.legacy_roots)
    })
    .await
    .map_err(|e| format!("Workspace registry bootstrap task failed: {e}"))?
}

#[tauri::command]
pub async fn add_workspace_root<R: Runtime>(
    app: AppHandle<R>,
    request: AddWorkspaceRootRequest,
) -> Result<WorkspaceRegistrySnapshot, String> {
    let registry_file = registry_path(&app)?;
    let default_root = resolve_default_workspace_root()?;
    tauri::async_runtime::spawn_blocking(move || {
        add_workspace_root_at(&registry_file, &default_root, &request.path)
    })
    .await
    .map_err(|e| format!("Add workspace root task failed: {e}"))?
}

#[tauri::command]
pub async fn remove_workspace_root<R: Runtime>(
    app: AppHandle<R>,
    request: RemoveWorkspaceRootRequest,
) -> Result<WorkspaceRegistrySnapshot, String> {
    let registry_file = registry_path(&app)?;
    let default_root = resolve_default_workspace_root()?;
    tauri::async_runtime::spawn_blocking(move || {
        remove_workspace_root_at(&registry_file, &default_root, &request.root_id)
    })
    .await
    .map_err(|e| format!("Remove workspace root task failed: {e}"))?
}

#[cfg(test)]
mod tests {
    use super::{
        add_workspace_root_at, bootstrap_registry_at, remove_workspace_root_at,
        WorkspaceRootProvenance,
    };
    use std::path::PathBuf;
    use uuid::Uuid;

    fn setup_home() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let home = tempdir.path().join("home");
        std::fs::create_dir_all(&home).expect("home");
        let registry_file = tempdir.path().join("workspace-root-registry.v1.json");
        (tempdir, home, registry_file)
    }

    #[test]
    fn workspace_registry_root_ids() {
        let (_tempdir, home, registry_file) = setup_home();
        let repo = home.join("repo-alpha");
        std::fs::create_dir_all(&repo).expect("repo");

        let first = bootstrap_registry_at(
            &registry_file,
            &home.join(".clawdstrike"),
            &[repo.to_string_lossy().to_string()],
        )
        .expect("first bootstrap");
        let second = bootstrap_registry_at(
            &registry_file,
            &home.join(".clawdstrike"),
            &[repo.to_string_lossy().to_string()],
        )
        .expect("second bootstrap");

        let first_root = first
            .snapshot
            .roots
            .iter()
            .find(|root| root.display_path == repo.to_string_lossy())
            .expect("first root");
        let second_root = second
            .snapshot
            .roots
            .iter()
            .find(|root| root.display_path == repo.to_string_lossy())
            .expect("second root");

        assert_eq!(first_root.root_id, second_root.root_id);
        assert!(Uuid::parse_str(&first_root.root_id).is_ok());
        assert_eq!(
            first_root.provenance,
            WorkspaceRootProvenance::LocalStorageMigration
        );

        let after_add = add_workspace_root_at(
            &registry_file,
            &home.join(".clawdstrike"),
            &repo.to_string_lossy(),
        )
        .expect("add existing root");
        assert_eq!(after_add.roots.len(), second.snapshot.roots.len());

        let default_id = after_add.default_root_id.clone().expect("default root id");
        let remove_default =
            remove_workspace_root_at(&registry_file, &home.join(".clawdstrike"), &default_id);
        assert!(remove_default.is_err());
    }

    #[test]
    fn workspace_registry_canonicalization() {
        let (_tempdir, home, registry_file) = setup_home();
        let repo = home.join("repo-bravo");
        std::fs::create_dir_all(&repo).expect("repo");

        let alias_path = home.join("repo-bravo").join(".");
        let mut legacy_roots = vec![
            repo.to_string_lossy().to_string(),
            alias_path.to_string_lossy().to_string(),
        ];

        #[cfg(unix)]
        {
            let symlink_path = home.join("repo-bravo-link");
            std::os::unix::fs::symlink(&repo, &symlink_path).expect("symlink");
            legacy_roots.push(symlink_path.to_string_lossy().to_string());
        }

        let response =
            bootstrap_registry_at(&registry_file, &home.join(".clawdstrike"), &legacy_roots)
                .expect("bootstrap");
        let root = response
            .snapshot
            .roots
            .iter()
            .find(|root| root.display_path == repo.to_string_lossy())
            .expect("root");

        assert_eq!(
            response
                .snapshot
                .roots
                .iter()
                .filter(|candidate| candidate.canonical_path == root.canonical_path)
                .count(),
            1
        );
        assert!(root
            .aliases
            .iter()
            .any(|alias| alias.contains("repo-bravo/.")));
        #[cfg(unix)]
        assert!(root
            .aliases
            .iter()
            .any(|alias| alias.contains("repo-bravo-link")));
    }

    #[test]
    fn workspace_registry_default_root_migration() {
        let (_tempdir, home, registry_file) = setup_home();
        let default_root = home.join(".clawdstrike");
        let legacy_workspace = default_root.join("workspace");
        std::fs::create_dir_all(&legacy_workspace).expect("legacy workspace");

        let first = bootstrap_registry_at(
            &registry_file,
            &default_root,
            &[legacy_workspace.to_string_lossy().to_string()],
        )
        .expect("first bootstrap");
        let second = bootstrap_registry_at(
            &registry_file,
            &default_root,
            &[legacy_workspace.to_string_lossy().to_string()],
        )
        .expect("second bootstrap");

        assert_eq!(first.snapshot.roots.len(), 1);
        let root = &first.snapshot.roots[0];
        assert_eq!(root.display_path, default_root.to_string_lossy());
        assert!(root.is_default);
        assert!(root
            .aliases
            .iter()
            .any(|alias| alias == &legacy_workspace.to_string_lossy()));
        assert_eq!(
            first.snapshot.default_root_id.as_deref(),
            Some(root.root_id.as_str())
        );

        assert_eq!(second.snapshot.roots.len(), 1);
        assert_eq!(second.snapshot.roots[0].root_id, root.root_id);
        assert_eq!(first.migrated_legacy_roots, second.migrated_legacy_roots);
    }

    #[test]
    fn workspace_registry_rejects_nested_managed_default_root_mounts() {
        let (_tempdir, home, registry_file) = setup_home();
        let default_root = home.join(".clawdstrike");
        let receipts_root = default_root.join("receipts");
        std::fs::create_dir_all(&receipts_root).expect("receipts");

        bootstrap_registry_at(&registry_file, &default_root, &[]).expect("bootstrap");

        let result = add_workspace_root_at(
            &registry_file,
            &default_root,
            &receipts_root.to_string_lossy(),
        );
        assert!(result.is_err());
        let message = result.err().unwrap_or_default();
        assert!(message.contains("managed default workspace"));
    }

    #[test]
    fn workspace_registry_keeps_default_root_identity_when_readding_default_path() {
        let (_tempdir, home, registry_file) = setup_home();
        let default_root = home.join(".clawdstrike");
        std::fs::create_dir_all(default_root.join("workspace")).expect("workspace");

        let bootstrapped =
            bootstrap_registry_at(&registry_file, &default_root, &[]).expect("bootstrap");
        let original = bootstrapped
            .snapshot
            .roots
            .iter()
            .find(|root| root.is_default)
            .expect("default root")
            .clone();

        let snapshot = add_workspace_root_at(&registry_file, &default_root, &default_root.to_string_lossy())
            .expect("re-add default path");
        assert_eq!(snapshot.roots.len(), 1);
        let current = snapshot
            .roots
            .iter()
            .find(|root| root.root_id == original.root_id)
            .expect("default root preserved");
        assert!(current.is_default);
        assert_eq!(current.kind, super::WorkspaceRootKind::DefaultHome);
        assert_eq!(current.provenance, WorkspaceRootProvenance::Bootstrap);
    }
}
