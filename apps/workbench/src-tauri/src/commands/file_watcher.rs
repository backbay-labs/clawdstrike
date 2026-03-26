use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use notify::RecursiveMode;
use notify_debouncer_mini::{
    new_debouncer,
    notify::{self, RecommendedWatcher},
    DebounceEventResult, Debouncer,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tauri::{AppHandle, Emitter, Runtime, State};

use super::persistence::{persistence_root, validate_filename};

pub const SWARM_FILE_WATCH_EVENT: &str = "swarm:file-watch";
const FILE_WATCH_DEBOUNCE_MS: u64 = 300;
const SELF_WRITE_TTL_MS: u64 = 1_500;
const MAX_ANCESTOR_WALK_DEPTH: usize = 4;

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(default)]
pub struct ConfigureSwarmFileWatcherRequest {
    pub persistence_filenames: Vec<String>,
    pub workspace_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SwarmFileWatchCategory {
    Persistence,
    Workspace,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SwarmFileWatchEvent {
    pub category: SwarmFileWatchCategory,
    pub paths: Vec<String>,
    pub filenames: Vec<String>,
}

#[derive(Clone, Default)]
pub struct SwarmFileWatcherState {
    runtime: Arc<Mutex<WatcherRuntime>>,
    self_writes: Arc<Mutex<HashMap<String, Instant>>>,
    content_hashes: Arc<Mutex<HashMap<String, [u8; 32]>>>,
}

#[derive(Default)]
struct WatcherRuntime {
    debouncer: Option<Debouncer<RecommendedWatcher>>,
}

#[derive(Debug, Clone)]
struct WatchPlan {
    watch_roots: Vec<(PathBuf, RecursiveMode)>,
    persistence_targets: HashMap<String, String>,
    workspace_targets: HashSet<String>,
}

impl WatchPlan {
    fn is_empty(&self) -> bool {
        self.watch_roots.is_empty()
    }
}

pub fn record_content_hash(state: &SwarmFileWatcherState, path: &Path, content: &[u8]) {
    let hash: [u8; 32] = Sha256::digest(content).into();
    record_content_hash_value(state, path, hash);
}

pub fn record_content_hash_value(state: &SwarmFileWatcherState, path: &Path, hash: [u8; 32]) {
    if let Ok(mut hashes) = state.content_hashes.lock() {
        hashes.insert(normalize_watch_path(path), hash);
    }
}

pub fn mark_self_writes(state: &SwarmFileWatcherState, paths: &[PathBuf]) {
    let now = Instant::now();
    let deadline = now + Duration::from_millis(SELF_WRITE_TTL_MS);
    if let Ok(mut writes) = state.self_writes.lock() {
        prune_expired_self_writes(&mut writes, now);
        for path in paths {
            writes.insert(normalize_watch_path(path), deadline);
        }
    }
}

#[tauri::command]
pub async fn configure_swarm_file_watcher<R: Runtime>(
    app: AppHandle<R>,
    watcher_state: State<'_, SwarmFileWatcherState>,
    request: ConfigureSwarmFileWatcherRequest,
) -> Result<(), String> {
    let persistence_dir = persistence_root(&app)?;
    let plan = build_watch_plan(&persistence_dir, request)?;

    let mut runtime = watcher_state
        .runtime
        .lock()
        .map_err(|_| "File watcher runtime mutex poisoned".to_string())?;
    runtime.debouncer.take();

    if plan.is_empty() {
        return Ok(());
    }

    let app_handle = app.clone();
    let self_writes = watcher_state.self_writes.clone();
    let content_hashes = watcher_state.content_hashes.clone();
    let plan_for_callback = plan.clone();
    let mut debouncer = new_debouncer(
        Duration::from_millis(FILE_WATCH_DEBOUNCE_MS),
        move |result: DebounceEventResult| {
            handle_debounced_events(
                &app_handle,
                &self_writes,
                &content_hashes,
                &plan_for_callback,
                result,
            );
        },
    )
    .map_err(|err| format!("Failed to create file watcher debouncer: {err}"))?;

    for (path, mode) in &plan.watch_roots {
        debouncer
            .watcher()
            .watch(path, *mode)
            .map_err(|err| format!("Failed to watch {}: {err}", path.display()))?;
    }

    runtime.debouncer = Some(debouncer);
    Ok(())
}

#[tauri::command]
pub fn stop_swarm_file_watcher(
    watcher_state: State<'_, SwarmFileWatcherState>,
) -> Result<(), String> {
    let mut runtime = watcher_state
        .runtime
        .lock()
        .map_err(|_| "File watcher runtime mutex poisoned".to_string())?;
    runtime.debouncer.take();
    Ok(())
}

fn build_watch_plan(
    persistence_dir: &Path,
    request: ConfigureSwarmFileWatcherRequest,
) -> Result<WatchPlan, String> {
    let mut persistence_targets = HashMap::new();
    let mut workspace_targets = HashSet::new();
    let mut workspace_paths = Vec::new();

    for filename in request.persistence_filenames {
        validate_filename(&filename)?;
        let target = persistence_dir.join(&filename);
        persistence_targets.insert(normalize_watch_path(&target), filename);
    }

    for path in request.workspace_paths {
        let target = normalize_workspace_target(&path)?;
        workspace_paths.push(target.clone());
        workspace_targets.insert(normalize_watch_path(&target));
    }

    let mut watch_roots = HashMap::new();
    if !persistence_targets.is_empty() {
        watch_roots.insert(persistence_dir.to_path_buf(), RecursiveMode::NonRecursive);
    }

    for target in workspace_paths {
        if let Some((root, mode)) = resolve_watch_root(&target) {
            watch_roots
                .entry(root)
                .and_modify(|existing_mode| {
                    if mode == RecursiveMode::Recursive {
                        *existing_mode = RecursiveMode::Recursive;
                    }
                })
                .or_insert(mode);
        }
    }

    let mut sorted_roots = watch_roots.into_iter().collect::<Vec<_>>();
    sorted_roots.sort_by(|(left_path, left_mode), (right_path, right_mode)| {
        left_path
            .cmp(right_path)
            .then_with(|| recursive_mode_rank(*left_mode).cmp(&recursive_mode_rank(*right_mode)))
    });

    Ok(WatchPlan {
        watch_roots: sorted_roots,
        persistence_targets,
        workspace_targets,
    })
}

fn normalize_workspace_target(path: &str) -> Result<PathBuf, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Workspace watch paths must not be empty".to_string());
    }

    let target = PathBuf::from(trimmed);
    if !target.is_absolute() {
        return Err(format!(
            "Workspace watch paths must be absolute: {}",
            target.display()
        ));
    }

    Ok(target)
}

fn resolve_watch_root(target: &Path) -> Option<(PathBuf, RecursiveMode)> {
    let candidate = if target.is_dir() {
        target
    } else {
        target.parent()?
    };

    if candidate.exists() {
        return Some((candidate.to_path_buf(), RecursiveMode::NonRecursive));
    }

    find_existing_watch_root(candidate).map(|root| (root, RecursiveMode::Recursive))
}

fn find_existing_watch_root(path: &Path) -> Option<PathBuf> {
    if path.exists() {
        return Some(path.to_path_buf());
    }

    // Walk ancestors with a depth limit to prevent watching the filesystem root
    // on deeply nested missing paths. Depth 0 is `path` itself (already checked
    // above), so we count hops starting from the first parent.
    let mut depth = 0usize;
    for ancestor in path.ancestors().skip(1) {
        depth += 1;
        if depth > MAX_ANCESTOR_WALK_DEPTH {
            return None;
        }
        if ancestor.exists() {
            return Some(ancestor.to_path_buf());
        }
    }

    None
}

fn recursive_mode_rank(mode: RecursiveMode) -> u8 {
    match mode {
        RecursiveMode::NonRecursive => 0,
        RecursiveMode::Recursive => 1,
    }
}

fn normalize_watch_path_value(raw: &str, fold_case: bool) -> String {
    let normalized = raw.replace('\\', "/");
    if fold_case {
        normalized.to_ascii_lowercase()
    } else {
        normalized
    }
}

fn normalize_watch_path(path: &Path) -> String {
    normalize_watch_path_value(path.to_string_lossy().as_ref(), cfg!(windows))
}

fn handle_debounced_events<R: Runtime>(
    app: &AppHandle<R>,
    self_writes: &Arc<Mutex<HashMap<String, Instant>>>,
    content_hashes: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
    plan: &WatchPlan,
    result: DebounceEventResult,
) {
    let events = match result {
        Ok(events) => events,
        Err(err) => {
            eprintln!("[workbench] file watcher error: {err}");
            return;
        }
    };

    let filtered = match classify_events(events, self_writes, content_hashes, plan) {
        Some(events) => events,
        None => return,
    };

    for event in filtered {
        let _ = app.emit(SWARM_FILE_WATCH_EVENT, event);
    }
}

fn classify_events(
    events: Vec<notify_debouncer_mini::DebouncedEvent>,
    self_writes: &Arc<Mutex<HashMap<String, Instant>>>,
    content_hashes: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
    plan: &WatchPlan,
) -> Option<Vec<SwarmFileWatchEvent>> {
    let mut persistence_paths = HashSet::new();
    let mut persistence_filenames = HashSet::new();
    let mut workspace_paths = HashSet::new();

    for event in events {
        if should_suppress_path(self_writes, content_hashes, &event.path) {
            continue;
        }

        let normalized_path = normalize_watch_path(&event.path);
        if let Some(filename) = plan.persistence_targets.get(&normalized_path) {
            persistence_filenames.insert(filename.clone());
            persistence_paths.insert(event.path.clone());
            continue;
        }

        if plan.workspace_targets.contains(&normalized_path) {
            workspace_paths.insert(event.path.clone());
        }
    }

    let mut payloads = Vec::new();
    if !persistence_paths.is_empty() {
        payloads.push(SwarmFileWatchEvent {
            category: SwarmFileWatchCategory::Persistence,
            paths: sorted_display_paths(persistence_paths),
            filenames: {
                let mut filenames = persistence_filenames.into_iter().collect::<Vec<_>>();
                filenames.sort();
                filenames
            },
        });
    }

    if !workspace_paths.is_empty() {
        payloads.push(SwarmFileWatchEvent {
            category: SwarmFileWatchCategory::Workspace,
            filenames: workspace_paths
                .iter()
                .filter_map(|path| {
                    path.file_name()
                        .map(|name| name.to_string_lossy().to_string())
                })
                .collect::<HashSet<_>>()
                .into_iter()
                .collect::<Vec<_>>()
                .into_iter()
                .collect(),
            paths: sorted_display_paths(workspace_paths),
        });
        if let Some(last) = payloads.last_mut() {
            last.filenames.sort();
        }
    }

    (!payloads.is_empty()).then_some(payloads)
}

fn sorted_display_paths(paths: HashSet<PathBuf>) -> Vec<String> {
    let mut items = paths
        .into_iter()
        .map(|path| path.to_string_lossy().to_string())
        .collect::<Vec<_>>();
    items.sort();
    items
}

fn should_suppress_path(
    self_writes: &Arc<Mutex<HashMap<String, Instant>>>,
    content_hashes: &Arc<Mutex<HashMap<String, [u8; 32]>>>,
    path: &Path,
) -> bool {
    let now = Instant::now();
    let normalized_path = normalize_watch_path(path);

    let within_ttl = {
        let Ok(mut writes) = self_writes.lock() else {
            // Mutex poisoned — conservative default: let events through.
            return false;
        };
        prune_expired_self_writes(&mut writes, now);
        matches!(writes.get(&normalized_path), Some(deadline) if *deadline > now)
    };

    // Look up the recorded content hash (if any).
    let recorded_hash = {
        let Ok(hashes) = content_hashes.lock() else {
            // Mutex poisoned — conservative default: let events through.
            return false;
        };
        hashes.get(&normalized_path).copied()
    };

    let Some(expected_hash) = recorded_hash else {
        // No content hash recorded -- fall back to TTL-only behavior.
        return within_ttl;
    };

    // Always consume the hash entry after reading it (single-use check).
    // The hash is recorded fresh on every persistence write, so stale entries
    // serve no purpose and would cause the map to grow without bound.
    if let Ok(mut hashes) = content_hashes.lock() {
        hashes.remove(&normalized_path);
    }

    // Read the on-disk content and compute its hash.
    let disk_hash_matches = std::fs::read(path)
        .map(|bytes| {
            let disk_hash: [u8; 32] = Sha256::digest(&bytes).into();
            disk_hash == expected_hash
        })
        .unwrap_or(false);

    if within_ttl {
        // Within TTL window: suppress only if content matches (our write).
        // If content differs, an external write landed -- let it through.
        disk_hash_matches
    } else {
        // Outside TTL window: suppress if content still matches (late debouncer fire).
        disk_hash_matches
    }
}

fn prune_expired_self_writes(writes: &mut HashMap<String, Instant>, now: Instant) {
    writes.retain(|_, deadline| *deadline > now);
}

#[cfg(test)]
mod tests {
    use super::{
        build_watch_plan, classify_events, find_existing_watch_root, mark_self_writes,
        normalize_watch_path_value, record_content_hash, ConfigureSwarmFileWatcherRequest,
        SwarmFileWatchCategory, SwarmFileWatcherState, MAX_ANCESTOR_WALK_DEPTH,
    };
    use notify::RecursiveMode;
    use notify_debouncer_mini::{DebouncedEvent, DebouncedEventKind};
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[test]
    fn build_watch_plan_resolves_persistence_and_parent_dirs() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let workspace_dir = tempdir.path().join("workspace");
        std::fs::create_dir_all(&workspace_dir).expect("create workspace");
        let workspace_file = workspace_dir.join("artifact.md");

        let plan = build_watch_plan(
            tempdir.path(),
            ConfigureSwarmFileWatcherRequest {
                persistence_filenames: vec!["board.json".to_string()],
                workspace_paths: vec![workspace_file.to_string_lossy().to_string()],
            },
        )
        .expect("plan");

        assert_eq!(plan.persistence_targets.len(), 1);
        assert!(plan
            .persistence_targets
            .contains_key(&normalize_watch_path_value(
                tempdir.path().join("board.json").to_string_lossy().as_ref(),
                cfg!(windows),
            )));
        assert!(plan.workspace_targets.contains(&normalize_watch_path_value(
            workspace_file.to_string_lossy().as_ref(),
            cfg!(windows),
        )));
        assert!(plan
            .watch_roots
            .iter()
            .any(|(path, _)| path == &tempdir.path().join("workspace")));
    }

    #[test]
    fn build_watch_plan_uses_recursive_root_for_missing_nested_targets() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let workspace_dir = tempdir.path().join("workspace");
        std::fs::create_dir_all(&workspace_dir).expect("create workspace");
        let nested_target = workspace_dir.join("reports").join("daily").join("artifact.md");

        let plan = build_watch_plan(
            tempdir.path(),
            ConfigureSwarmFileWatcherRequest {
                persistence_filenames: vec![],
                workspace_paths: vec![nested_target.to_string_lossy().to_string()],
            },
        )
        .expect("plan");

        assert!(plan.watch_roots.iter().any(|(path, mode)| {
            path == &workspace_dir && *mode == RecursiveMode::Recursive
        }));
    }

    #[test]
    fn normalize_watch_path_value_folds_case_and_separators() {
        assert_eq!(
            normalize_watch_path_value("C:\\Repo\\Artifacts\\Result.JSON", true),
            "c:/repo/artifacts/result.json"
        );
        assert_eq!(
            normalize_watch_path_value("/tmp/repo/artifact.md", false),
            "/tmp/repo/artifact.md"
        );
    }

    #[test]
    fn classify_events_suppresses_recent_self_writes() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let target = tempdir.path().join("state.json");
        let workspace_file = tempdir.path().join("artifact.md");

        let plan = build_watch_plan(
            tempdir.path(),
            ConfigureSwarmFileWatcherRequest {
                persistence_filenames: vec!["state.json".to_string()],
                workspace_paths: vec![workspace_file.to_string_lossy().to_string()],
            },
        )
        .expect("plan");

        let watcher_state = SwarmFileWatcherState::default();
        mark_self_writes(&watcher_state, std::slice::from_ref(&target));

        let events = classify_events(
            vec![
                DebouncedEvent::new(target.clone(), DebouncedEventKind::Any),
                DebouncedEvent::new(workspace_file.clone(), DebouncedEventKind::Any),
            ],
            &watcher_state.self_writes,
            &watcher_state.content_hashes,
            &plan,
        )
        .expect("classified");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].category, SwarmFileWatchCategory::Workspace);
        assert_eq!(
            events[0].paths,
            vec![workspace_file.to_string_lossy().to_string()]
        );
    }

    #[test]
    fn classify_events_emits_persistence_and_workspace_batches() {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let target = tempdir.path().join("state.json");
        let workspace_file = tempdir.path().join("artifact.md");
        let plan = build_watch_plan(
            tempdir.path(),
            ConfigureSwarmFileWatcherRequest {
                persistence_filenames: vec!["state.json".to_string()],
                workspace_paths: vec![workspace_file.to_string_lossy().to_string()],
            },
        )
        .expect("plan");

        let self_writes = Arc::new(Mutex::new(Default::default()));
        let content_hashes = Arc::new(Mutex::new(Default::default()));
        let events = classify_events(
            vec![
                DebouncedEvent::new(target.clone(), DebouncedEventKind::Any),
                DebouncedEvent::new(workspace_file.clone(), DebouncedEventKind::Any),
            ],
            &self_writes,
            &content_hashes,
            &plan,
        )
        .expect("classified");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].category, SwarmFileWatchCategory::Persistence);
        assert_eq!(events[0].filenames, vec!["state.json".to_string()]);
        assert_eq!(
            events[1].paths,
            vec![PathBuf::from(&workspace_file).to_string_lossy().to_string()]
        );
    }

    #[test]
    fn content_hash_suppression() {
        // A file with a recorded content hash is suppressed even after the TTL window
        // expires (hash matches on-disk content).
        let tempdir = tempfile::tempdir().expect("tempdir");
        let target = tempdir.path().join("state.json");
        let content = b"{\"v\":42}";
        std::fs::write(&target, content).expect("write test file");

        let plan = build_watch_plan(
            tempdir.path(),
            ConfigureSwarmFileWatcherRequest {
                persistence_filenames: vec!["state.json".to_string()],
                workspace_paths: vec![],
            },
        )
        .expect("plan");

        let watcher_state = SwarmFileWatcherState::default();

        // Record self-write with TTL in the past (already expired).
        {
            let mut writes = watcher_state.self_writes.lock().unwrap();
            let expired_deadline = Instant::now() - Duration::from_millis(100);
            writes.insert(
                normalize_watch_path_value(target.to_string_lossy().as_ref(), cfg!(windows)),
                expired_deadline,
            );
        }

        // Record the content hash (simulating what persistence write does).
        record_content_hash(&watcher_state, &target, content);

        // Event should be suppressed because content hash matches on-disk file.
        let events = classify_events(
            vec![DebouncedEvent::new(target.clone(), DebouncedEventKind::Any)],
            &watcher_state.self_writes,
            &watcher_state.content_hashes,
            &plan,
        );
        assert!(
            events.is_none(),
            "self-write with matching content hash should be suppressed even after TTL expires"
        );
    }

    #[test]
    fn content_hash_allows_different_content() {
        // A file within the TTL window is NOT suppressed when the on-disk content hash
        // differs from the last-written hash (external write detection).
        let tempdir = tempfile::tempdir().expect("tempdir");
        let target = tempdir.path().join("state.json");
        let our_content = b"{\"v\":1}";
        let external_content = b"{\"v\":999}";

        // Write the external content to disk (simulating an external editor).
        std::fs::write(&target, external_content).expect("write test file");

        let plan = build_watch_plan(
            tempdir.path(),
            ConfigureSwarmFileWatcherRequest {
                persistence_filenames: vec!["state.json".to_string()],
                workspace_paths: vec![],
            },
        )
        .expect("plan");

        let watcher_state = SwarmFileWatcherState::default();

        // Record self-write with TTL still valid.
        mark_self_writes(&watcher_state, std::slice::from_ref(&target));

        // Record the content hash for OUR content (which differs from what's on disk).
        record_content_hash(&watcher_state, &target, our_content);

        // Event should NOT be suppressed because on-disk content differs from our hash.
        let events = classify_events(
            vec![DebouncedEvent::new(target.clone(), DebouncedEventKind::Any)],
            &watcher_state.self_writes,
            &watcher_state.content_hashes,
            &plan,
        );
        assert!(
            events.is_some(),
            "external write with different content hash should NOT be suppressed"
        );
        let events = events.unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].category, SwarmFileWatchCategory::Persistence);
    }

    #[test]
    fn self_write_ttl_expiry_without_hash() {
        // A file that has no content hash recorded is correctly let through after TTL
        // expires (backward compatibility).
        let tempdir = tempfile::tempdir().expect("tempdir");
        let target = tempdir.path().join("state.json");
        std::fs::write(&target, b"data").expect("write test file");

        let plan = build_watch_plan(
            tempdir.path(),
            ConfigureSwarmFileWatcherRequest {
                persistence_filenames: vec!["state.json".to_string()],
                workspace_paths: vec![],
            },
        )
        .expect("plan");

        let watcher_state = SwarmFileWatcherState::default();

        // Record self-write with expired TTL, no content hash.
        {
            let mut writes = watcher_state.self_writes.lock().unwrap();
            let expired_deadline = Instant::now() - Duration::from_millis(100);
            writes.insert(
                normalize_watch_path_value(target.to_string_lossy().as_ref(), cfg!(windows)),
                expired_deadline,
            );
        }

        // No content hash recorded -- should let through after TTL.
        let events = classify_events(
            vec![DebouncedEvent::new(target.clone(), DebouncedEventKind::Any)],
            &watcher_state.self_writes,
            &watcher_state.content_hashes,
            &plan,
        );
        assert!(
            events.is_some(),
            "event without content hash should pass through after TTL expires"
        );
    }

    #[test]
    fn ancestor_walk_depth_limit() {
        // find_existing_watch_root returns None when no ancestor exists within
        // MAX_ANCESTOR_WALK_DEPTH levels above the target.
        let tempdir = tempfile::tempdir().expect("tempdir");
        let base = tempdir.path().join("existing_root");
        std::fs::create_dir_all(&base).expect("create base");

        // Build a path that is MAX_ANCESTOR_WALK_DEPTH + 1 levels below `base`.
        let mut deep_path = base.clone();
        for i in 0..=MAX_ANCESTOR_WALK_DEPTH {
            deep_path = deep_path.join(format!("level_{i}"));
        }

        // The deep path and its intermediates don't exist on disk.
        // From the deepest point, walking MAX_ANCESTOR_WALK_DEPTH ancestors should
        // NOT reach `base` (which does exist).
        let result = find_existing_watch_root(&deep_path);
        assert!(
            result.is_none(),
            "should return None when existing ancestor is beyond depth limit, got: {:?}",
            result
        );
    }

    #[test]
    fn ancestor_walk_within_limit() {
        // find_existing_watch_root succeeds when an ancestor exists within 4 levels.
        let tempdir = tempfile::tempdir().expect("tempdir");
        let base = tempdir.path().join("root");
        std::fs::create_dir_all(&base).expect("create base");

        // Build a path that is exactly MAX_ANCESTOR_WALK_DEPTH levels below `base`.
        let mut target_path = base.clone();
        for i in 0..MAX_ANCESTOR_WALK_DEPTH {
            target_path = target_path.join(format!("sub_{i}"));
        }

        // Only `base` exists. Walking up MAX_ANCESTOR_WALK_DEPTH should reach it.
        let result = find_existing_watch_root(&target_path);
        assert!(
            result.is_some(),
            "should find existing ancestor within depth limit"
        );
        assert_eq!(result.unwrap(), base);
    }
}
