//! Backend-owned approved repository root registry.
//!
//! Sensitive terminal/worktree commands must operate only inside approved
//! repository roots. Roots are loaded from backend-managed storage. In debug
//! builds, the process working directory is also implicitly seeded; release
//! builds require every root to be explicitly approved.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use tauri::{AppHandle, Manager, Runtime};

const APPROVED_ROOTS_FILE: &str = "approved-repo-roots.json";

static APPROVED_REPO_ROOTS: std::sync::OnceLock<std::sync::Mutex<HashSet<String>>> =
    std::sync::OnceLock::new();

fn approved_repo_roots() -> &'static std::sync::Mutex<HashSet<String>> {
    APPROVED_REPO_ROOTS.get_or_init(|| std::sync::Mutex::new(HashSet::new()))
}

fn canonical_path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn resolve_git_toplevel(path: &Path) -> Result<PathBuf, String> {
    let cwd = path.to_string_lossy().to_string();
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to resolve git toplevel for {}: {e}", path.display()))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(if stderr.is_empty() {
            format!("Path is not inside a git worktree: {}", path.display())
        } else {
            format!("Failed to resolve git toplevel: {stderr}")
        });
    }

    let top = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if top.is_empty() {
        return Err(format!(
            "git rev-parse returned an empty repo root for {}",
            path.display()
        ));
    }

    std::fs::canonicalize(&top)
        .map_err(|e| format!("Failed to canonicalize git repo root {top}: {e}"))
}

fn load_approved_roots(path: &Path) -> HashSet<String> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(_) => return HashSet::new(),
    };

    let parsed: Vec<String> = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(err) => {
            eprintln!(
                "[repo-roots] Failed to parse approved roots file {}: {}",
                path.display(),
                err
            );
            return HashSet::new();
        }
    };

    let mut roots = HashSet::new();
    for candidate in parsed {
        if let Ok(canonical) = std::fs::canonicalize(&candidate) {
            if canonical.is_dir() {
                roots.insert(canonical_path_to_string(&canonical));
            }
        }
    }
    roots
}

fn persist_approved_roots(path: &Path, roots: &HashSet<String>) -> Result<(), String> {
    let mut sorted: Vec<String> = roots.iter().cloned().collect();
    sorted.sort();

    let payload = serde_json::to_string_pretty(&sorted)
        .map_err(|e| format!("Failed to serialize approved repo roots: {e}"))?;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create approved roots directory {}: {e}",
                parent.display()
            )
        })?;
    }

    std::fs::write(path, payload)
        .map_err(|e| format!("Failed to persist approved roots {}: {e}", path.display()))
}

pub fn init_approved_repo_roots<R: Runtime>(app: &AppHandle<R>) -> Result<(), String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir for approved roots: {e}"))?;
    let roots_path = app_data_dir.join(APPROVED_ROOTS_FILE);

    let mut roots = load_approved_roots(&roots_path);

    // Only implicitly trust the process CWD in debug builds. In release
    // builds, every repo root must be explicitly approved by the user so that
    // the approved-roots boundary cannot be bypassed by launch context.
    #[cfg(debug_assertions)]
    {
        if let Ok(cwd) = std::env::current_dir() {
            if let Ok(git_root) = resolve_git_toplevel(&cwd) {
                roots.insert(canonical_path_to_string(&git_root));
            }
        }
    }

    {
        let mut guard = approved_repo_roots()
            .lock()
            .map_err(|_| "Approved repo roots lock poisoned".to_string())?;
        *guard = roots.clone();
    }

    persist_approved_roots(&roots_path, &roots)?;
    Ok(())
}

fn is_approved_repo_root(repo_root: &Path) -> Result<bool, String> {
    let canonical = std::fs::canonicalize(repo_root).map_err(|e| {
        format!(
            "Cannot resolve repository root {}: {e}",
            repo_root.display()
        )
    })?;
    let key = canonical_path_to_string(&canonical);

    let guard = approved_repo_roots()
        .lock()
        .map_err(|_| "Approved repo roots lock poisoned".to_string())?;
    Ok(guard.contains(&key))
}

pub fn ensure_repo_root_approved(repo_root: &Path) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(repo_root).map_err(|e| {
        format!(
            "Cannot resolve repository root {}: {e}",
            repo_root.display()
        )
    })?;
    let top_level = resolve_git_toplevel(&canonical)?;

    if !is_approved_repo_root(&top_level)? {
        return Err(format!(
            "Repository root is not approved for sensitive IPC operations: {}",
            top_level.display()
        ));
    }

    Ok(top_level)
}

pub fn ensure_path_within_approved_repo(path: &Path) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(path)
        .map_err(|e| format!("Cannot resolve path {}: {e}", path.display()))?;

    let top_level = resolve_git_toplevel(&canonical)?;
    if !is_approved_repo_root(&top_level)? {
        return Err(format!(
            "Path resolves to an unapproved repository root: {}",
            top_level.display()
        ));
    }

    if !canonical.starts_with(&top_level) {
        return Err(format!(
            "Path escapes approved repository root {}: {}",
            top_level.display(),
            canonical.display()
        ));
    }

    Ok(canonical)
}
