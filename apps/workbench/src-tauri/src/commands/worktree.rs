//! Git worktree management commands for SwarmBoard.
//!
//! Each agent session can operate in an isolated worktree created under
//! `{repo_root}/.swarm-worktrees/`. This avoids interference between
//! concurrent agents working on the same repository.

use serde::Serialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tauri::Runtime;

use crate::commands::capability::{authorize_sensitive_command, CommandCapabilityState};
use crate::commands::repo_roots;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Information about a git worktree.
#[derive(Serialize, Clone)]
pub struct WorktreeInfo {
    pub path: String,
    pub branch: String,
    pub head: String,
}

/// Diff statistics for a worktree.
#[derive(Serialize, Clone)]
pub struct WorktreeStatus {
    pub changed_files: Vec<String>,
    pub added_lines: usize,
    pub removed_lines: usize,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Subdirectory under the repo root where swarm worktrees are created.
const WORKTREE_DIR: &str = ".swarm-worktrees";
const GIT_OP_TIMEOUT_SECS: u64 = 20;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run a git command in the given directory and return its stdout as a string.
fn run_git(cwd: &str, args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .args(args)
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to run git: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!(
            "git {} failed: {}",
            args.join(" "),
            if stderr.is_empty() {
                format!("exit code {}", output.status.code().unwrap_or(-1))
            } else {
                stderr
            }
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Get the HEAD commit hash for a worktree path.
fn get_head_commit(worktree_path: &str) -> String {
    run_git(worktree_path, &["rev-parse", "--short", "HEAD"])
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Encode a branch name into a reversible filesystem-safe directory component.
///
/// Hex encoding avoids collisions that lossy sanitization can introduce.
fn branch_dir_name(branch: &str) -> String {
    format!("branch-{}", hex::encode(branch.as_bytes()))
}

async fn run_blocking_with_timeout<T, F>(operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    let join = tauri::async_runtime::spawn_blocking(operation);
    let timed = tokio::time::timeout(Duration::from_secs(GIT_OP_TIMEOUT_SECS), join)
        .await
        .map_err(|_| {
            format!(
                "Worktree operation timed out after {}s",
                GIT_OP_TIMEOUT_SECS
            )
        })?;
    timed.map_err(|e| format!("Worktree operation failed: {e}"))?
}

fn canonical_repo_root(repo_root: &str) -> Result<PathBuf, String> {
    let canonical = std::fs::canonicalize(repo_root)
        .map_err(|e| format!("Cannot resolve repo root '{repo_root}': {e}"))?;
    if !canonical.is_dir() {
        return Err(format!("Repository root is not a directory: {repo_root}"));
    }
    let canonical_str = canonical.to_string_lossy().to_string();
    let inside = run_git(&canonical_str, &["rev-parse", "--is-inside-work-tree"])?;
    if inside.trim() != "true" {
        return Err(format!(
            "Repository root is not a git work tree: {repo_root}"
        ));
    }
    repo_roots::ensure_repo_root_approved(&canonical)
}

fn normalize_branch_name(repo_root: &str, branch_name: &str) -> Result<String, String> {
    let trimmed = branch_name.trim();
    if trimmed.is_empty() {
        return Err("Branch name must not be empty".to_string());
    }
    if trimmed.len() > 255 {
        return Err("Branch name is too long".to_string());
    }
    if trimmed.starts_with('-') {
        return Err("Branch name must not start with '-'".to_string());
    }
    if trimmed.contains("..") {
        return Err("Branch name must not contain '..'".to_string());
    }
    if trimmed.chars().any(|c| c.is_ascii_control()) {
        return Err("Branch name contains control characters".to_string());
    }
    if trimmed.chars().any(|c| c.is_whitespace()) {
        return Err("Branch name must not contain whitespace".to_string());
    }
    // Reject shell metacharacters that could be used for injection.
    const SHELL_META: &[char] = &['`', '$', '(', ')', '{', '}', ';', '&', '|', '!', '#', '\\'];
    if trimmed.chars().any(|c| SHELL_META.contains(&c)) {
        return Err("Branch name contains disallowed shell metacharacters".to_string());
    }
    run_git(repo_root, &["check-ref-format", "--branch", trimmed])?;
    Ok(trimmed.to_string())
}

fn canonicalize_worktree_path(candidate: &str, expected_base: &Path) -> Result<PathBuf, String> {
    use std::path::Component;

    let candidate_path = Path::new(candidate);

    // Reject paths with parent-directory traversal components before canonicalization.
    // This catches `..` even if the path doesn't exist on disk yet.
    if candidate_path
        .components()
        .any(|c| matches!(c, Component::ParentDir))
    {
        return Err("Worktree path must not contain '..' components".to_string());
    }

    let canonical = std::fs::canonicalize(candidate)
        .map_err(|e| format!("Worktree path must exist and be resolvable: {e}"))?;
    if !canonical.is_dir() {
        return Err(format!(
            "Worktree path is not a directory: {}",
            canonical.display()
        ));
    }
    if !canonical.starts_with(expected_base) {
        return Err(format!(
            "Worktree path is not under {}: refusing to remove",
            expected_base.display()
        ));
    }
    Ok(canonical)
}

fn resolve_worktree_base(repo_root: &Path) -> Result<PathBuf, String> {
    let canonical_root = std::fs::canonicalize(repo_root).map_err(|e| {
        format!(
            "Cannot resolve repository root {}: {e}",
            repo_root.display()
        )
    })?;
    let worktree_base = repo_root.join(WORKTREE_DIR);

    if std::fs::symlink_metadata(&worktree_base)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(format!(
            "Worktree directory must not be a symlink: {}",
            worktree_base.display()
        ));
    }

    std::fs::create_dir_all(&worktree_base).map_err(|e| {
        format!(
            "Failed to create worktree directory {}: {e}",
            worktree_base.display()
        )
    })?;

    let canonical_base = std::fs::canonicalize(&worktree_base).map_err(|e| {
        format!(
            "Failed to resolve worktree directory {}: {e}",
            worktree_base.display()
        )
    })?;

    if canonical_base.parent() != Some(canonical_root.as_path())
        || !canonical_base.starts_with(&canonical_root)
    {
        return Err(format!(
            "Worktree directory escaped repository root: {}",
            canonical_base.display()
        ));
    }

    Ok(canonical_base)
}

fn is_registered_worktree(repo_root: &str, target: &Path) -> Result<bool, String> {
    let output = run_git(repo_root, &["worktree", "list", "--porcelain"])?;
    for line in output.lines() {
        if let Some(path) = line.strip_prefix("worktree ") {
            if let Ok(canonical) = std::fs::canonicalize(path) {
                if canonical == target {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Create a new git worktree for the given branch.
///
/// The worktree is created at `{repo_root}/.swarm-worktrees/{encoded_branch}`.
/// If the branch does not exist, it is created from HEAD.
#[tauri::command]
pub async fn worktree_create<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    repo_root: String,
    branch_name: String,
) -> Result<WorktreeInfo, String> {
    authorize_sensitive_command(&window, &capability_state, "worktree_create").await?;
    run_blocking_with_timeout(move || {
        let canonical_root = canonical_repo_root(&repo_root)?;
        let canonical_root_str = canonical_root.to_string_lossy().to_string();
        let normalized_branch = normalize_branch_name(&canonical_root_str, &branch_name)?;

        let worktree_base = resolve_worktree_base(&canonical_root)?;

        let dir_name = branch_dir_name(&normalized_branch);
        let worktree_path = worktree_base.join(&dir_name);
        let worktree_path_str = worktree_path.to_string_lossy().to_string();

        // If the worktree directory already exists, it might be a stale entry.
        // Let the user clean it up explicitly rather than silently overwriting.
        if worktree_path.exists() {
            return Err(format!(
                "Worktree directory already exists: {worktree_path_str}. \
                 Remove it with worktree_remove first."
            ));
        }

        // Use refs/heads/ prefix for rev-parse to prevent flag injection
        // (a branch named "--git-dir=..." would be interpreted as a flag without the prefix).
        let qualified_ref = format!("refs/heads/{normalized_branch}");

        // Check if the branch exists locally
        let branch_exists = run_git(
            &canonical_root_str,
            &["rev-parse", "--verify", &qualified_ref],
        )
        .is_ok();

        if branch_exists {
            // Syntax: git worktree add <path> <branch>
            // normalize_branch_name already rejects names starting with `-`,
            // containing `..`, or with shell metacharacters.
            run_git(
                &canonical_root_str,
                &["worktree", "add", &worktree_path_str, &normalized_branch],
            )?;
        } else {
            // Syntax: git worktree add -b <new-branch> <path>
            run_git(
                &canonical_root_str,
                &[
                    "worktree",
                    "add",
                    "-b",
                    &normalized_branch,
                    &worktree_path_str,
                ],
            )?;
        }

        let head = get_head_commit(&worktree_path_str);

        Ok(WorktreeInfo {
            path: worktree_path_str,
            branch: normalized_branch,
            head,
        })
    })
    .await
}

/// Remove a git worktree and prune the reference.
#[tauri::command]
pub async fn worktree_remove<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    repo_root: String,
    worktree_path: String,
) -> Result<(), String> {
    authorize_sensitive_command(&window, &capability_state, "worktree_remove").await?;
    run_blocking_with_timeout(move || {
        let canonical_root = canonical_repo_root(&repo_root)?;
        let canonical_root_str = canonical_root.to_string_lossy().to_string();

        // Validate that the worktree path exists and is under the expected directory
        // to prevent removal of arbitrary directories.
        let expected_base = canonical_root.join(WORKTREE_DIR);
        let canonical_wt = canonicalize_worktree_path(&worktree_path, &expected_base)?;
        if !is_registered_worktree(&canonical_root_str, &canonical_wt)? {
            return Err("Target path is not a registered git worktree".to_string());
        }
        let canonical_wt_str = canonical_wt.to_string_lossy().to_string();

        // Force-remove the worktree (handles dirty state)
        run_git(
            &canonical_root_str,
            &["worktree", "remove", "--force", &canonical_wt_str],
        )?;

        // Prune stale worktree references
        let _ = run_git(&canonical_root_str, &["worktree", "prune"]);

        Ok(())
    })
    .await
}

/// List all git worktrees for a repository.
#[tauri::command]
pub async fn worktree_list<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    repo_root: String,
) -> Result<Vec<WorktreeInfo>, String> {
    authorize_sensitive_command(&window, &capability_state, "worktree_list").await?;
    run_blocking_with_timeout(move || {
        let canonical_root = canonical_repo_root(&repo_root)?;
        let canonical_root_str = canonical_root.to_string_lossy().to_string();

        let output = run_git(&canonical_root_str, &["worktree", "list", "--porcelain"])?;
        let mut worktrees = Vec::new();
        let mut current_path = String::new();
        let mut current_head = String::new();
        let mut current_branch = String::new();

        for line in output.lines() {
            if let Some(path) = line.strip_prefix("worktree ") {
                // Flush the previous entry if any
                if !current_path.is_empty() {
                    worktrees.push(WorktreeInfo {
                        path: current_path.clone(),
                        branch: current_branch.clone(),
                        head: current_head.clone(),
                    });
                }
                current_path = path.to_string();
                current_head.clear();
                current_branch.clear();
            } else if let Some(head) = line.strip_prefix("HEAD ") {
                current_head = head.chars().take(7).collect();
            } else if let Some(branch) = line.strip_prefix("branch refs/heads/") {
                current_branch = branch.to_string();
            } else if line == "bare" || line == "detached" {
                // Mark detached HEAD or bare repos
                if current_branch.is_empty() {
                    current_branch = "(detached)".to_string();
                }
            }
        }

        // Don't forget the last entry
        if !current_path.is_empty() {
            worktrees.push(WorktreeInfo {
                path: current_path,
                branch: current_branch,
                head: current_head,
            });
        }

        Ok(worktrees)
    })
    .await
}

/// Get the diff status of a worktree (changed files, added/removed lines).
#[tauri::command]
pub async fn worktree_status<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    repo_root: String,
    worktree_path: String,
) -> Result<WorktreeStatus, String> {
    authorize_sensitive_command(&window, &capability_state, "worktree_status").await?;
    run_blocking_with_timeout(move || {
        let canonical_root = canonical_repo_root(&repo_root)?;
        let canonical_root_str = canonical_root.to_string_lossy().to_string();
        let expected_base = canonical_root.join(WORKTREE_DIR);
        let canonical_wt = canonicalize_worktree_path(&worktree_path, &expected_base)?;
        if !is_registered_worktree(&canonical_root_str, &canonical_wt)? {
            return Err("Target path is not a registered git worktree".to_string());
        }
        let worktree_path = canonical_wt.to_string_lossy().to_string();

        // Get the list of changed files from both unstaged and staged diffs.
        let diff_stat = run_git(&worktree_path, &["diff", "--stat"])?;
        let cached_stat =
            run_git(&worktree_path, &["diff", "--cached", "--stat"]).unwrap_or_default();

        let mut changed_files = Vec::new();
        let mut added_lines: usize = 0;
        let mut removed_lines: usize = 0;

        // Parse a `git diff --stat` block, accumulating files and line counts.
        let parse_stat_block =
            |block: &str, files: &mut Vec<String>, added: &mut usize, removed: &mut usize| {
                for line in block.lines() {
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }

                    // Check if this is the summary line.
                    // Match the specific git diff --stat format:
                    //   "N file(s) changed, N insertion(s)(+), N deletion(s)(-)"
                    // Require that the line starts with a number followed by "file"
                    // to avoid false positives on filenames containing these words.
                    let is_summary = trimmed
                        .split_whitespace()
                        .next()
                        .and_then(|first| first.parse::<usize>().ok())
                        .is_some()
                        && (trimmed.contains("file changed") || trimmed.contains("files changed"));
                    if is_summary {
                        for part in trimmed.split(',') {
                            let part = part.trim();
                            if part.contains("insertion") {
                                if let Some(num_str) = part.split_whitespace().next() {
                                    *added += num_str.parse::<usize>().unwrap_or(0);
                                }
                            } else if part.contains("deletion") {
                                if let Some(num_str) = part.split_whitespace().next() {
                                    *removed += num_str.parse::<usize>().unwrap_or(0);
                                }
                            }
                        }
                        continue;
                    }

                    // Otherwise it's a file line: "path/to/file | 10 +++---"
                    if let Some(pipe_idx) = trimmed.find('|') {
                        if let Some(file_part) = trimmed.get(..pipe_idx) {
                            let file_path = file_part.trim().to_string();
                            if !file_path.is_empty() && !files.contains(&file_path) {
                                files.push(file_path);
                            }
                        }
                    }
                }
            };

        // Parse unstaged changes
        parse_stat_block(
            &diff_stat,
            &mut changed_files,
            &mut added_lines,
            &mut removed_lines,
        );
        // Parse staged (cached) changes
        parse_stat_block(
            &cached_stat,
            &mut changed_files,
            &mut added_lines,
            &mut removed_lines,
        );

        // Also include untracked and staged changes.
        // `git status --porcelain` format: "XY filename" where XY is two status
        // chars followed by a space. Do NOT trim the line — leading chars are
        // part of the status code. Use char indexing to avoid panics on
        // multi-byte UTF-8 filenames.
        let status_output = run_git(&worktree_path, &["status", "--porcelain"]).unwrap_or_default();
        for line in status_output.lines() {
            if let Some(rest) = line.get(3..) {
                let file_path = rest.trim().to_string();
                if !file_path.is_empty() && !changed_files.contains(&file_path) {
                    changed_files.push(file_path);
                }
            }
        }

        Ok(WorktreeStatus {
            changed_files,
            added_lines,
            removed_lines,
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_worktree_base_accepts_real_directory() {
        let repo_root = tempfile::tempdir().expect("temp repo root");
        let resolved = resolve_worktree_base(repo_root.path()).expect("expected real directory");
        let expected = repo_root
            .path()
            .canonicalize()
            .expect("canonical repo root")
            .join(WORKTREE_DIR);

        assert_eq!(resolved, expected);
    }

    #[cfg(unix)]
    #[test]
    fn resolve_worktree_base_rejects_symlink() {
        let repo_root = tempfile::tempdir().expect("temp repo root");
        let escaped = tempfile::tempdir().expect("escaped target");
        let link_path = repo_root.path().join(WORKTREE_DIR);

        std::os::unix::fs::symlink(escaped.path(), &link_path).expect("create symlink");

        let err = resolve_worktree_base(repo_root.path()).expect_err("expected symlink rejection");
        assert!(err.contains("must not be a symlink"));
    }
}
