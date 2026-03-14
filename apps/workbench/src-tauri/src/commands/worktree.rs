//! Git worktree management commands for SwarmBoard.
//!
//! Each agent session can operate in an isolated worktree created under
//! `{repo_root}/.swarm-worktrees/`. This avoids interference between
//! concurrent agents working on the same repository.

use serde::Serialize;

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

/// Sanitise a branch name to be a valid directory name component.
/// Replaces path-unsafe characters and rejects traversal sequences.
fn sanitise_branch_name(branch: &str) -> Result<String, String> {
    let sanitised = branch.replace(
        ['/', '\\', ' ', ':', '*', '?', '"', '<', '>', '|', '.'],
        "-",
    );
    // Reject empty or pure-separator results
    let trimmed = sanitised.trim_matches('-');
    if trimmed.is_empty() {
        return Err(format!(
            "Branch name '{branch}' produces an empty directory name after sanitisation"
        ));
    }
    Ok(sanitised)
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Create a new git worktree for the given branch.
///
/// The worktree is created at `{repo_root}/.swarm-worktrees/{sanitised_branch}`.
/// If the branch does not exist, it is created from HEAD.
#[tauri::command]
pub async fn worktree_create(
    repo_root: String,
    branch_name: String,
) -> Result<WorktreeInfo, String> {
    if !std::path::Path::new(&repo_root).is_dir() {
        return Err(format!("Repository root does not exist: {repo_root}"));
    }
    if branch_name.is_empty() {
        return Err("Branch name must not be empty".to_string());
    }

    let worktree_base = std::path::Path::new(&repo_root).join(WORKTREE_DIR);
    std::fs::create_dir_all(&worktree_base).map_err(|e| {
        format!(
            "Failed to create worktree directory {}: {e}",
            worktree_base.display()
        )
    })?;

    let dir_name = sanitise_branch_name(&branch_name)?;
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

    // Check if the branch exists locally
    let branch_exists = run_git(
        &repo_root,
        &[
            "rev-parse",
            "--verify",
            &format!("refs/heads/{branch_name}"),
        ],
    )
    .is_ok();

    if branch_exists {
        // Add worktree using the existing branch
        run_git(
            &repo_root,
            &["worktree", "add", &worktree_path_str, &branch_name],
        )?;
    } else {
        // Create a new branch from HEAD
        run_git(
            &repo_root,
            &["worktree", "add", "-b", &branch_name, &worktree_path_str],
        )?;
    }

    let head = get_head_commit(&worktree_path_str);

    Ok(WorktreeInfo {
        path: worktree_path_str,
        branch: branch_name,
        head,
    })
}

/// Remove a git worktree and prune the reference.
#[tauri::command]
pub async fn worktree_remove(repo_root: String, worktree_path: String) -> Result<(), String> {
    if !std::path::Path::new(&repo_root).is_dir() {
        return Err(format!("Repository root does not exist: {repo_root}"));
    }

    // Validate that the worktree path is under the expected directory to
    // prevent removal of arbitrary directories.
    let canonical_root =
        std::fs::canonicalize(&repo_root).map_err(|e| format!("Cannot resolve repo root: {e}"))?;
    let expected_base = canonical_root.join(WORKTREE_DIR);

    // The worktree_path may or may not exist on disk (it might have been
    // manually deleted). We still try to remove via git, but we must verify
    // the path is under our worktree directory to prevent path traversal.
    if let Ok(canonical_wt) = std::fs::canonicalize(&worktree_path) {
        if !canonical_wt.starts_with(&expected_base) {
            return Err(format!(
                "Worktree path is not under {}: refusing to remove",
                expected_base.display()
            ));
        }
    } else {
        // Directory does not exist on disk — validate using lexical path
        // comparison. Resolve the worktree_path relative to repo_root if
        // it isn't absolute, then check it starts with the expected base.
        let wt_path = std::path::Path::new(&worktree_path);
        let resolved = if wt_path.is_absolute() {
            wt_path.to_path_buf()
        } else {
            canonical_root.join(wt_path)
        };
        // Check that the path, once joined, is under the expected base.
        // Use string prefix as a fallback since we can't canonicalize.
        if !resolved.starts_with(&expected_base) {
            return Err(format!(
                "Worktree path is not under {}: refusing to remove",
                expected_base.display()
            ));
        }
    }

    // Force-remove the worktree (handles dirty state)
    run_git(
        &repo_root,
        &["worktree", "remove", "--force", &worktree_path],
    )?;

    // Prune stale worktree references
    let _ = run_git(&repo_root, &["worktree", "prune"]);

    Ok(())
}

/// List all git worktrees for a repository.
#[tauri::command]
pub async fn worktree_list(repo_root: String) -> Result<Vec<WorktreeInfo>, String> {
    if !std::path::Path::new(&repo_root).is_dir() {
        return Err(format!("Repository root does not exist: {repo_root}"));
    }

    let output = run_git(&repo_root, &["worktree", "list", "--porcelain"])?;
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
}

/// Get the diff status of a worktree (changed files, added/removed lines).
#[tauri::command]
pub async fn worktree_status(worktree_path: String) -> Result<WorktreeStatus, String> {
    if !std::path::Path::new(&worktree_path).is_dir() {
        return Err(format!("Worktree path does not exist: {worktree_path}"));
    }

    // Get the list of changed files
    let diff_stat = run_git(&worktree_path, &["diff", "--stat"])?;

    let mut changed_files = Vec::new();
    let mut added_lines: usize = 0;
    let mut removed_lines: usize = 0;

    // Parse `git diff --stat` output. Each line looks like:
    //   src/main.rs | 10 +++++-----
    // The last line is a summary: "N files changed, M insertions(+), P deletions(-)"
    for line in diff_stat.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Check if this is the summary line
        if trimmed.contains("files changed")
            || trimmed.contains("file changed")
            || trimmed.contains("insertions")
            || trimmed.contains("deletions")
        {
            // Parse summary: "3 files changed, 15 insertions(+), 7 deletions(-)"
            for part in trimmed.split(',') {
                let part = part.trim();
                if part.contains("insertion") {
                    if let Some(num_str) = part.split_whitespace().next() {
                        added_lines = num_str.parse().unwrap_or(0);
                    }
                } else if part.contains("deletion") {
                    if let Some(num_str) = part.split_whitespace().next() {
                        removed_lines = num_str.parse().unwrap_or(0);
                    }
                }
            }
            continue;
        }

        // Otherwise it's a file line: "path/to/file | 10 +++---"
        if let Some(pipe_idx) = trimmed.find('|') {
            let file_path = trimmed[..pipe_idx].trim().to_string();
            if !file_path.is_empty() {
                changed_files.push(file_path);
            }
        }
    }

    // Also include untracked and staged changes.
    // `git status --porcelain` format: "XY filename" where XY is two status
    // chars followed by a space. Do NOT trim the line — leading chars are
    // part of the status code. Use char indexing to avoid panics on
    // multi-byte UTF-8 filenames.
    let status_output = run_git(&worktree_path, &["status", "--porcelain"]).unwrap_or_default();
    for line in status_output.lines() {
        if line.len() >= 4 {
            let file_path = line[3..].trim().to_string();
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
}
