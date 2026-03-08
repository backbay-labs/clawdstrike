#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Integration tests for nono sandbox enforcement.
//!
//! These tests invoke the `hush` CLI binary as a subprocess because
//! `Sandbox::apply()` restricts the calling process -- we need a fresh
//! process for each test case.
//!
//! Commands run under `--sandbox nono` use `execve` (not `execvp`), so
//! all command paths must be absolute (e.g. `/bin/echo` not `echo`).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..")
}

fn resolve_hush_binary() -> PathBuf {
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_hush") {
        return PathBuf::from(path);
    }

    let candidate = workspace_root()
        .join("target")
        .join("debug")
        .join(if cfg!(windows) { "hush.exe" } else { "hush" });

    if candidate.exists() {
        return candidate;
    }

    let status = Command::new("cargo")
        .current_dir(workspace_root())
        .arg("build")
        .arg("-p")
        .arg("hush-cli")
        .arg("--bin")
        .arg("hush")
        .status()
        .expect("build hush binary for sandbox nono tests");
    assert!(
        status.success(),
        "failed to build hush binary for sandbox nono tests"
    );
    candidate
}

fn create_temp_dir(prefix: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), seq));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

/// Write a minimal policy YAML and return its path.
fn write_policy(dir: &Path) -> PathBuf {
    let policy_path = dir.join("policy.yaml");
    fs::write(
        &policy_path,
        "version: \"1.1.0\"\nname: \"sandbox-nono-test\"\n",
    )
    .expect("write policy");
    policy_path
}

fn write_allowlist_policy(dir: &Path, allowed_path: &str) -> PathBuf {
    let policy_path = dir.join("policy-allowlist.yaml");
    fs::write(
        &policy_path,
        format!(
            "version: \"1.2.0\"\nname: \"sandbox-nono-allowlist\"\nguards:\n  path_allowlist:\n    enabled: true\n    file_access_allow:\n      - \"{allowed_path}\"\n"
        ),
    )
    .expect("write allowlist policy");
    policy_path
}

/// Find the absolute path to a command via `which`.
fn which(cmd: &str) -> Option<String> {
    Command::new("which")
        .arg(cmd)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

struct TestResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

/// Run `hush run` with the given sandbox mode and command, return result.
///
/// Uses `--no-proxy` to skip proxy startup for faster tests.
fn run_hush(sandbox_mode: &str, policy_path: &PathBuf, args: &[&str]) -> TestResult {
    let work_dir = create_temp_dir("hush-sandbox-nono-work");
    let events_path = work_dir.join("events.jsonl");
    let receipt_path = work_dir.join("receipt.json");
    let key_path = work_dir.join("hush.key");

    let mut cmd = Command::new(resolve_hush_binary());
    cmd.arg("run")
        .arg("--policy")
        .arg(policy_path)
        .arg("--events-out")
        .arg(&events_path)
        .arg("--receipt-out")
        .arg(&receipt_path)
        .arg("--signing-key")
        .arg(&key_path)
        .arg("--no-proxy")
        .arg("--sandbox")
        .arg(sandbox_mode)
        .arg("--");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn hush run");
    let started = Instant::now();
    let timeout = Duration::from_secs(30);

    loop {
        match child.try_wait().expect("try_wait hush") {
            Some(_) => {
                let output = child.wait_with_output().expect("wait_with_output hush");
                let _ = fs::remove_dir_all(&work_dir);
                return TestResult {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                };
            }
            None => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let output = child
                        .wait_with_output()
                        .expect("wait_with_output after kill");
                    let _ = fs::remove_dir_all(&work_dir);
                    return TestResult {
                        exit_code: output.status.code().unwrap_or(-1),
                        stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                        stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    };
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Returns true if nono sandbox enforcement was skipped (unsupported platform).
fn is_sandbox_unsupported(result: &TestResult) -> bool {
    result
        .stderr
        .contains("[nono] warning: sandbox not supported")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn sandbox_none_allows_basic_command() {
    let dir = create_temp_dir("hush-sandbox-none");
    let policy = write_policy(&dir);
    // --sandbox none uses Command::new which does PATH lookup, so bare names work
    let result = run_hush("none", &policy, &["echo", "hello"]);
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        result.exit_code, 0,
        "echo should succeed with --sandbox none; stderr:\n{}",
        result.stderr
    );
    assert!(
        result.stdout.contains("hello"),
        "should see echo output; stdout:\n{}",
        result.stdout
    );
}

#[test]
fn sandbox_none_skips_enforcement() {
    let dir = create_temp_dir("hush-sandbox-none-true");
    let policy = write_policy(&dir);
    let result = run_hush("none", &policy, &["true"]);
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        result.exit_code, 0,
        "true should succeed with --sandbox none; stderr:\n{}",
        result.stderr
    );
}

#[test]
fn sandbox_nono_runs_basic_command() {
    let echo = match which("echo") {
        Some(p) => p,
        None => return, // cannot find echo, skip
    };

    let dir = create_temp_dir("hush-sandbox-nono-basic");
    let policy = write_policy(&dir);
    let result = run_hush("nono", &policy, &[&echo, "sandbox_works"]);
    let _ = fs::remove_dir_all(&dir);

    if is_sandbox_unsupported(&result) {
        assert!(
            result.exit_code == 0 || result.exit_code == 126,
            "should exit 0 (fallback) or 126 (sandbox apply failed); got {}; stderr:\n{}",
            result.exit_code,
            result.stderr
        );
        return;
    }

    assert_eq!(
        result.exit_code, 0,
        "echo should succeed in nono sandbox; stderr:\n{}",
        result.stderr
    );
    assert!(
        result.stdout.contains("sandbox_works"),
        "should see echo output; stdout:\n{}",
        result.stdout
    );
}

#[test]
fn sandbox_nono_blocks_sensitive_paths() {
    let ls = match which("ls") {
        Some(p) => p,
        None => return,
    };
    let home = match std::env::var("HOME") {
        Ok(h) => h,
        Err(_) => return,
    };
    let ssh_path = format!("{}/.ssh", home);
    if !std::path::Path::new(&ssh_path).exists() {
        return;
    }

    let dir = create_temp_dir("hush-sandbox-nono-ssh");
    let policy = write_policy(&dir);
    let result = run_hush("nono", &policy, &[&ls, &ssh_path]);
    let _ = fs::remove_dir_all(&dir);

    if is_sandbox_unsupported(&result) {
        return;
    }

    assert_ne!(
        result.exit_code, 0,
        "ls ~/.ssh should fail in nono sandbox; stdout:\n{}\nstderr:\n{}",
        result.stdout, result.stderr
    );
}

#[test]
fn sandbox_nono_allows_tmp_listing() {
    let ls = match which("ls") {
        Some(p) => p,
        None => return,
    };

    // Use /tmp directly (not std::env::temp_dir() which may resolve to
    // /var/folders on macOS, outside the sandbox's allowed paths).
    let tmp_subdir = PathBuf::from("/tmp").join(format!(
        "hush-sandbox-nono-ls-{}-{}",
        std::process::id(),
        TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&tmp_subdir).expect("create /tmp subdir");

    let policy_dir = create_temp_dir("hush-sandbox-nono-ls-policy");
    let policy = write_policy(&policy_dir);

    let result = run_hush("nono", &policy, &[&ls, tmp_subdir.to_str().unwrap()]);

    let _ = fs::remove_dir_all(&tmp_subdir);
    let _ = fs::remove_dir_all(&policy_dir);

    if is_sandbox_unsupported(&result) {
        return;
    }

    assert_eq!(
        result.exit_code, 0,
        "ls of /tmp subdir should succeed; stderr:\n{}",
        result.stderr
    );
}

#[test]
fn sandbox_nono_stderr_shows_sandbox_note() {
    let true_bin = match which("true") {
        Some(p) => p,
        None => return,
    };

    let dir = create_temp_dir("hush-sandbox-nono-note");
    let policy = write_policy(&dir);
    let result = run_hush("nono", &policy, &[&true_bin]);
    let _ = fs::remove_dir_all(&dir);

    // When nono sandbox is used, stderr should mention "nono" in the
    // sandbox note or a warning about support.
    let stderr_lower = result.stderr.to_lowercase();
    assert!(
        stderr_lower.contains("nono"),
        "stderr should mention nono sandbox; stderr:\n{}",
        result.stderr
    );
}

#[test]
fn sandbox_nono_child_exit_code_propagated() {
    let false_bin = match which("false") {
        Some(p) => p,
        None => return,
    };

    let dir = create_temp_dir("hush-sandbox-nono-exit");
    let policy = write_policy(&dir);
    let result = run_hush("nono", &policy, &[&false_bin]);
    let _ = fs::remove_dir_all(&dir);

    if is_sandbox_unsupported(&result) {
        return;
    }

    // `false` exits with code 1; hush should propagate it
    assert_ne!(
        result.exit_code, 0,
        "false command should result in non-zero exit; stderr:\n{}",
        result.stderr
    );
}

#[test]
fn sandbox_nono_preflight_fail_exits_without_deadlock() {
    let true_bin = match which("true") {
        Some(p) => p,
        None => return,
    };

    let dir = create_temp_dir("hush-sandbox-nono-preflight");
    let allowed = dir.join("allowed.txt");
    fs::write(&allowed, "ok").expect("write allowlisted file");
    let policy = write_allowlist_policy(&dir, allowed.to_str().unwrap());

    let result = run_hush("nono", &policy, &[&true_bin]);
    let _ = fs::remove_dir_all(&dir);

    assert_eq!(
        result.exit_code, 4,
        "preflight failure should exit cleanly instead of hanging; stderr:\n{}",
        result.stderr
    );
    assert!(
        result
            .stderr
            .contains("sandbox pre-flight failed (fail-closed)"),
        "stderr should explain the fail-closed preflight result; stderr:\n{}",
        result.stderr
    );
}
