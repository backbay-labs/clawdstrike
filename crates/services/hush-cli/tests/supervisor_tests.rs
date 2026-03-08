#![allow(clippy::expect_used, clippy::unwrap_used)]

//! Integration tests for supervisor enforcement (Phase 4B).
//!
//! Tests verify:
//! 1. Receipt includes sandbox attestation with correct JSON schema
//! 2. Never-grant list blocks critical paths regardless of policy
//! 3. Attestation types serialize/deserialize correctly
//! 4. GuardSupervisorBackend correctly routes through ClawdStrike guards

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
        .expect("build hush binary for supervisor tests");
    assert!(
        status.success(),
        "failed to build hush binary for supervisor tests"
    );
    candidate
}

fn create_temp_dir(prefix: &str) -> PathBuf {
    let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("{}-{}-{}", prefix, std::process::id(), seq));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn which(cmd: &str) -> Option<String> {
    Command::new("which")
        .arg(cmd)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
}

#[allow(dead_code)]
struct TestResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
    receipt_json: Option<serde_json::Value>,
}

/// Run `hush run` and capture both output and receipt JSON.
fn run_hush_with_receipt(
    sandbox_mode: &str,
    supervised: bool,
    policy_path: &PathBuf,
    args: &[&str],
) -> TestResult {
    let work_dir = create_temp_dir("hush-supervisor-work");
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
        .arg(sandbox_mode);
    if supervised {
        cmd.arg("--supervised");
    }
    cmd.arg("--");
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
                let receipt_json = fs::read_to_string(&receipt_path)
                    .ok()
                    .and_then(|s| serde_json::from_str(&s).ok());
                let _ = fs::remove_dir_all(&work_dir);
                return TestResult {
                    exit_code: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    receipt_json,
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
                        receipt_json: None,
                    };
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

fn write_policy(dir: &Path) -> PathBuf {
    let policy_path = dir.join("policy.yaml");
    fs::write(
        &policy_path,
        "version: \"1.1.0\"\nname: \"supervisor-test\"\n",
    )
    .expect("write policy");
    policy_path
}

fn is_sandbox_unsupported(result: &TestResult) -> bool {
    result
        .stderr
        .contains("[nono] warning: sandbox not supported")
}

// ---------------------------------------------------------------------------
// Receipt attestation schema tests
// ---------------------------------------------------------------------------

#[test]
fn receipt_contains_sandbox_attestation() {
    let echo = match which("echo") {
        Some(p) => p,
        None => return,
    };
    let dir = create_temp_dir("hush-supervisor-receipt");
    let policy = write_policy(&dir);
    let result = run_hush_with_receipt("nono", false, &policy, &[&echo, "test"]);
    let _ = fs::remove_dir_all(&dir);

    if is_sandbox_unsupported(&result) {
        return;
    }

    let receipt = result
        .receipt_json
        .expect("receipt should exist after successful run");

    // SignedReceipt wraps the Receipt — metadata is at receipt.receipt.metadata
    let sandbox = &receipt["receipt"]["metadata"]["sandbox"];
    assert!(
        sandbox.is_object(),
        "receipt.metadata.sandbox should be an object; receipt:\n{}",
        serde_json::to_string_pretty(&receipt).unwrap()
    );

    // Verify required fields
    assert!(
        sandbox["enforced"].is_boolean(),
        "sandbox.enforced should be a boolean"
    );
    assert!(
        sandbox["enforcement_level"].is_string(),
        "sandbox.enforcement_level should be a string"
    );
    assert!(
        sandbox["platform"].is_object(),
        "sandbox.platform should be an object"
    );
    assert!(
        sandbox["capabilities"].is_object(),
        "sandbox.capabilities should be an object"
    );

    // Verify platform info
    let platform = &sandbox["platform"];
    assert!(
        platform["name"].is_string(),
        "platform.name should be a string"
    );
    assert!(
        platform["mechanism"].is_string(),
        "platform.mechanism should be a string"
    );

    // Verify capabilities schema
    let caps = &sandbox["capabilities"];
    assert!(caps["fs"].is_array(), "capabilities.fs should be an array");
    assert!(
        caps["network_mode"].is_string(),
        "capabilities.network_mode should be a string"
    );
    assert!(
        caps["signal_mode"].is_string(),
        "capabilities.signal_mode should be a string"
    );
    assert!(
        caps["blocked_commands"].is_array(),
        "capabilities.blocked_commands should be an array"
    );
}

#[test]
fn receipt_enforcement_level_is_kernel_for_static_sandbox() {
    let echo = match which("echo") {
        Some(p) => p,
        None => return,
    };
    let dir = create_temp_dir("hush-supervisor-level");
    let policy = write_policy(&dir);
    let result = run_hush_with_receipt("nono", false, &policy, &[&echo, "test"]);
    let _ = fs::remove_dir_all(&dir);

    if is_sandbox_unsupported(&result) {
        return;
    }

    let receipt = result.receipt_json.expect("receipt should exist");
    let level = receipt["receipt"]["metadata"]["sandbox"]["enforcement_level"]
        .as_str()
        .expect("enforcement_level should be a string");
    assert_eq!(
        level, "kernel",
        "static sandbox should have enforcement_level=kernel"
    );
}

#[test]
fn receipt_no_sandbox_attestation_with_sandbox_none() {
    let dir = create_temp_dir("hush-supervisor-no-attest");
    let policy = write_policy(&dir);
    let result = run_hush_with_receipt("none", false, &policy, &["echo", "test"]);
    let _ = fs::remove_dir_all(&dir);

    if let Some(receipt) = result.receipt_json {
        let sandbox = &receipt["receipt"]["metadata"]["sandbox"];
        assert!(
            sandbox.is_null(),
            "receipt should NOT have sandbox attestation with --sandbox none"
        );
    }
}

#[test]
fn receipt_fs_capabilities_include_working_dir() {
    let echo = match which("echo") {
        Some(p) => p,
        None => return,
    };
    let dir = create_temp_dir("hush-supervisor-fs-caps");
    let policy = write_policy(&dir);
    let result = run_hush_with_receipt("nono", false, &policy, &[&echo, "test"]);
    let _ = fs::remove_dir_all(&dir);

    if is_sandbox_unsupported(&result) {
        return;
    }

    let receipt = result.receipt_json.expect("receipt should exist");
    let fs_caps = receipt["receipt"]["metadata"]["sandbox"]["capabilities"]["fs"]
        .as_array()
        .expect("capabilities.fs should be an array");

    // At least one fs cap should exist (working dir, system paths, etc.)
    assert!(!fs_caps.is_empty(), "fs capabilities should not be empty");

    // Each entry should have required fields
    for cap in fs_caps {
        assert!(cap["original"].is_string(), "fs cap should have 'original'");
        assert!(cap["resolved"].is_string(), "fs cap should have 'resolved'");
        assert!(cap["access"].is_string(), "fs cap should have 'access'");
        assert!(cap["is_file"].is_boolean(), "fs cap should have 'is_file'");
    }
}

// ---------------------------------------------------------------------------
// Never-grant unit tests (via clawdstrike lib)
// ---------------------------------------------------------------------------

#[test]
fn never_grant_list_always_contains_ssh_keys() {
    let policy = clawdstrike::policy::Policy::default();
    let paths = clawdstrike::sandbox::build_never_grant_list(&policy);

    assert!(
        paths.contains(&"~/.ssh/id_rsa".to_string()),
        "never-grant should contain ~/.ssh/id_rsa"
    );
    assert!(
        paths.contains(&"~/.ssh/id_ed25519".to_string()),
        "never-grant should contain ~/.ssh/id_ed25519"
    );
    assert!(
        paths.contains(&"~/.ssh/id_ecdsa".to_string()),
        "never-grant should contain ~/.ssh/id_ecdsa"
    );
}

#[test]
fn never_grant_list_always_contains_system_secrets() {
    let policy = clawdstrike::policy::Policy::default();
    let paths = clawdstrike::sandbox::build_never_grant_list(&policy);

    assert!(
        paths.contains(&"/etc/shadow".to_string()),
        "never-grant should contain /etc/shadow"
    );
    assert!(
        paths.contains(&"/etc/sudoers".to_string()),
        "never-grant should contain /etc/sudoers"
    );
}

#[test]
fn never_grant_list_includes_policy_forbidden_patterns() {
    let policy_yaml = r#"
version: "1.1.0"
name: "test"
guards:
  forbidden_path:
    enabled: true
    additional_patterns:
      - "/custom/secret/path"
"#;
    let policy: clawdstrike::policy::Policy =
        serde_yaml::from_str(policy_yaml).expect("parse policy yaml");
    let paths = clawdstrike::sandbox::build_never_grant_list(&policy);

    assert!(
        paths.contains(&"/custom/secret/path".to_string()),
        "never-grant should include custom forbidden path; got: {:?}",
        paths
    );
}

// ---------------------------------------------------------------------------
// Attestation type tests
// ---------------------------------------------------------------------------

#[test]
fn attestation_with_supervisor_stats_serializes_correctly() {
    let tmp = tempfile::TempDir::new().unwrap();
    let caps = nono::CapabilitySet::new()
        .allow_path(tmp.path(), nono::AccessMode::ReadWrite)
        .unwrap()
        .block_network();

    let mut attestation = clawdstrike::sandbox::build_attestation(
        &caps,
        clawdstrike::sandbox::SandboxRuntimeState::supervised_mode(true, true, None),
    );
    attestation.supervisor = Some(clawdstrike::sandbox::SupervisorStats {
        enabled: true,
        backend: "clawdstrike-guard-supervisor".to_string(),
        requests_total: 47,
        requests_granted: 42,
        requests_denied: 5,
        never_grant_blocks: 2,
        rate_limit_blocks: 0,
    });
    attestation.denials = vec![clawdstrike::sandbox::TimestampedDenial {
        path: "/home/user/.ssh/id_rsa".to_string(),
        access: "Read".to_string(),
        reason: "Path is in never_grant list".to_string(),
        timestamp: "2026-03-07T12:01:23Z".to_string(),
    }];

    let json = serde_json::to_value(&attestation).unwrap();

    // Verify supervisor stats
    let supervisor = &json["supervisor"];
    assert!(supervisor["enabled"].as_bool().unwrap());
    assert_eq!(
        supervisor["backend"].as_str().unwrap(),
        "clawdstrike-guard-supervisor"
    );
    assert_eq!(supervisor["requests_total"].as_u64().unwrap(), 47);
    assert_eq!(supervisor["requests_granted"].as_u64().unwrap(), 42);
    assert_eq!(supervisor["requests_denied"].as_u64().unwrap(), 5);
    assert_eq!(supervisor["never_grant_blocks"].as_u64().unwrap(), 2);

    // Verify denials
    let denials = json["denials"].as_array().unwrap();
    assert_eq!(denials.len(), 1);
    assert_eq!(
        denials[0]["path"].as_str().unwrap(),
        "/home/user/.ssh/id_rsa"
    );
    assert_eq!(
        denials[0]["reason"].as_str().unwrap(),
        "Path is in never_grant list"
    );

    // Verify enforcement level
    assert_eq!(
        json["enforcement_level"].as_str().unwrap(),
        "kernel_supervised"
    );
}

#[test]
fn attestation_without_supervisor_omits_field() {
    let tmp = tempfile::TempDir::new().unwrap();
    let caps = nono::CapabilitySet::new()
        .allow_path(tmp.path(), nono::AccessMode::Read)
        .unwrap();

    let attestation = clawdstrike::sandbox::build_attestation(
        &caps,
        clawdstrike::sandbox::SandboxRuntimeState::static_mode(true, None),
    );
    let json = serde_json::to_value(&attestation).unwrap();

    // supervisor should be null/absent (skip_serializing_if = None)
    assert!(
        json.get("supervisor").is_none_or(|v| v.is_null()),
        "supervisor should be absent when not enabled"
    );
    // denials should be absent (skip_serializing_if = empty)
    assert!(
        json.get("denials")
            .is_none_or(|v| v.as_array().is_none_or(|a| a.is_empty())),
        "denials should be absent or empty when none occurred"
    );
}

#[test]
fn attestation_roundtrip_json() {
    let tmp = tempfile::TempDir::new().unwrap();
    let caps = nono::CapabilitySet::new()
        .allow_path(tmp.path(), nono::AccessMode::ReadWrite)
        .unwrap()
        .proxy_only(9090)
        .block_command("rm")
        .block_command("sudo");

    let original = clawdstrike::sandbox::build_attestation(
        &caps,
        clawdstrike::sandbox::SandboxRuntimeState::static_mode(true, None),
    );
    let json_str = serde_json::to_string(&original).unwrap();
    let deserialized: clawdstrike::sandbox::SandboxAttestation =
        serde_json::from_str(&json_str).unwrap();

    assert_eq!(
        deserialized.enforcement_level, original.enforcement_level,
        "enforcement_level should roundtrip"
    );
    assert_eq!(
        deserialized.capabilities.network_mode, original.capabilities.network_mode,
        "network_mode should roundtrip"
    );
    assert_eq!(
        deserialized.capabilities.proxy_port, original.capabilities.proxy_port,
        "proxy_port should roundtrip"
    );
    assert_eq!(
        deserialized.capabilities.blocked_commands, original.capabilities.blocked_commands,
        "blocked_commands should roundtrip"
    );
}
