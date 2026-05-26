#![allow(clippy::await_holding_lock, clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc;
use tokio::time::timeout;

use super::merge::{
    downgrade_stale_runtime_snapshot, mark_runtime_snapshot_stale, merge_approval_state,
    merge_install_state, merge_samples,
};
use super::reload::{network_extension_reload_args, parse_network_extension_reload_response};
use super::resolve::{
    resolve_direct_tool_from_env, resolve_package_status_tool_with_swift_availability,
};
use super::samples::{
    EndpointSecurityHostStatus, EndpointSecurityStatusSample, NetworkExtensionStatusSample,
};
use super::tool::{
    execute_tool, run_json_tool, ToolInvocation, ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV,
    ENDPOINT_SECURITY_TOOL_ENV, ENDPOINT_SECURITY_TOOL_NAME,
};
use super::{abort_status_probe, reply_to_pending_refreshes, retain_open_refresh_replies};

use crate::macos::host::{MacosNetworkExtensionReloadError, MacosNetworkExtensionReloadResult};
use crate::macos::status::{
    CombinedSystemExtensionStatus, EvidenceArtifact, ProviderApprovalStatus,
    ProviderAttestationState, ProviderAvailability, ProviderRuntimeState, ProviderStatus,
    SystemExtensionActivationState, SystemExtensionApproval, SystemExtensionInstallState,
};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn temp_script_path(name: &str) -> PathBuf {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_millis();
    std::env::temp_dir().join(format!(
        "clawdstrike-{name}-{millis}-{}",
        std::process::id()
    ))
}

fn write_script(name: &str, body: &str) -> PathBuf {
    let path = temp_script_path(name);
    fs::write(&path, body).expect("write temp script");
    let mut permissions = fs::metadata(&path).expect("stat temp script").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&path, permissions).expect("chmod temp script");
    path
}

fn set_env_var(key: &str, value: impl AsRef<std::ffi::OsStr>) {
    unsafe {
        std::env::set_var(key, value);
    }
}

fn remove_env_var(key: &str) {
    unsafe {
        std::env::remove_var(key);
    }
}

fn temp_package_dir(name: &str) -> PathBuf {
    let path = temp_script_path(name);
    let _ = fs::remove_file(&path);
    fs::create_dir_all(&path).expect("create temp package dir");
    fs::write(path.join("Package.swift"), "// swift-tools-version: 5.9\n")
        .expect("write test package manifest");
    path
}

fn endpoint_sample(runtime: ProviderRuntimeState) -> EndpointSecurityStatusSample {
    EndpointSecurityStatusSample {
        host_status: EndpointSecurityHostStatus {
            install_state: SystemExtensionInstallState::Installed,
            approval: SystemExtensionApproval::Approved,
            endpoint_security: ProviderStatus {
                runtime,
                ..ProviderStatus::unknown()
            },
        },
        provider_state: None,
        counters: BTreeMap::new(),
        evidence_paths: Vec::new(),
        policy_epoch: None,
        last_error: None,
    }
}

fn network_sample(runtime: ProviderRuntimeState) -> NetworkExtensionStatusSample {
    NetworkExtensionStatusSample {
        install_state: SystemExtensionInstallState::Installed,
        approval: SystemExtensionApproval::Approved,
        host_status: ProviderStatus {
            runtime,
            ..ProviderStatus::unknown()
        },
        provider_state: None,
        counters: BTreeMap::new(),
        evidence_paths: Vec::new(),
        policy_epoch: None,
        policy_synced: None,
        enforcement_ready: None,
        last_error: None,
        last_reload_observation: None,
    }
}

#[tokio::test]
async fn reply_to_pending_refreshes_completes_all_open_waiters() {
    let (first_tx, first_rx) = tokio::sync::oneshot::channel();
    let (second_tx, second_rx) = tokio::sync::oneshot::channel();
    let expected = CombinedSystemExtensionStatus {
        install_state: SystemExtensionInstallState::Installed,
        approval: SystemExtensionApproval::Approved,
        ..CombinedSystemExtensionStatus::default()
    };
    let mut replies = vec![first_tx, second_tx];

    reply_to_pending_refreshes(&mut replies, expected.clone());

    assert!(replies.is_empty());
    assert_eq!(first_rx.await.expect("first refresh reply"), expected);
    assert_eq!(second_rx.await.expect("second refresh reply"), expected);
}

#[test]
fn retain_open_refresh_replies_drops_closed_waiters() {
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
    let (open_tx, _open_rx) = tokio::sync::oneshot::channel();
    drop(closed_rx);
    let mut replies = vec![closed_tx, open_tx];

    retain_open_refresh_replies(&mut replies);

    assert_eq!(replies.len(), 1);
}

#[tokio::test]
async fn abort_status_probe_preserves_refresh_waiters_and_drains_results() {
    let handle = tokio::spawn(async {
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    let (status_tx, mut status_rx) = mpsc::channel(1);
    status_tx
        .send((7, CombinedSystemExtensionStatus::default()))
        .await
        .expect("queue stale status");
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel::<CombinedSystemExtensionStatus>();
    let mut active_probe = Some(handle);
    let mut active_generation = Some(7);
    let pending_replies = vec![reply_tx];

    abort_status_probe(&mut active_probe, &mut active_generation, &mut status_rx);

    assert!(active_probe.is_none());
    assert_eq!(active_generation, None);
    assert_eq!(pending_replies.len(), 1);
    drop(pending_replies);
    assert!(reply_rx.await.is_err());
    assert!(status_rx.try_recv().is_err());
}

#[tokio::test]
async fn invalid_helper_json_resets_provider_to_unknown() {
    let script = write_script("invalid-json", "#!/bin/sh\nprintf 'not-json'\n");
    let result = run_json_tool::<EndpointSecurityStatusSample>(&ToolInvocation::Direct {
        program: script.clone(),
        args: vec![OsString::from("live")],
    })
    .await;
    let _ = fs::remove_file(script);

    assert!(result.is_none());
}

#[tokio::test]
async fn timing_out_helper_resets_provider_to_unknown() {
    let script = write_script("slow-helper", "#!/bin/sh\nsleep 30\n");
    let timeout_result = timeout(
        Duration::from_millis(100),
        execute_tool(&ToolInvocation::Direct {
            program: script.clone(),
            args: vec![OsString::from("live")],
        }),
    )
    .await;
    let _ = fs::remove_file(script);

    assert!(
        timeout_result.is_err(),
        "helper should time out in the test harness"
    );
}

#[test]
fn status_tool_resolution_does_not_use_swift_run_without_dev_override() {
    let package = temp_package_dir("status-tool-package");

    let resolved = resolve_package_status_tool_with_swift_availability(
        &package,
        ENDPOINT_SECURITY_TOOL_NAME,
        false,
        true,
    );
    let _ = fs::remove_dir_all(&package);

    assert!(
        resolved.is_none(),
        "production status collection must not execute Swift package sources via swift run"
    );
}

#[test]
fn status_tool_resolution_prefers_bundled_bin_helper() {
    let package = temp_package_dir("status-tool-package-bin");
    let bin_dir = package.join("bin");
    fs::create_dir_all(&bin_dir).expect("create status tool bin dir");
    let helper = bin_dir.join(ENDPOINT_SECURITY_TOOL_NAME);
    fs::write(&helper, "#!/bin/sh\n").expect("write bundled helper");

    let resolved = resolve_package_status_tool_with_swift_availability(
        &package,
        ENDPOINT_SECURITY_TOOL_NAME,
        false,
        false,
    );
    let _ = fs::remove_dir_all(&package);

    match resolved {
        Some(ToolInvocation::Direct { program, args }) => {
            assert_eq!(program, helper);
            assert_eq!(args, vec![OsString::from("live")]);
        }
        other => panic!("expected bundled direct status helper, got {other:?}"),
    }
}

#[test]
fn status_tool_resolution_finds_platform_scoped_swift_build_output() {
    let package = temp_package_dir("status-tool-package-platform-build");
    let helper_dir = package
        .join(".build")
        .join("arm64-apple-macosx")
        .join("release");
    fs::create_dir_all(&helper_dir).expect("create platform build dir");
    let helper = helper_dir.join(ENDPOINT_SECURITY_TOOL_NAME);
    fs::write(&helper, "#!/bin/sh\n").expect("write built helper");

    let resolved = resolve_package_status_tool_with_swift_availability(
        &package,
        ENDPOINT_SECURITY_TOOL_NAME,
        false,
        false,
    );
    let _ = fs::remove_dir_all(&package);

    match resolved {
        Some(ToolInvocation::Direct { program, args }) => {
            assert_eq!(program, helper);
            assert_eq!(args, vec![OsString::from("live")]);
        }
        other => panic!("expected platform-scoped direct status helper, got {other:?}"),
    }
}

#[test]
fn status_tool_resolution_allows_swift_run_only_with_dev_override() {
    let package = temp_package_dir("status-tool-package-dev");

    let resolved = resolve_package_status_tool_with_swift_availability(
        &package,
        ENDPOINT_SECURITY_TOOL_NAME,
        true,
        true,
    );
    let _ = fs::remove_dir_all(&package);

    match resolved {
        Some(ToolInvocation::SwiftRun {
            package_path,
            executable,
        }) => {
            assert_eq!(package_path, package);
            assert_eq!(executable, ENDPOINT_SECURITY_TOOL_NAME);
        }
        other => panic!("expected dev-only SwiftRun helper, got {other:?}"),
    }
}

#[test]
fn direct_status_tool_override_requires_dev_flag_and_absolute_path() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    let script = write_script("direct-helper", "#!/bin/sh\nprintf '{}'\n");
    let previous_tool = std::env::var_os(ENDPOINT_SECURITY_TOOL_ENV);
    let previous_allow = std::env::var_os(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV);

    set_env_var(ENDPOINT_SECURITY_TOOL_ENV, &script);
    remove_env_var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV);
    assert!(resolve_direct_tool_from_env(ENDPOINT_SECURITY_TOOL_ENV).is_none());

    set_env_var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV, "1");
    match resolve_direct_tool_from_env(ENDPOINT_SECURITY_TOOL_ENV) {
        Some(ToolInvocation::Direct { program, args }) => {
            assert_eq!(program, script);
            assert_eq!(args, vec![OsString::from("live")]);
        }
        other => panic!("expected direct helper override with dev flag, got {other:?}"),
    }

    set_env_var(ENDPOINT_SECURITY_TOOL_ENV, "relative-helper");
    assert!(resolve_direct_tool_from_env(ENDPOINT_SECURITY_TOOL_ENV).is_none());

    if let Some(value) = previous_tool {
        set_env_var(ENDPOINT_SECURITY_TOOL_ENV, value);
    } else {
        remove_env_var(ENDPOINT_SECURITY_TOOL_ENV);
    }
    if let Some(value) = previous_allow {
        set_env_var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV, value);
    } else {
        remove_env_var(ALLOW_DIRECT_STATUS_TOOL_OVERRIDES_ENV);
    }
    let _ = fs::remove_file(script);
}

#[tokio::test(flavor = "current_thread")]
async fn status_tool_execution_does_not_inherit_ambient_secret_environment() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    let previous_secret = std::env::var_os("CLAWDSTRIKE_TEST_AMBIENT_SECRET");
    set_env_var("CLAWDSTRIKE_TEST_AMBIENT_SECRET", "do-not-leak");
    let script = write_script(
        "env-helper",
        "#!/bin/sh\nprintf '%s' \"${CLAWDSTRIKE_TEST_AMBIENT_SECRET:-cleared}\"\n",
    );

    let output = execute_tool(&ToolInvocation::Direct {
        program: script.clone(),
        args: vec![OsString::from("live")],
    })
    .await
    .expect("execute helper");
    assert_eq!(String::from_utf8(output).expect("utf8 output"), "cleared");

    if let Some(value) = previous_secret {
        set_env_var("CLAWDSTRIKE_TEST_AMBIENT_SECRET", value);
    } else {
        remove_env_var("CLAWDSTRIKE_TEST_AMBIENT_SECRET");
    }
    let _ = fs::remove_file(script);
}

#[tokio::test(flavor = "current_thread")]
async fn status_tool_execution_preserves_swift_toolchain_environment() {
    let _guard = ENV_LOCK.lock().expect("lock env");
    let previous_home = std::env::var_os("HOME");
    let previous_developer_dir = std::env::var_os("DEVELOPER_DIR");
    let home = temp_script_path("swift-home");
    fs::create_dir_all(&home).expect("create test HOME");
    set_env_var("HOME", &home);
    set_env_var(
        "DEVELOPER_DIR",
        "/Applications/Xcode.app/Contents/Developer",
    );
    let script = write_script(
        "toolchain-env-helper",
        "#!/bin/sh\nprintf '%s\\n%s' \"${HOME:-missing}\" \"${DEVELOPER_DIR:-missing}\"\n",
    );

    let output = execute_tool(&ToolInvocation::Direct {
        program: script.clone(),
        args: vec![OsString::from("live")],
    })
    .await
    .expect("execute helper");
    let rendered = String::from_utf8(output).expect("utf8 output");
    assert!(rendered.contains(home.to_str().expect("home path should be utf8")));
    assert!(rendered.contains("/Applications/Xcode.app/Contents/Developer"));

    if let Some(value) = previous_home {
        set_env_var("HOME", value);
    } else {
        remove_env_var("HOME");
    }
    if let Some(value) = previous_developer_dir {
        set_env_var("DEVELOPER_DIR", value);
    } else {
        remove_env_var("DEVELOPER_DIR");
    }
    let _ = fs::remove_file(script);
    let _ = fs::remove_dir_all(home);
}

#[test]
fn network_extension_reload_args_forward_policy_path_and_generation() {
    let args =
        network_extension_reload_args(Path::new("/tmp/clawdstrike-network-policy.json"), 5150);

    assert_eq!(args[0], OsString::from("request-reload"));
    assert_eq!(
        args[1],
        OsString::from("/tmp/clawdstrike-network-policy.json")
    );
    assert_eq!(args[2], OsString::from("5150"));
}

#[test]
fn network_extension_reload_response_parser_validates_command_and_generation() {
    let expected_path = Path::new("/tmp/clawdstrike-network-policy.json");
    let result = parse_network_extension_reload_response(
        br#"{"requestId":"reload-test","command":"reload_policy","policySnapshotPath":"/tmp/clawdstrike-network-policy.json","generation":5150,"saved":true}"#,
        expected_path,
        5150,
    )
    .expect("valid reload helper response should parse");

    assert_eq!(
        result,
        MacosNetworkExtensionReloadResult {
            requested: true,
            saved: true,
            request_id: "reload-test".to_string(),
            policy_snapshot_path: "/tmp/clawdstrike-network-policy.json".to_string(),
            generation: 5150,
        }
    );

    assert_eq!(
        parse_network_extension_reload_response(
            br#"{"requestId":"reload-test","command":"other","policySnapshotPath":"/tmp/clawdstrike-network-policy.json","generation":5150,"saved":true}"#,
            expected_path,
            5150,
        ),
        Err(MacosNetworkExtensionReloadError::InvalidResponse(
            "unexpected command other".to_string()
        ))
    );
    assert_eq!(
        parse_network_extension_reload_response(
            br#"{"requestId":"reload-test","command":"reload_policy","policySnapshotPath":"/tmp/clawdstrike-network-policy.json","generation":5151,"saved":true}"#,
            expected_path,
            5150,
        ),
        Err(MacosNetworkExtensionReloadError::InvalidResponse(
            "generation mismatch: requested 5150, helper returned 5151".to_string()
        ))
    );
    assert_eq!(
        parse_network_extension_reload_response(
            br#"{"requestId":"reload-test","command":"reload_policy","policySnapshotPath":"/tmp/other-policy.json","generation":5150,"saved":true}"#,
            expected_path,
            5150,
        ),
        Err(MacosNetworkExtensionReloadError::InvalidResponse(
            "policy snapshot path mismatch: requested /tmp/clawdstrike-network-policy.json, helper returned /tmp/other-policy.json".to_string()
        ))
    );
}

#[tokio::test]
async fn execute_tool_passes_provider_runtime_snapshot_paths() {
    let script = write_script(
        "network-env",
        r#"#!/bin/sh
printf '%s
%s
%s
' "$CLAWDSTRIKE_ENDPOINT_SECURITY_RUNTIME_SNAPSHOT_PATH" "$CLAWDSTRIKE_NETWORK_EXTENSION_EGRESS_POLICY_PATH" "$CLAWDSTRIKE_NETWORK_EXTENSION_RUNTIME_SNAPSHOT_PATH"
"#,
    );
    let stdout = execute_tool(&ToolInvocation::Direct {
        program: script.clone(),
        args: vec![OsString::from("live")],
    })
    .await
    .unwrap_or_else(|err| panic!("env helper should succeed: {err}"));
    let _ = fs::remove_file(script);
    let rendered = String::from_utf8(stdout).expect("helper stdout should be utf8");

    assert!(
        rendered.contains("endpoint-security-runtime.json\n"),
        "endpoint security runtime snapshot env path should be passed to the helper: {rendered}"
    );
    assert!(
        rendered.contains("network-extension-egress-policy.json\n"),
        "egress policy env path should be passed to the helper: {rendered}"
    );
    assert!(
        rendered.contains("network-extension-egress-policy.json.provider-runtime.json\n"),
        "network extension runtime snapshot env path should be passed to the helper: {rendered}"
    );
}

#[test]
fn stale_runtime_snapshot_marker_downgrades_active_provider() {
    let path = Path::new("/tmp/clawdstrike-stale-runtime-snapshot.json");
    let mut status = ProviderStatus {
        runtime: ProviderRuntimeState::Active,
        provider_state: Some(ProviderAttestationState {
            provider: "endpoint_security".to_string(),
            installed: true,
            approval_status: ProviderApprovalStatus::Approved,
            active: true,
            healthy: true,
            availability: ProviderAvailability::Active,
            degraded_reasons: Vec::new(),
            last_healthy_timestamp: Some("2026-05-22T14:00:00Z".to_string()),
        }),
        ..ProviderStatus::unknown()
    };

    mark_runtime_snapshot_stale(&mut status, "endpoint-security", path);

    assert_eq!(
        status.runtime,
        ProviderRuntimeState::Degraded {
            reason: "provider_runtime_snapshot_stale".to_string()
        }
    );
    assert_eq!(
        status.last_error.as_deref(),
        Some("provider_runtime_snapshot_stale")
    );
    assert_eq!(status.evidence_paths.len(), 1);
    assert_eq!(status.evidence_paths[0].kind, "stale_runtime_snapshot");
    let provider_state = status
        .provider_state
        .as_ref()
        .expect("provider state should remain attached");
    assert!(!provider_state.active);
    assert!(!provider_state.healthy);
    assert_eq!(provider_state.availability, ProviderAvailability::Degraded);
    assert!(provider_state
        .degraded_reasons
        .contains(&"provider_runtime_snapshot_stale".to_string()));
}

#[test]
fn missing_runtime_snapshot_downgrades_active_provider() {
    let path = temp_script_path("missing-runtime-snapshot");
    let _ = fs::remove_file(&path);
    let mut status = ProviderStatus {
        runtime: ProviderRuntimeState::Active,
        provider_state: Some(ProviderAttestationState {
            provider: "network_extension".to_string(),
            installed: true,
            approval_status: ProviderApprovalStatus::Approved,
            active: true,
            healthy: true,
            availability: ProviderAvailability::Active,
            degraded_reasons: Vec::new(),
            last_healthy_timestamp: Some("2026-05-22T14:00:00Z".to_string()),
        }),
        ..ProviderStatus::unknown()
    };

    downgrade_stale_runtime_snapshot(&mut status, "network-extension", &path);

    assert_eq!(
        status.runtime,
        ProviderRuntimeState::Degraded {
            reason: "provider_runtime_snapshot_stale".to_string()
        }
    );
    assert_eq!(
        status.last_error.as_deref(),
        Some("provider_runtime_snapshot_stale")
    );
}

#[test]
fn merge_samples_preserves_valid_provider_status_and_marks_missing_sample_unknown() {
    let combined = merge_samples(Some(endpoint_sample(ProviderRuntimeState::Active)), None);

    assert_eq!(combined.install_state, SystemExtensionInstallState::Unknown);
    assert_eq!(combined.approval, SystemExtensionApproval::Unknown);
    assert_eq!(
        combined.endpoint_security,
        ProviderStatus {
            runtime: ProviderRuntimeState::Active,
            ..ProviderStatus::unknown()
        }
    );
    assert_eq!(combined.network_extension, ProviderStatus::unknown());
}

#[test]
fn merge_samples_promotes_consistent_install_and_approval_proof() {
    let combined = merge_samples(
        Some(endpoint_sample(ProviderRuntimeState::Active)),
        Some(network_sample(ProviderRuntimeState::Active)),
    );

    assert_eq!(
        combined.install_state,
        SystemExtensionInstallState::Installed
    );
    assert_eq!(combined.approval, SystemExtensionApproval::Approved);
    assert_eq!(
        combined.endpoint_security,
        ProviderStatus {
            runtime: ProviderRuntimeState::Active,
            ..ProviderStatus::unknown()
        }
    );
    assert_eq!(
        combined.network_extension,
        ProviderStatus {
            runtime: ProviderRuntimeState::Active,
            ..ProviderStatus::unknown()
        }
    );
}

#[test]
fn merge_samples_preserves_provider_runtime_readouts() {
    let mut endpoint = endpoint_sample(ProviderRuntimeState::Active);
    endpoint.provider_state = Some(ProviderAttestationState {
        provider: "endpoint_security".to_string(),
        installed: true,
        approval_status: ProviderApprovalStatus::Approved,
        active: true,
        healthy: true,
        availability: ProviderAvailability::Active,
        degraded_reasons: Vec::new(),
        last_healthy_timestamp: Some("2026-05-14T12:00:00Z".to_string()),
    });
    endpoint.counters.insert("auth_open_allowed".to_string(), 7);
    endpoint.policy_epoch = Some(42);
    endpoint.evidence_paths.push(EvidenceArtifact {
        kind: "status".to_string(),
        path: "/tmp/clawdstrike/es-status.json".to_string(),
        detail: "endpoint security helper output".to_string(),
    });

    let combined = merge_samples(
        Some(endpoint),
        Some(network_sample(ProviderRuntimeState::Active)),
    );

    assert_eq!(
        combined.activation_state,
        SystemExtensionActivationState::Active
    );
    assert_eq!(combined.endpoint_security.policy_epoch, Some(42));
    assert_eq!(
        combined.endpoint_security.counters.get("auth_open_allowed"),
        Some(&7)
    );
    assert_eq!(
        combined.endpoint_security.last_healthy_timestamp.as_deref(),
        Some("2026-05-14T12:00:00Z")
    );
    assert_eq!(combined.endpoint_security.evidence_paths.len(), 1);
    assert_eq!(
        combined
            .endpoint_security
            .provider_state
            .as_ref()
            .map(|state| state.provider.as_str()),
        Some("endpoint_security")
    );
}

#[test]
fn merge_samples_preserves_network_extension_policy_readout() {
    let mut network = network_sample(ProviderRuntimeState::Unknown);
    network.policy_synced = Some(true);
    network.enforcement_ready = Some(true);
    network
        .counters
        .insert("remediation_requests".to_string(), 2);

    let combined = merge_samples(
        Some(endpoint_sample(ProviderRuntimeState::Active)),
        Some(network),
    );

    assert_eq!(combined.network_extension.policy_synced, Some(true));
    assert_eq!(combined.network_extension.enforcement_ready, Some(true));
    assert_eq!(
        combined
            .network_extension
            .counters
            .get("remediation_requests"),
        Some(&2)
    );
    assert_eq!(
        combined.network_extension.runtime,
        ProviderRuntimeState::Unknown
    );
    assert_eq!(
        combined.activation_state,
        SystemExtensionActivationState::Pending
    );
}

#[test]
fn merge_install_state_fails_closed_for_partial_installation() {
    assert_eq!(
        merge_install_state(
            SystemExtensionInstallState::Installed,
            SystemExtensionInstallState::NotInstalled,
        ),
        SystemExtensionInstallState::NotInstalled
    );
    assert_eq!(
        merge_install_state(
            SystemExtensionInstallState::NotInstalled,
            SystemExtensionInstallState::Installed,
        ),
        SystemExtensionInstallState::NotInstalled
    );
    assert_eq!(
        merge_install_state(
            SystemExtensionInstallState::Installed,
            SystemExtensionInstallState::Unknown,
        ),
        SystemExtensionInstallState::Unknown
    );
    assert_eq!(
        merge_install_state(
            SystemExtensionInstallState::Unknown,
            SystemExtensionInstallState::Installed,
        ),
        SystemExtensionInstallState::Unknown
    );
}

#[test]
fn merge_approval_state_requires_consistent_approval_proof() {
    assert_eq!(
        merge_approval_state(
            SystemExtensionApproval::Approved,
            SystemExtensionApproval::Unknown,
        ),
        SystemExtensionApproval::Unknown
    );
    assert_eq!(
        merge_approval_state(
            SystemExtensionApproval::Unknown,
            SystemExtensionApproval::Approved,
        ),
        SystemExtensionApproval::Unknown
    );
    assert_eq!(
        merge_approval_state(
            SystemExtensionApproval::Approved,
            SystemExtensionApproval::Approved,
        ),
        SystemExtensionApproval::Approved
    );
}
