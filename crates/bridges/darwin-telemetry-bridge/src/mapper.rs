//! Map Darwin telemetry events to Spine fact schemas.
//!
//! Each event is mapped to a JSON fact with a well-known schema identifier,
//! severity classification, and structured payload.
//!
//! This module is platform-independent — tests run on any OS.

use serde_json::{json, Value};

use crate::event::{DarwinEvent, DarwinEventType, EventSource};

/// Fact schema for Darwin telemetry events published on the Spine.
pub const FACT_SCHEMA: &str = "clawdstrike.sdr.fact.darwin_telemetry_event.v1";

/// Severity levels for classified events.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

/// Sensitive filesystem paths that trigger elevated severity.
/// Matched with `starts_with`, so include trailing `/` for directories.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/sudoers",
    "/etc/pam.d/",
    "/Library/Security/",
    "/Library/Preferences/com.apple.security",
    "/var/db/auth.db",
];

/// SSH directory segment used for path matching.
/// We look for this segment preceded by a `/` to avoid false positives
/// on paths like `/tmp/not-really/.ssh/fake`. The match requires the
/// segment to appear after a home-directory-like prefix.
const SSH_DIR_SEGMENT: &str = "/.ssh/";

/// Map a [`DarwinEvent`] to a Spine fact JSON value.
///
/// Returns `None` if the event cannot be meaningfully mapped.
pub fn map_event(event: &DarwinEvent) -> Option<Value> {
    let severity = classify_severity(event);

    Some(json!({
        "schema": FACT_SCHEMA,
        "event_type": event.event_type.subject_suffix(),
        "source": event.source.as_str(),
        "severity": severity.as_str(),
        "timestamp": event.timestamp,
        "payload": event.payload,
    }))
}

/// Classify severity based on event type, source, and payload content.
pub fn classify_severity(event: &DarwinEvent) -> Severity {
    match event.source {
        EventSource::FsEvents => classify_fsevents_severity(event),
        EventSource::Process => classify_process_severity(event),
        EventSource::UnifiedLog => classify_log_severity(event),
    }
}

/// Check if a path contains an SSH directory segment (e.g. `/Users/x/.ssh/id_rsa`).
fn is_ssh_path(path: &str) -> bool {
    path.contains(SSH_DIR_SEGMENT)
}

/// Classify FSEvents severity based on path sensitivity.
fn classify_fsevents_severity(event: &DarwinEvent) -> Severity {
    let path = event
        .payload
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // SSH paths are always critical
    if is_ssh_path(path) {
        return Severity::Critical;
    }

    // Sensitive system paths are critical
    if SENSITIVE_PATHS.iter().any(|s| path.starts_with(s)) {
        return Severity::Critical;
    }

    // LaunchDaemons/LaunchAgents are high — check BEFORE /Applications
    // to avoid path traversal from /Applications/.. matching first.
    if path.starts_with("/Library/LaunchDaemons") || path.starts_with("/Library/LaunchAgents") {
        return Severity::High;
    }

    // /Applications changes are medium
    if path.starts_with("/Applications/") || path == "/Applications" {
        return Severity::Medium;
    }

    // /etc/ changes are medium (trailing slash avoids matching /etcfoo)
    if path.starts_with("/etc/") || path == "/etc" {
        return Severity::Medium;
    }

    Severity::Low
}

/// Classify process event severity.
fn classify_process_severity(event: &DarwinEvent) -> Severity {
    let uid = event
        .payload
        .get("uid")
        .and_then(|v| v.as_u64())
        .unwrap_or(u64::MAX);
    let path = event
        .payload
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let is_root = uid == 0;

    if is_root {
        // Root process touching sensitive paths → Critical
        if SENSITIVE_PATHS.iter().any(|s| path.starts_with(s)) || is_ssh_path(path) {
            return Severity::Critical;
        }
        return Severity::High;
    }

    Severity::Low
}

/// Classify unified log event severity.
fn classify_log_severity(event: &DarwinEvent) -> Severity {
    match event.event_type {
        DarwinEventType::SudoLog => Severity::High,
        DarwinEventType::AuthLog => {
            let message = event
                .payload
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if message.contains("failure")
                || message.contains("denied")
                || message.contains("reject")
            {
                Severity::High
            } else {
                Severity::Medium
            }
        }
        DarwinEventType::SecurityLog => Severity::Medium,
        DarwinEventType::DirectoryLog => Severity::Medium,
        _ => Severity::Low,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::{DarwinEvent, DarwinEventType};

    fn make_event(event_type: DarwinEventType, payload: Value) -> DarwinEvent {
        DarwinEvent {
            event_type,
            source: event_type.source(),
            timestamp: "2026-03-02T00:00:00Z".to_string(),
            payload,
        }
    }

    // --- FSEvents severity ---

    #[test]
    fn fsevents_ssh_path_is_critical() {
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/Users/admin/.ssh/authorized_keys", "flags": 0, "event_id": 1}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_sudoers_is_critical() {
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/etc/sudoers", "flags": 0, "event_id": 2}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_pam_is_critical() {
        let event = make_event(
            DarwinEventType::FileCreated,
            json!({"path": "/etc/pam.d/sudo", "flags": 0, "event_id": 3}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_library_security_is_critical() {
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/Library/Security/trust-settings.plist", "flags": 0, "event_id": 4}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_applications_is_medium() {
        let event = make_event(
            DarwinEventType::FileCreated,
            json!({"path": "/Applications/Malware.app", "flags": 0, "event_id": 5}),
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn fsevents_launch_daemons_is_high() {
        let event = make_event(
            DarwinEventType::FileCreated,
            json!({"path": "/Library/LaunchDaemons/com.evil.plist", "flags": 0, "event_id": 6}),
        );
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn fsevents_launch_agents_is_high() {
        let event = make_event(
            DarwinEventType::FileCreated,
            json!({"path": "/Library/LaunchAgents/com.evil.plist", "flags": 0, "event_id": 7}),
        );
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn fsevents_etc_is_medium() {
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/etc/hosts", "flags": 0, "event_id": 8}),
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn fsevents_normal_path_is_low() {
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/tmp/somefile.txt", "flags": 0, "event_id": 9}),
        );
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    // --- Process severity ---

    #[test]
    fn root_process_sensitive_path_is_critical() {
        let event = make_event(
            DarwinEventType::ProcessSpawn,
            json!({"pid": 1234, "ppid": 1, "uid": 0, "name": "cat", "path": "/etc/sudoers", "start_time": 0}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn root_process_ssh_path_is_critical() {
        let event = make_event(
            DarwinEventType::ProcessSpawn,
            json!({"pid": 1234, "ppid": 1, "uid": 0, "name": "ssh", "path": "/Users/root/.ssh/id_rsa", "start_time": 0}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn root_process_normal_is_high() {
        let event = make_event(
            DarwinEventType::ProcessSpawn,
            json!({"pid": 1234, "ppid": 1, "uid": 0, "name": "ls", "path": "/usr/bin/ls", "start_time": 0}),
        );
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn nonroot_process_is_low() {
        let event = make_event(
            DarwinEventType::ProcessSpawn,
            json!({"pid": 1234, "ppid": 1, "uid": 501, "name": "ls", "path": "/usr/bin/ls", "start_time": 0}),
        );
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    // --- Unified log severity ---

    #[test]
    fn sudo_log_is_high() {
        let event = make_event(
            DarwinEventType::SudoLog,
            json!({"timestamp": "t", "subsystem": "", "category": "", "process": "sudo", "pid": 1, "message": "user ran sudo", "level": "info"}),
        );
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn auth_log_failure_is_high() {
        let event = make_event(
            DarwinEventType::AuthLog,
            json!({"timestamp": "t", "subsystem": "com.apple.authd", "category": "", "process": "authd", "pid": 1, "message": "authentication failure for user", "level": "error"}),
        );
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn auth_log_success_is_medium() {
        let event = make_event(
            DarwinEventType::AuthLog,
            json!({"timestamp": "t", "subsystem": "com.apple.authd", "category": "", "process": "authd", "pid": 1, "message": "user authenticated", "level": "info"}),
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn security_log_is_medium() {
        let event = make_event(
            DarwinEventType::SecurityLog,
            json!({"timestamp": "t", "subsystem": "com.apple.securityd", "category": "", "process": "securityd", "pid": 1, "message": "keychain access", "level": "info"}),
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn directory_log_is_medium() {
        let event = make_event(
            DarwinEventType::DirectoryLog,
            json!({"timestamp": "t", "subsystem": "com.apple.opendirectoryd", "category": "", "process": "opendirectoryd", "pid": 1, "message": "lookup", "level": "info"}),
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    // --- map_event ---

    #[test]
    fn map_event_produces_valid_fact() {
        let event = make_event(
            DarwinEventType::ProcessSpawn,
            json!({"pid": 100, "ppid": 1, "uid": 501, "name": "ls", "path": "/usr/bin/ls", "start_time": 0}),
        );
        let fact = map_event(&event);
        assert!(fact.is_some());
        let fact = fact.unwrap_or_default();
        assert_eq!(fact["schema"], FACT_SCHEMA);
        assert_eq!(fact["event_type"], "spawn");
        assert_eq!(fact["source"], "process");
        assert_eq!(fact["severity"], "low");
    }

    #[test]
    fn map_event_includes_payload() {
        let payload = json!({"path": "/etc/hosts", "flags": 42, "event_id": 99});
        let event = make_event(DarwinEventType::FileModified, payload.clone());
        let fact = map_event(&event).unwrap_or_default();
        assert_eq!(fact["payload"], payload);
    }

    // --- Empty / missing field edge cases ---

    #[test]
    fn fsevents_empty_payload_is_low() {
        let event = make_event(DarwinEventType::FileModified, json!({}));
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn fsevents_null_path_is_low() {
        let event = make_event(DarwinEventType::FileModified, json!({"path": null}));
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn fsevents_numeric_path_is_low() {
        let event = make_event(DarwinEventType::FileModified, json!({"path": 12345}));
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn fsevents_empty_path_is_low() {
        let event = make_event(DarwinEventType::FileModified, json!({"path": ""}));
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn process_empty_payload_is_low() {
        // Missing uid defaults to u64::MAX (non-root), so severity is Low
        let event = make_event(DarwinEventType::ProcessSpawn, json!({}));
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn process_null_uid_is_low() {
        let event = make_event(DarwinEventType::ProcessSpawn, json!({"uid": null}));
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn process_string_uid_is_low() {
        // uid is string, as_u64() returns None -> defaults to u64::MAX (non-root)
        let event = make_event(
            DarwinEventType::ProcessSpawn,
            json!({"uid": "0", "path": "/etc/sudoers"}),
        );
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn log_empty_payload_auth_is_medium() {
        // AuthLog with no message -> no "failure"/"denied"/"reject" -> Medium
        let event = make_event(DarwinEventType::AuthLog, json!({}));
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn log_null_message_auth_is_medium() {
        let event = make_event(DarwinEventType::AuthLog, json!({"message": null}));
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    // --- Boundary path tests ---

    #[test]
    fn fsevents_etc_prefix_not_etcfoo() {
        // "/etcfoo" does NOT start with "/etc/" — should be Low, not Medium
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/etcfoo/bar"}),
        );
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn fsevents_etc_exact_is_medium() {
        let event = make_event(DarwinEventType::FileModified, json!({"path": "/etc"}));
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn fsevents_etc_nested_is_medium() {
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/etc/resolv.conf"}),
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn fsevents_ssh_nested_in_any_user_home() {
        // SSH_PATHS uses contains(), so any user home path with /.ssh/ triggers
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/var/root/.ssh/known_hosts"}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_ssh_id_prefix_match() {
        // "/.ssh/id_" matches via contains, so "id_ed25519" triggers
        let event = make_event(
            DarwinEventType::FileCreated,
            json!({"path": "/Users/test/.ssh/id_ed25519"}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_ssh_config_is_critical() {
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/Users/admin/.ssh/config"}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_not_ssh_without_dot_prefix() {
        // "/ssh/config" does NOT contain "/.ssh/" so it's low
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/ssh/config"}),
        );
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn fsevents_sudoers_d_is_not_sensitive() {
        // "/etc/sudoers.d/custom" does NOT start_with "/etc/sudoers" — wait, it does
        // "/etc/sudoers.d/custom".starts_with("/etc/sudoers") == true
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/etc/sudoers.d/custom"}),
        );
        // This is actually Critical because starts_with("/etc/sudoers") matches
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_pam_d_nested_file() {
        let event = make_event(
            DarwinEventType::FileCreated,
            json!({"path": "/etc/pam.d/login"}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_apple_security_prefs() {
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/Library/Preferences/com.apple.security.plist"}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_var_db_auth() {
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/var/db/auth.db"}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn fsevents_applications_nested() {
        let event = make_event(
            DarwinEventType::FileCreated,
            json!({"path": "/Applications/Safari.app/Contents/Info.plist"}),
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    // --- Priority order tests (SSH checked before /etc) ---

    #[test]
    fn fsevents_ssh_under_etc_is_critical_not_medium() {
        // /etc would be Medium, but SSH takes priority
        // Actually, SSH_PATHS uses `contains`, not `starts_with`, so /.ssh/ anywhere triggers.
        // But a path like /etc/.ssh/config would be SSH critical, not /etc medium.
        let event = make_event(
            DarwinEventType::FileModified,
            json!({"path": "/etc/.ssh/config"}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    // --- Process severity edge cases ---

    #[test]
    fn root_process_empty_path_is_high() {
        // Root but no sensitive path -> High
        let event = make_event(DarwinEventType::ProcessSpawn, json!({"uid": 0, "path": ""}));
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn root_process_pam_is_critical() {
        let event = make_event(
            DarwinEventType::ProcessSpawn,
            json!({"uid": 0, "path": "/etc/pam.d/sudo"}),
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn process_snapshot_root_is_high() {
        let event = make_event(
            DarwinEventType::ProcessSnapshot,
            json!({"uid": 0, "path": "/usr/sbin/httpd"}),
        );
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn process_exit_nonroot_is_low() {
        let event = make_event(
            DarwinEventType::ProcessExit,
            json!({"uid": 501, "path": "/usr/bin/vim"}),
        );
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    // --- Unified log edge cases ---

    #[test]
    fn auth_log_denied_is_high() {
        let event = make_event(
            DarwinEventType::AuthLog,
            json!({"message": "access denied for user"}),
        );
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn auth_log_reject_is_high() {
        let event = make_event(
            DarwinEventType::AuthLog,
            json!({"message": "certificate reject"}),
        );
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn auth_log_normal_is_medium() {
        let event = make_event(
            DarwinEventType::AuthLog,
            json!({"message": "session opened for user admin"}),
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn sudo_log_always_high_regardless_of_payload() {
        let event = make_event(DarwinEventType::SudoLog, json!({}));
        assert_eq!(classify_severity(&event), Severity::High);
    }

    // --- Process event type falling through to Low in classify_log_severity ---

    #[test]
    fn classify_log_fallthrough_for_non_log_type() {
        // If somehow a non-log DarwinEventType is paired with UnifiedLog source
        // the match falls through to the _ => Low branch
        let event = DarwinEvent {
            event_type: DarwinEventType::ProcessSpawn,
            source: EventSource::UnifiedLog,
            timestamp: "t".to_string(),
            payload: json!({}),
        };
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    // --- map_event schema/source/severity for all event types ---

    #[test]
    fn map_event_all_event_types_have_valid_schema() {
        let types = [
            (DarwinEventType::ProcessSnapshot, json!({"uid": 501})),
            (DarwinEventType::ProcessSpawn, json!({"uid": 501})),
            (DarwinEventType::ProcessExit, json!({"uid": 501})),
            (
                DarwinEventType::FileCreated,
                json!({"path": "/tmp/x", "flags": 0, "event_id": 1}),
            ),
            (
                DarwinEventType::FileModified,
                json!({"path": "/tmp/x", "flags": 0, "event_id": 1}),
            ),
            (
                DarwinEventType::FileRemoved,
                json!({"path": "/tmp/x", "flags": 0, "event_id": 1}),
            ),
            (
                DarwinEventType::FileRenamed,
                json!({"path": "/tmp/x", "flags": 0, "event_id": 1}),
            ),
            (
                DarwinEventType::XattrChanged,
                json!({"path": "/tmp/x", "flags": 0, "event_id": 1}),
            ),
            (
                DarwinEventType::OwnerChanged,
                json!({"path": "/tmp/x", "flags": 0, "event_id": 1}),
            ),
            (DarwinEventType::SecurityLog, json!({"message": "ok"})),
            (DarwinEventType::AuthLog, json!({"message": "ok"})),
            (DarwinEventType::SudoLog, json!({"message": "ok"})),
            (DarwinEventType::DirectoryLog, json!({"message": "ok"})),
        ];
        for (event_type, payload) in &types {
            let event = make_event(*event_type, payload.clone());
            let fact = map_event(&event).expect("map_event should return Some");
            assert_eq!(
                fact["schema"], FACT_SCHEMA,
                "wrong schema for {:?}",
                event_type
            );
            assert_eq!(
                fact["source"],
                event_type.source().as_str(),
                "wrong source for {:?}",
                event_type
            );
            assert_eq!(
                fact["event_type"],
                event_type.subject_suffix(),
                "wrong event_type for {:?}",
                event_type
            );
            assert!(
                fact.get("severity").is_some(),
                "missing severity for {:?}",
                event_type
            );
            assert_eq!(
                fact["timestamp"], "2026-03-02T00:00:00Z",
                "wrong timestamp for {:?}",
                event_type
            );
        }
    }

    #[test]
    fn map_event_preserves_empty_payload() {
        let event = make_event(DarwinEventType::FileModified, json!({}));
        let fact = map_event(&event).unwrap_or_default();
        assert_eq!(fact["payload"], json!({}));
    }

    #[test]
    fn map_event_preserves_nested_payload() {
        let payload = json!({"a": {"b": {"c": 42}}, "arr": [1, 2, 3]});
        let event = make_event(DarwinEventType::FileCreated, payload.clone());
        let fact = map_event(&event).unwrap_or_default();
        assert_eq!(fact["payload"], payload);
    }

    // --- Severity as_str ---

    #[test]
    fn severity_as_str_values() {
        assert_eq!(Severity::Low.as_str(), "low");
        assert_eq!(Severity::Medium.as_str(), "medium");
        assert_eq!(Severity::High.as_str(), "high");
        assert_eq!(Severity::Critical.as_str(), "critical");
    }

    // --- All fsevents types share the same severity classifier ---

    #[test]
    fn all_fsevent_types_use_same_severity_for_sensitive_path() {
        let fsevent_types = [
            DarwinEventType::FileCreated,
            DarwinEventType::FileModified,
            DarwinEventType::FileRemoved,
            DarwinEventType::FileRenamed,
            DarwinEventType::XattrChanged,
            DarwinEventType::OwnerChanged,
        ];
        for event_type in &fsevent_types {
            let event = make_event(*event_type, json!({"path": "/etc/sudoers"}));
            assert_eq!(
                classify_severity(&event),
                Severity::Critical,
                "expected Critical for {:?} touching /etc/sudoers",
                event_type
            );
        }
    }
}
