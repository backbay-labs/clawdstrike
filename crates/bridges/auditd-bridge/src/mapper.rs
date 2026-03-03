//! Map auditd events to Spine fact schemas.
//!
//! Each audit event is mapped to a JSON fact with a well-known schema
//! identifier, severity classification, and structured payload.

use serde_json::{json, Value};

use crate::audit::{AuditEvent, AuditEventType};

/// Fact schema for auditd events published on the Spine.
pub const FACT_SCHEMA: &str = "clawdstrike.sdr.fact.auditd_event.v1";

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

/// Sensitive file paths that trigger critical severity for EXECVE/SYSCALL events.
const SENSITIVE_PATHS: &[&str] = &[
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/root/.ssh/",
    "/proc/kcore",
    "/dev/mem",
    "/dev/kmem",
    "/var/run/secrets/kubernetes.io/",
];

/// Map an [`AuditEvent`] to a Spine fact JSON value.
///
/// Returns `None` if the event cannot be meaningfully mapped.
pub fn map_event(event: &AuditEvent) -> Option<Value> {
    let timestamp = event
        .datetime()
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_default();

    let severity = classify_severity(event);

    // Build records array
    let records: Vec<Value> = event
        .records
        .iter()
        .map(|r| {
            let fields: Value = r
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect::<serde_json::Map<String, Value>>()
                .into();

            json!({
                "type": r.raw_type,
                "fields": fields,
            })
        })
        .collect();

    // Extract key fields from the primary record for top-level fact
    let primary = event.records.first()?;
    let uid = primary.fields.get("uid").cloned().unwrap_or_default();
    let exe = primary.fields.get("exe").cloned().unwrap_or_default();
    let comm = primary.fields.get("comm").cloned().unwrap_or_default();
    let key = primary.fields.get("key").cloned().unwrap_or_default();

    Some(json!({
        "schema": FACT_SCHEMA,
        "event_type": event.primary_type.subject_suffix(),
        "severity": severity.as_str(),
        "timestamp": timestamp,
        "serial": event.serial,
        "uid": uid,
        "exe": exe,
        "comm": comm,
        "audit_key": key,
        "records": records,
    }))
}

/// Classify severity based on event type and content.
pub fn classify_severity(event: &AuditEvent) -> Severity {
    match event.primary_type {
        // AVC denials and integrity violations are always critical.
        AuditEventType::Avc => Severity::Critical,
        AuditEventType::IntegrityData => Severity::Critical,

        // Authentication failures are high severity.
        AuditEventType::UserAuth | AuditEventType::UserLogin => classify_auth_severity(event),

        // Execve: check for uid=0 + sensitive paths.
        AuditEventType::Execve => classify_execve_severity(event),

        // Syscall: check for sensitive paths.
        AuditEventType::Syscall => classify_syscall_severity(event),

        // User commands: medium baseline.
        AuditEventType::UserCmd => Severity::Medium,

        // Everything else is low.
        _ => Severity::Low,
    }
}

/// Classify auth event severity based on success/failure.
fn classify_auth_severity(event: &AuditEvent) -> Severity {
    for record in &event.records {
        // Check structured fields first.
        if let Some(res) = record.fields.get("res") {
            if is_auth_failure_result(res) {
                return Severity::High;
            }
            // Structured result is authoritative for this record.
            continue;
        }

        // Fallback for records where res is only present in raw line text.
        if raw_line_has_auth_failure_result(&record.raw_line) {
            return Severity::High;
        }
    }
    Severity::Medium
}

fn is_auth_failure_result(res: &str) -> bool {
    let normalized = res.trim_matches(|c| c == '\'' || c == '"');
    normalized.eq_ignore_ascii_case("failed") || normalized == "0"
}

fn raw_line_has_auth_failure_result(raw_line: &str) -> bool {
    raw_line
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("res="))
        .any(is_auth_failure_result)
}

fn is_path_like_field_key(key: &str) -> bool {
    matches!(key, "exe" | "name" | "path" | "cwd")
        || key
            .strip_prefix('a')
            .map(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
            .unwrap_or(false)
}

/// Classify EXECVE severity: uid=0 + sensitive paths → Critical.
fn classify_execve_severity(event: &AuditEvent) -> Severity {
    let mut is_root = false;
    let mut touches_sensitive = false;

    for record in &event.records {
        // Check for root execution
        if record.fields.get("uid").map(|s| s.as_str()) == Some("0") {
            is_root = true;
        }

        // Check path-bearing fields only (exe/name/path/cwd/aN args).
        for (key, value) in &record.fields {
            if is_path_like_field_key(key) && SENSITIVE_PATHS.iter().any(|s| value.starts_with(s)) {
                touches_sensitive = true;
            }
        }
    }

    if is_root && touches_sensitive {
        Severity::Critical
    } else if is_root {
        Severity::Medium
    } else {
        Severity::Low
    }
}

/// Classify SYSCALL severity based on sensitive path access.
fn classify_syscall_severity(event: &AuditEvent) -> Severity {
    for record in &event.records {
        // PATH records contain the actual files being accessed
        if record.event_type == AuditEventType::Path {
            if let Some(name) = record.fields.get("name") {
                if SENSITIVE_PATHS.iter().any(|s| name.starts_with(s)) {
                    return Severity::Critical;
                }
            }
        }

        // Check exe field in SYSCALL record
        if let Some(exe) = record.fields.get("exe") {
            if SENSITIVE_PATHS.iter().any(|s| exe.starts_with(s)) {
                return Severity::Critical;
            }
        }
    }

    Severity::Low
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEventType, AuditRecord};

    fn make_record(event_type: AuditEventType, fields: &[(&str, &str)]) -> AuditRecord {
        AuditRecord {
            event_type,
            raw_type: format!("{event_type:?}").to_uppercase(),
            timestamp: 1_614_556_843.937,
            serial: 100,
            fields: fields
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            raw_line: String::new(),
        }
    }

    fn make_event(primary_type: AuditEventType, records: Vec<AuditRecord>) -> AuditEvent {
        AuditEvent {
            serial: 100,
            timestamp: 1_614_556_843.937,
            primary_type,
            records,
        }
    }

    #[test]
    fn avc_is_critical() {
        let event = make_event(
            AuditEventType::Avc,
            vec![make_record(AuditEventType::Avc, &[("avc", "denied")])],
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn integrity_is_critical() {
        let event = make_event(
            AuditEventType::IntegrityData,
            vec![make_record(AuditEventType::IntegrityData, &[])],
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn failed_auth_is_high() {
        let mut record = make_record(AuditEventType::UserAuth, &[("res", "failed")]);
        record.raw_line = "type=USER_AUTH msg=audit(1614556843.937:999): res=failed".to_string();
        let event = make_event(AuditEventType::UserAuth, vec![record]);
        assert_eq!(classify_severity(&event), Severity::High);
    }

    #[test]
    fn successful_auth_is_medium() {
        let event = make_event(
            AuditEventType::UserAuth,
            vec![make_record(AuditEventType::UserAuth, &[("res", "success")])],
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn auth_result_substring_does_not_false_positive() {
        let mut record = make_record(AuditEventType::UserAuth, &[("res", "success")]);
        record.raw_line =
            "type=USER_AUTH msg=audit(1614556843.937:999): adres=0 result=success".to_string();
        let event = make_event(AuditEventType::UserAuth, vec![record]);
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn auth_result_numeric_prefix_does_not_false_positive() {
        let mut record = make_record(AuditEventType::UserAuth, &[("res", "success")]);
        record.raw_line =
            "type=USER_AUTH msg=audit(1614556843.937:999): uid=0 msg='op=PAM:auth res=0123'"
                .to_string();
        let event = make_event(AuditEventType::UserAuth, vec![record]);
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn structured_auth_success_is_not_overridden_by_raw_line_fallback() {
        let mut record = make_record(AuditEventType::UserAuth, &[("res", "success")]);
        record.raw_line =
            "type=USER_AUTH msg=audit(1614556843.937:999): res=success msg='nested res=0'"
                .to_string();
        let event = make_event(AuditEventType::UserAuth, vec![record]);
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn root_execve_sensitive_path_is_critical() {
        let event = make_event(
            AuditEventType::Execve,
            vec![
                make_record(
                    AuditEventType::Syscall,
                    &[("uid", "0"), ("exe", "/usr/bin/cat")],
                ),
                make_record(AuditEventType::Execve, &[("a0", "cat")]),
                make_record(AuditEventType::Path, &[("name", "/etc/shadow")]),
            ],
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn root_execve_normal_path_is_medium() {
        let event = make_event(
            AuditEventType::Execve,
            vec![make_record(
                AuditEventType::Syscall,
                &[("uid", "0"), ("exe", "/usr/bin/ls")],
            )],
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn nonroot_execve_is_low() {
        let event = make_event(
            AuditEventType::Execve,
            vec![make_record(
                AuditEventType::Syscall,
                &[("uid", "1000"), ("exe", "/usr/bin/ls")],
            )],
        );
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn root_execve_non_path_fields_do_not_trigger_sensitive_match() {
        let event = make_event(
            AuditEventType::Execve,
            vec![make_record(
                AuditEventType::Syscall,
                &[
                    ("uid", "0"),
                    ("comm", "/etc/shadow"), // non-path semantic field
                    ("key", "/etc/shadow"),  // non-path semantic field
                ],
            )],
        );
        assert_eq!(classify_severity(&event), Severity::Medium);
    }

    #[test]
    fn normal_syscall_is_low() {
        let event = make_event(
            AuditEventType::Syscall,
            vec![make_record(AuditEventType::Syscall, &[("syscall", "59")])],
        );
        assert_eq!(classify_severity(&event), Severity::Low);
    }

    #[test]
    fn syscall_with_sensitive_path_is_critical() {
        let event = make_event(
            AuditEventType::Syscall,
            vec![
                make_record(AuditEventType::Syscall, &[("syscall", "2")]),
                make_record(AuditEventType::Path, &[("name", "/etc/shadow")]),
            ],
        );
        assert_eq!(classify_severity(&event), Severity::Critical);
    }

    #[test]
    fn map_event_produces_valid_fact() {
        let event = make_event(
            AuditEventType::Syscall,
            vec![make_record(
                AuditEventType::Syscall,
                &[("uid", "1000"), ("exe", "/usr/bin/ls"), ("comm", "ls")],
            )],
        );
        let fact = map_event(&event);
        assert!(fact.is_some());
        let fact = fact.unwrap_or_default();
        assert_eq!(fact["schema"], FACT_SCHEMA);
        assert_eq!(fact["event_type"], "syscall");
        assert_eq!(fact["serial"], 100);
    }

    #[test]
    fn map_event_empty_records_returns_none() {
        let event = AuditEvent {
            serial: 1,
            timestamp: 0.0,
            primary_type: AuditEventType::Unknown,
            records: vec![],
        };
        assert!(map_event(&event).is_none());
    }
}
