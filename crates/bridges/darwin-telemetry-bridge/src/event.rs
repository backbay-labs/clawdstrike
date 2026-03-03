//! Darwin telemetry event types.
//!
//! Platform-independent definitions — tests run on any OS.

use serde::{Deserialize, Serialize};

/// Source collector that produced the event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Process,
    #[serde(rename = "fsevents", alias = "fs_events")]
    FsEvents,
    UnifiedLog,
}

impl EventSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Process => "process",
            Self::FsEvents => "fsevents",
            Self::UnifiedLog => "unified_log",
        }
    }
}

/// Event types produced by darwin telemetry collectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DarwinEventType {
    // Process events
    ProcessSnapshot,
    ProcessSpawn,
    ProcessExit,

    // FSEvents events
    FileCreated,
    FileModified,
    FileRemoved,
    FileRenamed,
    XattrChanged,
    OwnerChanged,

    // Unified log events
    SecurityLog,
    AuthLog,
    SudoLog,
    DirectoryLog,
}

impl DarwinEventType {
    /// NATS subject suffix for this event type.
    pub fn subject_suffix(&self) -> &'static str {
        match self {
            Self::ProcessSnapshot => "snapshot",
            Self::ProcessSpawn => "spawn",
            Self::ProcessExit => "exit",
            Self::FileCreated => "created",
            Self::FileModified => "modified",
            Self::FileRemoved => "removed",
            Self::FileRenamed => "renamed",
            Self::XattrChanged => "xattr_changed",
            Self::OwnerChanged => "owner_changed",
            Self::SecurityLog => "securityd",
            Self::AuthLog => "authd",
            Self::SudoLog => "sudo",
            Self::DirectoryLog => "opendirectoryd",
        }
    }

    /// Source collector for this event type.
    pub fn source(&self) -> EventSource {
        match self {
            Self::ProcessSnapshot | Self::ProcessSpawn | Self::ProcessExit => EventSource::Process,
            Self::FileCreated
            | Self::FileModified
            | Self::FileRemoved
            | Self::FileRenamed
            | Self::XattrChanged
            | Self::OwnerChanged => EventSource::FsEvents,
            Self::SecurityLog | Self::AuthLog | Self::SudoLog | Self::DirectoryLog => {
                EventSource::UnifiedLog
            }
        }
    }

    /// Parse from a string (for CLI filter parsing).
    pub fn from_str_loose(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "process_snapshot" | "snapshot" => Some(Self::ProcessSnapshot),
            "process_spawn" | "spawn" => Some(Self::ProcessSpawn),
            "process_exit" | "exit" => Some(Self::ProcessExit),
            "file_created" | "created" => Some(Self::FileCreated),
            "file_modified" | "modified" => Some(Self::FileModified),
            "file_removed" | "removed" => Some(Self::FileRemoved),
            "file_renamed" | "renamed" => Some(Self::FileRenamed),
            "xattr_changed" => Some(Self::XattrChanged),
            "owner_changed" => Some(Self::OwnerChanged),
            "security_log" | "securityd" => Some(Self::SecurityLog),
            "auth_log" | "authd" => Some(Self::AuthLog),
            "sudo_log" | "sudo" => Some(Self::SudoLog),
            "directory_log" | "opendirectoryd" => Some(Self::DirectoryLog),
            _ => None,
        }
    }
}

/// Process information captured by the process collector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: i32,
    pub ppid: i32,
    pub uid: u32,
    pub name: String,
    pub path: String,
    pub start_time: i64,
}

/// Filesystem event captured by FSEvents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsEventInfo {
    pub path: String,
    pub flags: u32,
    pub event_id: u64,
}

/// Unified log entry captured by `log stream`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedLogEntry {
    pub timestamp: String,
    pub subsystem: String,
    pub category: String,
    pub process: String,
    pub pid: i64,
    pub message: String,
    pub level: String,
}

/// A telemetry event from any macOS collector.
#[derive(Debug, Clone)]
pub struct DarwinEvent {
    pub event_type: DarwinEventType,
    pub source: EventSource,
    pub timestamp: String,
    pub payload: serde_json::Value,
}

impl DarwinEvent {
    /// Full NATS subject suffix: `{source}.{event_type}`
    pub fn subject_suffix(&self) -> String {
        format!(
            "{}.{}",
            self.source.as_str(),
            self.event_type.subject_suffix()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_subject_suffixes() {
        assert_eq!(
            DarwinEventType::ProcessSnapshot.subject_suffix(),
            "snapshot"
        );
        assert_eq!(DarwinEventType::ProcessSpawn.subject_suffix(), "spawn");
        assert_eq!(DarwinEventType::ProcessExit.subject_suffix(), "exit");
        assert_eq!(DarwinEventType::FileCreated.subject_suffix(), "created");
        assert_eq!(DarwinEventType::FileModified.subject_suffix(), "modified");
        assert_eq!(DarwinEventType::FileRemoved.subject_suffix(), "removed");
        assert_eq!(DarwinEventType::FileRenamed.subject_suffix(), "renamed");
        assert_eq!(
            DarwinEventType::XattrChanged.subject_suffix(),
            "xattr_changed"
        );
        assert_eq!(
            DarwinEventType::OwnerChanged.subject_suffix(),
            "owner_changed"
        );
        assert_eq!(DarwinEventType::SecurityLog.subject_suffix(), "securityd");
        assert_eq!(DarwinEventType::AuthLog.subject_suffix(), "authd");
        assert_eq!(DarwinEventType::SudoLog.subject_suffix(), "sudo");
        assert_eq!(
            DarwinEventType::DirectoryLog.subject_suffix(),
            "opendirectoryd"
        );
    }

    #[test]
    fn event_type_sources() {
        assert_eq!(DarwinEventType::ProcessSpawn.source(), EventSource::Process);
        assert_eq!(DarwinEventType::FileCreated.source(), EventSource::FsEvents);
        assert_eq!(DarwinEventType::SudoLog.source(), EventSource::UnifiedLog);
    }

    #[test]
    fn event_source_as_str() {
        assert_eq!(EventSource::Process.as_str(), "process");
        assert_eq!(EventSource::FsEvents.as_str(), "fsevents");
        assert_eq!(EventSource::UnifiedLog.as_str(), "unified_log");
    }

    #[test]
    fn event_subject_suffix_format() {
        let event = DarwinEvent {
            event_type: DarwinEventType::ProcessSpawn,
            source: EventSource::Process,
            timestamp: "2026-03-02T00:00:00Z".to_string(),
            payload: serde_json::json!({}),
        };
        assert_eq!(event.subject_suffix(), "process.spawn");
    }

    #[test]
    fn from_str_loose_parses_variants() {
        assert_eq!(
            DarwinEventType::from_str_loose("process_spawn"),
            Some(DarwinEventType::ProcessSpawn)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("spawn"),
            Some(DarwinEventType::ProcessSpawn)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("SECURITYD"),
            Some(DarwinEventType::SecurityLog)
        );
        assert_eq!(DarwinEventType::from_str_loose("bogus"), None);
    }

    #[test]
    fn darwin_event_type_roundtrip_serde() {
        let t = DarwinEventType::ProcessSpawn;
        let json = serde_json::to_string(&t).unwrap_or_default();
        assert_eq!(json, r#""process_spawn""#);
        let parsed: DarwinEventType =
            serde_json::from_str(&json).unwrap_or(DarwinEventType::ProcessSnapshot);
        assert_eq!(parsed, t);
    }

    // --- Exhaustive from_str_loose tests ---

    #[test]
    fn from_str_loose_all_primary_variants() {
        let cases: &[(&str, DarwinEventType)] = &[
            ("process_snapshot", DarwinEventType::ProcessSnapshot),
            ("process_spawn", DarwinEventType::ProcessSpawn),
            ("process_exit", DarwinEventType::ProcessExit),
            ("file_created", DarwinEventType::FileCreated),
            ("file_modified", DarwinEventType::FileModified),
            ("file_removed", DarwinEventType::FileRemoved),
            ("file_renamed", DarwinEventType::FileRenamed),
            ("xattr_changed", DarwinEventType::XattrChanged),
            ("owner_changed", DarwinEventType::OwnerChanged),
            ("security_log", DarwinEventType::SecurityLog),
            ("auth_log", DarwinEventType::AuthLog),
            ("sudo_log", DarwinEventType::SudoLog),
            ("directory_log", DarwinEventType::DirectoryLog),
        ];
        for (input, expected) in cases {
            assert_eq!(
                DarwinEventType::from_str_loose(input),
                Some(*expected),
                "failed for primary variant: {input}"
            );
        }
    }

    #[test]
    fn from_str_loose_all_alias_variants() {
        let cases: &[(&str, DarwinEventType)] = &[
            ("snapshot", DarwinEventType::ProcessSnapshot),
            ("spawn", DarwinEventType::ProcessSpawn),
            ("exit", DarwinEventType::ProcessExit),
            ("created", DarwinEventType::FileCreated),
            ("modified", DarwinEventType::FileModified),
            ("removed", DarwinEventType::FileRemoved),
            ("renamed", DarwinEventType::FileRenamed),
            ("securityd", DarwinEventType::SecurityLog),
            ("authd", DarwinEventType::AuthLog),
            ("sudo", DarwinEventType::SudoLog),
            ("opendirectoryd", DarwinEventType::DirectoryLog),
        ];
        for (input, expected) in cases {
            assert_eq!(
                DarwinEventType::from_str_loose(input),
                Some(*expected),
                "failed for alias variant: {input}"
            );
        }
    }

    #[test]
    fn from_str_loose_case_insensitive() {
        assert_eq!(
            DarwinEventType::from_str_loose("PROCESS_SPAWN"),
            Some(DarwinEventType::ProcessSpawn)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("File_Created"),
            Some(DarwinEventType::FileCreated)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("XATTR_CHANGED"),
            Some(DarwinEventType::XattrChanged)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("OWNER_CHANGED"),
            Some(DarwinEventType::OwnerChanged)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("Snapshot"),
            Some(DarwinEventType::ProcessSnapshot)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("SUDO"),
            Some(DarwinEventType::SudoLog)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("OpenDirectoryD"),
            Some(DarwinEventType::DirectoryLog)
        );
    }

    #[test]
    fn from_str_loose_trims_whitespace() {
        assert_eq!(
            DarwinEventType::from_str_loose("  spawn  "),
            Some(DarwinEventType::ProcessSpawn)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("\tfile_created\n"),
            Some(DarwinEventType::FileCreated)
        );
        assert_eq!(
            DarwinEventType::from_str_loose("  SECURITYD  "),
            Some(DarwinEventType::SecurityLog)
        );
    }

    #[test]
    fn from_str_loose_empty_returns_none() {
        assert_eq!(DarwinEventType::from_str_loose(""), None);
    }

    #[test]
    fn from_str_loose_whitespace_only_returns_none() {
        assert_eq!(DarwinEventType::from_str_loose("   "), None);
        assert_eq!(DarwinEventType::from_str_loose("\t"), None);
        assert_eq!(DarwinEventType::from_str_loose("\n"), None);
    }

    #[test]
    fn from_str_loose_unknown_returns_none() {
        assert_eq!(DarwinEventType::from_str_loose("bogus"), None);
        assert_eq!(DarwinEventType::from_str_loose("file"), None);
        assert_eq!(DarwinEventType::from_str_loose("process"), None);
        assert_eq!(DarwinEventType::from_str_loose("log"), None);
        assert_eq!(DarwinEventType::from_str_loose("xattr"), None);
        assert_eq!(DarwinEventType::from_str_loose("owner"), None);
    }

    // --- Exhaustive DarwinEvent::subject_suffix() tests ---

    #[test]
    fn subject_suffix_all_process_events() {
        let cases: &[(DarwinEventType, &str)] = &[
            (DarwinEventType::ProcessSnapshot, "process.snapshot"),
            (DarwinEventType::ProcessSpawn, "process.spawn"),
            (DarwinEventType::ProcessExit, "process.exit"),
        ];
        for (event_type, expected) in cases {
            let event = DarwinEvent {
                event_type: *event_type,
                source: EventSource::Process,
                timestamp: "t".to_string(),
                payload: serde_json::json!({}),
            };
            assert_eq!(
                event.subject_suffix(),
                *expected,
                "failed for {:?}",
                event_type
            );
        }
    }

    #[test]
    fn subject_suffix_all_fsevents_events() {
        let cases: &[(DarwinEventType, &str)] = &[
            (DarwinEventType::FileCreated, "fsevents.created"),
            (DarwinEventType::FileModified, "fsevents.modified"),
            (DarwinEventType::FileRemoved, "fsevents.removed"),
            (DarwinEventType::FileRenamed, "fsevents.renamed"),
            (DarwinEventType::XattrChanged, "fsevents.xattr_changed"),
            (DarwinEventType::OwnerChanged, "fsevents.owner_changed"),
        ];
        for (event_type, expected) in cases {
            let event = DarwinEvent {
                event_type: *event_type,
                source: EventSource::FsEvents,
                timestamp: "t".to_string(),
                payload: serde_json::json!({}),
            };
            assert_eq!(
                event.subject_suffix(),
                *expected,
                "failed for {:?}",
                event_type
            );
        }
    }

    #[test]
    fn subject_suffix_all_unified_log_events() {
        let cases: &[(DarwinEventType, &str)] = &[
            (DarwinEventType::SecurityLog, "unified_log.securityd"),
            (DarwinEventType::AuthLog, "unified_log.authd"),
            (DarwinEventType::SudoLog, "unified_log.sudo"),
            (DarwinEventType::DirectoryLog, "unified_log.opendirectoryd"),
        ];
        for (event_type, expected) in cases {
            let event = DarwinEvent {
                event_type: *event_type,
                source: EventSource::UnifiedLog,
                timestamp: "t".to_string(),
                payload: serde_json::json!({}),
            };
            assert_eq!(
                event.subject_suffix(),
                *expected,
                "failed for {:?}",
                event_type
            );
        }
    }

    // --- source() exhaustive ---

    #[test]
    fn event_type_sources_exhaustive() {
        // Process events
        assert_eq!(
            DarwinEventType::ProcessSnapshot.source(),
            EventSource::Process
        );
        assert_eq!(DarwinEventType::ProcessSpawn.source(), EventSource::Process);
        assert_eq!(DarwinEventType::ProcessExit.source(), EventSource::Process);
        // FsEvents events
        assert_eq!(DarwinEventType::FileCreated.source(), EventSource::FsEvents);
        assert_eq!(
            DarwinEventType::FileModified.source(),
            EventSource::FsEvents
        );
        assert_eq!(DarwinEventType::FileRemoved.source(), EventSource::FsEvents);
        assert_eq!(DarwinEventType::FileRenamed.source(), EventSource::FsEvents);
        assert_eq!(
            DarwinEventType::XattrChanged.source(),
            EventSource::FsEvents
        );
        assert_eq!(
            DarwinEventType::OwnerChanged.source(),
            EventSource::FsEvents
        );
        // UnifiedLog events
        assert_eq!(
            DarwinEventType::SecurityLog.source(),
            EventSource::UnifiedLog
        );
        assert_eq!(DarwinEventType::AuthLog.source(), EventSource::UnifiedLog);
        assert_eq!(DarwinEventType::SudoLog.source(), EventSource::UnifiedLog);
        assert_eq!(
            DarwinEventType::DirectoryLog.source(),
            EventSource::UnifiedLog
        );
    }

    // --- Serde roundtrip for all event types ---

    #[test]
    fn serde_roundtrip_all_event_types() {
        let all_types = [
            DarwinEventType::ProcessSnapshot,
            DarwinEventType::ProcessSpawn,
            DarwinEventType::ProcessExit,
            DarwinEventType::FileCreated,
            DarwinEventType::FileModified,
            DarwinEventType::FileRemoved,
            DarwinEventType::FileRenamed,
            DarwinEventType::XattrChanged,
            DarwinEventType::OwnerChanged,
            DarwinEventType::SecurityLog,
            DarwinEventType::AuthLog,
            DarwinEventType::SudoLog,
            DarwinEventType::DirectoryLog,
        ];
        for t in &all_types {
            let json = serde_json::to_string(t).expect("serialize");
            let parsed: DarwinEventType = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*t, parsed, "roundtrip failed for {json}");
        }
    }

    #[test]
    fn serde_roundtrip_event_source() {
        let all_sources = [
            EventSource::Process,
            EventSource::FsEvents,
            EventSource::UnifiedLog,
        ];
        for s in &all_sources {
            let json = serde_json::to_string(s).expect("serialize");
            let parsed: EventSource = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(*s, parsed, "roundtrip failed for {json}");
        }
    }

    #[test]
    fn event_source_serde_values() {
        assert_eq!(
            serde_json::to_string(&EventSource::Process).unwrap_or_default(),
            r#""process""#
        );
        assert_eq!(
            serde_json::to_string(&EventSource::FsEvents).unwrap_or_default(),
            r#""fsevents""#
        );
        assert_eq!(
            serde_json::to_string(&EventSource::UnifiedLog).unwrap_or_default(),
            r#""unified_log""#
        );
    }

    #[test]
    fn event_source_serde_accepts_legacy_fs_events_alias() {
        let parsed: EventSource = serde_json::from_str(r#""fs_events""#).expect("deserialize");
        assert_eq!(parsed, EventSource::FsEvents);
    }
}
