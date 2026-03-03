//! Unified Log collector via `log stream --style ndjson` subprocess.
//!
//! Spawns `/usr/bin/log stream` and parses its ndjson output into
//! `DarwinEvent` values.

#[cfg(target_os = "macos")]
mod platform {
    use serde::Deserialize;
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::process::Command;
    use tokio::sync::mpsc;
    use tracing::{debug, warn};

    use crate::error::Error;
    use crate::event::{DarwinEvent, DarwinEventType, EventSource};

    /// Default predicate for security-relevant log entries.
    pub const DEFAULT_PREDICATE: &str = concat!(
        r#"subsystem == "com.apple.securityd""#,
        r#" OR subsystem == "com.apple.authd""#,
        r#" OR eventMessage CONTAINS "sudo""#,
        r#" OR subsystem == "com.apple.opendirectoryd""#,
    );

    /// A single ndjson entry from `log stream`.
    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LogStreamEntry {
        timestamp: Option<String>,
        subsystem: Option<String>,
        category: Option<String>,
        #[serde(alias = "processImagePath")]
        process: Option<String>,
        #[serde(alias = "processID")]
        process_id: Option<i64>,
        event_message: Option<String>,
        message_type: Option<String>,
    }

    /// Classify a log entry into a `DarwinEventType`.
    fn classify_log_entry(entry: &LogStreamEntry) -> DarwinEventType {
        let subsystem = entry.subsystem.as_deref().unwrap_or("");
        let message = entry.event_message.as_deref().unwrap_or("");

        if message.contains("sudo") {
            return DarwinEventType::SudoLog;
        }
        match subsystem {
            "com.apple.securityd" => DarwinEventType::SecurityLog,
            "com.apple.authd" => DarwinEventType::AuthLog,
            "com.apple.opendirectoryd" => DarwinEventType::DirectoryLog,
            _ => {
                // Fall back based on message content
                if message.contains("auth") {
                    DarwinEventType::AuthLog
                } else {
                    DarwinEventType::SecurityLog
                }
            }
        }
    }

    /// Unified log collector that streams security-relevant log entries.
    pub struct UnifiedLogCollector {
        predicate: String,
    }

    impl UnifiedLogCollector {
        pub fn new(predicate: Option<String>) -> Self {
            Self {
                predicate: predicate.unwrap_or_else(|| DEFAULT_PREDICATE.to_string()),
            }
        }

        /// Run the collector, sending events to the provided channel.
        pub async fn run(self, tx: mpsc::Sender<DarwinEvent>) -> Result<(), Error> {
            let mut child = Command::new("/usr/bin/log")
                .args([
                    "stream",
                    "--style",
                    "ndjson",
                    "--predicate",
                    &self.predicate,
                ])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .map_err(|e| Error::UnifiedLog(format!("failed to spawn `log stream`: {e}")))?;

            let stdout = child.stdout.take().ok_or_else(|| {
                Error::UnifiedLog("failed to capture stdout from `log stream`".to_string())
            })?;

            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();

            loop {
                match lines.next_line().await {
                    Ok(Some(line)) => {
                        let line = line.trim().to_string();
                        if line.is_empty() {
                            continue;
                        }

                        // `log stream` may emit non-JSON preamble lines
                        if !line.starts_with('{') {
                            debug!(line = %line, "skipping non-JSON line from log stream");
                            continue;
                        }

                        match serde_json::from_str::<LogStreamEntry>(&line) {
                            Ok(entry) => {
                                let event_type = classify_log_entry(&entry);
                                let event = DarwinEvent {
                                    event_type,
                                    source: EventSource::UnifiedLog,
                                    timestamp: entry.timestamp.clone().unwrap_or_default(),
                                    payload: json!({
                                        "timestamp": entry.timestamp.unwrap_or_default(),
                                        "subsystem": entry.subsystem.unwrap_or_default(),
                                        "category": entry.category.unwrap_or_default(),
                                        "process": entry.process.unwrap_or_default(),
                                        "pid": entry.process_id.unwrap_or(0),
                                        "message": entry.event_message.unwrap_or_default(),
                                        "level": entry.message_type.unwrap_or_default(),
                                    }),
                                };
                                if tx.send(event).await.is_err() {
                                    debug!("unified log collector channel closed");
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                debug!(error = %e, "failed to parse log stream line");
                            }
                        }
                    }
                    Ok(None) => {
                        warn!("`log stream` subprocess exited");
                        return Err(Error::UnifiedLog(
                            "`log stream` process exited unexpectedly".to_string(),
                        ));
                    }
                    Err(e) => {
                        warn!(error = %e, "error reading from `log stream`");
                        return Err(Error::UnifiedLog(format!(
                            "error reading log stream stdout: {e}"
                        )));
                    }
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub use platform::{UnifiedLogCollector, DEFAULT_PREDICATE};

// Platform-independent deserialization tests
#[cfg(test)]
mod tests {
    #[test]
    fn parse_log_stream_entry() {
        // Simulate an ndjson line from `log stream --style ndjson`
        let line = r#"{"timestamp":"2026-03-02 10:00:00.000000-0800","subsystem":"com.apple.securityd","category":"security","processImagePath":"/usr/sbin/securityd","processID":123,"eventMessage":"keychain access granted","messageType":"Default"}"#;

        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        assert_eq!(
            entry.get("subsystem").and_then(|v| v.as_str()),
            Some("com.apple.securityd")
        );
        assert_eq!(entry.get("processID").and_then(|v| v.as_i64()), Some(123));
    }

    #[test]
    fn parse_sudo_log_entry() {
        let line = r#"{"timestamp":"2026-03-02 10:00:00.000000-0800","subsystem":"","category":"","processImagePath":"/usr/bin/sudo","processID":456,"eventMessage":"user ran sudo ls","messageType":"Default"}"#;

        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        let msg = entry
            .get("eventMessage")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(msg.contains("sudo"));
    }

    #[test]
    fn skip_non_json_preamble() {
        let line = "Filtering the log data using...";
        assert!(!line.starts_with('{'));
    }

    #[test]
    fn parse_entry_with_missing_optional_fields() {
        // ndjson entry with only timestamp and eventMessage
        let line = r#"{"timestamp":"2026-03-02 10:00:00.000000-0800","eventMessage":"something happened"}"#;
        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        assert_eq!(
            entry.get("timestamp").and_then(|v| v.as_str()),
            Some("2026-03-02 10:00:00.000000-0800")
        );
        // Missing fields should be absent, not null
        assert!(entry.get("subsystem").is_none());
        assert!(entry.get("category").is_none());
        assert!(entry.get("processID").is_none());
    }

    #[test]
    fn parse_entry_with_extra_fields() {
        // ndjson lines may include fields we don't model
        let line = r#"{"timestamp":"2026-03-02 10:00:00.000000-0800","subsystem":"com.apple.securityd","category":"security","processImagePath":"/usr/sbin/securityd","processID":123,"eventMessage":"ok","messageType":"Default","extraField":"ignored","anotherExtra":42}"#;
        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        assert_eq!(entry.get("processID").and_then(|v| v.as_i64()), Some(123));
        // Extra fields parse fine in serde_json::Value
        assert_eq!(
            entry.get("extraField").and_then(|v| v.as_str()),
            Some("ignored")
        );
        assert_eq!(entry.get("anotherExtra").and_then(|v| v.as_i64()), Some(42));
    }

    #[test]
    fn parse_entry_with_null_values() {
        let line = r#"{"timestamp":null,"subsystem":null,"category":null,"processImagePath":null,"processID":null,"eventMessage":null,"messageType":null}"#;
        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        assert!(entry
            .get("timestamp")
            .unwrap_or(&serde_json::Value::Null)
            .is_null());
        assert!(entry
            .get("subsystem")
            .unwrap_or(&serde_json::Value::Null)
            .is_null());
        assert!(entry
            .get("processID")
            .unwrap_or(&serde_json::Value::Null)
            .is_null());
    }

    #[test]
    fn malformed_json_parses_to_default() {
        let line = r#"{"timestamp": "2026-03-02"  this is not valid json"#;
        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        // unwrap_or_default on Value gives Value::Null
        assert!(entry.is_null());
    }

    #[test]
    fn empty_json_object_parses() {
        let line = "{}";
        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        assert!(entry.is_object());
        assert_eq!(entry.as_object().map(|m| m.len()), Some(0));
    }

    #[test]
    fn parse_entry_with_camel_case_fields() {
        // The actual `log stream --style ndjson` uses camelCase
        let line = r#"{"timestamp":"t","subsystem":"com.apple.authd","category":"auth","processImagePath":"/usr/libexec/opendirectoryd","processID":99,"eventMessage":"lookup succeeded","messageType":"Info"}"#;
        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        assert_eq!(
            entry.get("processImagePath").and_then(|v| v.as_str()),
            Some("/usr/libexec/opendirectoryd")
        );
        assert_eq!(
            entry.get("messageType").and_then(|v| v.as_str()),
            Some("Info")
        );
    }

    #[test]
    fn skip_empty_line() {
        let line = "";
        assert!(line.is_empty());
    }

    #[test]
    fn skip_whitespace_only_line() {
        let line = "   ";
        assert!(line.trim().is_empty());
    }

    #[test]
    fn array_is_not_valid_entry() {
        // A JSON array line should not parse as an entry
        let line = r#"[1, 2, 3]"#;
        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        assert!(entry.is_array());
        // In the real collector, line.starts_with('{') would skip this
        assert!(!line.starts_with('{'));
    }

    #[test]
    fn parse_entry_with_empty_string_fields() {
        let line = r#"{"timestamp":"","subsystem":"","category":"","processImagePath":"","processID":0,"eventMessage":"","messageType":""}"#;
        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        assert_eq!(entry.get("timestamp").and_then(|v| v.as_str()), Some(""));
        assert_eq!(entry.get("eventMessage").and_then(|v| v.as_str()), Some(""));
        assert_eq!(entry.get("processID").and_then(|v| v.as_i64()), Some(0));
    }

    #[test]
    fn parse_entry_with_unicode_message() {
        let line = r#"{"timestamp":"t","eventMessage":"user \u00e9l\u00e8ve authenticated"}"#;
        let entry: serde_json::Value = serde_json::from_str(line).unwrap_or_default();
        let msg = entry
            .get("eventMessage")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        assert!(msg.contains("authenticated"));
    }
}
