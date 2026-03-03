//! Linux auditd log parser, multi-line record grouper, and async file tailer.
//!
//! Auditd records follow the format:
//! ```text
//! type=SYSCALL msg=audit(1614556843.937:123456): arch=c000003e syscall=59 ...
//! type=EXECVE msg=audit(1614556843.937:123456): argc=3 a0="ls" ...
//! type=CWD msg=audit(1614556843.937:123456): cwd="/home/user"
//! type=PATH msg=audit(1614556843.937:123456): item=0 name="/usr/bin/ls" ...
//! ```
//!
//! Records sharing the same serial number (after the colon in `msg=audit(ts:serial)`)
//! form a single logical event and are grouped by [`AuditEventGrouper`].

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Audit event types we recognize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEventType {
    Syscall,
    Execve,
    Path,
    Cwd,
    UserAuth,
    UserLogin,
    UserCmd,
    Avc,
    IntegrityData,
    Proctitle,
    Unknown,
}

impl AuditEventType {
    /// Parse from the `type=` field in an audit log line.
    pub fn from_type_str(s: &str) -> Self {
        match s.to_uppercase().as_str() {
            "SYSCALL" => Self::Syscall,
            "EXECVE" => Self::Execve,
            "PATH" => Self::Path,
            "CWD" => Self::Cwd,
            "USER_AUTH" => Self::UserAuth,
            "USER_LOGIN" => Self::UserLogin,
            "USER_CMD" => Self::UserCmd,
            "AVC" => Self::Avc,
            "INTEGRITY_DATA" | "INTEGRITY_RULE" | "INTEGRITY_STATUS" => Self::IntegrityData,
            "PROCTITLE" => Self::Proctitle,
            _ => Self::Unknown,
        }
    }

    /// Subject suffix for NATS topic routing.
    pub fn subject_suffix(&self) -> &'static str {
        match self {
            Self::Syscall => "syscall",
            Self::Execve => "execve",
            Self::Path => "path",
            Self::Cwd => "cwd",
            Self::UserAuth => "user_auth",
            Self::UserLogin => "user_login",
            Self::UserCmd => "user_cmd",
            Self::Avc => "avc",
            Self::IntegrityData => "integrity",
            Self::Proctitle => "proctitle",
            Self::Unknown => "unknown",
        }
    }
}

/// A single parsed audit log line.
#[derive(Debug, Clone)]
pub struct AuditRecord {
    /// The event type (e.g. SYSCALL, EXECVE, AVC).
    pub event_type: AuditEventType,
    /// The raw type string from the log.
    pub raw_type: String,
    /// Unix timestamp from the `msg=audit(ts:serial)` header.
    pub timestamp: f64,
    /// Serial number from the `msg=audit(ts:serial)` header.
    pub serial: u64,
    /// Key-value fields parsed from the record body.
    pub fields: HashMap<String, String>,
    /// The original raw log line.
    pub raw_line: String,
}

/// A grouped audit event: one or more records sharing the same serial number.
#[derive(Debug, Clone)]
pub struct AuditEvent {
    /// Serial number shared by all records in this event.
    pub serial: u64,
    /// Timestamp from the first record.
    pub timestamp: f64,
    /// The primary event type (from the first/most significant record).
    pub primary_type: AuditEventType,
    /// All records in this event, in order received.
    pub records: Vec<AuditRecord>,
}

impl AuditEvent {
    /// Parsed timestamp as a UTC `DateTime`.
    pub fn datetime(&self) -> Option<DateTime<Utc>> {
        let secs = self.timestamp as i64;
        let nanos = ((self.timestamp - secs as f64) * 1_000_000_000.0) as u32;
        DateTime::from_timestamp(secs, nanos)
    }

    /// Get the primary subject suffix for NATS routing.
    /// Uses the highest-priority record type in the group.
    pub fn subject_suffix(&self) -> &'static str {
        self.primary_type.subject_suffix()
    }
}

/// Parse a single audit log line into an [`AuditRecord`].
///
/// Expected format:
/// ```text
/// type=SYSCALL msg=audit(1614556843.937:123456): key=value key2=value2 ...
/// ```
pub fn parse_audit_line(line: &str) -> Result<AuditRecord> {
    let line = line.trim();
    if line.is_empty() {
        return Err(Error::Parse("empty line".to_string()));
    }

    // Extract type=VALUE
    let raw_type = extract_field(line, "type=")
        .ok_or_else(|| Error::Parse(format!("missing type= field: {line}")))?;

    let event_type = AuditEventType::from_type_str(&raw_type);

    // Extract msg=audit(TIMESTAMP:SERIAL)
    let (timestamp, serial) = parse_audit_header(line)?;

    // Parse body fields after the ): delimiter
    let fields = parse_body_fields(line);

    Ok(AuditRecord {
        event_type,
        raw_type,
        timestamp,
        serial,
        fields,
        raw_line: line.to_string(),
    })
}

/// Extract the `msg=audit(TS:SERIAL)` header from a log line.
fn parse_audit_header(line: &str) -> Result<(f64, u64)> {
    let msg_start = line
        .find("msg=audit(")
        .ok_or_else(|| Error::Parse(format!("missing msg=audit( header: {line}")))?;

    let after_paren = msg_start + "msg=audit(".len();
    let close_paren = line[after_paren..]
        .find(')')
        .ok_or_else(|| Error::Parse(format!("missing closing paren in audit header: {line}")))?;

    let inner = &line[after_paren..after_paren + close_paren];

    let colon_pos = inner
        .find(':')
        .ok_or_else(|| Error::Parse(format!("missing colon in audit header: {inner}")))?;

    let ts_str = &inner[..colon_pos];
    let serial_str = &inner[colon_pos + 1..];

    let timestamp: f64 = ts_str
        .parse()
        .map_err(|e| Error::Parse(format!("invalid timestamp '{ts_str}': {e}")))?;

    let serial: u64 = serial_str
        .parse()
        .map_err(|e| Error::Parse(format!("invalid serial '{serial_str}': {e}")))?;

    Ok((timestamp, serial))
}

/// Extract a simple `key=VALUE` where VALUE ends at the next space.
fn extract_field(line: &str, prefix: &str) -> Option<String> {
    let start = line.find(prefix)?;
    let value_start = start + prefix.len();
    let rest = &line[value_start..];
    let end = rest.find(' ').unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

/// Parse key=value pairs from the body after `): `.
fn parse_body_fields(line: &str) -> HashMap<String, String> {
    // Find the body after "): "
    let body = match line.find("): ") {
        Some(pos) => &line[pos + 3..],
        None => return HashMap::new(),
    };

    let mut fields = parse_fields_from_body(body);

    // USER_AUTH/USER_LOGIN records often embed key-value pairs inside msg='...'.
    // Preserve the full msg field while also extracting nested fields like res=.
    if let Some(msg_value) = fields.get("msg").cloned() {
        for (key, value) in parse_fields_from_body(&msg_value) {
            fields.entry(key).or_insert(value);
        }
    }

    fields
}

fn parse_fields_from_body(body: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();

    // Parse key=value pairs, handling single and double-quoted values.
    let mut chars = body.chars().peekable();
    let mut current_key = String::new();
    let mut current_value = String::new();
    let mut in_key = true;
    let mut quote_char: Option<char> = None;

    while let Some(ch) = chars.next() {
        if in_key {
            if ch == '=' {
                in_key = false;
                current_value.clear();
                // Check if value starts with a quote.
                if matches!(chars.peek().copied(), Some('"') | Some('\'')) {
                    quote_char = chars.next();
                }
            } else if ch == ' ' {
                // Key without value (shouldn't happen often)
                if !current_key.is_empty() {
                    fields.insert(current_key.clone(), String::new());
                    current_key.clear();
                }
            } else {
                current_key.push(ch);
            }
        } else if let Some(expected_quote) = quote_char {
            if ch == expected_quote {
                quote_char = None;
                fields.insert(current_key.clone(), current_value.clone());
                current_key.clear();
                current_value.clear();
                in_key = true;
                // Skip the space after the closing quote.
                if chars.peek() == Some(&' ') {
                    chars.next();
                }
            } else {
                current_value.push(ch);
            }
        } else if ch == ' ' {
            fields.insert(current_key.clone(), current_value.clone());
            current_key.clear();
            current_value.clear();
            in_key = true;
        } else {
            current_value.push(ch);
        }
    }

    // Don't forget the last key=value pair
    if !current_key.is_empty() {
        fields.insert(current_key, current_value);
    }

    fields
}

/// Groups audit records by serial number with a flush timeout.
///
/// Auditd emits multi-line records sharing the same serial. The grouper
/// collects them and flushes a complete [`AuditEvent`] when:
/// - A new serial is seen (previous group is complete)
/// - The flush timeout expires since the last record for a given serial
pub struct AuditEventGrouper {
    /// Pending groups keyed by serial number.
    pending: HashMap<u64, Vec<AuditRecord>>,
    /// Flush timeout in milliseconds.
    flush_timeout_ms: u64,
    /// Last insert time per serial (monotonic instant).
    last_insert: HashMap<u64, std::time::Instant>,
}

impl AuditEventGrouper {
    /// Create a new grouper with the given flush timeout.
    pub fn new(flush_timeout_ms: u64) -> Self {
        Self {
            pending: HashMap::new(),
            flush_timeout_ms,
            last_insert: HashMap::new(),
        }
    }

    /// Add a record to the grouper.
    ///
    /// Returns any events that have been completed (different serial seen)
    /// or timed out.
    pub fn add_record(&mut self, record: AuditRecord) -> Vec<AuditEvent> {
        let serial = record.serial;
        let mut completed = self.flush_expired();

        // A new serial indicates previously pending serial groups are complete.
        let completed_serials: Vec<u64> = self
            .pending
            .keys()
            .copied()
            .filter(|pending_serial| *pending_serial != serial)
            .collect();
        for completed_serial in completed_serials {
            if let Some(records) = self.pending.remove(&completed_serial) {
                self.last_insert.remove(&completed_serial);
                if let Some(event) = build_event(completed_serial, records) {
                    completed.push(event);
                }
            }
        }

        self.pending.entry(serial).or_default().push(record);
        self.last_insert.insert(serial, std::time::Instant::now());
        completed
    }

    /// Flush any groups that have exceeded the timeout.
    pub fn flush_expired(&mut self) -> Vec<AuditEvent> {
        let timeout = std::time::Duration::from_millis(self.flush_timeout_ms);
        let now = std::time::Instant::now();

        let expired_serials: Vec<u64> = self
            .last_insert
            .iter()
            .filter(|(_, &instant)| now.duration_since(instant) >= timeout)
            .map(|(&serial, _)| serial)
            .collect();

        let mut events = Vec::new();
        for serial in expired_serials {
            if let Some(records) = self.pending.remove(&serial) {
                self.last_insert.remove(&serial);
                if let Some(event) = build_event(serial, records) {
                    events.push(event);
                }
            }
        }

        events
    }

    /// Flush all pending groups regardless of timeout.
    pub fn flush_all(&mut self) -> Vec<AuditEvent> {
        let serials: Vec<u64> = self.pending.keys().copied().collect();
        let mut events = Vec::new();

        for serial in serials {
            if let Some(records) = self.pending.remove(&serial) {
                self.last_insert.remove(&serial);
                if let Some(event) = build_event(serial, records) {
                    events.push(event);
                }
            }
        }

        events
    }
}

/// Build an [`AuditEvent`] from a group of records sharing the same serial.
fn build_event(serial: u64, records: Vec<AuditRecord>) -> Option<AuditEvent> {
    if records.is_empty() {
        return None;
    }

    let timestamp = records[0].timestamp;
    let primary_type = determine_primary_type(&records);

    Some(AuditEvent {
        serial,
        timestamp,
        primary_type,
        records,
    })
}

/// Determine the primary (most significant) event type from a group of records.
///
/// Priority: AVC > IntegrityData > UserAuth > UserLogin > UserCmd > Execve > Syscall > others
fn determine_primary_type(records: &[AuditRecord]) -> AuditEventType {
    let priority = |t: &AuditEventType| -> u8 {
        match t {
            AuditEventType::Avc => 10,
            AuditEventType::IntegrityData => 9,
            AuditEventType::UserAuth => 8,
            AuditEventType::UserLogin => 7,
            AuditEventType::UserCmd => 6,
            AuditEventType::Execve => 5,
            AuditEventType::Syscall => 4,
            AuditEventType::Path => 3,
            AuditEventType::Cwd => 2,
            AuditEventType::Proctitle => 1,
            AuditEventType::Unknown => 0,
        }
    };

    records
        .iter()
        .map(|r| r.event_type)
        .max_by_key(priority)
        .unwrap_or(AuditEventType::Unknown)
}

/// Async file tailer for audit logs with rotation detection.
///
/// Tails the audit log file, yielding lines as they appear. Detects log
/// rotation (file truncation or inode change) and re-opens the file.
pub struct AuditLogTailer {
    path: String,
    poll_interval: std::time::Duration,
}

impl AuditLogTailer {
    pub fn new(path: &str, poll_interval_ms: u64) -> Self {
        Self {
            path: path.to_string(),
            poll_interval: std::time::Duration::from_millis(poll_interval_ms),
        }
    }

    /// Run the tailer, sending lines to the provided channel.
    ///
    /// This function runs indefinitely, re-opening the file on rotation.
    pub async fn run(
        &self,
        tx: tokio::sync::mpsc::Sender<String>,
    ) -> std::result::Result<(), Error> {
        use tokio::io::AsyncBufReadExt;

        let mut last_inode: Option<u64> = None;
        let mut offset: u64 = 0;

        loop {
            // Check if file exists
            let metadata = match tokio::fs::metadata(&self.path).await {
                Ok(m) => m,
                Err(_) => {
                    tracing::debug!(path = %self.path, "audit log not found, waiting...");
                    tokio::time::sleep(self.poll_interval).await;
                    continue;
                }
            };

            // Detect rotation by inode change or file shrinkage
            #[cfg(unix)]
            let current_inode = {
                use std::os::unix::fs::MetadataExt;
                metadata.ino()
            };
            #[cfg(not(unix))]
            let current_inode = 0u64;

            let file_len = metadata.len();
            let rotated = match last_inode {
                Some(prev) => current_inode != prev || file_len < offset,
                None => true, // First open, start from end
            };

            if rotated {
                let first_open = last_inode.is_none();
                tracing::info!(
                    path = %self.path,
                    inode = current_inode,
                    first_open,
                    "opening audit log (rotation detected or first open)"
                );
                // On first open, start from end to avoid replaying old events.
                // On rotation, start from beginning of new file.
                offset = if first_open { file_len } else { 0 };
                last_inode = Some(current_inode);
            }

            // Open and seek directly to offset
            let mut file = match tokio::fs::File::open(&self.path).await {
                Ok(f) => f,
                Err(e) => {
                    tracing::warn!(error = %e, "failed to open audit log");
                    tokio::time::sleep(self.poll_interval).await;
                    continue;
                }
            };

            if offset > 0 {
                use tokio::io::AsyncSeekExt;
                if let Err(e) = file.seek(std::io::SeekFrom::Start(offset)).await {
                    tracing::warn!(error = %e, offset, "failed to seek audit log");
                    tokio::time::sleep(self.poll_interval).await;
                    continue;
                }
            }

            let mut reader = tokio::io::BufReader::new(file);

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) => {
                        // EOF reached, wait and check for new data or rotation
                        break;
                    }
                    Ok(bytes_read) => {
                        let Some(line) = finalize_complete_line(line, bytes_read, &mut offset)
                        else {
                            // `read_line` can return bytes at EOF without a trailing newline.
                            // Keep `offset` unchanged so we re-read and stitch the full line.
                            tracing::debug!(
                                bytes_read,
                                "partial audit line at EOF, waiting for newline before emitting"
                            );
                            break;
                        };

                        if tx.send(line).await.is_err() {
                            tracing::warn!("line receiver dropped, stopping tailer");
                            return Ok(());
                        }
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "error reading audit log");
                        break;
                    }
                }
            }

            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

/// Convert a freshly-read buffer into a complete line ready for downstream parsing.
///
/// Returns `None` for partial EOF fragments that do not end in `\n`; in that case,
/// `offset` is intentionally left unchanged so the fragment is re-read next poll.
fn finalize_complete_line(mut line: String, bytes_read: usize, offset: &mut u64) -> Option<String> {
    if !line.ends_with('\n') {
        return None;
    }

    *offset += bytes_read as u64;
    line.pop(); // trailing '\n'
    if line.ends_with('\r') {
        line.pop();
    }
    Some(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_syscall_line() {
        let line = r#"type=SYSCALL msg=audit(1614556843.937:123456): arch=c000003e syscall=59 success=yes exit=0 a0=55f1e2 a1=55f1e3 a2=55f1e4 a3=0 items=2 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts0 ses=3 comm="ls" exe="/usr/bin/ls" key="file_access""#;

        let record = parse_audit_line(line).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(record.event_type, AuditEventType::Syscall);
        assert_eq!(record.serial, 123456);
        assert!((record.timestamp - 1_614_556_843.937).abs() < 0.001);
        assert_eq!(record.fields.get("syscall"), Some(&"59".to_string()));
        assert_eq!(record.fields.get("uid"), Some(&"0".to_string()));
        assert_eq!(record.fields.get("exe"), Some(&"/usr/bin/ls".to_string()));
    }

    #[test]
    fn parse_execve_line() {
        let line =
            r#"type=EXECVE msg=audit(1614556843.937:123456): argc=3 a0="ls" a1="-la" a2="/tmp""#;

        let record = parse_audit_line(line).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(record.event_type, AuditEventType::Execve);
        assert_eq!(record.serial, 123456);
        assert_eq!(record.fields.get("argc"), Some(&"3".to_string()));
        assert_eq!(record.fields.get("a0"), Some(&"ls".to_string()));
    }

    #[test]
    fn parse_avc_line() {
        let line = r#"type=AVC msg=audit(1614556843.937:789): avc:  denied  { read } for  pid=1234 comm="httpd" name="shadow" dev="sda1" ino=12345 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0"#;

        let record = parse_audit_line(line).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(record.event_type, AuditEventType::Avc);
        assert_eq!(record.serial, 789);
    }

    #[test]
    fn parse_user_auth_line() {
        let line = r#"type=USER_AUTH msg=audit(1614556843.937:999): pid=5678 uid=0 auid=1000 ses=3 msg='op=PAM:authentication grantors=pam_unix acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=success'"#;

        let record = parse_audit_line(line).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(record.event_type, AuditEventType::UserAuth);
        assert_eq!(record.serial, 999);
        assert_eq!(record.fields.get("res"), Some(&"success".to_string()));
        assert_eq!(
            record.fields.get("terminal"),
            Some(&"/dev/pts/0".to_string())
        );
    }

    #[test]
    fn parse_user_auth_failed_single_quoted_msg() {
        let line = r#"type=USER_AUTH msg=audit(1614556843.937:1000): pid=5678 uid=0 auid=1000 ses=3 msg='op=PAM:authentication grantors=pam_unix acct="root" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/0 res=failed'"#;

        let record = parse_audit_line(line).unwrap_or_else(|e| panic!("parse failed: {e}"));
        assert_eq!(record.event_type, AuditEventType::UserAuth);
        assert_eq!(record.serial, 1000);
        assert_eq!(record.fields.get("res"), Some(&"failed".to_string()));
    }

    #[test]
    fn parse_empty_line_returns_error() {
        assert!(parse_audit_line("").is_err());
    }

    #[test]
    fn parse_garbage_returns_error() {
        assert!(parse_audit_line("this is not an audit line").is_err());
    }

    #[test]
    fn finalize_complete_line_advances_offset_on_newline() {
        let mut offset = 10_u64;
        let line = "type=SYSCALL msg=...\n".to_string();
        let bytes_read = line.len();

        let finalized = finalize_complete_line(line, bytes_read, &mut offset);

        assert_eq!(finalized, Some("type=SYSCALL msg=...".to_string()));
        assert_eq!(offset, 10 + bytes_read as u64);
    }

    #[test]
    fn finalize_complete_line_preserves_offset_for_partial_line() {
        let mut offset = 42_u64;
        let line = "type=SYSCALL msg=partial".to_string();
        let bytes_read = line.len();

        let finalized = finalize_complete_line(line, bytes_read, &mut offset);

        assert_eq!(finalized, None);
        assert_eq!(offset, 42);
    }

    #[test]
    fn grouper_groups_by_serial() {
        let mut grouper = AuditEventGrouper::new(60_000); // Long timeout — we flush manually

        let line1 = r#"type=SYSCALL msg=audit(1614556843.937:100): syscall=59 uid=0"#;
        let line2 = r#"type=EXECVE msg=audit(1614556843.937:100): argc=1 a0="ls""#;
        let line3 = r#"type=CWD msg=audit(1614556843.937:100): cwd="/home""#;

        let r1 = parse_audit_line(line1).unwrap_or_else(|e| panic!("{e}"));
        let r2 = parse_audit_line(line2).unwrap_or_else(|e| panic!("{e}"));
        let r3 = parse_audit_line(line3).unwrap_or_else(|e| panic!("{e}"));

        // Adding records with same serial
        let _ = grouper.add_record(r1);
        let _ = grouper.add_record(r2);
        let _ = grouper.add_record(r3);

        // Flush all pending (regardless of timeout)
        let events = grouper.flush_all();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].serial, 100);
        assert_eq!(events[0].records.len(), 3);
        // Primary type should be EXECVE (higher priority than SYSCALL/CWD)
        assert_eq!(events[0].primary_type, AuditEventType::Execve);
    }

    #[test]
    fn grouper_separates_different_serials() {
        let mut grouper = AuditEventGrouper::new(60_000);

        let line1 = r#"type=SYSCALL msg=audit(1614556843.937:100): syscall=59"#;
        let line2 = r#"type=AVC msg=audit(1614556843.937:200): avc: denied"#;

        let r1 = parse_audit_line(line1).unwrap_or_else(|e| panic!("{e}"));
        let r2 = parse_audit_line(line2).unwrap_or_else(|e| panic!("{e}"));

        let events_after_first = grouper.add_record(r1);
        assert_eq!(events_after_first.len(), 0);

        let events_after_second = grouper.add_record(r2);
        assert_eq!(events_after_second.len(), 1);
        assert_eq!(events_after_second[0].serial, 100);

        let events = grouper.flush_all();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].serial, 200);
    }

    #[test]
    fn grouper_flushes_previous_serial_immediately() {
        let mut grouper = AuditEventGrouper::new(60_000);

        let line1 = r#"type=SYSCALL msg=audit(1614556843.937:100): syscall=59"#;
        let line2 = r#"type=AVC msg=audit(1614556843.937:200): avc: denied"#;

        let r1 = parse_audit_line(line1).unwrap_or_else(|e| panic!("{e}"));
        let r2 = parse_audit_line(line2).unwrap_or_else(|e| panic!("{e}"));

        let events_after_first = grouper.add_record(r1);
        assert_eq!(events_after_first.len(), 0);

        let events_after_second = grouper.add_record(r2);
        assert_eq!(events_after_second.len(), 1);
        assert_eq!(events_after_second[0].serial, 100);

        let remaining = grouper.flush_all();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].serial, 200);
    }

    #[test]
    fn primary_type_priority() {
        let records = vec![
            AuditRecord {
                event_type: AuditEventType::Syscall,
                raw_type: "SYSCALL".to_string(),
                timestamp: 0.0,
                serial: 1,
                fields: HashMap::new(),
                raw_line: String::new(),
            },
            AuditRecord {
                event_type: AuditEventType::Avc,
                raw_type: "AVC".to_string(),
                timestamp: 0.0,
                serial: 1,
                fields: HashMap::new(),
                raw_line: String::new(),
            },
        ];

        assert_eq!(determine_primary_type(&records), AuditEventType::Avc);
    }

    #[test]
    fn event_type_subject_suffixes() {
        assert_eq!(AuditEventType::Syscall.subject_suffix(), "syscall");
        assert_eq!(AuditEventType::Execve.subject_suffix(), "execve");
        assert_eq!(AuditEventType::UserAuth.subject_suffix(), "user_auth");
        assert_eq!(AuditEventType::Avc.subject_suffix(), "avc");
        assert_eq!(AuditEventType::IntegrityData.subject_suffix(), "integrity");
    }
}
