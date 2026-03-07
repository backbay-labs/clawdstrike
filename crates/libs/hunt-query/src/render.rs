//! Terminal rendering for hunt query results and timelines.

use std::io::{self, Write};

use crossterm::style::{Color, ResetColor, SetForegroundColor};

use crate::query::EventSource;
use crate::timeline::{NormalizedVerdict, TimelineEvent};

/// Configuration for output rendering.
#[derive(Debug, Clone)]
pub struct RenderConfig {
    pub color: bool,
    pub json: bool,
    pub jsonl: bool,
}

impl Default for RenderConfig {
    fn default() -> Self {
        Self {
            color: true,
            json: false,
            jsonl: false,
        }
    }
}

/// Render events according to the config.
pub fn render_events(
    events: &[TimelineEvent],
    config: &RenderConfig,
    out: &mut dyn Write,
) -> io::Result<()> {
    if config.json {
        render_json(events, out)
    } else if config.jsonl {
        render_jsonl(events, out)
    } else {
        render_table(events, config.color, out)
    }
}

/// Render as a formatted table with optional color.
fn render_table(events: &[TimelineEvent], color: bool, out: &mut dyn Write) -> io::Result<()> {
    // Header
    writeln!(
        out,
        "{:<24} {:<10} {:<14} {:<10} SUMMARY",
        "TIMESTAMP", "SOURCE", "KIND", "VERDICT",
    )?;
    writeln!(out, "{}", "-".repeat(80))?;

    for event in events {
        let ts = event.timestamp.format("%Y-%m-%d %H:%M:%S UTC");
        let source_str = format!("{}", event.source);
        let kind_str = format!("{}", event.kind);
        let verdict_str = format!("{}", event.verdict);
        let summary = truncate_str(&event.summary, 40);

        if color {
            let sc = source_color(&event.source);
            let vc = verdict_color(&event.verdict);

            write!(out, "{:<24} ", ts)?;
            write!(
                out,
                "{}{:<10}{} ",
                SetForegroundColor(sc),
                source_str,
                ResetColor
            )?;
            write!(out, "{:<14} ", kind_str)?;
            write!(
                out,
                "{}{:<10}{} ",
                SetForegroundColor(vc),
                verdict_str,
                ResetColor
            )?;
            writeln!(out, "{}", summary)?;
        } else {
            writeln!(
                out,
                "{:<24} {:<10} {:<14} {:<10} {}",
                ts, source_str, kind_str, verdict_str, summary
            )?;
        }
    }

    Ok(())
}

fn source_color(source: &EventSource) -> Color {
    match source {
        EventSource::Tetragon => Color::Cyan,
        EventSource::Hubble => Color::Blue,
        EventSource::Receipt => Color::Magenta,
        EventSource::Scan => Color::White,
        EventSource::Response => Color::Yellow,
        EventSource::Directory => Color::Green,
        EventSource::Detection => Color::Red,
    }
}

fn verdict_color(verdict: &NormalizedVerdict) -> Color {
    match verdict {
        NormalizedVerdict::Allow => Color::Green,
        NormalizedVerdict::Deny => Color::Red,
        NormalizedVerdict::Warn => Color::Yellow,
        NormalizedVerdict::Forwarded => Color::Green,
        NormalizedVerdict::Dropped => Color::Red,
        NormalizedVerdict::None => Color::White,
    }
}

fn render_json(events: &[TimelineEvent], out: &mut dyn Write) -> io::Result<()> {
    let json_str = serde_json::to_string_pretty(events).map_err(io::Error::other)?;
    writeln!(out, "{json_str}")
}

fn render_jsonl(events: &[TimelineEvent], out: &mut dyn Write) -> io::Result<()> {
    for event in events {
        let line = serde_json::to_string(event).map_err(io::Error::other)?;
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// Render a timeline header with entity info.
pub fn render_timeline_header(
    entity: Option<&str>,
    event_count: usize,
    sources: &[EventSource],
    out: &mut dyn Write,
) -> io::Result<()> {
    if let Some(name) = entity {
        writeln!(out, "Timeline for: {name}")?;
    }
    let source_names: Vec<String> = sources.iter().map(|s| format!("{s}")).collect();
    writeln!(
        out,
        "Events: {event_count} | Sources: {}",
        source_names.join(", ")
    )?;
    writeln!(out)
}

fn truncate_str(s: &str, max_len: usize) -> &str {
    if s.len() <= max_len {
        s
    } else {
        // Find a char boundary at or before max_len to avoid panicking on
        // multi-byte UTF-8 sequences.
        let mut end = max_len;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::EventSource;
    use crate::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};
    use chrono::TimeZone;
    use chrono::Utc;

    fn make_event() -> TimelineEvent {
        TimelineEvent {
            event_id: None,
            timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            source: EventSource::Tetragon,
            kind: TimelineEventKind::ProcessExec,
            verdict: NormalizedVerdict::Allow,
            severity: None,
            summary: "process_exec /usr/bin/curl".to_string(),
            process: Some("/usr/bin/curl".to_string()),
            namespace: Some("default".to_string()),
            pod: Some("agent-pod-abc123".to_string()),
            action_type: Some("process".to_string()),
            signature_valid: None,
            raw: None,
        }
    }

    fn make_deny_event() -> TimelineEvent {
        TimelineEvent {
            event_id: None,
            timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 5, 0).unwrap(),
            source: EventSource::Receipt,
            kind: TimelineEventKind::GuardDecision,
            verdict: NormalizedVerdict::Deny,
            severity: Some("high".to_string()),
            summary: "shell_exec blocked: rm -rf /".to_string(),
            process: Some("bash".to_string()),
            namespace: Some("production".to_string()),
            pod: Some("worker-pod-xyz".to_string()),
            action_type: Some("shell".to_string()),
            signature_valid: Some(true),
            raw: None,
        }
    }

    #[test]
    fn render_table_no_color_output() {
        let events = vec![make_event()];
        let config = RenderConfig {
            color: false,
            json: false,
            jsonl: false,
        };
        let mut buf = Vec::new();
        render_events(&events, &config, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("TIMESTAMP"));
        assert!(output.contains("SOURCE"));
        assert!(output.contains("KIND"));
        assert!(output.contains("VERDICT"));
        assert!(output.contains("SUMMARY"));
        assert!(output.contains("tetragon"));
        assert!(output.contains("process_exec"));
        assert!(output.contains("allow"));
        assert!(output.contains("process_exec /usr/bin/curl"));
    }

    #[test]
    fn render_table_with_color_contains_ansi() {
        let events = vec![make_event()];
        let config = RenderConfig {
            color: true,
            json: false,
            jsonl: false,
        };
        let mut buf = Vec::new();
        render_events(&events, &config, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // ANSI escape codes start with ESC[
        assert!(output.contains("\x1b["), "should contain ANSI escape codes");
        assert!(output.contains("tetragon"));
        assert!(output.contains("allow"));
    }

    #[test]
    fn render_table_multiple_events() {
        let events = vec![make_event(), make_deny_event()];
        let config = RenderConfig {
            color: false,
            json: false,
            jsonl: false,
        };
        let mut buf = Vec::new();
        render_events(&events, &config, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("tetragon"));
        assert!(output.contains("receipt"));
        assert!(output.contains("allow"));
        assert!(output.contains("deny"));
    }

    #[test]
    fn render_table_empty_events() {
        let events: Vec<TimelineEvent> = vec![];
        let config = RenderConfig {
            color: false,
            json: false,
            jsonl: false,
        };
        let mut buf = Vec::new();
        render_events(&events, &config, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Should still have headers
        assert!(output.contains("TIMESTAMP"));
        assert!(output.contains("SOURCE"));
    }

    #[test]
    fn render_json_output() {
        let events = vec![make_event()];
        let config = RenderConfig {
            color: false,
            json: true,
            jsonl: false,
        };
        let mut buf = Vec::new();
        render_events(&events, &config, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Should be valid JSON array
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
        assert_eq!(parsed.as_array().unwrap().len(), 1);
    }

    #[test]
    fn render_json_empty_events() {
        let events: Vec<TimelineEvent> = vec![];
        let config = RenderConfig {
            color: false,
            json: true,
            jsonl: false,
        };
        let mut buf = Vec::new();
        render_events(&events, &config, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
        assert!(parsed.as_array().unwrap().is_empty());
    }

    #[test]
    fn render_jsonl_output() {
        let events = vec![make_event(), make_deny_event()];
        let config = RenderConfig {
            color: false,
            json: false,
            jsonl: true,
        };
        let mut buf = Vec::new();
        render_events(&events, &config, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Each line should be valid JSON
        let lines: Vec<&str> = output.trim().split('\n').collect();
        assert_eq!(lines.len(), 2);
        for line in lines {
            let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(parsed.is_object());
        }
    }

    #[test]
    fn render_jsonl_empty_events() {
        let events: Vec<TimelineEvent> = vec![];
        let config = RenderConfig {
            color: false,
            json: false,
            jsonl: true,
        };
        let mut buf = Vec::new();
        render_events(&events, &config, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.is_empty());
    }

    #[test]
    fn render_timeline_header_with_entity() {
        let mut buf = Vec::new();
        let sources = vec![EventSource::Tetragon, EventSource::Receipt];
        render_timeline_header(Some("agent-1"), 42, &sources, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Timeline for: agent-1"));
        assert!(output.contains("Events: 42"));
        assert!(output.contains("tetragon"));
        assert!(output.contains("receipt"));
    }

    #[test]
    fn render_timeline_header_without_entity() {
        let mut buf = Vec::new();
        let sources = vec![EventSource::Hubble];
        render_timeline_header(None, 10, &sources, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(!output.contains("Timeline for:"));
        assert!(output.contains("Events: 10"));
        assert!(output.contains("hubble"));
    }

    #[test]
    fn truncate_str_short() {
        assert_eq!(truncate_str("hello", 10), "hello");
    }

    #[test]
    fn truncate_str_exact() {
        assert_eq!(truncate_str("hello", 5), "hello");
    }

    #[test]
    fn truncate_str_long() {
        assert_eq!(truncate_str("hello world", 5), "hello");
    }

    #[test]
    fn truncate_str_multibyte_utf8() {
        // "café" is 5 bytes (é = 2 bytes), truncating at byte 4 would
        // land inside the multi-byte sequence and panic without the fix.
        let result = truncate_str("café", 4);
        assert_eq!(result, "caf");

        // CJK characters are 3 bytes each
        let result = truncate_str("日本語テスト", 5);
        assert_eq!(result, "日"); // only first char (3 bytes) fits within 5

        // Emoji (4 bytes each)
        let result = truncate_str("🚀🎉", 5);
        assert_eq!(result, "🚀"); // only first emoji (4 bytes) fits within 5
    }

    #[test]
    fn render_config_default() {
        let config = RenderConfig::default();
        assert!(config.color);
        assert!(!config.json);
        assert!(!config.jsonl);
    }

    #[test]
    fn json_takes_priority_over_table() {
        // When both json and jsonl are false, table is used
        let events = vec![make_event()];

        let mut json_buf = Vec::new();
        let json_config = RenderConfig {
            color: false,
            json: true,
            jsonl: false,
        };
        render_events(&events, &json_config, &mut json_buf).unwrap();
        let json_output = String::from_utf8(json_buf).unwrap();

        // json output should be parseable as JSON array
        let parsed: serde_json::Value = serde_json::from_str(&json_output).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn json_takes_priority_over_jsonl() {
        // When both json and jsonl are true, json wins
        let events = vec![make_event()];
        let config = RenderConfig {
            color: false,
            json: true,
            jsonl: true,
        };
        let mut buf = Vec::new();
        render_events(&events, &config, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // Should be a JSON array (not JSONL)
        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        assert!(parsed.is_array());
    }

    #[test]
    fn source_colors_are_distinct() {
        assert_ne!(
            source_color(&EventSource::Tetragon),
            source_color(&EventSource::Hubble)
        );
        assert_ne!(
            source_color(&EventSource::Hubble),
            source_color(&EventSource::Receipt)
        );
    }

    #[test]
    fn verdict_colors_deny_is_red() {
        assert_eq!(verdict_color(&NormalizedVerdict::Deny), Color::Red);
        assert_eq!(verdict_color(&NormalizedVerdict::Dropped), Color::Red);
    }

    #[test]
    fn verdict_colors_allow_is_green() {
        assert_eq!(verdict_color(&NormalizedVerdict::Allow), Color::Green);
        assert_eq!(verdict_color(&NormalizedVerdict::Forwarded), Color::Green);
    }
}
