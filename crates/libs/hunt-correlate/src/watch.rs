//! Real-time NATS watch mode — subscribes to spine envelope subjects,
//! evaluates correlation rules via [`CorrelationEngine`], and emits alerts.

use std::io::{self, Write};

use chrono::{DateTime, Duration, Utc};
use crossterm::style::{Attribute, Color, ResetColor, SetAttribute, SetForegroundColor};
use serde::Serialize;
use tokio_stream::StreamExt;

use crate::engine::{Alert, CorrelationEngine};
use crate::error::{Error, Result};
use crate::rules::{CorrelationRule, RuleSeverity};

/// Configuration for the real-time watch mode.
pub struct WatchConfig {
    /// NATS server URL.
    pub nats_url: String,
    /// Path to NATS credentials file.
    pub nats_creds: Option<String>,
    /// Bearer token for NATS authentication.
    pub nats_token: Option<String>,
    /// NKey seed for NATS authentication.
    pub nats_nkey_seed: Option<String>,
    /// Correlation rules to evaluate.
    pub rules: Vec<CorrelationRule>,
    /// Maximum sliding window duration for eviction.
    pub max_window: Duration,
    /// Whether to use colored output.
    pub color: bool,
    /// Whether to emit JSON output.
    pub json: bool,
}

/// Statistics from a watch session.
#[derive(Debug, Clone, Serialize)]
pub struct WatchStats {
    /// Total events processed.
    pub events_processed: u64,
    /// Total alerts triggered.
    pub alerts_triggered: u64,
    /// When the watch session started.
    pub start_time: DateTime<Utc>,
}

/// Run the real-time watch mode.
///
/// Connects to NATS, subscribes to `clawdstrike.sdr.fact.>`, creates a
/// [`CorrelationEngine`] with the provided rules, and processes messages
/// in a loop until ctrl-c is received.
pub async fn run_watch(
    config: WatchConfig,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> Result<WatchStats> {
    let auth = if config.nats_creds.is_some()
        || config.nats_token.is_some()
        || config.nats_nkey_seed.is_some()
    {
        Some(spine::nats_transport::NatsAuthConfig {
            creds_file: config.nats_creds.clone(),
            token: config.nats_token.clone(),
            nkey_seed: config.nats_nkey_seed.clone(),
        })
    } else {
        None
    };

    let client = spine::nats_transport::connect_with_auth(&config.nats_url, auth.as_ref())
        .await
        .map_err(|e| {
            Error::Nats(format!(
                "failed to connect to NATS at {}: {e}",
                config.nats_url
            ))
        })?;

    let mut sub = client
        .subscribe("clawdstrike.sdr.fact.>")
        .await
        .map_err(|e| Error::Nats(format!("failed to subscribe: {e}")))?;

    // Ensure SUB interest is processed by the server before callers publish
    // probe events; otherwise the first burst can be missed under CI timing.
    client
        .flush()
        .await
        .map_err(|e| Error::Nats(format!("failed to flush watch subscription: {e}")))?;

    let mut engine = CorrelationEngine::new(config.rules)?;

    let mut stats = WatchStats {
        events_processed: 0,
        alerts_triggered: 0,
        start_time: Utc::now(),
    };

    writeln!(
        stderr,
        "watch: connected to {}, waiting for events...",
        config.nats_url
    )
    .map_err(Error::Io)?;

    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            msg = sub.next() => {
                let msg = match msg {
                    Some(msg) => msg,
                    None => {
                        // Subscription closed
                        writeln!(stderr, "watch: subscription closed").map_err(Error::Io)?;
                        break;
                    }
                };

                // Parse payload as JSON envelope
                let envelope: serde_json::Value = match serde_json::from_slice(&msg.payload) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("skipping non-JSON message: {e}");
                        continue;
                    }
                };

                // Parse envelope into TimelineEvent
                let event = match hunt_query::timeline::parse_envelope(&envelope, false) {
                    Some(ev) => ev,
                    None => {
                        tracing::debug!("skipping unparseable envelope");
                        continue;
                    }
                };

                stats.events_processed += 1;

                // Enforce the configured sliding-window cap for every processed
                // event so stale windows never participate in a correlation.
                engine.evict_expired_capped(config.max_window);

                // Process event through correlation engine
                let alerts = engine.process_event(&event);

                for alert in &alerts {
                    stats.alerts_triggered += 1;
                    if config.json {
                        render_alert_json(alert, stdout).map_err(Error::Io)?;
                    } else {
                        render_alert(alert, config.color, stdout).map_err(Error::Io)?;
                    }
                }

            }
            _ = &mut shutdown => {
                writeln!(stderr, "\nwatch: shutting down (ctrl-c)").map_err(Error::Io)?;
                break;
            }
        }
    }

    // Flush any remaining alerts from completed windows
    let final_alerts = engine.flush();
    for alert in &final_alerts {
        stats.alerts_triggered += 1;
        if config.json {
            render_alert_json(alert, stdout).map_err(Error::Io)?;
        } else {
            render_alert(alert, config.color, stdout).map_err(Error::Io)?;
        }
    }

    Ok(stats)
}

/// Map a [`RuleSeverity`] to a display string.
fn severity_str(severity: RuleSeverity) -> &'static str {
    match severity {
        RuleSeverity::Critical => "critical",
        RuleSeverity::High => "high",
        RuleSeverity::Medium => "medium",
        RuleSeverity::Low => "low",
    }
}

/// Map a [`RuleSeverity`] to a crossterm color.
fn severity_color(severity: RuleSeverity) -> Color {
    match severity {
        RuleSeverity::Critical => Color::Red,
        RuleSeverity::High => Color::Red,
        RuleSeverity::Medium => Color::Yellow,
        RuleSeverity::Low => Color::White,
    }
}

/// Render a single alert to the given writer with optional color coding.
///
/// Format:
/// ```text
/// [ALERT] severity=high rule="MCP Tool Exfiltration Attempt"
///   Potential data exfiltration via MCP tool
///   Evidence:
///     file_access: 2025-06-15 12:00:00 UTC receipt guard_decision allow
///     egress_event: 2025-06-15 12:00:25 UTC hubble network_flow forwarded
/// ```
pub fn render_alert(alert: &Alert, color: bool, out: &mut dyn Write) -> io::Result<()> {
    let sev = severity_str(alert.severity);

    if color {
        let sc = severity_color(alert.severity);
        let bold = alert.severity == RuleSeverity::Critical;

        if bold {
            write!(out, "{}", SetAttribute(Attribute::Bold))?;
        }
        write!(out, "{}", SetForegroundColor(sc))?;
        write!(out, "[ALERT]")?;
        write!(out, "{}", ResetColor)?;
        if bold {
            write!(out, "{}", SetAttribute(Attribute::Reset))?;
        }
        writeln!(out, " severity={sev} rule=\"{}\"", alert.rule_name)?;
    } else {
        writeln!(out, "[ALERT] severity={sev} rule=\"{}\"", alert.rule_name)?;
    }

    writeln!(out, "  {}", alert.title)?;

    if !alert.evidence.is_empty() {
        writeln!(out, "  Evidence:")?;
        for ev in &alert.evidence {
            let ts = ev.timestamp.format("%Y-%m-%d %H:%M:%S UTC");
            writeln!(out, "    {ts} {} {} {}", ev.source, ev.kind, ev.verdict,)?;
        }
    }

    Ok(())
}

/// Render a single alert as a JSON line.
pub fn render_alert_json(alert: &Alert, out: &mut dyn Write) -> io::Result<()> {
    let json = serde_json::to_string(alert).map_err(io::Error::other)?;
    writeln!(out, "{json}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSeverity;
    use chrono::{TimeZone, Utc};
    use hunt_query::query::EventSource;
    use hunt_query::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};

    fn make_test_alert(severity: RuleSeverity) -> Alert {
        let evidence = vec![
            TimelineEvent {
                event_id: None,
                timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
                source: EventSource::Receipt,
                kind: TimelineEventKind::GuardDecision,
                verdict: NormalizedVerdict::Allow,
                severity: None,
                summary: "read /etc/passwd".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: Some("file".to_string()),
                signature_valid: None,
                raw: None,
            },
            TimelineEvent {
                event_id: None,
                timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 25).unwrap(),
                source: EventSource::Hubble,
                kind: TimelineEventKind::NetworkFlow,
                verdict: NormalizedVerdict::Forwarded,
                severity: None,
                summary: "evil.com:443".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: Some("egress".to_string()),
                signature_valid: None,
                raw: None,
            },
        ];

        Alert {
            rule_name: "MCP Tool Exfiltration Attempt".to_string(),
            severity,
            title: "Potential data exfiltration via MCP tool".to_string(),
            triggered_at: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 25).unwrap(),
            evidence,
            description: "Detects exfiltration".to_string(),
        }
    }

    #[test]
    fn render_alert_includes_rule_name_and_severity() {
        let alert = make_test_alert(RuleSeverity::High);
        let mut buf = Vec::new();
        render_alert(&alert, false, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("[ALERT]"), "missing [ALERT] tag");
        assert!(output.contains("severity=high"), "missing severity");
        assert!(
            output.contains("MCP Tool Exfiltration Attempt"),
            "missing rule name"
        );
    }

    #[test]
    fn render_alert_includes_title() {
        let alert = make_test_alert(RuleSeverity::High);
        let mut buf = Vec::new();
        render_alert(&alert, false, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(
            output.contains("Potential data exfiltration via MCP tool"),
            "missing title"
        );
    }

    #[test]
    fn render_alert_includes_evidence() {
        let alert = make_test_alert(RuleSeverity::High);
        let mut buf = Vec::new();
        render_alert(&alert, false, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("Evidence:"), "missing evidence header");
        assert!(
            output.contains("2025-06-15 12:00:00 UTC"),
            "missing first timestamp"
        );
        assert!(
            output.contains("2025-06-15 12:00:25 UTC"),
            "missing second timestamp"
        );
        assert!(output.contains("receipt"), "missing receipt source");
        assert!(output.contains("hubble"), "missing hubble source");
        assert!(output.contains("guard_decision"), "missing kind");
        assert!(output.contains("network_flow"), "missing kind");
    }

    #[test]
    fn render_alert_no_evidence() {
        let alert = Alert {
            rule_name: "Test Rule".to_string(),
            severity: RuleSeverity::Low,
            title: "Test alert".to_string(),
            triggered_at: Utc::now(),
            evidence: vec![],
            description: "test".to_string(),
        };
        let mut buf = Vec::new();
        render_alert(&alert, false, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("[ALERT]"));
        assert!(output.contains("severity=low"));
        assert!(!output.contains("Evidence:"));
    }

    #[test]
    fn render_alert_with_color_contains_ansi() {
        let alert = make_test_alert(RuleSeverity::High);
        let mut buf = Vec::new();
        render_alert(&alert, true, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(
            output.contains("\x1b["),
            "colored output should contain ANSI escape codes"
        );
        assert!(output.contains("[ALERT]"));
        assert!(output.contains("severity=high"));
    }

    #[test]
    fn render_alert_critical_uses_bold() {
        let alert = make_test_alert(RuleSeverity::Critical);
        let mut buf = Vec::new();
        render_alert(&alert, true, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("severity=critical"));
        // Bold attribute should be present in ANSI codes
        assert!(
            output.contains("\x1b["),
            "critical alert with color should contain ANSI codes"
        );
    }

    #[test]
    fn render_alert_medium_severity() {
        let alert = make_test_alert(RuleSeverity::Medium);
        let mut buf = Vec::new();
        render_alert(&alert, false, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("severity=medium"));
    }

    #[test]
    fn render_alert_json_produces_valid_json() {
        let alert = make_test_alert(RuleSeverity::High);
        let mut buf = Vec::new();
        render_alert_json(&alert, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert!(parsed.is_object());
        assert_eq!(
            parsed["rule_name"].as_str(),
            Some("MCP Tool Exfiltration Attempt")
        );
        assert_eq!(parsed["severity"].as_str(), Some("high"));
        assert_eq!(
            parsed["title"].as_str(),
            Some("Potential data exfiltration via MCP tool")
        );
        assert!(parsed["evidence"].is_array());
        assert_eq!(parsed["evidence"].as_array().map(|a| a.len()), Some(2));
    }

    #[test]
    fn render_alert_json_no_evidence() {
        let alert = Alert {
            rule_name: "Empty Rule".to_string(),
            severity: RuleSeverity::Low,
            title: "No evidence".to_string(),
            triggered_at: Utc::now(),
            evidence: vec![],
            description: "test".to_string(),
        };
        let mut buf = Vec::new();
        render_alert_json(&alert, &mut buf).unwrap();
        let output = String::from_utf8(buf).unwrap();

        let parsed: serde_json::Value = serde_json::from_str(output.trim()).unwrap();
        assert!(parsed["evidence"]
            .as_array()
            .map(|a| a.is_empty())
            .unwrap_or(false));
    }

    #[test]
    fn watch_stats_serialization() {
        let stats = WatchStats {
            events_processed: 42,
            alerts_triggered: 3,
            start_time: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
        };

        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["events_processed"], 42);
        assert_eq!(json["alerts_triggered"], 3);
        assert!(json["start_time"].is_string());
    }

    #[test]
    fn severity_str_values() {
        assert_eq!(severity_str(RuleSeverity::Critical), "critical");
        assert_eq!(severity_str(RuleSeverity::High), "high");
        assert_eq!(severity_str(RuleSeverity::Medium), "medium");
        assert_eq!(severity_str(RuleSeverity::Low), "low");
    }

    #[test]
    fn severity_color_values() {
        assert_eq!(severity_color(RuleSeverity::Critical), Color::Red);
        assert_eq!(severity_color(RuleSeverity::High), Color::Red);
        assert_eq!(severity_color(RuleSeverity::Medium), Color::Yellow);
        assert_eq!(severity_color(RuleSeverity::Low), Color::White);
    }
}
