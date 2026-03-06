//! Correlation engine — evaluates correlation rules against event streams using sliding windows.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::Serialize;

use crate::error::{Error, Result};
use crate::rules::{CorrelationRule, RuleCondition, RuleSeverity};
use hunt_query::timeline::{NormalizedVerdict, TimelineEvent};

/// An alert generated when a correlation rule fires.
#[derive(Debug, Clone, Serialize)]
pub struct Alert {
    /// Rule name that generated this alert.
    pub rule_name: String,
    /// Severity level.
    pub severity: RuleSeverity,
    /// Alert title from rule output.
    pub title: String,
    /// When the alert was triggered (timestamp of the final matching event).
    pub triggered_at: DateTime<Utc>,
    /// Evidence: the timeline events that contributed to this alert.
    pub evidence: Vec<TimelineEvent>,
    /// Alert description from rule.
    pub description: String,
}

/// Tracks in-flight event bindings for a single detection sequence of a rule.
#[derive(Debug, Clone)]
struct WindowState {
    /// Events bound by condition bind name.
    bound_events: HashMap<String, Vec<TimelineEvent>>,
    /// Timestamp of the first bound event (window start).
    window_start: DateTime<Utc>,
}

/// Pre-compiled regex pair for a single condition.
#[derive(Debug, Clone)]
struct CompiledPatterns {
    target: Option<Regex>,
    not_target: Option<Regex>,
}

/// The correlation engine evaluates events against loaded rules using sliding windows.
#[derive(Debug)]
pub struct CorrelationEngine {
    /// Parsed rules.
    rules: Vec<CorrelationRule>,
    /// Pre-compiled regex patterns, keyed by (rule index, condition index).
    patterns: HashMap<(usize, usize), CompiledPatterns>,
    /// In-flight window states: keyed by rule index, each rule can have multiple concurrent windows.
    windows: HashMap<usize, Vec<WindowState>>,
}

impl CorrelationEngine {
    /// Create a new correlation engine, pre-compiling all regex patterns.
    pub fn new(rules: Vec<CorrelationRule>) -> Result<Self> {
        let mut patterns = HashMap::new();

        for (ri, rule) in rules.iter().enumerate() {
            for (ci, cond) in rule.conditions.iter().enumerate() {
                let target = match &cond.target_pattern {
                    Some(pat) => Some(Regex::new(pat).map_err(|e| {
                        Error::Regex(format!("rule '{}' condition {ci}: {e}", rule.name))
                    })?),
                    None => None,
                };
                let not_target = match &cond.not_target_pattern {
                    Some(pat) => Some(Regex::new(pat).map_err(|e| {
                        Error::Regex(format!(
                            "rule '{}' condition {ci} not_target: {e}",
                            rule.name
                        ))
                    })?),
                    None => None,
                };
                patterns.insert((ri, ci), CompiledPatterns { target, not_target });
            }
        }

        Ok(Self {
            rules,
            patterns,
            windows: HashMap::new(),
        })
    }

    /// Process a single event against all loaded rules.
    /// Evicts expired windows first, then evaluates conditions.
    /// Returns any alerts that were generated.
    pub fn process_event(&mut self, event: &TimelineEvent) -> Vec<Alert> {
        self.evict_expired_at(event.timestamp);

        let mut alerts = Vec::new();

        for ri in 0..self.rules.len() {
            let rule_alerts = self.evaluate_rule(ri, event);
            alerts.extend(rule_alerts);
        }

        alerts
    }

    /// Remove window states that have exceeded their rule's window duration,
    /// using the given reference time (typically the current event's timestamp).
    pub fn evict_expired_at(&mut self, now: DateTime<Utc>) {
        for (ri, windows) in &mut self.windows {
            let window_dur = self.rules[*ri].window;
            windows.retain(|ws| {
                let elapsed = now.signed_duration_since(ws.window_start);
                elapsed <= window_dur
            });
        }

        // Remove empty entries.
        self.windows.retain(|_, v| !v.is_empty());
    }

    /// Remove window states that have exceeded their rule's window duration
    /// using wall-clock time.
    pub fn evict_expired(&mut self) {
        self.evict_expired_at(Utc::now());
    }

    /// Remove window states that have exceeded the shorter of the rule's own
    /// window duration and the provided `max_window` cap, using wall-clock time.
    pub fn evict_expired_capped(&mut self, max_window: chrono::Duration) {
        let now = Utc::now();
        for (ri, windows) in &mut self.windows {
            let rule_dur = self.rules[*ri].window;
            let effective = if max_window < rule_dur {
                max_window
            } else {
                rule_dur
            };
            windows.retain(|ws| {
                let elapsed = now.signed_duration_since(ws.window_start);
                elapsed <= effective
            });
        }
        self.windows.retain(|_, v| !v.is_empty());
    }

    /// Return a reference to the loaded rules.
    pub fn rules(&self) -> &[CorrelationRule] {
        &self.rules
    }

    /// Flush all windows and return alerts for any fully-matched sequences.
    pub fn flush(&mut self) -> Vec<Alert> {
        self.evict_expired();

        let mut alerts = Vec::new();

        for (ri, windows) in self.windows.drain() {
            let rule = &self.rules[ri];
            for ws in windows {
                if all_conditions_met(rule, &ws) {
                    alerts.push(build_alert(rule, &ws));
                }
            }
        }

        alerts
    }

    /// Evaluate a single rule against an event. May create new windows or advance existing ones.
    fn evaluate_rule(&mut self, ri: usize, event: &TimelineEvent) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let rule = &self.rules[ri];

        // Snapshot the number of windows that existed before processing this event.
        // Dependent conditions (`after` is Some) must only iterate windows that
        // existed before this event was processed, preventing a single event from
        // binding to both a newly-created root window and its dependent condition.
        let pre_existing_count = self.windows.get(&ri).map_or(0, |w| w.len());
        // Track whether this event already advanced each pre-existing window
        // through a dependent condition in this pass.
        let mut dependent_advanced = vec![false; pre_existing_count];

        // Check each condition to see if this event matches it.
        for (ci, cond) in rule.conditions.iter().enumerate() {
            let cp = match self.patterns.get(&(ri, ci)) {
                Some(cp) => cp,
                None => continue,
            };

            if !condition_matches(cond, cp, event) {
                continue;
            }

            if cond.after.is_none() {
                // This is a root condition (no dependency). Start a new window.
                let mut bound = HashMap::new();
                bound.insert(cond.bind.clone(), vec![event.clone()]);
                let ws = WindowState {
                    bound_events: bound,
                    window_start: event.timestamp,
                };

                self.windows.entry(ri).or_default().push(ws);
            } else {
                // This condition depends on a prior bind. Try to advance existing windows.
                let after_bind = cond.after.as_deref();

                if pre_existing_count == 0 {
                    continue;
                }

                let windows = match self.windows.get_mut(&ri) {
                    Some(w) => w,
                    None => continue,
                };

                for (wi, ws) in windows.iter_mut().take(pre_existing_count).enumerate() {
                    // A single event may advance at most one dependent bind per window.
                    if dependent_advanced.get(wi).copied().unwrap_or(false) {
                        continue;
                    }

                    // Skip windows that already have this bind matched.
                    if ws.bound_events.contains_key(&cond.bind) {
                        continue;
                    }

                    // Check that the `after` bind exists in this window.
                    let after_ok = match after_bind {
                        Some(ab) => ws.bound_events.contains_key(ab),
                        None => true,
                    };
                    if !after_ok {
                        continue;
                    }

                    // Dependent events must never be earlier than the latest
                    // prerequisite event, even when `within` is not set.
                    if let Some(ab) = after_bind {
                        if let Some(after_events) = ws.bound_events.get(ab) {
                            if let Some(latest_after) =
                                after_events.iter().map(|e| e.timestamp).max()
                            {
                                let elapsed = event.timestamp.signed_duration_since(latest_after);
                                if elapsed < chrono::Duration::zero() {
                                    continue;
                                }
                                if let Some(within_dur) = cond.within {
                                    if elapsed > within_dur {
                                        continue;
                                    }
                                }
                            }
                        }
                    }

                    // Bind this event.
                    ws.bound_events
                        .entry(cond.bind.clone())
                        .or_default()
                        .push(event.clone());
                    if let Some(slot) = dependent_advanced.get_mut(wi) {
                        *slot = true;
                    }
                }
            }
        }

        // Check if any windows for this rule are now fully matched.
        if let Some(windows) = self.windows.get_mut(&ri) {
            let rule = &self.rules[ri];
            let mut completed_indices = Vec::new();

            for (wi, ws) in windows.iter().enumerate() {
                if all_conditions_met(rule, ws) {
                    alerts.push(build_alert(rule, ws));
                    completed_indices.push(wi);
                }
            }

            // Remove completed windows in reverse order to preserve indices.
            for wi in completed_indices.into_iter().rev() {
                windows.remove(wi);
            }
        }

        alerts
    }
}

/// Check if all conditions in a rule have at least one bound event.
fn all_conditions_met(rule: &CorrelationRule, ws: &WindowState) -> bool {
    rule.conditions
        .iter()
        .all(|cond| ws.bound_events.contains_key(&cond.bind))
}

/// Check if a single condition matches a timeline event.
fn condition_matches(
    cond: &RuleCondition,
    compiled: &CompiledPatterns,
    event: &TimelineEvent,
) -> bool {
    // Source check: condition.source must contain event.source (case-insensitive).
    let event_source_str = event.source.to_string().to_lowercase();
    let source_ok = cond
        .source
        .iter()
        .any(|s| s.to_lowercase() == event_source_str);
    if !source_ok {
        return false;
    }

    // Action type check (case-insensitive).
    if let Some(ref at) = cond.action_type {
        match &event.action_type {
            Some(eat) => {
                if !eat.eq_ignore_ascii_case(at) {
                    return false;
                }
            }
            None => return false,
        }
    }

    // Verdict check.
    if let Some(ref v) = cond.verdict {
        let expected = match v.to_lowercase().as_str() {
            "allow" => NormalizedVerdict::Allow,
            "deny" => NormalizedVerdict::Deny,
            "warn" => NormalizedVerdict::Warn,
            "forwarded" => NormalizedVerdict::Forwarded,
            "dropped" => NormalizedVerdict::Dropped,
            "none" => NormalizedVerdict::None,
            _ => return false,
        };
        if event.verdict != expected {
            return false;
        }
    }

    // Target pattern: regex must match event.summary.
    if let Some(ref re) = compiled.target {
        if !re.is_match(&event.summary) {
            return false;
        }
    }

    // Not-target pattern: regex must NOT match event.summary.
    if let Some(ref re) = compiled.not_target {
        if re.is_match(&event.summary) {
            return false;
        }
    }

    true
}

/// Build an alert from a completed window state.
fn build_alert(rule: &CorrelationRule, ws: &WindowState) -> Alert {
    // Collect evidence events in the order specified by output.evidence.
    let mut evidence = Vec::new();
    for bind_name in &rule.output.evidence {
        if let Some(events) = ws.bound_events.get(bind_name) {
            evidence.extend(events.iter().cloned());
        }
    }

    // Triggered at = timestamp of the latest evidence event.
    let triggered_at = evidence
        .iter()
        .map(|e| e.timestamp)
        .max()
        .unwrap_or_else(Utc::now);

    Alert {
        rule_name: rule.name.clone(),
        severity: rule.severity,
        title: rule.output.title.clone(),
        triggered_at,
        evidence,
        description: rule.description.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::parse_rule;
    use chrono::TimeZone;
    use hunt_query::query::EventSource;
    use hunt_query::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};

    fn make_event(
        source: EventSource,
        action_type: &str,
        verdict: NormalizedVerdict,
        summary: &str,
        ts: DateTime<Utc>,
    ) -> TimelineEvent {
        TimelineEvent {
            event_id: None,
            timestamp: ts,
            source,
            kind: TimelineEventKind::GuardDecision,
            verdict,
            severity: None,
            summary: summary.to_string(),
            process: None,
            namespace: None,
            pod: None,
            action_type: Some(action_type.to_string()),
            signature_valid: None,
            raw: None,
        }
    }

    fn exfil_rule() -> CorrelationRule {
        parse_rule(
            r#"
schema: clawdstrike.hunt.correlation.v1
name: "MCP Tool Exfiltration Attempt"
severity: high
description: >
  Detects an MCP tool reading sensitive files followed by
  network egress to an external domain within 30 seconds.
window: 30s
conditions:
  - source: receipt
    action_type: file
    verdict: allow
    target_pattern: "/etc/passwd|/etc/shadow|\\.ssh/|\\.(env|pem|key)$"
    bind: file_access
  - source: [receipt, hubble]
    action_type: egress
    not_target_pattern: "->\\s*(localhost|127\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|10\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|172\\.(1[6-9]|2[0-9]|3[01])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])|192\\.168\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9]))(?::[0-9]{1,5})?(?:$|[^A-Za-z0-9.:-])"
    after: file_access
    within: 30s
    bind: egress_event
output:
  title: "Potential data exfiltration via MCP tool"
  evidence:
    - file_access
    - egress_event
"#,
        )
        .unwrap()
    }

    fn single_condition_rule() -> CorrelationRule {
        parse_rule(
            r#"
schema: clawdstrike.hunt.correlation.v1
name: "Forbidden Path Access"
severity: critical
description: "Detects any denied file access"
window: 5m
conditions:
  - source: receipt
    action_type: file
    verdict: deny
    bind: denied_access
output:
  title: "File access denied"
  evidence:
    - denied_access
"#,
        )
        .unwrap()
    }

    #[test]
    fn engine_new_compiles_regex() {
        let rule = exfil_rule();
        let engine = CorrelationEngine::new(vec![rule]).unwrap();
        assert_eq!(engine.rules().len(), 1);
    }

    #[test]
    fn engine_new_rejects_bad_regex() {
        let mut rule = exfil_rule();
        rule.conditions[0].target_pattern = Some("[invalid".to_string());
        let result = CorrelationEngine::new(vec![rule]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("regex"), "got: {msg}");
    }

    #[test]
    fn single_condition_rule_fires_immediately() {
        let rule = single_condition_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let event = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Deny,
            "/etc/passwd",
            ts,
        );

        let alerts = engine.process_event(&event);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].rule_name, "Forbidden Path Access");
        assert_eq!(alerts[0].severity, RuleSeverity::Critical);
        assert_eq!(alerts[0].evidence.len(), 1);
    }

    #[test]
    fn two_condition_sequence_generates_alert() {
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 10).unwrap();

        // First event: file access to sensitive path
        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts1,
        );
        let alerts = engine.process_event(&e1);
        assert!(
            alerts.is_empty(),
            "should not alert on first condition only"
        );

        // Second event: egress to external domain
        let e2 = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "egress TCP 10.0.0.1:8080 -> 93.184.216.34:443",
            ts2,
        );
        let alerts = engine.process_event(&e2);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].title, "Potential data exfiltration via MCP tool");
        assert_eq!(alerts[0].evidence.len(), 2);
    }

    #[test]
    fn egress_to_internal_excluded_by_not_target() {
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 10).unwrap();

        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts1,
        );
        engine.process_event(&e1);

        // Egress to internal IP — should be excluded by not_target_pattern
        let e2 = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "egress TCP 10.0.0.1:8080 -> 192.168.1.1:8080",
            ts2,
        );
        let alerts = engine.process_event(&e2);
        assert!(
            alerts.is_empty(),
            "internal egress should not trigger alert"
        );
    }

    #[test]
    fn egress_to_localhost_subdomain_still_alerts() {
        // localhost.evil.com must not be treated as plain localhost.
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 10).unwrap();

        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts1,
        );
        engine.process_event(&e1);

        let e2 = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "egress TCP 10.0.0.1:8080 -> localhost.evil.com:443",
            ts2,
        );
        let alerts = engine.process_event(&e2);
        assert_eq!(
            alerts.len(),
            1,
            "localhost subdomains are external and should not be excluded"
        );
    }

    #[test]
    fn egress_to_172_20_range_excluded_as_private() {
        // 172.20.x.x is RFC 1918 private (172.16.0.0/12) and must be excluded.
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 10).unwrap();

        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts1,
        );
        engine.process_event(&e1);

        // 172.25.0.1 is private — should NOT trigger alert
        let e2 = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "egress TCP 10.0.0.1:8080 -> 172.25.0.1:8080",
            ts2,
        );
        let alerts = engine.process_event(&e2);
        assert!(
            alerts.is_empty(),
            "172.25.x.x is RFC 1918 private and should be excluded"
        );
    }

    #[test]
    fn egress_to_172_2_not_excluded_as_public() {
        // 172.2.x.x is NOT RFC 1918 private — it should trigger an alert.
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 10).unwrap();

        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts1,
        );
        engine.process_event(&e1);

        // 172.2.0.1 is public — SHOULD trigger alert
        let e2 = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "egress TCP 10.0.0.1:8080 -> 172.2.0.1:8080",
            ts2,
        );
        let alerts = engine.process_event(&e2);
        assert_eq!(
            alerts.len(),
            1,
            "172.2.x.x is a public IP and should trigger exfiltration alert"
        );
    }

    #[test]
    fn egress_to_100_not_excluded_as_public() {
        // 100.x.x.x is public and must not be excluded by a 10.x prefix.
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 10).unwrap();

        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts1,
        );
        engine.process_event(&e1);

        let e2 = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "egress TCP 10.0.0.1:8080 -> 100.1.2.3:8080",
            ts2,
        );
        let alerts = engine.process_event(&e2);
        assert_eq!(
            alerts.len(),
            1,
            "100.x.x.x is a public IP and should trigger exfiltration alert"
        );
    }

    #[test]
    fn egress_without_direction_prefix_private_source_public_dest_still_alerts() {
        // Some summaries may omit the direction prefix and start with source IP.
        // The not_target_pattern must not exclude based on private source.
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 10).unwrap();

        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts1,
        );
        engine.process_event(&e1);

        let e2 = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "10.0.0.1 -> 93.184.216.34:443",
            ts2,
        );
        let alerts = engine.process_event(&e2);
        assert_eq!(
            alerts.len(),
            1,
            "private source at summary start must not suppress external destination alerts"
        );
    }

    #[test]
    fn within_constraint_rejects_late_event() {
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        // 31 seconds later — exceeds 30s within constraint
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 31).unwrap();

        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /home/user/.ssh/id_rsa",
            ts1,
        );
        engine.process_event(&e1);

        let e2 = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "evil.com:443",
            ts2,
        );
        let alerts = engine.process_event(&e2);
        assert!(
            alerts.is_empty(),
            "event outside within window should not trigger"
        );
    }

    #[test]
    fn after_without_within_rejects_out_of_order_event() {
        let rule = parse_rule(
            r#"
schema: clawdstrike.hunt.correlation.v1
name: "Ordered Dependent Sequence"
severity: medium
description: "Dependent events must occur after their prerequisite"
window: 5m
conditions:
  - source: receipt
    action_type: file
    bind: first
  - source: receipt
    action_type: egress
    after: first
    bind: second
output:
  title: "Ordered sequence matched"
  evidence:
    - first
    - second
"#,
        )
        .unwrap();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts_first = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 10).unwrap();
        let ts_older = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 5).unwrap();
        let ts_newer = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 20).unwrap();

        let first = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts_first,
        );
        engine.process_event(&first);

        let out_of_order = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "egress TCP 10.0.0.1:8080 -> 93.184.216.34:443",
            ts_older,
        );
        let alerts = engine.process_event(&out_of_order);
        assert!(
            alerts.is_empty(),
            "dependent event older than prerequisite must not match"
        );

        let ordered = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "egress TCP 10.0.0.1:8080 -> 93.184.216.34:443",
            ts_newer,
        );
        let alerts = engine.process_event(&ordered);
        assert_eq!(
            alerts.len(),
            1,
            "dependent event after prerequisite should still match"
        );
    }

    #[test]
    fn event_matching_no_rules() {
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        // Tetragon process event — does not match any condition in the exfil rule
        let event = make_event(
            EventSource::Tetragon,
            "process",
            NormalizedVerdict::None,
            "process_exec /usr/bin/ls",
            ts,
        );

        let alerts = engine.process_event(&event);
        assert!(alerts.is_empty());
    }

    #[test]
    fn multiple_rules_same_event() {
        let rule1 = single_condition_rule();
        let rule2 = parse_rule(
            r#"
schema: clawdstrike.hunt.correlation.v1
name: "Any File Deny"
severity: medium
description: "Any file denial"
window: 1m
conditions:
  - source: receipt
    action_type: file
    verdict: deny
    bind: evt
output:
  title: "File denial observed"
  evidence:
    - evt
"#,
        )
        .unwrap();

        let mut engine = CorrelationEngine::new(vec![rule1, rule2]).unwrap();

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let event = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Deny,
            "/secret",
            ts,
        );

        let alerts = engine.process_event(&event);
        assert_eq!(alerts.len(), 2, "both rules should fire");

        let names: Vec<&str> = alerts.iter().map(|a| a.rule_name.as_str()).collect();
        assert!(names.contains(&"Forbidden Path Access"));
        assert!(names.contains(&"Any File Deny"));
    }

    #[test]
    fn single_event_cannot_satisfy_root_and_dependent_condition() {
        // Regression: a single event that matches both a root condition and
        // a dependent condition (with `after` pointing to the root) must NOT
        // bind to both in the same pass. The dependent condition should only
        // match against windows that existed *before* this event was processed.
        let rule = parse_rule(
            r#"
schema: clawdstrike.hunt.correlation.v1
name: "Self-match guard"
severity: high
description: "Should require two distinct events"
window: 30s
conditions:
  - source: receipt
    action_type: egress
    bind: first
  - source: receipt
    action_type: egress
    after: first
    within: 30s
    bind: second
output:
  title: "Two egress events"
  evidence:
    - first
    - second
"#,
        )
        .unwrap();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let event = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "evil.com:443",
            ts,
        );

        // A single event should open a window but NOT complete it.
        let alerts = engine.process_event(&event);
        assert!(
            alerts.is_empty(),
            "a single event must not satisfy both root and dependent conditions"
        );

        // A second distinct event should now complete the window.
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 5).unwrap();
        let event2 = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "other.com:443",
            ts2,
        );
        let alerts = engine.process_event(&event2);
        assert_eq!(
            alerts.len(),
            1,
            "two distinct events should complete the sequence"
        );
    }

    #[test]
    fn single_event_cannot_satisfy_chained_dependent_conditions() {
        let rule = parse_rule(
            r#"
schema: clawdstrike.hunt.correlation.v1
name: "Dependent chain"
severity: high
description: "Should require three distinct events"
window: 30s
conditions:
  - source: receipt
    action_type: file
    bind: first
  - source: receipt
    action_type: egress
    after: first
    within: 30s
    bind: second
  - source: receipt
    action_type: egress
    after: second
    within: 30s
    bind: third
output:
  title: "Three-step sequence"
  evidence:
    - first
    - second
    - third
"#,
        )
        .unwrap();

        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();
        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 5).unwrap();
        let ts3 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 10).unwrap();

        let first = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /tmp/data",
            ts1,
        );
        assert!(engine.process_event(&first).is_empty());

        // This event matches both dependent conditions by predicate; it must
        // only satisfy the first dependent bind in this pass.
        let second = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "evil.com:443",
            ts2,
        );
        assert!(
            engine.process_event(&second).is_empty(),
            "a single dependent event must not satisfy an entire chain"
        );

        let third = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "other.com:443",
            ts3,
        );
        assert_eq!(engine.process_event(&third).len(), 1);
    }

    #[test]
    fn condition_matches_source_check() {
        let cond = RuleCondition {
            source: vec!["receipt".to_string()],
            action_type: None,
            verdict: None,
            target_pattern: None,
            not_target_pattern: None,
            after: None,
            within: None,
            bind: "test".to_string(),
        };
        let cp = CompiledPatterns {
            target: None,
            not_target: None,
        };

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let receipt_event = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "test",
            ts,
        );
        assert!(condition_matches(&cond, &cp, &receipt_event));

        let tetragon_event = make_event(
            EventSource::Tetragon,
            "process",
            NormalizedVerdict::None,
            "test",
            ts,
        );
        assert!(!condition_matches(&cond, &cp, &tetragon_event));
    }

    #[test]
    fn condition_matches_target_pattern() {
        let cond = RuleCondition {
            source: vec!["receipt".to_string()],
            action_type: None,
            verdict: None,
            target_pattern: Some(r"\.env$".to_string()),
            not_target_pattern: None,
            after: None,
            within: None,
            bind: "test".to_string(),
        };
        let cp = CompiledPatterns {
            target: Some(Regex::new(r"\.env$").unwrap()),
            not_target: None,
        };

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let matching = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /app/.env",
            ts,
        );
        assert!(condition_matches(&cond, &cp, &matching));

        let non_matching = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /app/config.toml",
            ts,
        );
        assert!(!condition_matches(&cond, &cp, &non_matching));
    }

    #[test]
    fn condition_matches_not_target_pattern() {
        let cond = RuleCondition {
            source: vec!["receipt".to_string()],
            action_type: None,
            verdict: None,
            target_pattern: None,
            not_target_pattern: Some(r"^localhost".to_string()),
            after: None,
            within: None,
            bind: "test".to_string(),
        };
        let cp = CompiledPatterns {
            target: None,
            not_target: Some(Regex::new(r"^localhost").unwrap()),
        };

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let excluded = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "localhost:8080",
            ts,
        );
        assert!(!condition_matches(&cond, &cp, &excluded));

        let allowed = make_event(
            EventSource::Receipt,
            "egress",
            NormalizedVerdict::Allow,
            "evil.com:443",
            ts,
        );
        assert!(condition_matches(&cond, &cp, &allowed));
    }

    #[test]
    fn condition_matches_verdict_filter() {
        let cond = RuleCondition {
            source: vec!["receipt".to_string()],
            action_type: None,
            verdict: Some("deny".to_string()),
            target_pattern: None,
            not_target_pattern: None,
            after: None,
            within: None,
            bind: "test".to_string(),
        };
        let cp = CompiledPatterns {
            target: None,
            not_target: None,
        };

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let deny_event = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Deny,
            "test",
            ts,
        );
        assert!(condition_matches(&cond, &cp, &deny_event));

        let allow_event = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "test",
            ts,
        );
        assert!(!condition_matches(&cond, &cp, &allow_event));
    }

    #[test]
    fn flush_emits_partially_complete_windows() {
        // Flush should emit alerts for fully-matched windows only
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts1,
        );
        engine.process_event(&e1);

        // Only first condition matched — flush should NOT produce an alert
        let alerts = engine.flush();
        assert!(
            alerts.is_empty(),
            "incomplete window should not produce alert on flush"
        );
    }

    #[test]
    fn flush_does_not_emit_alerts_from_expired_windows() {
        let rule = single_condition_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();
        let stale_ts = Utc::now() - chrono::Duration::minutes(10);
        let stale_event = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Deny,
            "/etc/passwd",
            stale_ts,
        );

        let mut bound_events = std::collections::HashMap::new();
        bound_events.insert("denied_access".to_string(), vec![stale_event]);
        engine.windows.insert(
            0,
            vec![WindowState {
                bound_events,
                window_start: stale_ts,
            }],
        );

        let alerts = engine.flush();
        assert!(
            alerts.is_empty(),
            "expired windows should be evicted before flush emits alerts"
        );
    }

    #[test]
    fn condition_matches_verdict_forwarded() {
        let cond = RuleCondition {
            source: vec!["hubble".to_string()],
            action_type: None,
            verdict: Some("forwarded".to_string()),
            target_pattern: None,
            not_target_pattern: None,
            after: None,
            within: None,
            bind: "test".to_string(),
        };
        let cp = CompiledPatterns {
            target: None,
            not_target: None,
        };

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let forwarded_event = make_event(
            EventSource::Hubble,
            "egress",
            NormalizedVerdict::Forwarded,
            "evil.com:443",
            ts,
        );
        assert!(condition_matches(&cond, &cp, &forwarded_event));

        let allow_event = make_event(
            EventSource::Hubble,
            "egress",
            NormalizedVerdict::Allow,
            "evil.com:443",
            ts,
        );
        assert!(!condition_matches(&cond, &cp, &allow_event));
    }

    #[test]
    fn condition_matches_verdict_dropped() {
        let cond = RuleCondition {
            source: vec!["hubble".to_string()],
            action_type: None,
            verdict: Some("dropped".to_string()),
            target_pattern: None,
            not_target_pattern: None,
            after: None,
            within: None,
            bind: "test".to_string(),
        };
        let cp = CompiledPatterns {
            target: None,
            not_target: None,
        };

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let dropped_event = make_event(
            EventSource::Hubble,
            "egress",
            NormalizedVerdict::Dropped,
            "evil.com:443",
            ts,
        );
        assert!(condition_matches(&cond, &cp, &dropped_event));

        let forwarded_event = make_event(
            EventSource::Hubble,
            "egress",
            NormalizedVerdict::Forwarded,
            "evil.com:443",
            ts,
        );
        assert!(!condition_matches(&cond, &cp, &forwarded_event));
    }

    #[test]
    fn condition_matches_verdict_none() {
        let cond = RuleCondition {
            source: vec!["tetragon".to_string()],
            action_type: None,
            verdict: Some("none".to_string()),
            target_pattern: None,
            not_target_pattern: None,
            after: None,
            within: None,
            bind: "test".to_string(),
        };
        let cp = CompiledPatterns {
            target: None,
            not_target: None,
        };

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let none_event = make_event(
            EventSource::Tetragon,
            "process",
            NormalizedVerdict::None,
            "process_exec /bin/sh",
            ts,
        );
        assert!(condition_matches(&cond, &cp, &none_event));

        let allow_event = make_event(
            EventSource::Tetragon,
            "process",
            NormalizedVerdict::Allow,
            "process_exec /bin/sh",
            ts,
        );
        assert!(!condition_matches(&cond, &cp, &allow_event));
    }

    #[test]
    fn condition_matches_verdict_unknown_rejects() {
        let cond = RuleCondition {
            source: vec!["receipt".to_string()],
            action_type: None,
            verdict: Some("invalid_verdict".to_string()),
            target_pattern: None,
            not_target_pattern: None,
            after: None,
            within: None,
            bind: "test".to_string(),
        };
        let cp = CompiledPatterns {
            target: None,
            not_target: None,
        };

        let ts = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        let event = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "test",
            ts,
        );
        assert!(
            !condition_matches(&cond, &cp, &event),
            "unknown verdict string should never match"
        );
    }

    #[test]
    fn hubble_source_matches_egress_condition() {
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();
        let ts2 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 5).unwrap();

        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /home/user/.env",
            ts1,
        );
        engine.process_event(&e1);

        // Hubble source should also match the second condition (source: [receipt, hubble])
        let e2 = make_event(
            EventSource::Hubble,
            "egress",
            NormalizedVerdict::Allow,
            "evil.com:443",
            ts2,
        );
        let alerts = engine.process_event(&e2);
        assert_eq!(alerts.len(), 1);
    }

    #[test]
    fn evict_expired_capped_uses_shorter_window() {
        // The exfil rule has a 30s window. Use a max_window of 10s so that
        // windows older than 10s are evicted even though the rule allows 30s.
        let rule = exfil_rule();
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts1 = Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap();

        // Inject a file-access event to start a window.
        let e1 = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts1,
        );
        engine.process_event(&e1);

        // Verify there is one active window.
        assert_eq!(engine.windows.len(), 1);

        // Evict with max_window = 0s — should immediately evict everything.
        engine.evict_expired_capped(chrono::Duration::zero());
        assert!(
            engine.windows.is_empty(),
            "zero max_window should evict all windows"
        );
    }

    #[test]
    fn evict_expired_capped_preserves_when_cap_larger_than_rule_window() {
        // With a cap larger than the rule window, eviction should
        // behave identically to the uncapped variant.
        let rule = exfil_rule(); // 30s window
        let mut engine = CorrelationEngine::new(vec![rule]).unwrap();

        let ts = Utc::now();
        // Feed a root-matching event that opens a window but does not complete
        // the rule sequence (no matching egress event yet).
        let root_only = make_event(
            EventSource::Receipt,
            "file",
            NormalizedVerdict::Allow,
            "read /etc/passwd",
            ts,
        );
        let alerts = engine.process_event(&root_only);
        assert!(
            alerts.is_empty(),
            "root-only event should not complete rule"
        );
        let before = engine.windows.get(&0).map_or(0, Vec::len);
        assert_eq!(before, 1, "expected one active correlation window");

        // A huge cap should not evict a just-created window.
        engine.evict_expired_capped(chrono::Duration::hours(24));
        let after = engine.windows.get(&0).map_or(0, Vec::len);
        assert_eq!(
            after, 1,
            "cap larger than rule window should preserve a fresh window"
        );
    }
}
