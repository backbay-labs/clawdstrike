use chrono::Utc;
use hunt_query::query::EventSource;
use hunt_query::timeline::TimelineEvent;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::engine::CorrelationEngine;
use crate::error::{Error, Result};
use crate::rules::{parse_rule, RuleSeverity};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRuleCompilation {
    pub engine_kind: String,
    pub warnings: Vec<String>,
    pub compiled_artifact: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRuleTestFinding {
    pub title: String,
    pub severity: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionRuleTestResult {
    pub valid: bool,
    pub findings: Vec<DetectionRuleTestFinding>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

pub fn compile_rule_source(
    source_format: &str,
    source_text: &str,
) -> Result<DetectionRuleCompilation> {
    match source_format {
        "native_correlation" => compile_native_correlation_rule(source_text),
        "sigma" => compile_sigma_rule(source_text),
        "yara" => prepare_yara_rule(source_text),
        "clawdstrike_policy" => Ok(DetectionRuleCompilation {
            engine_kind: "policy_guard".to_string(),
            warnings: vec![
                "policy-backed detections are stored as metadata hooks in phase 1".to_string(),
            ],
            compiled_artifact: json!({
                "kind": "policy_guard_hook",
                "translation_status": "passthrough",
            }),
        }),
        "threshold" => compile_threshold_rule(source_text),
        other => Err(Error::InvalidRule(format!(
            "unsupported source format '{other}'"
        ))),
    }
}

pub fn test_rule_source(
    source_format: &str,
    source_text: &str,
    sample_events: &[TimelineEvent],
) -> Result<DetectionRuleTestResult> {
    match source_format {
        "native_correlation" | "sigma" => {
            test_correlation_rule(source_format, source_text, sample_events)
        }
        "yara" => Ok(DetectionRuleTestResult {
            valid: true,
            findings: Vec::new(),
            warnings: vec![
                "YARA execution remains a hook point; test validates the rule envelope only"
                    .to_string(),
            ],
            errors: Vec::new(),
        }),
        "clawdstrike_policy" | "threshold" => Ok(DetectionRuleTestResult {
            valid: true,
            findings: Vec::new(),
            warnings: vec![
                "phase-1 test mode validates storage contracts before engine execution".to_string(),
            ],
            errors: Vec::new(),
        }),
        other => Err(Error::InvalidRule(format!(
            "unsupported source format '{other}'"
        ))),
    }
}

fn compile_native_correlation_rule(source_text: &str) -> Result<DetectionRuleCompilation> {
    let rule = parse_rule(source_text)?;
    Ok(DetectionRuleCompilation {
        engine_kind: "correlation".to_string(),
        warnings: Vec::new(),
        compiled_artifact: json!({
            "kind": "native_correlation",
            "schema": rule.schema,
            "window_seconds": rule.window.num_seconds(),
            "condition_count": rule.conditions.len(),
            "evidence_bind_count": rule.output.evidence.len(),
            "compiled_at": Utc::now().to_rfc3339(),
        }),
    })
}

fn compile_sigma_rule(source_text: &str) -> Result<DetectionRuleCompilation> {
    let parsed: Value = serde_yaml::from_str(source_text)
        .map_err(|err| Error::InvalidRule(format!("invalid Sigma YAML: {err}")))?;
    let title = parsed
        .get("title")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::InvalidRule("Sigma import requires a title".to_string()))?;
    let detection = parsed
        .get("detection")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            Error::InvalidRule("Sigma import requires a detection section".to_string())
        })?;
    let has_timeframe = detection.get("timeframe").is_some();
    let warnings = vec![
        "Sigma import is stored as a compatibility surface and compiled toward native correlation"
            .to_string(),
        "Unsupported Sigma constructs should be tracked in compiled_artifact.translation_warnings"
            .to_string(),
    ];
    Ok(DetectionRuleCompilation {
        engine_kind: "correlation".to_string(),
        warnings,
        compiled_artifact: json!({
            "kind": "sigma_import",
            "title": title,
            "translation_status": "validated_boundary",
            "timeframe_present": has_timeframe,
            "translation_warnings": [
                "phase-1 preserves Sigma source and metadata while native execution remains canonical"
            ],
        }),
    })
}

fn prepare_yara_rule(source_text: &str) -> Result<DetectionRuleCompilation> {
    let trimmed = source_text.trim();
    let rule_count = yara_rule_declaration_count(trimmed)?;
    if rule_count == 0 {
        return Err(Error::InvalidRule(
            "YARA import requires at least one `rule` declaration".to_string(),
        ));
    }
    Ok(DetectionRuleCompilation {
        engine_kind: "content".to_string(),
        warnings: vec![
            "YARA source is preserved and queued for a future executor hook".to_string(),
        ],
        compiled_artifact: json!({
            "kind": "yara_hook",
            "translation_status": "executor_pending",
            "rule_count_estimate": rule_count,
        }),
    })
}

fn compile_threshold_rule(source_text: &str) -> Result<DetectionRuleCompilation> {
    let parsed: Value = serde_json::from_str(source_text)
        .map_err(|err| Error::InvalidRule(format!("invalid threshold JSON: {err}")))?;
    let threshold = parsed
        .get("threshold")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            Error::InvalidRule("threshold rules require a numeric `threshold`".to_string())
        })?;
    Ok(DetectionRuleCompilation {
        engine_kind: "threshold".to_string(),
        warnings: vec![
            "threshold execution is stored as a first-class hook point in phase 1".to_string(),
        ],
        compiled_artifact: json!({
            "kind": "threshold",
            "threshold": threshold,
        }),
    })
}

fn test_correlation_rule(
    source_format: &str,
    source_text: &str,
    sample_events: &[TimelineEvent],
) -> Result<DetectionRuleTestResult> {
    let rule_yaml = if source_format == "sigma" {
        sigma_preview_to_native_rule(source_text)?
    } else {
        source_text.to_string()
    };
    let rule = parse_rule(&rule_yaml)?;
    let mut engine = CorrelationEngine::new(vec![rule])?;
    let mut findings = Vec::new();
    for event in sample_events {
        for alert in engine.process_event(event) {
            findings.push(DetectionRuleTestFinding {
                title: alert.title,
                severity: severity_label(alert.severity).to_string(),
                evidence_refs: alert.evidence.iter().map(|ev| ev.summary.clone()).collect(),
            });
        }
    }
    for alert in engine.flush() {
        findings.push(DetectionRuleTestFinding {
            title: alert.title,
            severity: severity_label(alert.severity).to_string(),
            evidence_refs: alert.evidence.iter().map(|ev| ev.summary.clone()).collect(),
        });
    }

    Ok(DetectionRuleTestResult {
        valid: true,
        findings,
        warnings: if source_format == "sigma" {
            vec![
                "Sigma test mode uses the compatibility preview translator before native execution"
                    .to_string(),
            ]
        } else {
            Vec::new()
        },
        errors: Vec::new(),
    })
}

fn sigma_preview_to_native_rule(source_text: &str) -> Result<String> {
    let parsed: Value = serde_yaml::from_str(source_text)
        .map_err(|err| Error::InvalidRule(format!("invalid Sigma YAML: {err}")))?;
    let title = parsed
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or("Sigma imported rule");
    let severity = parsed
        .get("level")
        .and_then(Value::as_str)
        .unwrap_or("medium");
    let detection = parsed
        .get("detection")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            Error::InvalidRule("Sigma import requires a detection section".to_string())
        })?;
    let timeframe = detection
        .get("timeframe")
        .and_then(Value::as_str)
        .unwrap_or("5m");
    let selection = sigma_preview_selection(detection)?;
    let target_pattern = sigma_preview_target_pattern(selection).unwrap_or(".*");
    let source = sigma_preview_source(&parsed);
    let preview = json!({
        "schema": "clawdstrike.hunt.correlation.v1",
        "name": title,
        "severity": severity,
        "description": "Sigma compatibility preview",
        "window": timeframe,
        "conditions": [
            {
                "source": source.to_string(),
                "target_pattern": target_pattern,
                "bind": "sigma_selection",
            }
        ],
        "output": {
            "title": title,
            "evidence": ["sigma_selection"],
        },
    });
    render_preview_yaml(&preview)
}

fn sigma_preview_selection(detection: &Map<String, Value>) -> Result<&Map<String, Value>> {
    if let Some(selection) = detection.get("selection").and_then(Value::as_object) {
        return Ok(selection);
    }

    if let Some(condition) = detection.get("condition").and_then(Value::as_str) {
        for selector_name in sigma_condition_selector_candidates(condition, detection)? {
            if let Some(selection) = detection.get(&selector_name).and_then(Value::as_object) {
                return Ok(selection);
            }
        }
    }

    detection
        .iter()
        .filter(|(key, _)| !matches!(key.as_str(), "condition" | "timeframe"))
        .find_map(|(_, value)| value.as_object())
        .ok_or_else(|| {
            Error::InvalidRule(
                "Sigma import requires at least one object-valued detection selector".to_string(),
            )
        })
}

fn sigma_preview_target_pattern(selection: &Map<String, Value>) -> Option<&str> {
    let mut string_patterns: Vec<(&str, &str)> = selection
        .iter()
        .filter_map(|(field, value)| value.as_str().map(|pattern| (field.as_str(), pattern)))
        .collect();
    string_patterns.sort_by(|left, right| {
        sigma_preview_field_priority(left.0)
            .cmp(&sigma_preview_field_priority(right.0))
            .then_with(|| sigma_preview_field_stem(left.0).cmp(sigma_preview_field_stem(right.0)))
            .then_with(|| left.0.cmp(right.0))
    });
    string_patterns
        .into_iter()
        .map(|(_, pattern)| pattern)
        .next()
}

fn sigma_preview_field_priority(field: &str) -> usize {
    match sigma_preview_field_stem(field)
        .to_ascii_lowercase()
        .as_str()
    {
        "targetfilename"
        | "targetfile"
        | "filepath"
        | "filename"
        | "targetpath"
        | "path"
        | "targetobject"
        | "registrypath"
        | "registrykey"
        | "objectname"
        | "url"
        | "uri"
        | "destinationhostname"
        | "destinationip"
        | "destinationport"
        | "queryname"
        | "hostname"
        | "domain" => 0,
        "commandline" | "parentcommandline" => 1,
        "image" | "parentimage" | "processname" | "originalfilename" | "imagepath" => 2,
        _ => 3,
    }
}

fn sigma_preview_field_stem(field: &str) -> &str {
    field.split('|').next().unwrap_or(field)
}

fn sigma_condition_selector_candidates(
    condition: &str,
    detection: &Map<String, Value>,
) -> Result<Vec<String>> {
    let token_re = Regex::new(r"[A-Za-z_][A-Za-z0-9_]*\*?")
        .map_err(|err| Error::Regex(format!("invalid Sigma token regex: {err}")))?;
    let mut selectors = Vec::new();
    for token in token_re
        .find_iter(condition)
        .map(|matched| matched.as_str())
    {
        let lowered = token.to_ascii_lowercase();
        if matches!(
            lowered.as_str(),
            "and"
                | "or"
                | "not"
                | "of"
                | "all"
                | "them"
                | "near"
                | "by"
                | "count"
                | "true"
                | "false"
        ) {
            continue;
        }

        if let Some(prefix) = token.strip_suffix('*') {
            selectors.extend(
                detection
                    .keys()
                    .filter(|key| key.starts_with(prefix))
                    .cloned(),
            );
            continue;
        }

        selectors.push(token.to_string());
    }

    if selectors.is_empty() {
        selectors.push("selection".to_string());
    }

    Ok(selectors)
}

fn yara_rule_declaration_count(source_text: &str) -> Result<usize> {
    let declaration_re =
        Regex::new(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+[A-Za-z_][A-Za-z0-9_]*\b")
            .map_err(|err| Error::Regex(format!("invalid YARA declaration regex: {err}")))?;
    let sanitized = strip_yara_comments_and_literals(source_text);
    Ok(declaration_re.find_iter(&sanitized).count())
}

fn sigma_preview_source(parsed: &Value) -> EventSource {
    let logsource = parsed.get("logsource").and_then(Value::as_object);
    let category = logsource
        .and_then(|logsource| logsource.get("category"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let product = logsource
        .and_then(|logsource| logsource.get("product"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();
    let service = logsource
        .and_then(|logsource| logsource.get("service"))
        .and_then(Value::as_str)
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();

    match category.as_str() {
        "process_creation" | "process_access" | "image_load" | "file_event" | "registry_event" => {
            EventSource::Tetragon
        }
        "network_connection" | "dns_query" | "dns" | "network" | "proxy" => EventSource::Hubble,
        _ if matches!(
            product.as_str(),
            "linux" | "windows" | "macos" | "endpoint" | "container"
        ) =>
        {
            EventSource::Tetragon
        }
        _ if matches!(service.as_str(), "dns" | "network" | "proxy") => EventSource::Hubble,
        _ => EventSource::Receipt,
    }
}

pub(crate) fn severity_label(severity: RuleSeverity) -> &'static str {
    match severity {
        RuleSeverity::Low => "low",
        RuleSeverity::Medium => "medium",
        RuleSeverity::High => "high",
        RuleSeverity::Critical => "critical",
    }
}

fn render_preview_yaml(value: &Value) -> Result<String> {
    let yaml = serde_yaml::to_string(value)
        .map_err(|err| Error::InvalidRule(format!("failed to serialize preview YAML: {err}")))?;
    Ok(yaml
        .strip_prefix("---\n")
        .unwrap_or(yaml.as_str())
        .to_string())
}

fn strip_yara_comments_and_literals(source_text: &str) -> String {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum State {
        Code,
        LineComment,
        BlockComment,
        DoubleQuotedString,
    }

    let chars = source_text.chars().collect::<Vec<_>>();
    let mut sanitized = String::with_capacity(source_text.len());
    let mut state = State::Code;
    let mut index = 0usize;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();

        match state {
            State::Code => match (ch, next) {
                ('/', Some('/')) => {
                    sanitized.push(' ');
                    sanitized.push(' ');
                    index += 2;
                    state = State::LineComment;
                }
                ('/', Some('*')) => {
                    sanitized.push(' ');
                    sanitized.push(' ');
                    index += 2;
                    state = State::BlockComment;
                }
                ('"', _) => {
                    sanitized.push(' ');
                    index += 1;
                    state = State::DoubleQuotedString;
                }
                _ => {
                    sanitized.push(ch);
                    index += 1;
                }
            },
            State::LineComment => {
                if ch == '\n' {
                    sanitized.push('\n');
                    state = State::Code;
                } else {
                    sanitized.push(' ');
                }
                index += 1;
            }
            State::BlockComment => match (ch, next) {
                ('*', Some('/')) => {
                    sanitized.push(' ');
                    sanitized.push(' ');
                    index += 2;
                    state = State::Code;
                }
                _ => {
                    sanitized.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            },
            State::DoubleQuotedString => match (ch, next) {
                ('\\', Some(escaped)) => {
                    sanitized.push(' ');
                    sanitized.push(if escaped == '\n' { '\n' } else { ' ' });
                    index += 2;
                }
                ('"', _) => {
                    sanitized.push(' ');
                    index += 1;
                    state = State::Code;
                }
                _ => {
                    sanitized.push(if ch == '\n' { '\n' } else { ' ' });
                    index += 1;
                }
            },
        }
    }

    sanitized
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, TimeZone};
    use hunt_query::query::EventSource;
    use hunt_query::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};

    use super::*;

    fn sample_event(summary: &str) -> TimelineEvent {
        TimelineEvent {
            event_id: None,
            timestamp: Utc
                .timestamp_opt(1_710_000_000, 0)
                .single()
                .expect("timestamp"),
            source: EventSource::Receipt,
            kind: TimelineEventKind::GuardDecision,
            verdict: NormalizedVerdict::Allow,
            severity: Some("high".to_string()),
            summary: summary.to_string(),
            process: None,
            namespace: None,
            pod: None,
            action_type: Some("file".to_string()),
            signature_valid: Some(true),
            raw: None,
        }
    }

    #[test]
    fn compile_native_rule_returns_compiled_metadata() {
        let yaml = "schema: clawdstrike.hunt.correlation.v1\nname: test\nseverity: high\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    bind: one\noutput:\n  title: test\n  evidence:\n    - one\n";
        let compiled = compile_rule_source("native_correlation", yaml).expect("compile");
        assert_eq!(compiled.engine_kind, "correlation");
        assert_eq!(compiled.compiled_artifact["condition_count"], 1);
    }

    #[test]
    fn sigma_compile_preserves_boundary_metadata() {
        let sigma = "title: Suspicious Access\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: secret\n  condition: selection\n";
        let compiled = compile_rule_source("sigma", sigma).expect("compile sigma");
        assert_eq!(compiled.engine_kind, "correlation");
        assert_eq!(
            compiled.compiled_artifact["translation_status"],
            "validated_boundary"
        );
    }

    #[test]
    fn sigma_preview_source_uses_logsource_category() {
        let sigma = "title: Suspicious Access\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: secret\n  condition: selection\n";
        let preview = sigma_preview_to_native_rule(sigma).expect("build preview");
        assert!(preview.contains("source: tetragon"));
    }

    #[test]
    fn native_rule_test_returns_findings() {
        let yaml = "schema: clawdstrike.hunt.correlation.v1\nname: test\nseverity: high\ndescription: test\nwindow: 30s\nconditions:\n  - source: receipt\n    target_pattern: secret\n    bind: one\noutput:\n  title: test finding\n  evidence:\n    - one\n";
        let result = test_rule_source(
            "native_correlation",
            yaml,
            &[sample_event("read secret file")],
        )
        .expect("test rule");
        assert!(result.valid);
        assert_eq!(result.findings.len(), 1);
        assert_eq!(result.findings[0].title, "test finding");
    }

    #[test]
    fn yara_requires_rule_keyword() {
        let err = compile_rule_source("yara", "meta: nope").expect_err("should reject");
        assert!(err.to_string().contains("rule"));
    }

    #[test]
    fn yara_validation_accepts_tabbed_rule_declaration_and_ignores_comments() {
        let source = "// rule this is only a comment\nrule\tcontains_payload { condition: true }";
        let compiled = compile_rule_source("yara", source).expect("compile yara");
        assert_eq!(compiled.compiled_artifact["rule_count_estimate"], 1);
    }

    #[test]
    fn yara_validation_ignores_block_comments_and_string_literals() {
        let source = "/* rule commented_out { condition: true } */\nrule real_rule {\n  meta:\n    note = \"rule fake_rule\"\n  condition:\n    true\n}";
        let compiled = compile_rule_source("yara", source).expect("compile yara");
        assert_eq!(compiled.compiled_artifact["rule_count_estimate"], 1);
    }

    #[test]
    fn yara_validation_keeps_slashes_in_rule_bodies() {
        let source = "rule first_rule {\n  condition:\n    filesize / 2 > 10\n}\nrule second_rule { condition: true }";
        let compiled = compile_rule_source("yara", source).expect("compile yara");
        assert_eq!(compiled.compiled_artifact["rule_count_estimate"], 2);
    }

    #[test]
    fn sigma_preview_supports_compound_condition_expressions() {
        let sigma = "title: Suspicious Access\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: secret\n  filter:\n    Image: trusted\n  condition: selection and not filter\n";
        let preview = sigma_preview_to_native_rule(sigma).expect("build preview");
        assert!(preview.contains("source: tetragon"));
        assert!(preview.contains("target_pattern: secret"));
    }

    #[test]
    fn sigma_preview_selects_target_pattern_deterministically() {
        let sigma = "title: Ordered Selection\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    Image: /usr/bin/curl\n    CommandLine: secret\n  condition: selection\n";
        let preview = sigma_preview_to_native_rule(sigma).expect("build preview");
        assert!(preview.contains("target_pattern: secret"));
    }

    #[test]
    fn sigma_preview_prefers_target_artifacts_over_command_lines() {
        let sigma = "title: Target Selection\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    TargetFilename: secret.txt\n    CommandLine: benign\n  condition: selection\n";
        let preview = sigma_preview_to_native_rule(sigma).expect("build preview");
        assert!(preview.contains("target_pattern: secret.txt"));
    }

    #[test]
    fn sigma_preview_supports_wildcard_condition_selectors() {
        let sigma = "title: Wildcard Selection\nlogsource:\n  category: process_creation\ndetection:\n  selection_alpha:\n    CommandLine: secret\n  selection_beta:\n    Image: /usr/bin/curl\n  condition: 1 of selection_*\n";
        let preview = sigma_preview_to_native_rule(sigma).expect("build preview");
        assert!(preview.contains("target_pattern: secret"));
    }

    #[test]
    fn sigma_preview_serialization_escapes_yaml_control_characters() {
        let sigma = "title: \"Escalation\\nseverity: low\"\nlevel: high\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: \"curl: --config\"\n  condition: selection\n";
        let preview = sigma_preview_to_native_rule(sigma).expect("build preview");
        let parsed: Value = serde_yaml::from_str(&preview).expect("parse preview yaml");
        assert_eq!(
            parsed.get("name").and_then(Value::as_str),
            Some("Escalation\nseverity: low")
        );
        assert_eq!(parsed.get("severity").and_then(Value::as_str), Some("high"));
        assert_eq!(
            parsed["conditions"][0]["target_pattern"].as_str(),
            Some("curl: --config")
        );
    }

    #[test]
    fn sigma_preview_test_uses_native_engine() {
        let sigma = "title: Suspicious Access\nlevel: high\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: secret\n  condition: selection\n  timeframe: 30s\n";
        let mut event = sample_event("read secret file");
        event.source = EventSource::Tetragon;
        event.timestamp += Duration::seconds(1);
        let result = test_rule_source("sigma", sigma, &[event]).expect("sigma test");
        assert!(result.valid);
        assert_eq!(result.findings.len(), 1);
    }
}
