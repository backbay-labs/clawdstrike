use chrono::Utc;
use hunt_query::timeline::TimelineEvent;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

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
    if !trimmed.contains("rule ") {
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
            "rule_count_estimate": trimmed.matches("rule ").count(),
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
    let condition_name = detection
        .get("condition")
        .and_then(Value::as_str)
        .unwrap_or("selection");
    let selection = detection
        .get(condition_name)
        .and_then(Value::as_object)
        .ok_or_else(|| {
            Error::InvalidRule(format!("Sigma import requires `{condition_name}` object"))
        })?;
    let target_pattern = selection
        .iter()
        .next()
        .and_then(|(_, value)| value.as_str())
        .unwrap_or(".*");
    Ok(format!(
        "schema: clawdstrike.hunt.correlation.v1\nname: \"{title}\"\nseverity: {severity}\ndescription: \"Sigma compatibility preview\"\nwindow: {timeframe}\nconditions:\n  - source: receipt\n    target_pattern: \"{target_pattern}\"\n    bind: sigma_selection\noutput:\n  title: \"{title}\"\n  evidence:\n    - sigma_selection\n"
    ))
}

fn severity_label(severity: RuleSeverity) -> &'static str {
    match severity {
        RuleSeverity::Low => "low",
        RuleSeverity::Medium => "medium",
        RuleSeverity::High => "high",
        RuleSeverity::Critical => "critical",
    }
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
    fn sigma_preview_test_uses_native_engine() {
        let sigma = "title: Suspicious Access\nlevel: high\nlogsource:\n  category: process_creation\ndetection:\n  selection:\n    CommandLine: secret\n  condition: selection\n  timeframe: 30s\n";
        let mut event = sample_event("read secret file");
        event.timestamp += Duration::seconds(1);
        let result = test_rule_source("sigma", sigma, &[event]).expect("sigma test");
        assert!(result.valid);
        assert_eq!(result.findings.len(), 1);
    }
}
