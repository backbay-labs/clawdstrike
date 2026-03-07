//! Convert hunt-query timeline events to OCSF events.
//!
//! The legacy `ocsf` cargo feature remains as a compatibility shim, but the
//! OCSF conversion surface is always available.

use serde_json::Value;

use clawdstrike_ocsf::convert::from_timeline_event::{
    timeline_event_to_ocsf, TimelineEventInput, TimelineOcsfEvent,
};

use crate::query::EventSource;
use crate::timeline::TimelineEvent;

/// Convert a slice of timeline events to OCSF JSON values.
///
/// Events without `raw` data are skipped. Events from sources that do not map
/// to an OCSF class (e.g. `Scan`) are also skipped.
pub fn timeline_to_ocsf(events: &[TimelineEvent]) -> Vec<Value> {
    let mut out = Vec::new();
    for event in events {
        let raw = match event.raw.as_ref() {
            Some(r) => r,
            None => continue,
        };

        let source_str = match event.source {
            EventSource::Tetragon => "tetragon",
            EventSource::Hubble => "hubble",
            EventSource::Receipt => "receipt",
            EventSource::Scan => "scan",
            EventSource::Response => "response",
            EventSource::Directory => "directory",
            EventSource::Detection => "detection",
        };

        let input = TimelineEventInput {
            kind: &event.kind.to_string(),
            source: source_str,
            time_ms: event.timestamp.timestamp_millis(),
            raw,
            product_version: env!("CARGO_PKG_VERSION"),
        };

        if let Some(ocsf_event) = timeline_event_to_ocsf(&input) {
            let value = match ocsf_event {
                TimelineOcsfEvent::Process(pa) => serde_json::to_value(pa),
                TimelineOcsfEvent::Network(na) => serde_json::to_value(na),
                TimelineOcsfEvent::Detection(df) => serde_json::to_value(df),
            };
            if let Ok(v) = value {
                out.push(v);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::EventSource;
    use crate::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    fn make_tetragon_event() -> TimelineEvent {
        TimelineEvent {
            event_id: None,
            timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 0, 0).unwrap(),
            source: EventSource::Tetragon,
            kind: TimelineEventKind::ProcessExec,
            verdict: NormalizedVerdict::None,
            severity: Some("info".to_string()),
            summary: "process_exec /usr/bin/curl".to_string(),
            process: Some("/usr/bin/curl".to_string()),
            namespace: Some("default".to_string()),
            pod: Some("agent-pod-abc123".to_string()),
            action_type: Some("process".to_string()),
            signature_valid: None,
            raw: Some(json!({
                "fact": {
                    "event_type": "PROCESS_EXEC",
                    "process": { "binary": "/usr/bin/curl", "pid": 1234 },
                    "severity": "info"
                }
            })),
        }
    }

    fn make_hubble_event() -> TimelineEvent {
        TimelineEvent {
            event_id: None,
            timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 5, 0).unwrap(),
            source: EventSource::Hubble,
            kind: TimelineEventKind::NetworkFlow,
            verdict: NormalizedVerdict::Forwarded,
            severity: None,
            summary: "egress TCP flow".to_string(),
            process: None,
            namespace: Some("production".to_string()),
            pod: Some("web-server-xyz".to_string()),
            action_type: Some("egress".to_string()),
            signature_valid: None,
            raw: Some(json!({
                "fact": {
                    "verdict": "FORWARDED",
                    "traffic_direction": "EGRESS",
                    "summary": "TCP 10.0.0.1:8080 -> 93.184.216.34:443"
                }
            })),
        }
    }

    fn make_receipt_event() -> TimelineEvent {
        TimelineEvent {
            event_id: None,
            timestamp: Utc.with_ymd_and_hms(2025, 6, 15, 12, 10, 0).unwrap(),
            source: EventSource::Receipt,
            kind: TimelineEventKind::GuardDecision,
            verdict: NormalizedVerdict::Deny,
            severity: Some("critical".to_string()),
            summary: "ForbiddenPathGuard decision=deny".to_string(),
            process: None,
            namespace: None,
            pod: None,
            action_type: Some("file".to_string()),
            signature_valid: None,
            raw: Some(json!({
                "fact": {
                    "decision": "deny",
                    "guard": "ForbiddenPathGuard",
                    "action_type": "file",
                    "severity": "critical"
                }
            })),
        }
    }

    #[test]
    fn tetragon_event_produces_process_activity() {
        let events = vec![make_tetragon_event()];
        let ocsf = timeline_to_ocsf(&events);
        assert_eq!(ocsf.len(), 1);

        let pa = &ocsf[0];
        assert_eq!(pa["class_uid"], 1007);
        assert_eq!(pa["category_uid"], 1);
        assert_eq!(pa["type_uid"], 100701);
    }

    #[test]
    fn hubble_event_produces_network_activity() {
        let events = vec![make_hubble_event()];
        let ocsf = timeline_to_ocsf(&events);
        assert_eq!(ocsf.len(), 1);

        let na = &ocsf[0];
        assert_eq!(na["class_uid"], 4001);
        assert_eq!(na["category_uid"], 4);
    }

    #[test]
    fn receipt_event_produces_detection_finding() {
        let events = vec![make_receipt_event()];
        let ocsf = timeline_to_ocsf(&events);
        assert_eq!(ocsf.len(), 1);

        let df = &ocsf[0];
        assert_eq!(df["class_uid"], 2004);
        assert_eq!(df["category_uid"], 2);
        assert_eq!(df["severity_id"], 5); // critical = 5
    }

    #[test]
    fn events_without_raw_data_are_skipped() {
        let mut event = make_tetragon_event();
        event.raw = None;

        let ocsf = timeline_to_ocsf(&[event]);
        assert!(ocsf.is_empty());
    }

    #[test]
    fn mixed_events_produce_correct_types() {
        let events = vec![
            make_tetragon_event(),
            make_hubble_event(),
            make_receipt_event(),
        ];
        let ocsf = timeline_to_ocsf(&events);
        assert_eq!(ocsf.len(), 3);

        // Verify ordering and class_uid values
        assert_eq!(ocsf[0]["class_uid"], 1007); // ProcessActivity
        assert_eq!(ocsf[1]["class_uid"], 4001); // NetworkActivity
        assert_eq!(ocsf[2]["class_uid"], 2004); // DetectionFinding
    }
}
