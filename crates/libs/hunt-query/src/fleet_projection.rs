use chrono::{DateTime, Utc};
use clawdstrike_ocsf::fleet::{
    FleetEventEnvelope, FleetEventKind, FleetEventSeverity, FleetEventSource, FleetEventVerdict,
};
use serde_json::Value;

use crate::query::EventSource;
use crate::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};

pub(crate) fn looks_like_fleet_event_fact(fact: &Value) -> bool {
    let Some(object) = fact.as_object() else {
        return false;
    };
    object.get("eventId").and_then(Value::as_str).is_some()
        && object.get("tenantId").and_then(Value::as_str).is_some()
        && object.get("source").and_then(Value::as_str).is_some()
        && object.get("kind").and_then(Value::as_str).is_some()
        && object.get("occurredAt").and_then(Value::as_str).is_some()
        && object.get("ingestedAt").and_then(Value::as_str).is_some()
        && object
            .get("evidence")
            .and_then(Value::as_object)
            .and_then(|evidence| evidence.get("rawRef"))
            .and_then(Value::as_str)
            .is_some()
}

pub(crate) fn fleet_event_to_timeline_event(
    event: FleetEventEnvelope,
    sig: Option<bool>,
    raw: Value,
) -> Option<TimelineEvent> {
    let timestamp = DateTime::parse_from_rfc3339(&event.occurred_at)
        .ok()?
        .with_timezone(&Utc);

    Some(TimelineEvent {
        event_id: Some(event.event_id),
        timestamp,
        source: fleet_event_source_as_query_source(event.source),
        kind: fleet_event_kind_as_timeline_kind(event.kind),
        verdict: fleet_verdict_as_normalized(event.verdict),
        severity: event.severity.map(fleet_severity_label),
        summary: event.summary,
        process: event
            .attributes
            .get("process")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        namespace: event
            .attributes
            .get("namespace")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        pod: event
            .attributes
            .get("pod")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned),
        action_type: event.action_type,
        signature_valid: sig.or(event.evidence.signature_valid),
        raw: Some(raw),
    })
}

pub(crate) fn fleet_event_source_as_query_source(source: FleetEventSource) -> EventSource {
    match source {
        FleetEventSource::Receipt => EventSource::Receipt,
        FleetEventSource::Tetragon => EventSource::Tetragon,
        FleetEventSource::Hubble => EventSource::Hubble,
        FleetEventSource::Scan => EventSource::Scan,
        FleetEventSource::Response => EventSource::Response,
        FleetEventSource::Directory => EventSource::Directory,
        FleetEventSource::Detection => EventSource::Detection,
    }
}

pub(crate) fn fleet_event_kind_as_timeline_kind(kind: FleetEventKind) -> TimelineEventKind {
    match kind {
        FleetEventKind::GuardDecision => TimelineEventKind::GuardDecision,
        FleetEventKind::ProcessExec => TimelineEventKind::ProcessExec,
        FleetEventKind::ProcessExit => TimelineEventKind::ProcessExit,
        FleetEventKind::ProcessKprobe => TimelineEventKind::ProcessKprobe,
        FleetEventKind::NetworkFlow => TimelineEventKind::NetworkFlow,
        FleetEventKind::ScanResult => TimelineEventKind::ScanResult,
        FleetEventKind::JoinCompleted => TimelineEventKind::JoinCompleted,
        FleetEventKind::PrincipalStateChanged => TimelineEventKind::PrincipalStateChanged,
        FleetEventKind::ResponseActionCreated => TimelineEventKind::ResponseActionCreated,
        FleetEventKind::ResponseActionUpdated => TimelineEventKind::ResponseActionUpdated,
        FleetEventKind::DetectionFired => TimelineEventKind::DetectionFired,
    }
}

pub(crate) fn fleet_verdict_as_normalized(verdict: Option<FleetEventVerdict>) -> NormalizedVerdict {
    match verdict.unwrap_or(FleetEventVerdict::None) {
        FleetEventVerdict::Allow => NormalizedVerdict::Allow,
        FleetEventVerdict::Deny => NormalizedVerdict::Deny,
        FleetEventVerdict::Warn => NormalizedVerdict::Warn,
        FleetEventVerdict::None => NormalizedVerdict::None,
        FleetEventVerdict::Forwarded => NormalizedVerdict::Forwarded,
        FleetEventVerdict::Dropped => NormalizedVerdict::Dropped,
    }
}

pub(crate) fn fleet_severity_label(severity: FleetEventSeverity) -> String {
    match severity {
        FleetEventSeverity::Info => "info",
        FleetEventSeverity::Low => "low",
        FleetEventSeverity::Medium => "medium",
        FleetEventSeverity::High => "high",
        FleetEventSeverity::Critical => "critical",
    }
    .to_string()
}
