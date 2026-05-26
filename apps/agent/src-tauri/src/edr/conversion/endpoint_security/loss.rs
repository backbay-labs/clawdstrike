//! Event-loss field extraction and sensor state synthesis for EndpointSecurity.

use crate::api_server::trimmed_owned;
use crate::edr::dto::{EdrEndpointSecurityEvent, EdrEndpointSecurityEventKind};
use clawdstrike_policy_event::edr::{
    EndpointProviderKind, EndpointProviderState, EndpointSensorState,
};
use std::collections::BTreeMap;

pub(crate) fn endpoint_security_event_loss_fields(
    event: &EdrEndpointSecurityEvent,
) -> BTreeMap<String, serde_json::Value> {
    let mut fields = BTreeMap::new();
    if let Some(value) = event.dropped_event_count {
        fields.insert("droppedEventCount".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.deadline_miss_count {
        fields.insert("deadlineMissCount".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.deadline_missed {
        fields.insert("deadlineMissed".to_string(), serde_json::json!(value));
    }
    if let Some(value) = event.full_disk_access {
        fields.insert("fullDiskAccess".to_string(), serde_json::json!(value));
    }
    if let Some(reason) = trimmed_owned(event.reason.as_deref()) {
        fields.insert("reason".to_string(), serde_json::Value::String(reason));
    }
    fields
}

pub(crate) fn endpoint_security_event_loss_sensor_state(
    events: &[EdrEndpointSecurityEvent],
) -> Option<EndpointSensorState> {
    let mut dropped_event_count = 0_u64;
    let mut deadline_miss_count = 0_u64;
    let mut full_disk_access = None;
    let mut saw_degradation_signal = false;
    let mut degradation_reasons = Vec::new();

    for event in events {
        let dropped_events = event.dropped_event_count.unwrap_or(0);
        let deadline_misses = event.deadline_miss_count.unwrap_or(0);
        dropped_event_count = dropped_event_count.saturating_add(dropped_events);
        deadline_miss_count = deadline_miss_count.saturating_add(deadline_misses);

        let event_loss = matches!(event.kind, EdrEndpointSecurityEventKind::EventLoss);
        if event_loss || dropped_events > 0 || deadline_misses > 0 {
            saw_degradation_signal = true;
        }
        if event_loss {
            degradation_reasons.push("endpoint security event loss reported".to_string());
        }
        if dropped_events > 0 {
            degradation_reasons.push("provider dropped enforcement events".to_string());
        }
        if deadline_misses > 0 {
            degradation_reasons.push("provider authorization deadline misses".to_string());
        }
        if event.deadline_missed == Some(true) {
            saw_degradation_signal = true;
            if event.deadline_miss_count.is_none() {
                deadline_miss_count = deadline_miss_count.saturating_add(1);
            }
            degradation_reasons.push("provider authorization deadline misses".to_string());
        }
        if event.full_disk_access == Some(false) {
            saw_degradation_signal = true;
            full_disk_access = Some(false);
            degradation_reasons.push("missing_full_disk_access".to_string());
        }
        if let Some(reason) = trimmed_owned(event.reason.as_deref()) {
            if event_loss
                || dropped_events > 0
                || deadline_misses > 0
                || event.deadline_missed == Some(true)
                || event.full_disk_access == Some(false)
            {
                degradation_reasons.push(reason);
            }
        }
    }

    if !saw_degradation_signal {
        return None;
    }
    if degradation_reasons.is_empty() {
        degradation_reasons.push("endpoint security provider degraded".to_string());
    }
    degradation_reasons.sort();
    degradation_reasons.dedup();

    Some(EndpointSensorState {
        providers: vec![EndpointProviderState {
            provider_id: "macos.endpoint_security".to_string(),
            provider_kind: EndpointProviderKind::EndpointSecurity,
            installed: true,
            active: true,
            healthy: false,
            degraded: true,
            degradation_reasons,
            dropped_event_count,
            deadline_miss_count,
            full_disk_access,
            last_seen: Some(chrono::Utc::now()),
        }],
    })
}
