//! NATS JetStream replay consumer for historical envelope retrieval.

use std::time::Duration;

use async_nats::jetstream::consumer::pull;
use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio_stream::StreamExt;

use crate::error::{Error, Result};
use crate::query::{EventSource, HuntQuery};
use crate::timeline::{self, TimelineEvent};

/// Default timeout for historical replay: if no new messages arrive within
/// this duration after we have already received at least one message, we
/// treat the historical backlog as fully drained and stop.
const DEFAULT_REPLAY_TIMEOUT: Duration = Duration::from_secs(3);

fn next_poll_timeout(idle_timeout: Duration, received_any: bool) -> Duration {
    if received_any {
        idle_timeout
    } else {
        idle_timeout * 3
    }
}

fn is_past_end(end: Option<&DateTime<Utc>>, event_ts: DateTime<Utc>) -> bool {
    end.is_some_and(|e| event_ts > *e)
}

fn truncate_to_newest(events: &mut Vec<TimelineEvent>, limit: usize) {
    if limit == 0 {
        events.clear();
        return;
    }
    if events.len() > limit {
        events.sort_by_key(|e| e.timestamp);
        let keep_from = events.len() - limit;
        events.drain(0..keep_from);
    }
}

fn deliver_policy_for(
    start: Option<&DateTime<Utc>>,
) -> async_nats::jetstream::consumer::DeliverPolicy {
    if let Some(start) = start {
        let ts = start.timestamp();
        let offset_dt = time::OffsetDateTime::from_unix_timestamp(ts)
            .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
        async_nats::jetstream::consumer::DeliverPolicy::ByStartTime {
            start_time: offset_dt,
        }
    } else {
        async_nats::jetstream::consumer::DeliverPolicy::All
    }
}

fn parse_envelope_payload(
    payload: &[u8],
    verify: bool,
    stream_name: &str,
) -> Option<TimelineEvent> {
    let payload: Value = match serde_json::from_slice(payload) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!("skipping non-JSON message from {stream_name}: {e}");
            return None;
        }
    };
    timeline::parse_envelope(&payload, verify)
}

/// Replay envelopes from a single JetStream stream, filtered by query predicates.
///
/// Uses a timeout mechanism to detect when the historical backlog has been
/// drained: after receiving at least one message, if no new message arrives
/// within the default replay timeout, the stream is considered exhausted.
pub async fn replay_stream(
    js: &async_nats::jetstream::Context,
    source: &EventSource,
    query: &HuntQuery,
    verify: bool,
) -> Result<Vec<TimelineEvent>> {
    replay_stream_with_timeout(js, source, query, verify, DEFAULT_REPLAY_TIMEOUT).await
}

/// Like [`replay_stream`] but with a caller-specified idle timeout.
pub async fn replay_stream_with_timeout(
    js: &async_nats::jetstream::Context,
    source: &EventSource,
    query: &HuntQuery,
    verify: bool,
    idle_timeout: Duration,
) -> Result<Vec<TimelineEvent>> {
    if query.limit == 0 {
        return Ok(Vec::new());
    }

    let stream_name = source.stream_name();

    // Get stream — if missing, warn and return empty
    let stream = match js.get_stream(stream_name).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("stream {stream_name} not found, skipping: {e}");
            return Ok(Vec::new());
        }
    };

    let config = pull::Config {
        filter_subject: source.subject_filter().to_string(),
        deliver_policy: deliver_policy_for(query.start.as_ref()),
        ..Default::default()
    };

    let consumer = stream.create_consumer(config).await.map_err(|e| {
        Error::JetStream(format!("failed to create consumer on {stream_name}: {e}"))
    })?;

    let mut messages = consumer.messages().await.map_err(|e| {
        Error::JetStream(format!(
            "failed to get message stream from {stream_name}: {e}"
        ))
    })?;

    let mut events = Vec::new();
    let mut received_any = false;

    loop {
        let poll_timeout = next_poll_timeout(idle_timeout, received_any);
        let msg_result = if received_any {
            // After receiving at least one message, apply an idle timeout so
            // we don't block forever waiting for new messages once the
            // historical backlog is drained.
            match tokio::time::timeout(poll_timeout, messages.next()).await {
                Ok(Some(r)) => r,
                Ok(None) => break, // stream ended
                Err(_elapsed) => {
                    tracing::debug!(
                        "replay idle timeout ({poll_timeout:?}) on {stream_name}, \
                         treating as end-of-stream"
                    );
                    break;
                }
            }
        } else {
            // First message: use a longer initial timeout so we don't give up
            // too quickly if the consumer is still being created.
            match tokio::time::timeout(poll_timeout, messages.next()).await {
                Ok(Some(r)) => r,
                Ok(None) => break,
                Err(_elapsed) => {
                    tracing::debug!("no messages received within initial timeout on {stream_name}");
                    break;
                }
            }
        };

        let msg = match msg_result {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("error reading message from {stream_name}: {e}");
                continue;
            }
        };

        received_any = true;

        // Acknowledge the message so the pull consumer does not redeliver it.
        msg.ack().await.ok();

        // Parse envelope into TimelineEvent
        if let Some(event) = parse_envelope_payload(&msg.payload, verify, stream_name) {
            // Skip events past end time, but keep consuming: envelope timestamps
            // are producer-provided and may be out-of-order within a stream.
            if is_past_end(query.end.as_ref(), event.timestamp) {
                continue;
            }

            if query.matches(&event) {
                events.push(event);
                let trim_threshold = query.limit.saturating_mul(2);
                if trim_threshold > 0 && events.len() > trim_threshold {
                    truncate_to_newest(&mut events, query.limit);
                }
            }
        }
    }

    truncate_to_newest(&mut events, query.limit);
    Ok(events)
}

/// Replay and merge envelopes from all query sources.
pub async fn replay_all(
    query: &HuntQuery,
    nats_url: &str,
    nats_creds: Option<&str>,
    nats_token: Option<&str>,
    nats_nkey_seed: Option<&str>,
    verify: bool,
) -> Result<Vec<TimelineEvent>> {
    let auth = if nats_creds.is_some() || nats_token.is_some() || nats_nkey_seed.is_some() {
        Some(spine::nats_transport::NatsAuthConfig {
            creds_file: nats_creds.map(ToString::to_string),
            token: nats_token.map(ToString::to_string),
            nkey_seed: nats_nkey_seed.map(ToString::to_string),
        })
    } else {
        None
    };

    let client = spine::nats_transport::connect_with_auth(nats_url, auth.as_ref())
        .await
        .map_err(|e| Error::Nats(format!("failed to connect to NATS at {nats_url}: {e}")))?;

    let js = spine::nats_transport::jetstream(client);

    let mut all_events = Vec::new();

    for source in &query.effective_sources() {
        match replay_stream(&js, source, query, verify).await {
            Ok(events) => {
                all_events.extend(events);
                let trim_threshold = query.limit.saturating_mul(2);
                if trim_threshold > 0 && all_events.len() > trim_threshold {
                    truncate_to_newest(&mut all_events, query.limit);
                }
            }
            Err(e) => {
                tracing::warn!("failed to replay {source} stream: {e}");
            }
        }
    }

    let mut merged = timeline::merge_timeline(all_events);
    truncate_to_newest(&mut merged, query.limit);
    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_nats::jetstream::consumer::DeliverPolicy;
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    #[test]
    fn default_replay_timeout_is_reasonable() {
        // The default idle timeout should be between 1 and 10 seconds.
        assert!(
            DEFAULT_REPLAY_TIMEOUT >= Duration::from_secs(1),
            "timeout should be at least 1s"
        );
        assert!(
            DEFAULT_REPLAY_TIMEOUT <= Duration::from_secs(10),
            "timeout should be at most 10s"
        );
    }

    #[test]
    fn initial_timeout_is_triple_idle() {
        let timeout = DEFAULT_REPLAY_TIMEOUT;
        let initial = next_poll_timeout(timeout, false);
        assert_eq!(initial, Duration::from_secs(9));
    }

    #[test]
    fn steady_state_timeout_uses_idle_duration() {
        let timeout = DEFAULT_REPLAY_TIMEOUT;
        let steady = next_poll_timeout(timeout, true);
        assert_eq!(steady, timeout);
    }

    #[test]
    fn is_past_end_respects_end_boundary() {
        let end = chrono::Utc::now();
        assert!(is_past_end(Some(&end), end + chrono::Duration::seconds(1)));
        assert!(!is_past_end(Some(&end), end));
        assert!(!is_past_end(None, end + chrono::Duration::seconds(1)));
    }

    #[test]
    fn deliver_policy_defaults_to_all_without_start() {
        assert!(matches!(deliver_policy_for(None), DeliverPolicy::All));
    }

    #[test]
    fn deliver_policy_uses_start_time_when_present() {
        let start = Utc.with_ymd_and_hms(2026, 2, 1, 12, 30, 0).unwrap();
        match deliver_policy_for(Some(&start)) {
            DeliverPolicy::ByStartTime { start_time } => {
                assert_eq!(start_time.unix_timestamp(), start.timestamp());
            }
            other => panic!("unexpected deliver policy: {other:?}"),
        }
    }

    #[test]
    fn parse_envelope_payload_rejects_invalid_json() {
        assert!(parse_envelope_payload(b"not json", false, "TEST").is_none());
    }

    #[test]
    fn parse_envelope_payload_parses_valid_envelope() {
        let envelope = json!({
            "issued_at": "2026-02-01T12:00:00Z",
            "fact": {
                "schema": "clawdstrike.sdr.fact.scan.v1",
                "scan_type": "mcp",
                "status": "pass",
            }
        });
        let payload = serde_json::to_vec(&envelope).unwrap();
        let event = parse_envelope_payload(&payload, false, "CLAWDSTRIKE_SCANS");
        assert!(event.is_some());
        let event = event.unwrap();
        assert_eq!(event.source, crate::query::EventSource::Scan);
        assert_eq!(event.action_type.as_deref(), Some("scan"));
    }

    #[test]
    fn truncate_to_newest_keeps_most_recent_events() {
        let mut events = vec![
            TimelineEvent {
                timestamp: Utc.with_ymd_and_hms(2026, 2, 1, 10, 0, 0).unwrap(),
                source: EventSource::Receipt,
                kind: timeline::TimelineEventKind::GuardDecision,
                verdict: timeline::NormalizedVerdict::Allow,
                severity: None,
                summary: "oldest".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: None,
                signature_valid: None,
                raw: None,
            },
            TimelineEvent {
                timestamp: Utc.with_ymd_and_hms(2026, 2, 1, 11, 0, 0).unwrap(),
                source: EventSource::Receipt,
                kind: timeline::TimelineEventKind::GuardDecision,
                verdict: timeline::NormalizedVerdict::Allow,
                severity: None,
                summary: "middle".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: None,
                signature_valid: None,
                raw: None,
            },
            TimelineEvent {
                timestamp: Utc.with_ymd_and_hms(2026, 2, 1, 12, 0, 0).unwrap(),
                source: EventSource::Receipt,
                kind: timeline::TimelineEventKind::GuardDecision,
                verdict: timeline::NormalizedVerdict::Allow,
                severity: None,
                summary: "newest".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: None,
                signature_valid: None,
                raw: None,
            },
        ];

        truncate_to_newest(&mut events, 2);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].summary, "middle");
        assert_eq!(events[1].summary, "newest");
    }

    #[test]
    fn truncate_to_newest_keeps_most_recent_events_when_unsorted() {
        let mut events = vec![
            TimelineEvent {
                timestamp: Utc.with_ymd_and_hms(2026, 2, 1, 12, 0, 0).unwrap(),
                source: EventSource::Receipt,
                kind: timeline::TimelineEventKind::GuardDecision,
                verdict: timeline::NormalizedVerdict::Allow,
                severity: None,
                summary: "newest".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: None,
                signature_valid: None,
                raw: None,
            },
            TimelineEvent {
                timestamp: Utc.with_ymd_and_hms(2026, 2, 1, 10, 0, 0).unwrap(),
                source: EventSource::Receipt,
                kind: timeline::TimelineEventKind::GuardDecision,
                verdict: timeline::NormalizedVerdict::Allow,
                severity: None,
                summary: "oldest".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: None,
                signature_valid: None,
                raw: None,
            },
            TimelineEvent {
                timestamp: Utc.with_ymd_and_hms(2026, 2, 1, 11, 0, 0).unwrap(),
                source: EventSource::Receipt,
                kind: timeline::TimelineEventKind::GuardDecision,
                verdict: timeline::NormalizedVerdict::Allow,
                severity: None,
                summary: "middle".to_string(),
                process: None,
                namespace: None,
                pod: None,
                action_type: None,
                signature_valid: None,
                raw: None,
            },
        ];

        truncate_to_newest(&mut events, 2);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].summary, "middle");
        assert_eq!(events[1].summary, "newest");
    }

    /// Verify that `replay_all` returns an error (not a hang) when NATS is
    /// unreachable.
    #[tokio::test]
    async fn replay_all_unreachable_nats_returns_error() {
        let query = HuntQuery::default();
        // Use a port that is almost certainly not running NATS.
        let result = replay_all(&query, "nats://127.0.0.1:14223", None, None, None, false).await;
        assert!(result.is_err(), "should fail when NATS is unreachable");
    }
}
