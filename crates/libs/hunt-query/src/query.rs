//! Structured query predicates for hunt envelope filtering.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::timeline::{NormalizedVerdict, TimelineEvent};

const ADAPTIVE_INGRESS_STREAM_NAME: &str = "clawdstrike_adaptive_ingress";
const ADAPTIVE_INGRESS_SUBJECT_FILTER: &str = "tenant-*.>";

/// Source system for events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    Tetragon,
    Hubble,
    Receipt,
    Scan,
    Response,
    Directory,
    Detection,
}

impl EventSource {
    /// Parse a source string (case-insensitive).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "tetragon" => Some(Self::Tetragon),
            "hubble" => Some(Self::Hubble),
            "receipt" | "receipts" => Some(Self::Receipt),
            "scan" | "scans" => Some(Self::Scan),
            "response" => Some(Self::Response),
            "directory" => Some(Self::Directory),
            "detection" => Some(Self::Detection),
            _ => None,
        }
    }

    /// Parse a comma-separated list of sources.
    pub fn parse_list(s: &str) -> Vec<Self> {
        s.split(',')
            .filter_map(|part| Self::parse(part.trim()))
            .collect()
    }

    /// JetStream stream name.
    pub fn stream_name(&self) -> &'static str {
        match self {
            Self::Tetragon => "CLAWDSTRIKE_TETRAGON",
            Self::Hubble => "CLAWDSTRIKE_HUBBLE",
            Self::Receipt => "CLAWDSTRIKE_RECEIPTS",
            Self::Scan => "CLAWDSTRIKE_SCANS",
            Self::Response | Self::Directory | Self::Detection => ADAPTIVE_INGRESS_STREAM_NAME,
        }
    }

    /// NATS subject filter pattern.
    pub fn subject_filter(&self) -> &'static str {
        match self {
            Self::Tetragon => "clawdstrike.sdr.fact.tetragon_event.>",
            Self::Hubble => "clawdstrike.sdr.fact.hubble_flow.>",
            Self::Receipt => "clawdstrike.sdr.fact.receipt.>",
            Self::Scan => "clawdstrike.sdr.fact.scan.>",
            Self::Response | Self::Directory | Self::Detection => ADAPTIVE_INGRESS_SUBJECT_FILTER,
        }
    }

    /// JetStream replay identity. Sources that share this tuple can be
    /// consumed from a single subscription without losing source fidelity,
    /// because the envelope parser still projects the original event source.
    pub fn replay_key(&self) -> (&'static str, &'static str) {
        (self.stream_name(), self.subject_filter())
    }

    /// All known sources.
    pub fn all() -> Vec<Self> {
        vec![
            Self::Tetragon,
            Self::Hubble,
            Self::Receipt,
            Self::Scan,
            Self::Response,
            Self::Directory,
            Self::Detection,
        ]
    }
}

impl std::fmt::Display for EventSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tetragon => write!(f, "tetragon"),
            Self::Hubble => write!(f, "hubble"),
            Self::Receipt => write!(f, "receipt"),
            Self::Scan => write!(f, "scan"),
            Self::Response => write!(f, "response"),
            Self::Directory => write!(f, "directory"),
            Self::Detection => write!(f, "detection"),
        }
    }
}

/// Verdict filter for queries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueryVerdict {
    Allow,
    Deny,
    Warn,
    Forwarded,
    Dropped,
}

impl QueryVerdict {
    /// Parse a verdict string (case-insensitive, supports aliases).
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_lowercase().as_str() {
            "allow" | "allowed" | "pass" | "passed" => Some(Self::Allow),
            "deny" | "denied" | "block" | "blocked" => Some(Self::Deny),
            "warn" | "warned" | "warning" => Some(Self::Warn),
            "forwarded" | "forward" => Some(Self::Forwarded),
            "dropped" | "drop" => Some(Self::Dropped),
            _ => None,
        }
    }
}

/// Structured query over historical events.
#[derive(Debug, Clone)]
pub struct HuntQuery {
    pub sources: Vec<EventSource>,
    pub verdict: Option<QueryVerdict>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub action_type: Option<String>,
    pub process: Option<String>,
    pub namespace: Option<String>,
    pub pod: Option<String>,
    pub limit: usize,
    pub entity: Option<String>,
}

impl Default for HuntQuery {
    fn default() -> Self {
        Self {
            sources: Vec::new(),
            verdict: None,
            start: None,
            end: None,
            action_type: None,
            process: None,
            namespace: None,
            pod: None,
            limit: 100,
            entity: None,
        }
    }
}

impl HuntQuery {
    /// Returns the effective sources: the configured list, or all sources if empty.
    pub fn effective_sources(&self) -> Vec<EventSource> {
        if self.sources.is_empty() {
            EventSource::all()
        } else {
            let mut deduped = Vec::with_capacity(self.sources.len());
            for source in &self.sources {
                if !deduped.contains(source) {
                    deduped.push(*source);
                }
            }
            deduped
        }
    }

    /// Returns the distinct replay subscriptions needed to satisfy this query.
    ///
    /// Multiple logical sources can share a single JetStream stream/subject
    /// pair. Replay should consume each pair once and let envelope parsing
    /// recover the concrete event source for downstream filtering.
    pub fn effective_replay_sources(&self) -> Vec<EventSource> {
        let mut deduped = Vec::new();
        let mut replay_keys = Vec::new();
        for source in self.effective_sources() {
            let replay_key = source.replay_key();
            if replay_keys.contains(&replay_key) {
                continue;
            }
            replay_keys.push(replay_key);
            deduped.push(source);
        }
        deduped
    }

    /// Returns true if the event matches ALL active predicates.
    pub fn matches(&self, event: &TimelineEvent) -> bool {
        // Check source filter
        if !self.sources.is_empty() && !self.sources.contains(&event.source) {
            return false;
        }

        // Check verdict filter
        if let Some(ref v) = self.verdict {
            let expected = match v {
                QueryVerdict::Allow => NormalizedVerdict::Allow,
                QueryVerdict::Deny => NormalizedVerdict::Deny,
                QueryVerdict::Warn => NormalizedVerdict::Warn,
                QueryVerdict::Forwarded => NormalizedVerdict::Forwarded,
                QueryVerdict::Dropped => NormalizedVerdict::Dropped,
            };
            if event.verdict != expected {
                return false;
            }
        }

        // Check time range
        if let Some(ref start) = self.start {
            if event.timestamp < *start {
                return false;
            }
        }
        if let Some(ref end) = self.end {
            if event.timestamp > *end {
                return false;
            }
        }

        // Check optional string fields (case-insensitive)
        if let Some(ref at) = self.action_type {
            if !event
                .action_type
                .as_ref()
                .is_some_and(|ea| ea.eq_ignore_ascii_case(at))
            {
                return false;
            }
        }

        if let Some(ref p) = self.process {
            if !event
                .process
                .as_ref()
                .is_some_and(|ep| ep.to_lowercase().contains(&p.to_lowercase()))
            {
                return false;
            }
        }

        if let Some(ref ns) = self.namespace {
            if !event
                .namespace
                .as_ref()
                .is_some_and(|en| en.eq_ignore_ascii_case(ns))
            {
                return false;
            }
        }

        if let Some(ref pod_filter) = self.pod {
            if !event
                .pod
                .as_ref()
                .is_some_and(|ep| ep.to_lowercase().contains(&pod_filter.to_lowercase()))
            {
                return false;
            }
        }

        // Entity: matches against pod name or namespace (case-insensitive substring)
        if let Some(ref entity) = self.entity {
            let entity_lower = entity.to_lowercase();
            let pod_match = event
                .pod
                .as_ref()
                .is_some_and(|p| p.to_lowercase().contains(&entity_lower));
            let ns_match = event
                .namespace
                .as_ref()
                .is_some_and(|n| n.to_lowercase().contains(&entity_lower));
            if !pod_match && !ns_match {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timeline::{NormalizedVerdict, TimelineEvent, TimelineEventKind};
    use chrono::TimeZone;

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

    #[test]
    fn event_source_parse() {
        assert_eq!(EventSource::parse("tetragon"), Some(EventSource::Tetragon));
        assert_eq!(EventSource::parse("HUBBLE"), Some(EventSource::Hubble));
        assert_eq!(EventSource::parse("Receipt"), Some(EventSource::Receipt));
        assert_eq!(EventSource::parse("receipts"), Some(EventSource::Receipt));
        assert_eq!(EventSource::parse("scan"), Some(EventSource::Scan));
        assert_eq!(EventSource::parse("scans"), Some(EventSource::Scan));
        assert_eq!(EventSource::parse("response"), Some(EventSource::Response));
        assert_eq!(
            EventSource::parse("directory"),
            Some(EventSource::Directory)
        );
        assert_eq!(
            EventSource::parse("detection"),
            Some(EventSource::Detection)
        );
        assert_eq!(EventSource::parse("unknown"), None);
    }

    #[test]
    fn event_source_parse_list() {
        let sources = EventSource::parse_list("tetragon, hubble");
        assert_eq!(sources, vec![EventSource::Tetragon, EventSource::Hubble]);

        let sources = EventSource::parse_list("SCAN");
        assert_eq!(sources, vec![EventSource::Scan]);

        let empty = EventSource::parse_list("");
        assert!(empty.is_empty());
    }

    #[test]
    fn event_source_stream_names() {
        assert_eq!(EventSource::Tetragon.stream_name(), "CLAWDSTRIKE_TETRAGON");
        assert_eq!(EventSource::Hubble.stream_name(), "CLAWDSTRIKE_HUBBLE");
        assert_eq!(EventSource::Receipt.stream_name(), "CLAWDSTRIKE_RECEIPTS");
        assert_eq!(EventSource::Scan.stream_name(), "CLAWDSTRIKE_SCANS");
        assert_eq!(
            EventSource::Response.stream_name(),
            ADAPTIVE_INGRESS_STREAM_NAME
        );
    }

    #[test]
    fn event_source_subject_filters() {
        assert_eq!(
            EventSource::Tetragon.subject_filter(),
            "clawdstrike.sdr.fact.tetragon_event.>"
        );
        assert_eq!(
            EventSource::Hubble.subject_filter(),
            "clawdstrike.sdr.fact.hubble_flow.>"
        );
        assert_eq!(
            EventSource::Directory.subject_filter(),
            ADAPTIVE_INGRESS_SUBJECT_FILTER
        );
    }

    #[test]
    fn event_source_display() {
        assert_eq!(EventSource::Tetragon.to_string(), "tetragon");
        assert_eq!(EventSource::Hubble.to_string(), "hubble");
        assert_eq!(EventSource::Receipt.to_string(), "receipt");
        assert_eq!(EventSource::Scan.to_string(), "scan");
        assert_eq!(EventSource::Response.to_string(), "response");
        assert_eq!(EventSource::Directory.to_string(), "directory");
        assert_eq!(EventSource::Detection.to_string(), "detection");
    }

    #[test]
    fn event_source_all() {
        let all = EventSource::all();
        assert_eq!(all.len(), 7);
        assert!(all.contains(&EventSource::Tetragon));
        assert!(all.contains(&EventSource::Hubble));
        assert!(all.contains(&EventSource::Receipt));
        assert!(all.contains(&EventSource::Scan));
        assert!(all.contains(&EventSource::Response));
        assert!(all.contains(&EventSource::Directory));
        assert!(all.contains(&EventSource::Detection));
    }

    #[test]
    fn query_verdict_parse() {
        assert_eq!(QueryVerdict::parse("allow"), Some(QueryVerdict::Allow));
        assert_eq!(QueryVerdict::parse("ALLOWED"), Some(QueryVerdict::Allow));
        assert_eq!(QueryVerdict::parse("pass"), Some(QueryVerdict::Allow));
        assert_eq!(QueryVerdict::parse("passed"), Some(QueryVerdict::Allow));
        assert_eq!(QueryVerdict::parse("deny"), Some(QueryVerdict::Deny));
        assert_eq!(QueryVerdict::parse("DENIED"), Some(QueryVerdict::Deny));
        assert_eq!(QueryVerdict::parse("block"), Some(QueryVerdict::Deny));
        assert_eq!(QueryVerdict::parse("blocked"), Some(QueryVerdict::Deny));
        assert_eq!(QueryVerdict::parse("warn"), Some(QueryVerdict::Warn));
        assert_eq!(QueryVerdict::parse("warned"), Some(QueryVerdict::Warn));
        assert_eq!(QueryVerdict::parse("warning"), Some(QueryVerdict::Warn));
        assert_eq!(
            QueryVerdict::parse("forwarded"),
            Some(QueryVerdict::Forwarded)
        );
        assert_eq!(
            QueryVerdict::parse("forward"),
            Some(QueryVerdict::Forwarded)
        );
        assert_eq!(QueryVerdict::parse("dropped"), Some(QueryVerdict::Dropped));
        assert_eq!(QueryVerdict::parse("drop"), Some(QueryVerdict::Dropped));
        assert_eq!(QueryVerdict::parse("unknown"), None);
    }

    #[test]
    fn hunt_query_matches_forwarded_verdict() {
        let mut event = make_event();
        event.verdict = NormalizedVerdict::Forwarded;

        let q = HuntQuery {
            verdict: Some(QueryVerdict::Forwarded),
            ..Default::default()
        };
        assert!(q.matches(&event));

        let q2 = HuntQuery {
            verdict: Some(QueryVerdict::Allow),
            ..Default::default()
        };
        assert!(!q2.matches(&event));
    }

    #[test]
    fn hunt_query_matches_dropped_verdict() {
        let mut event = make_event();
        event.verdict = NormalizedVerdict::Dropped;

        let q = HuntQuery {
            verdict: Some(QueryVerdict::Dropped),
            ..Default::default()
        };
        assert!(q.matches(&event));

        let q2 = HuntQuery {
            verdict: Some(QueryVerdict::Deny),
            ..Default::default()
        };
        assert!(!q2.matches(&event));
    }

    #[test]
    fn hunt_query_default() {
        let q = HuntQuery::default();
        assert!(q.sources.is_empty());
        assert!(q.verdict.is_none());
        assert!(q.start.is_none());
        assert!(q.end.is_none());
        assert_eq!(q.limit, 100);
    }

    #[test]
    fn hunt_query_effective_sources_empty() {
        let q = HuntQuery::default();
        assert_eq!(q.effective_sources(), EventSource::all());
    }

    #[test]
    fn hunt_query_effective_sources_specified() {
        let q = HuntQuery {
            sources: vec![EventSource::Tetragon],
            ..Default::default()
        };
        assert_eq!(q.effective_sources(), vec![EventSource::Tetragon]);
    }

    #[test]
    fn hunt_query_effective_sources_deduplicates_preserving_order() {
        let q = HuntQuery {
            sources: vec![
                EventSource::Receipt,
                EventSource::Receipt,
                EventSource::Hubble,
                EventSource::Receipt,
                EventSource::Hubble,
            ],
            ..Default::default()
        };
        assert_eq!(
            q.effective_sources(),
            vec![EventSource::Receipt, EventSource::Hubble]
        );
    }

    #[test]
    fn hunt_query_effective_replay_sources_collapse_shared_streams() {
        let q = HuntQuery::default();
        assert_eq!(
            q.effective_replay_sources(),
            vec![
                EventSource::Tetragon,
                EventSource::Hubble,
                EventSource::Receipt,
                EventSource::Scan,
                EventSource::Response,
            ]
        );
    }

    #[test]
    fn hunt_query_effective_replay_sources_preserve_first_matching_source() {
        let q = HuntQuery {
            sources: vec![
                EventSource::Detection,
                EventSource::Response,
                EventSource::Directory,
                EventSource::Tetragon,
            ],
            ..Default::default()
        };
        assert_eq!(
            q.effective_replay_sources(),
            vec![EventSource::Detection, EventSource::Tetragon]
        );
    }

    #[test]
    fn hunt_query_matches_all_default() {
        let q = HuntQuery::default();
        let event = make_event();
        assert!(q.matches(&event));
    }

    #[test]
    fn hunt_query_matches_source_filter() {
        let q = HuntQuery {
            sources: vec![EventSource::Hubble],
            ..Default::default()
        };
        let event = make_event(); // source is Tetragon
        assert!(!q.matches(&event));

        let q2 = HuntQuery {
            sources: vec![EventSource::Tetragon],
            ..Default::default()
        };
        assert!(q2.matches(&event));
    }

    #[test]
    fn hunt_query_matches_verdict_filter() {
        let q = HuntQuery {
            verdict: Some(QueryVerdict::Deny),
            ..Default::default()
        };
        let event = make_event(); // verdict is Allow
        assert!(!q.matches(&event));

        let q2 = HuntQuery {
            verdict: Some(QueryVerdict::Allow),
            ..Default::default()
        };
        assert!(q2.matches(&event));
    }

    #[test]
    fn hunt_query_matches_time_range() {
        let event = make_event(); // 2025-06-15 12:00:00

        let q = HuntQuery {
            start: Some(Utc.with_ymd_and_hms(2025, 6, 15, 13, 0, 0).unwrap()),
            ..Default::default()
        };
        assert!(!q.matches(&event));

        let q2 = HuntQuery {
            end: Some(Utc.with_ymd_and_hms(2025, 6, 15, 11, 0, 0).unwrap()),
            ..Default::default()
        };
        assert!(!q2.matches(&event));

        let q3 = HuntQuery {
            start: Some(Utc.with_ymd_and_hms(2025, 6, 15, 11, 0, 0).unwrap()),
            end: Some(Utc.with_ymd_and_hms(2025, 6, 15, 13, 0, 0).unwrap()),
            ..Default::default()
        };
        assert!(q3.matches(&event));
    }

    #[test]
    fn hunt_query_matches_action_type() {
        let q = HuntQuery {
            action_type: Some("PROCESS".to_string()),
            ..Default::default()
        };
        let event = make_event(); // action_type is "process"
        assert!(q.matches(&event)); // case-insensitive
    }

    #[test]
    fn hunt_query_matches_process_contains() {
        let q = HuntQuery {
            process: Some("curl".to_string()),
            ..Default::default()
        };
        let event = make_event(); // process is "/usr/bin/curl"
        assert!(q.matches(&event)); // contains match
    }

    #[test]
    fn hunt_query_matches_namespace() {
        let q = HuntQuery {
            namespace: Some("kube-system".to_string()),
            ..Default::default()
        };
        let event = make_event(); // namespace is "default"
        assert!(!q.matches(&event));
    }

    #[test]
    fn hunt_query_matches_pod_contains() {
        let q = HuntQuery {
            pod: Some("agent-pod".to_string()),
            ..Default::default()
        };
        let event = make_event(); // pod is "agent-pod-abc123"
        assert!(q.matches(&event)); // contains match
    }

    #[test]
    fn hunt_query_matches_combined_predicates() {
        let q = HuntQuery {
            sources: vec![EventSource::Tetragon],
            verdict: Some(QueryVerdict::Allow),
            process: Some("curl".to_string()),
            namespace: Some("default".to_string()),
            ..Default::default()
        };
        let event = make_event();
        assert!(q.matches(&event));
    }

    #[test]
    fn hunt_query_no_match_missing_optional_field() {
        let mut event = make_event();
        event.process = None;

        let q = HuntQuery {
            process: Some("curl".to_string()),
            ..Default::default()
        };
        assert!(!q.matches(&event));
    }

    #[test]
    fn hunt_query_entity_matches_pod() {
        let q = HuntQuery {
            entity: Some("agent-pod".to_string()),
            ..Default::default()
        };
        let event = make_event(); // pod is "agent-pod-abc123"
        assert!(q.matches(&event));
    }

    #[test]
    fn hunt_query_entity_matches_namespace() {
        let q = HuntQuery {
            entity: Some("default".to_string()),
            ..Default::default()
        };
        let event = make_event(); // namespace is "default"
        assert!(q.matches(&event));
    }

    #[test]
    fn hunt_query_entity_no_match() {
        let q = HuntQuery {
            entity: Some("nonexistent".to_string()),
            ..Default::default()
        };
        let event = make_event();
        assert!(!q.matches(&event));
    }
}
