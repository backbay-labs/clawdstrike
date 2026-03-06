use crate::base::{ActionId, DispositionId, StatusId};
use crate::classes::detection_finding::{DetectionFinding, DetectionFindingActivity};
use crate::objects::actor::{Actor, ActorSession};
use crate::objects::evidence::Evidence;
use crate::objects::finding_info::{Analytic, FindingInfo};
use crate::objects::metadata::Metadata;
use crate::objects::observable::{Observable, ObservableTypeId};
use crate::severity::map_severity;

pub struct PersistedDetectionFindingInput<'a> {
    pub finding_id: &'a str,
    pub time_ms: i64,
    pub severity: &'a str,
    pub status: &'a str,
    pub title: &'a str,
    pub summary: &'a str,
    pub rule_id: &'a str,
    pub rule_name: &'a str,
    pub source_format: &'a str,
    pub session_id: Option<&'a str>,
    pub principal_id: Option<&'a str>,
    pub evidence_refs: &'a [String],
    pub product_version: &'a str,
}

#[must_use]
pub fn persisted_detection_finding_to_ocsf(
    input: &PersistedDetectionFindingInput<'_>,
) -> DetectionFinding {
    let severity = map_severity(input.severity);
    let (status_id, action_id, disposition) = detection_outcome(input.status);
    let metadata = Metadata::clawdstrike(input.product_version).with_original_uid(input.finding_id);
    let finding_info = FindingInfo {
        uid: input.finding_id.to_string(),
        title: input.title.to_string(),
        analytic: Analytic {
            name: input.rule_name.to_string(),
            type_id: 1,
            r#type: Some("Rule".to_string()),
            uid: Some(input.rule_id.to_string()),
            version: Some(input.source_format.to_string()),
        },
        desc: Some(input.summary.to_string()),
        related_analytics: None,
    };

    let mut finding = DetectionFinding::new(
        DetectionFindingActivity::Create,
        input.time_ms,
        severity.as_u8(),
        status_id.as_u8(),
        action_id.as_u8(),
        disposition.as_u8(),
        metadata,
        finding_info,
    )
    .with_severity_label(severity.label())
    .with_message(input.summary);

    if let Some(principal_id) = input.principal_id {
        finding.actor = Some(Actor {
            user: Some(crate::objects::process::OcsfUser {
                name: None,
                uid: Some(principal_id.to_string()),
            }),
            app_name: Some("clawdstrike-control-api".to_string()),
            app_uid: None,
            session: input.session_id.map(|value| ActorSession {
                uid: Some(value.to_string()),
            }),
        });
    }

    if !input.evidence_refs.is_empty() {
        finding.evidence = Some(Evidence {
            data: Some(serde_json::json!({
                "artifact_refs": input.evidence_refs,
                "provider": "clawdstrike-control-api",
                "type": "artifact_ref",
            })),
        });
        finding.observables = Some(
            input
                .evidence_refs
                .iter()
                .map(|reference| Observable {
                    name: "artifact_ref".to_string(),
                    type_id: ObservableTypeId::Other.as_u8(),
                    value: reference.clone(),
                    r#type: Some("Other".to_string()),
                })
                .collect(),
        );
    }

    finding
}

fn detection_outcome(status: &str) -> (StatusId, ActionId, DispositionId) {
    match status {
        "resolved" | "false_positive" | "expired" => {
            (StatusId::Success, ActionId::Allowed, DispositionId::Allowed)
        }
        "suppressed" | "open" => (StatusId::Unknown, ActionId::Unknown, DispositionId::Logged),
        _ => (StatusId::Unknown, ActionId::Unknown, DispositionId::Unknown),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_detection_finding_maps_to_ocsf() {
        let evidence = vec!["artifact://evt-1".to_string()];
        let finding = persisted_detection_finding_to_ocsf(&PersistedDetectionFindingInput {
            finding_id: "finding-1",
            time_ms: 1_710_000_000_000,
            severity: "high",
            status: "open",
            title: "Suspicious file access",
            summary: "matched test rule",
            rule_id: "rule-1",
            rule_name: "test-rule",
            source_format: "native_correlation",
            session_id: Some("session-1"),
            principal_id: Some("principal-1"),
            evidence_refs: &evidence,
            product_version: "0.1.0",
        });
        assert_eq!(finding.finding_info.uid, "finding-1");
        assert_eq!(finding.finding_info.analytic.uid.as_deref(), Some("rule-1"));
        assert_eq!(
            finding.finding_info.analytic.version.as_deref(),
            Some("native_correlation")
        );
        assert_eq!(finding.status_id, StatusId::Unknown.as_u8());
        assert_eq!(finding.action_id, ActionId::Unknown.as_u8());
        assert_eq!(finding.disposition_id, DispositionId::Logged.as_u8());
        assert!(finding.evidence.is_some());
    }

    #[test]
    fn resolved_detection_finding_maps_to_successful_allowed_outcome() {
        let finding = persisted_detection_finding_to_ocsf(&PersistedDetectionFindingInput {
            finding_id: "finding-2",
            time_ms: 1_710_000_000_000,
            severity: "medium",
            status: "resolved",
            title: "Resolved finding",
            summary: "closed by analyst",
            rule_id: "rule-2",
            rule_name: "resolved-rule",
            source_format: "sigma",
            session_id: None,
            principal_id: None,
            evidence_refs: &[],
            product_version: "0.1.0",
        });

        assert_eq!(finding.status_id, StatusId::Success.as_u8());
        assert_eq!(finding.action_id, ActionId::Allowed.as_u8());
        assert_eq!(finding.disposition_id, DispositionId::Allowed.as_u8());
    }

    #[test]
    fn unknown_detection_status_falls_back_to_unknown_outcome() {
        let finding = persisted_detection_finding_to_ocsf(&PersistedDetectionFindingInput {
            finding_id: "finding-3",
            time_ms: 1_710_000_000_000,
            severity: "low",
            status: "triaging",
            title: "Triaging finding",
            summary: "still under review",
            rule_id: "rule-3",
            rule_name: "triage-rule",
            source_format: "native_correlation",
            session_id: None,
            principal_id: None,
            evidence_refs: &[],
            product_version: "0.1.0",
        });

        assert_eq!(finding.status_id, StatusId::Unknown.as_u8());
        assert_eq!(finding.action_id, ActionId::Unknown.as_u8());
        assert_eq!(finding.disposition_id, DispositionId::Unknown.as_u8());
    }
}
