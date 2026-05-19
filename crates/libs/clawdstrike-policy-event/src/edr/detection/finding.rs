use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionEvidence {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetectionFinding {
    pub finding_id: String,
    pub rule_id: String,
    pub title: String,
    pub severity: DetectionSeverity,
    pub confidence: f32,
    pub description: String,
    pub observation_id: String,
    pub timestamp: DateTime<Utc>,
    pub evidence: Vec<DetectionEvidence>,
    pub mitre_attack: Vec<String>,
    pub tags: Vec<String>,
    pub remediation: String,
}

