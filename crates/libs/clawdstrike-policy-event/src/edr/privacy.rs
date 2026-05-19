use serde::{Deserialize, Serialize};

use super::event::EndpointObservation;
use super::receipt::evidence::EndpointEvidenceRedactionClass;
use super::{
    count_projection_class, project_observation_privacy, telemetry_privacy_report_id_from_values,
};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointTelemetryPrivacyMode {
    LocalOnly,
    #[default]
    HashesFeatures,
    SummaryWithReceipts,
    RawArtifactPermitted,
}

impl EndpointTelemetryPrivacyMode {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::HashesFeatures => "hashes_features",
            Self::SummaryWithReceipts => "summary_with_receipts",
            Self::RawArtifactPermitted => "raw_artifact_permitted",
        }
    }

    #[must_use]
    pub fn permits_raw_artifacts(&self) -> bool {
        matches!(self, Self::RawArtifactPermitted)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointTelemetryFieldProjection {
    pub field_path: String,
    pub redaction_class: EndpointEvidenceRedactionClass,
    pub value_hash: Option<String>,
    pub feature_value: Option<String>,
    pub raw_value: Option<String>,
    pub reason: String,
}

impl Default for EndpointTelemetryFieldProjection {
    fn default() -> Self {
        Self {
            field_path: String::new(),
            redaction_class: EndpointEvidenceRedactionClass::HashOnly,
            value_hash: None,
            feature_value: None,
            raw_value: None,
            reason: String::new(),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointTelemetryObservationProjection {
    pub observation_id: String,
    pub event_kind: String,
    pub field_count: usize,
    pub raw_suppressed_count: usize,
    pub local_only_count: usize,
    pub projections: Vec<EndpointTelemetryFieldProjection>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointTelemetryPrivacyReport {
    pub report_id: String,
    pub privacy_mode: EndpointTelemetryPrivacyMode,
    pub raw_artifact_upload_permitted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_artifact_approval_reason_hash: Option<String>,
    pub observation_count: usize,
    pub field_count: usize,
    pub hash_only_count: usize,
    pub metadata_only_count: usize,
    pub redacted_count: usize,
    pub raw_suppressed_count: usize,
    pub local_only_count: usize,
    pub observations: Vec<EndpointTelemetryObservationProjection>,
}

impl EndpointTelemetryPrivacyReport {
    #[must_use]
    pub fn from_observations(
        observations: &[EndpointObservation],
        privacy_mode: EndpointTelemetryPrivacyMode,
    ) -> Self {
        Self::from_observations_with_raw_artifact_approval(observations, privacy_mode, None, None)
    }

    #[must_use]
    pub fn from_observations_with_raw_artifact_approval(
        observations: &[EndpointObservation],
        privacy_mode: EndpointTelemetryPrivacyMode,
        raw_artifact_approval_id: Option<&str>,
        raw_artifact_approval_reason_hash: Option<&str>,
    ) -> Self {
        let raw_artifact_upload_permitted = privacy_mode.permits_raw_artifacts();
        let raw_artifact_approval_id = raw_artifact_upload_permitted
            .then(|| raw_artifact_approval_id.map(ToString::to_string))
            .flatten();
        let raw_artifact_approval_reason_hash = raw_artifact_upload_permitted
            .then(|| raw_artifact_approval_reason_hash.map(ToString::to_string))
            .flatten();
        let projected_observations = observations
            .iter()
            .map(|observation| project_observation_privacy(observation, &privacy_mode))
            .collect::<Vec<_>>();

        let field_count: usize = projected_observations
            .iter()
            .map(|projection| projection.field_count)
            .sum();
        let raw_suppressed_count: usize = projected_observations
            .iter()
            .map(|projection| projection.raw_suppressed_count)
            .sum();
        let local_only_count: usize = projected_observations
            .iter()
            .map(|projection| projection.local_only_count)
            .sum();
        let hash_only_count = count_projection_class(
            &projected_observations,
            EndpointEvidenceRedactionClass::HashOnly,
        );
        let metadata_only_count = count_projection_class(
            &projected_observations,
            EndpointEvidenceRedactionClass::MetadataOnly,
        );
        let redacted_count = count_projection_class(
            &projected_observations,
            EndpointEvidenceRedactionClass::Redacted,
        );
        let mode = privacy_mode.as_str();
        let observation_count_text = observations.len().to_string();
        let field_count_text = field_count.to_string();
        let hash_only_count_text = hash_only_count.to_string();
        let metadata_only_count_text = metadata_only_count.to_string();
        let redacted_count_text = redacted_count.to_string();
        let raw_suppressed_count_text = raw_suppressed_count.to_string();
        let local_only_count_text = local_only_count.to_string();
        let report_id = telemetry_privacy_report_id_from_values(
            mode,
            raw_artifact_upload_permitted,
            raw_artifact_approval_id.as_deref(),
            raw_artifact_approval_reason_hash.as_deref(),
            [
                observation_count_text.as_str(),
                field_count_text.as_str(),
                hash_only_count_text.as_str(),
                metadata_only_count_text.as_str(),
                redacted_count_text.as_str(),
                raw_suppressed_count_text.as_str(),
                local_only_count_text.as_str(),
            ],
        );

        Self {
            report_id,
            privacy_mode,
            raw_artifact_upload_permitted,
            raw_artifact_approval_id,
            raw_artifact_approval_reason_hash,
            observation_count: observations.len(),
            field_count,
            hash_only_count,
            metadata_only_count,
            redacted_count,
            raw_suppressed_count,
            local_only_count,
            observations: projected_observations,
        }
    }
}
