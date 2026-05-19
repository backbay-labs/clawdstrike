use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::event::EndpointObservation;
use super::{agent_id_field, approval_id_field, string_field, workload_id_field};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointClockState {
    pub captured_at: DateTime<Utc>,
    pub source: String,
    pub synchronized: Option<bool>,
    pub uncertainty_ms: Option<u64>,
}

impl Default for EndpointClockState {
    fn default() -> Self {
        Self {
            captured_at: Utc::now(),
            source: "system".to_string(),
            synchronized: None,
            uncertainty_ms: None,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointDecisionActor {
    pub endpoint_id: String,
    pub host_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub posture: Option<String>,
    pub agent_id: Option<String>,
    pub workload_id: Option<String>,
    pub approval_id: Option<String>,
}

impl EndpointDecisionActor {
    #[must_use]
    pub fn from_observation(
        endpoint_id: impl Into<String>,
        observation: &EndpointObservation,
    ) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            host_id: observation.host_id.clone(),
            user_id: observation.user_id.clone(),
            session_id: observation.session_id.clone(),
            posture: string_field(
                &observation.metadata,
                &["posture", "postureState", "posture_state"],
            ),
            agent_id: agent_id_field(&observation.metadata),
            workload_id: workload_id_field(&observation.metadata),
            approval_id: approval_id_field(&observation.metadata),
        }
    }

    #[must_use]
    pub fn with_endpoint_id(endpoint_id: impl Into<String>) -> Self {
        Self {
            endpoint_id: endpoint_id.into(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn with_endpoint_id_if_missing(mut self, endpoint_id: impl Into<String>) -> Self {
        if self.endpoint_id.trim().is_empty() {
            self.endpoint_id = endpoint_id.into();
        }
        self
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointPolicySnapshot {
    pub policy_version: String,
    pub policy_hash: String,
    pub policy_epoch: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointReceiptSigner {
    pub signer_identity: String,
    pub signer_public_key: Option<String>,
}

