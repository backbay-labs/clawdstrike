//! Recent EDR findings ring buffer and EDR request-size validators.

use super::super::*;
use axum::http::StatusCode;

pub(crate) async fn append_recent_edr_findings(
    state: &AgentApiState,
    findings: &[clawdstrike_policy_event::edr::DetectionFinding],
) {
    let mut recent = state.edr_recent_findings.lock().await;
    for finding in findings {
        recent.push_back(finding.clone());
    }
    while recent.len() > EDR_MAX_STORED_FINDINGS {
        let _ = recent.pop_front();
    }
}

pub(crate) fn validate_edr_request_sizes(
    observation_count: usize,
    honey_artifact_count: usize,
) -> Result<(), (StatusCode, String)> {
    if observation_count > EDR_MAX_OBSERVATIONS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "too many observations: max {}",
                EDR_MAX_OBSERVATIONS_PER_REQUEST
            ),
        ));
    }
    if honey_artifact_count > EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "too many honey artifacts: max {}",
                EDR_MAX_HONEY_ARTIFACTS_PER_REQUEST
            ),
        ));
    }
    Ok(())
}
