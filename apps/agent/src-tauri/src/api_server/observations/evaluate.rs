use super::*;

pub(crate) fn developer_activity_file_operation(
    activity: &EdrDeveloperActivity,
    fallback: FileOperation,
) -> FileOperation {
    match activity
        .operation
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("read" | "open" | "file_read") => FileOperation::Read,
        Some("write" | "file_write") => FileOperation::Write,
        Some("create") => FileOperation::Create,
        Some("delete" | "unlink") => FileOperation::Delete,
        Some("rename" | "move") => FileOperation::Rename,
        Some("execute" | "exec") => FileOperation::Execute,
        Some("chmod") => FileOperation::Chmod,
        Some(_) | None => fallback,
    }
}

pub(crate) fn file_operation_name(operation: &FileOperation) -> &'static str {
    match operation {
        FileOperation::Read => "read",
        FileOperation::Write => "write",
        FileOperation::Create => "create",
        FileOperation::Delete => "delete",
        FileOperation::Rename => "rename",
        FileOperation::Execute => "execute",
        FileOperation::Chmod => "chmod",
        FileOperation::Unknown => "unknown",
    }
}

pub(crate) fn developer_activity_parameters(activity: &EdrDeveloperActivity) -> serde_json::Value {
    let mut parameters = activity.parameters.clone().unwrap_or_else(|| {
        serde_json::Value::Object(serde_json::Map::<String, serde_json::Value>::new())
    });
    if let serde_json::Value::Object(object) = &mut parameters {
        for (key, value) in [
            ("action", activity.action.as_deref()),
            ("target", activity.target.as_deref()),
            ("browser", activity.browser.as_deref()),
            ("path", activity.path.as_deref()),
            ("sourceUrl", activity.source_url.as_deref()),
            ("query", activity.query.as_deref()),
            ("recordType", activity.record_type.as_deref()),
            ("resolver", activity.resolver.as_deref()),
            ("status", activity.status.as_deref()),
        ] {
            if let Some(value) = trimmed_owned(value) {
                object
                    .entry(key.to_string())
                    .or_insert(serde_json::Value::String(value));
            }
        }
        if !activity.answers.is_empty() {
            let answers = activity
                .answers
                .iter()
                .filter_map(|answer| trimmed_owned(Some(answer.as_str())))
                .map(serde_json::Value::String)
                .collect::<Vec<_>>();
            if !answers.is_empty() {
                object
                    .entry("answers".to_string())
                    .or_insert(serde_json::Value::Array(answers));
            }
        }
    }
    parameters
}

pub(crate) fn developer_activity_stable_id(
    activity: &EdrDeveloperActivity,
    index: usize,
) -> String {
    let index = index.to_string();
    let primary = activity
        .path
        .as_deref()
        .or(activity.name.as_deref())
        .or(activity.query.as_deref())
        .or(activity.host.as_deref())
        .or(activity.url.as_deref())
        .or(activity.target.as_deref())
        .or(activity.tool_name.as_deref())
        .or(activity.operation.as_deref())
        .or(activity.script.as_deref())
        .unwrap_or_default();
    local_stable_id(
        "devact",
        [
            activity.kind.as_str(),
            activity.session_id.as_deref().unwrap_or_default(),
            activity.agent_id.as_deref().unwrap_or_default(),
            primary,
            index.as_str(),
        ],
    )
}

pub(crate) fn required_activity_string(
    activity: &EdrDeveloperActivity,
    field: &str,
    value: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    trimmed_owned(value).ok_or_else(|| {
        bad_activity_request(
            activity,
            &format!("{field} is required for {}", activity.kind.as_str()),
        )
    })
}

pub(crate) fn trimmed_owned(value: Option<&str>) -> Option<String> {
    non_empty(value).map(ToString::to_string)
}

pub(crate) fn bad_activity_request(
    activity: &EdrDeveloperActivity,
    message: &str,
) -> (StatusCode, String) {
    (
        StatusCode::BAD_REQUEST,
        format!(
            "invalid {} developer activity: {message}",
            activity.kind.as_str()
        ),
    )
}

pub(crate) async fn evaluate_record_and_receipt_edr_observations(
    state: &AgentApiState,
    detection_observations: &[EndpointObservation],
    recorded_observations: &[EndpointObservation],
    submitted_honey_artifacts: Vec<HoneyArtifact>,
) -> Result<EdrEvaluatedFindings, (StatusCode, String)> {
    validate_edr_request_sizes(recorded_observations.len(), submitted_honey_artifacts.len())?;
    if detection_observations.len() != recorded_observations.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            "detection and recording observation counts must match".to_string(),
        ));
    }

    let honey_artifacts = state
        .edr_honey_registry
        .lock()
        .await
        .load()
        .map_err(internal_error)?;
    require_submitted_honey_artifacts_registered(&submitted_honey_artifacts, &honey_artifacts)?;
    validate_edr_request_sizes(recorded_observations.len(), honey_artifacts.len())?;

    let guard = SupplyChainRuntimeGuard::with_honey_artifacts(honey_artifacts);
    let mut findings = Vec::new();
    for (detection_observation, recorded_observation) in
        detection_observations.iter().zip(recorded_observations)
    {
        findings.extend(guard.evaluate(recorded_observation));

        for finding in guard
            .evaluate(detection_observation)
            .into_iter()
            .filter(is_local_only_honey_marker_finding)
        {
            if !findings
                .iter()
                .any(|existing| existing.finding_id == finding.finding_id)
            {
                findings.push(finding);
            }
        }
    }
    record_edr_observations(state, recorded_observations).await?;
    let graph = state.edr_flight_recorder.lock().await.graph().clone();
    let receipts = emit_edr_detection_receipts(state, recorded_observations, &findings, &graph)
        .await
        .map_err(internal_error)?;
    append_recent_edr_findings(state, &findings).await;
    publish_current_agent_secret_touches_to_fleet_best_effort(state, recorded_observations).await;

    Ok(EdrEvaluatedFindings { findings, receipts })
}

fn require_submitted_honey_artifacts_registered(
    submitted_honey_artifacts: &[HoneyArtifact],
    registered_honey_artifacts: &[HoneyArtifact],
) -> Result<(), (StatusCode, String)> {
    for submitted in submitted_honey_artifacts {
        let Some(registered) = registered_honey_artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == submitted.artifact_id)
        else {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "submitted honey artifact {} is not a registered honey artifact",
                    submitted.artifact_id
                ),
            ));
        };

        if registered != submitted {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "submitted honey artifact {} does not match the registered honey artifact",
                    submitted.artifact_id
                ),
            ));
        }
    }
    Ok(())
}

fn is_local_only_honey_marker_finding(finding: &DetectionFinding) -> bool {
    finding.rule_id == "deception.honey_artifact_touched"
        && finding
            .evidence
            .iter()
            .any(|item| item.key == "matchType" && item.value == "marker")
}
