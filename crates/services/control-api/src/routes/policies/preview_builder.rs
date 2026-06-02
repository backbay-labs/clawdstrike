//! Proposal preview, fleet-history, and rule-diff validation-plan builders.

use super::*;

pub(crate) fn active_policy_candidate_from_base(
    tenant_id: Uuid,
    tenant_slug: &str,
    policy_yaml: &str,
    description: Option<&str>,
    base_policy_version: i64,
) -> Result<policy_distribution::ActiveTenantPolicy, ApiError> {
    let version = base_policy_version.checked_add(1).ok_or_else(|| {
        ApiError::Internal(format!(
            "active policy version {base_policy_version} cannot be incremented"
        ))
    })?;
    Ok(policy_distribution::ActiveTenantPolicy {
        tenant_id,
        tenant_slug: tenant_slug.to_string(),
        policy_yaml: policy_yaml.to_string(),
        checksum_sha256: policy_distribution::policy_yaml_checksum_sha256(policy_yaml),
        description: description.map(str::to_string),
        version,
        updated_at: Utc::now(),
    })
}

pub(crate) async fn build_policy_proposal_preview(
    db: &PgPool,
    tenant_id: Uuid,
    candidate: &policy_distribution::ActiveTenantPolicy,
    active_policy: Option<&policy_distribution::ActiveTenantPolicy>,
) -> Result<serde_json::Value, ApiError> {
    let distribution_policy_yaml =
        policy_distribution::distribution_policy_yaml(candidate).map_err(ApiError::Internal)?;
    let distribution_policy_sha256 =
        policy_distribution::policy_yaml_checksum_sha256(&distribution_policy_yaml);
    let proposed_value = serde_yaml::from_str::<serde_yaml::Value>(&candidate.policy_yaml)
        .map_err(|err| {
            ApiError::Internal(format!("proposal candidate policy is invalid YAML: {err}"))
        })?;
    let base_value = match active_policy {
        Some(policy) => Some(
            serde_yaml::from_str::<serde_yaml::Value>(&policy.policy_yaml).map_err(|err| {
                ApiError::Internal(format!("active tenant policy is invalid YAML: {err}"))
            })?,
        ),
        None => None,
    };
    let change_summary = top_level_policy_change_summary(base_value.as_ref(), &proposed_value);
    let fleet_history_impact = build_policy_proposal_fleet_history_impact(db, tenant_id).await?;
    let fleet_rule_diff_validation = build_policy_proposal_fleet_rule_diff_validation_plan(
        db,
        tenant_id,
        candidate,
        active_policy,
    )
    .await?;
    let simulation_status = fleet_history_impact
        .get("status")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown");

    Ok(serde_json::json!({
        "baseActivePolicyVersion": active_policy.map(|policy| policy.version).unwrap_or(0),
        "basePolicySha256": active_policy.map(|policy| policy.checksum_sha256.as_str()),
        "proposedPolicyVersion": candidate.version,
        "proposedPolicySha256": candidate.checksum_sha256,
        "distributionPolicySha256": distribution_policy_sha256,
        "distributionPolicyEpoch": candidate.version,
        "topLevelChanges": change_summary,
        "simulationStatus": simulation_status,
        "simulationReason": "control-plane estimate from recent fleet hunt history; exact endpoint policy-event replay receipts are still required for rule-diff proof",
        "fleetHistoryImpact": fleet_history_impact,
        "fleetRuleDiffValidation": fleet_rule_diff_validation
    }))
}

pub(crate) async fn build_policy_proposal_fleet_history_impact(
    db: &PgPool,
    tenant_id: Uuid,
) -> Result<serde_json::Value, ApiError> {
    let since = Utc::now() - chrono::Duration::hours(POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS);
    let rows = sqlx::query::query(
        r#"SELECT verdict,
                  action_type,
                  endpoint_agent_id,
                  runtime_agent_id,
                  principal_id,
                  session_id,
                  detection_ids
           FROM hunt_events
           WHERE tenant_id = $1
             AND timestamp >= $2
           ORDER BY timestamp DESC, event_id DESC
           LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(since)
    .bind(POLICY_PROPOSAL_HISTORY_LIMIT)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let mut verdict_counts = BTreeMap::<String, i64>::new();
    let mut action_type_counts = BTreeMap::<String, i64>::new();
    let mut detection_counts = BTreeMap::<String, i64>::new();
    let mut affected_identities = BTreeSet::<String>::new();
    let mut affected_tools = BTreeSet::<String>::new();
    let mut affected_endpoints = BTreeSet::<String>::new();
    let mut candidate_breakage_count = 0_i64;
    let mut blocking_event_count = 0_i64;

    for row in rows {
        let verdict: String = row.try_get("verdict").map_err(ApiError::Database)?;
        let normalized_verdict = normalize_policy_proposal_history_verdict(&verdict);
        *verdict_counts
            .entry(normalized_verdict.to_string())
            .or_insert(0) += 1;
        match normalized_verdict {
            "allow" | "warn" => candidate_breakage_count += 1,
            "block" => blocking_event_count += 1,
            _ => {}
        }

        let action_type = row
            .try_get::<Option<String>, _>("action_type")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "unknown".to_string());
        *action_type_counts.entry(action_type.clone()).or_insert(0) += 1;
        affected_tools.insert(format!("action:{action_type}"));

        if let Some(endpoint_id) = row
            .try_get::<Option<String>, _>("endpoint_agent_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
        {
            affected_endpoints.insert(endpoint_id);
        }
        if let Some(runtime_id) = row
            .try_get::<Option<String>, _>("runtime_agent_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
        {
            affected_tools.insert(format!("runtime:{runtime_id}"));
        }
        if let Some(principal_id) = row
            .try_get::<Option<String>, _>("principal_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
        {
            affected_identities.insert(format!("principal:{principal_id}"));
        }
        if let Some(session_id) = row
            .try_get::<Option<String>, _>("session_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty())
        {
            affected_identities.insert(format!("session:{session_id}"));
        }

        let detection_ids: Vec<String> =
            row.try_get("detection_ids").map_err(ApiError::Database)?;
        for detection_id in detection_ids
            .into_iter()
            .filter(|value| !value.trim().is_empty())
        {
            *detection_counts.entry(detection_id).or_insert(0) += 1;
        }
    }

    let events_sampled = verdict_counts.values().sum::<i64>();
    let status = if events_sampled == 0 {
        "no_fleet_history"
    } else {
        "estimated_from_fleet_history"
    };
    let developer_breakage_score = if events_sampled == 0 {
        0
    } else {
        ((candidate_breakage_count * 100) / events_sampled).clamp(0, 100)
    };
    let recommendation = if events_sampled == 0 {
        "collect_history"
    } else if candidate_breakage_count == 0 {
        "approve_with_observation"
    } else if developer_breakage_score >= 50 {
        "simulate_on_endpoints"
    } else {
        "stage_with_audit"
    };

    let mut impact = serde_json::json!({
        "schemaVersion": 1,
        "source": "control_api_hunt_events",
        "status": status,
        "lookbackHours": POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS,
        "selectionLimit": POLICY_PROPOSAL_HISTORY_LIMIT,
        "eventsSampled": events_sampled,
        "candidateBreakageCount": candidate_breakage_count,
        "blockingEventCount": blocking_event_count,
        "developerBreakageScore": developer_breakage_score,
        "affectedIdentityCount": affected_identities.len(),
        "affectedToolCount": affected_tools.len(),
        "affectedEndpointCount": affected_endpoints.len(),
        "verdictCounts": verdict_counts,
        "topActionTypes": top_policy_proposal_history_counts(&action_type_counts, 5),
        "topDetectionIds": top_policy_proposal_history_counts(&detection_counts, 5),
        "recommendation": recommendation,
        "limitations": "estimated from normalized hunt_events only; exact proposal impact still requires endpoint policy-event history replay"
    });
    let hash_input = serde_json::to_string(&impact)
        .map_err(|err| ApiError::Internal(format!("serialize fleet history impact: {err}")))?;
    impact["historySha256"] = serde_json::Value::String(
        policy_distribution::policy_yaml_checksum_sha256(&hash_input),
    );

    Ok(impact)
}

pub(crate) struct PolicyProposalFleetRuleDiffEndpointSelection {
    pub(crate) endpoint_agent_id: String,
    pub(crate) event_count: i64,
    pub(crate) candidate_breakage_count: i64,
    pub(crate) blocking_event_count: i64,
    pub(crate) first_seen: DateTime<Utc>,
    pub(crate) last_seen: DateTime<Utc>,
    pub(crate) event_ids: Vec<String>,
    pub(crate) action_type_counts: BTreeMap<String, i64>,
    pub(crate) detection_counts: BTreeMap<String, i64>,
    pub(crate) principal_ids: BTreeSet<String>,
    pub(crate) runtime_agent_ids: BTreeSet<String>,
    pub(crate) session_ids: BTreeSet<String>,
}

pub(crate) struct PolicyProposalFleetRuleDiffObservation {
    pub(crate) event_id: String,
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) verdict: String,
    pub(crate) action_type: Option<String>,
    pub(crate) runtime_agent_id: Option<String>,
    pub(crate) principal_id: Option<String>,
    pub(crate) session_id: Option<String>,
    pub(crate) detection_ids: Vec<String>,
}

impl PolicyProposalFleetRuleDiffEndpointSelection {
    fn new(endpoint_agent_id: String, timestamp: DateTime<Utc>) -> Self {
        Self {
            endpoint_agent_id,
            event_count: 0,
            candidate_breakage_count: 0,
            blocking_event_count: 0,
            first_seen: timestamp,
            last_seen: timestamp,
            event_ids: Vec::new(),
            action_type_counts: BTreeMap::new(),
            detection_counts: BTreeMap::new(),
            principal_ids: BTreeSet::new(),
            runtime_agent_ids: BTreeSet::new(),
            session_ids: BTreeSet::new(),
        }
    }

    fn observe(&mut self, observation: PolicyProposalFleetRuleDiffObservation) {
        self.event_count += 1;
        if observation.timestamp < self.first_seen {
            self.first_seen = observation.timestamp;
        }
        if observation.timestamp > self.last_seen {
            self.last_seen = observation.timestamp;
        }
        if self.event_ids.len() < POLICY_PROPOSAL_FLEET_VALIDATION_EVENT_ID_LIMIT {
            self.event_ids.push(observation.event_id);
        }

        match normalize_policy_proposal_history_verdict(&observation.verdict) {
            "allow" | "warn" => self.candidate_breakage_count += 1,
            "block" => self.blocking_event_count += 1,
            _ => {}
        }

        if let Some(action_type) = observation
            .action_type
            .filter(|value| !value.trim().is_empty())
        {
            *self.action_type_counts.entry(action_type).or_insert(0) += 1;
        }
        if let Some(runtime_agent_id) = observation
            .runtime_agent_id
            .filter(|value| !value.trim().is_empty())
        {
            self.runtime_agent_ids.insert(runtime_agent_id);
        }
        if let Some(principal_id) = observation
            .principal_id
            .filter(|value| !value.trim().is_empty())
        {
            self.principal_ids.insert(principal_id);
        }
        if let Some(session_id) = observation
            .session_id
            .filter(|value| !value.trim().is_empty())
        {
            self.session_ids.insert(session_id);
        }
        for detection_id in observation
            .detection_ids
            .into_iter()
            .filter(|value| !value.trim().is_empty())
        {
            *self.detection_counts.entry(detection_id).or_insert(0) += 1;
        }
    }
}

pub(crate) async fn build_policy_proposal_fleet_rule_diff_validation_plan(
    db: &PgPool,
    tenant_id: Uuid,
    candidate: &policy_distribution::ActiveTenantPolicy,
    active_policy: Option<&policy_distribution::ActiveTenantPolicy>,
) -> Result<serde_json::Value, ApiError> {
    let since = Utc::now() - chrono::Duration::hours(POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS);
    let rows = sqlx::query::query(
        r#"SELECT event_id,
                  timestamp,
                  verdict,
                  action_type,
                  endpoint_agent_id,
                  runtime_agent_id,
                  principal_id,
                  session_id,
                  detection_ids
           FROM hunt_events
           WHERE tenant_id = $1
             AND timestamp >= $2
             AND endpoint_agent_id IS NOT NULL
           ORDER BY timestamp DESC, event_id DESC
           LIMIT $3"#,
    )
    .bind(tenant_id)
    .bind(since)
    .bind(POLICY_PROPOSAL_HISTORY_LIMIT)
    .fetch_all(db)
    .await
    .map_err(ApiError::Database)?;

    let mut endpoints = BTreeMap::<String, PolicyProposalFleetRuleDiffEndpointSelection>::new();
    for row in rows {
        let endpoint_agent_id = row
            .try_get::<Option<String>, _>("endpoint_agent_id")
            .map_err(ApiError::Database)?
            .filter(|value| !value.trim().is_empty());
        let Some(endpoint_agent_id) = endpoint_agent_id else {
            continue;
        };
        let timestamp: DateTime<Utc> = row.try_get("timestamp").map_err(ApiError::Database)?;
        let event_id: String = row.try_get("event_id").map_err(ApiError::Database)?;
        let verdict: String = row.try_get("verdict").map_err(ApiError::Database)?;
        let action_type = row
            .try_get::<Option<String>, _>("action_type")
            .map_err(ApiError::Database)?;
        let runtime_agent_id = row
            .try_get::<Option<String>, _>("runtime_agent_id")
            .map_err(ApiError::Database)?;
        let principal_id = row
            .try_get::<Option<String>, _>("principal_id")
            .map_err(ApiError::Database)?;
        let session_id = row
            .try_get::<Option<String>, _>("session_id")
            .map_err(ApiError::Database)?;
        let detection_ids: Vec<String> =
            row.try_get("detection_ids").map_err(ApiError::Database)?;
        endpoints
            .entry(endpoint_agent_id.clone())
            .or_insert_with(|| {
                PolicyProposalFleetRuleDiffEndpointSelection::new(
                    endpoint_agent_id.clone(),
                    timestamp,
                )
            })
            .observe(PolicyProposalFleetRuleDiffObservation {
                event_id,
                timestamp,
                verdict,
                action_type,
                runtime_agent_id,
                principal_id,
                session_id,
                detection_ids,
            });
    }

    let mut endpoint_selections = endpoints.into_values().collect::<Vec<_>>();
    endpoint_selections.sort_by(|left, right| {
        right
            .candidate_breakage_count
            .cmp(&left.candidate_breakage_count)
            .then_with(|| right.event_count.cmp(&left.event_count))
            .then_with(|| left.endpoint_agent_id.cmp(&right.endpoint_agent_id))
    });
    endpoint_selections.truncate(POLICY_PROPOSAL_FLEET_VALIDATION_ENDPOINT_LIMIT);

    let endpoint_requests = endpoint_selections
        .iter()
        .map(|selection| {
            serde_json::json!({
                "endpointAgentId": selection.endpoint_agent_id,
                "eventCount": selection.event_count,
                "candidateBreakageCount": selection.candidate_breakage_count,
                "blockingEventCount": selection.blocking_event_count,
                "firstSeen": selection.first_seen,
                "lastSeen": selection.last_seen,
                "sampleEventIds": selection.event_ids,
                "topActionTypes": top_policy_proposal_history_counts(&selection.action_type_counts, 5),
                "topDetectionIds": top_policy_proposal_history_counts(&selection.detection_counts, 5),
                "principalIds": selection.principal_ids,
                "runtimeAgentIds": selection.runtime_agent_ids,
                "sessionIds": selection.session_ids,
                "request": {
                    "method": "POST",
                    "path": "/api/v1/agent/edr/policy-events/impact/history",
                    "body": {
                        "since": selection.first_seen,
                        "until": selection.last_seen,
                        "limit": selection.event_count.min(POLICY_PROPOSAL_HISTORY_LIMIT),
                        "agentId": selection.endpoint_agent_id,
                        "trackPosture": true,
                        "validationWindowSeconds": 3600,
                        "proposedPolicyYaml": candidate.policy_yaml,
                    }
                },
                "expectedReceipt": {
                    "receiptFamily": POLICY_PROPOSAL_SIMULATION_RECEIPT_FAMILY,
                    "ruleId": POLICY_PROPOSAL_SIMULATION_RULE_ID,
                    "graphProcessNodeId": POLICY_PROPOSAL_SIMULATION_PROCESS_NODE_ID,
                    "proposedPolicyHash": candidate.checksum_sha256,
                    "proposedPolicyEpoch": candidate.version,
                    "requiredEvidenceKeys": [
                        "impactId",
                        "eventStreamHash",
                        "currentResultHash",
                        "proposedResultHash",
                        "impactHash",
                        "proposedPolicyHash",
                        "proposedPolicyEpoch",
                        "eventCount",
                        "changedCount",
                        "allowToBlockCount",
                        "trackPosture"
                    ]
                }
            })
        })
        .collect::<Vec<_>>();
    let selected_event_count = endpoint_selections
        .iter()
        .map(|selection| selection.event_count)
        .sum::<i64>();
    let status = if endpoint_requests.is_empty() {
        "no_endpoint_history"
    } else {
        "ready_for_endpoint_receipt_collection"
    };
    let mut plan = serde_json::json!({
        "schemaVersion": 1,
        "source": "control_api_hunt_events",
        "status": status,
        "lookbackHours": POLICY_PROPOSAL_HISTORY_LOOKBACK_HOURS,
        "selectionLimit": POLICY_PROPOSAL_HISTORY_LIMIT,
        "endpointLimit": POLICY_PROPOSAL_FLEET_VALIDATION_ENDPOINT_LIMIT,
        "selectedEndpointCount": endpoint_requests.len(),
        "selectedEventCount": selected_event_count,
        "currentPolicyVersion": active_policy.map(|policy| policy.version).unwrap_or(0),
        "currentPolicySha256": active_policy.map(|policy| policy.checksum_sha256.as_str()),
        "proposedPolicyVersion": candidate.version,
        "proposedPolicySha256": candidate.checksum_sha256,
        "receiptAttachmentField": "simulation_receipts",
        "endpointRequests": endpoint_requests,
        "limitations": "control-plane selection plan only; endpoint agents must execute local history impact replay and return signed receipts"
    });
    let hash_input = serde_json::to_string(&plan)
        .map_err(|err| ApiError::Internal(format!("serialize fleet validation plan: {err}")))?;
    plan["planSha256"] = serde_json::Value::String(
        policy_distribution::policy_yaml_checksum_sha256(&hash_input),
    );
    Ok(plan)
}

pub(crate) fn normalize_policy_proposal_history_verdict(verdict: &str) -> &'static str {
    match verdict.trim().to_ascii_lowercase().as_str() {
        "allow" | "allowed" | "forward" | "forwarded" => "allow",
        "warn" | "warning" => "warn",
        "block" | "blocked" | "deny" | "denied" => "block",
        _ => "other",
    }
}

pub(crate) fn top_policy_proposal_history_counts(
    counts: &BTreeMap<String, i64>,
    limit: usize,
) -> Vec<serde_json::Value> {
    let mut entries = counts.iter().collect::<Vec<_>>();
    entries.sort_by(|(left_key, left_count), (right_key, right_count)| {
        right_count
            .cmp(left_count)
            .then_with(|| left_key.cmp(right_key))
    });
    entries
        .into_iter()
        .take(limit)
        .map(|(value, count)| {
            serde_json::json!({
                "value": value,
                "count": count,
            })
        })
        .collect()
}
