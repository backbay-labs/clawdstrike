use super::super::*;

pub(crate) fn require_sensor_state_evidence(
    evidence: &[EndpointReceiptEvidence],
    decision: &EndpointDecisionRecord,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    sensor_state: &EndpointSensorState,
) -> Result<()> {
    let signed_id = decision
        .finding_id
        .as_deref()
        .ok_or_else(|| anyhow!("sensor state signed id is required"))?;
    let rule_id = decision
        .rule_id
        .as_deref()
        .ok_or_else(|| anyhow!("sensor state rule id is required"))?;
    if rule_id != "endpoint.sensor_state" {
        return Err(anyhow!("sensor state rule id is invalid"));
    }

    let provider_count = sensor_state.providers.len();
    let active_provider_count = sensor_state
        .providers
        .iter()
        .filter(|provider| provider.active)
        .count();
    let healthy_provider_count = sensor_state
        .providers
        .iter()
        .filter(|provider| provider.healthy)
        .count();
    let degraded_provider_count = sensor_state
        .providers
        .iter()
        .filter(|provider| provider.degraded)
        .count();
    let provider_ids = sensor_state
        .providers
        .iter()
        .map(|provider| provider.provider_id.as_str())
        .collect::<Vec<_>>()
        .join(",");
    let provider_count_text = provider_count.to_string();
    let active_count_text = active_provider_count.to_string();
    let healthy_count_text = healthy_provider_count.to_string();
    let degraded_count_text = degraded_provider_count.to_string();
    let sensor_state_hash = endpoint_sensor_state_content_hash(sensor_state);
    let policy_epoch = policy.policy_epoch.to_string();
    let expected_sensor_state_id = stable_id(
        "sensor_state",
        [
            actor.endpoint_id.as_str(),
            policy.policy_hash.as_str(),
            policy_epoch.as_str(),
            provider_count_text.as_str(),
            active_count_text.as_str(),
            healthy_count_text.as_str(),
            degraded_count_text.as_str(),
            provider_ids.as_str(),
            sensor_state_hash.as_str(),
        ],
    );
    if signed_id != expected_sensor_state_id {
        return Err(anyhow!(
            "sensor state id must match endpoint, policy, provider counts, degraded count, provider ids, and sensor state hash"
        ));
    }
    let expected_passed = provider_count > 0 && healthy_provider_count == provider_count;
    if decision.passed != expected_passed {
        return Err(anyhow!(
            "sensor state passed flag must match provider health"
        ));
    }

    require_nonempty_hashed_evidence(evidence, "reason", "sensor state reason evidence")?;
    require_evidence_value_hash(
        evidence,
        "providerCount",
        provider_count.to_string(),
        "sensor state provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "activeProviderCount",
        active_count_text,
        "sensor state active-provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "healthyProviderCount",
        healthy_count_text,
        "sensor state healthy-provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "degradedProviderCount",
        degraded_provider_count.to_string(),
        "sensor state degraded-provider count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "providerIds",
        provider_ids,
        "sensor state provider ids evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "sensorStateHash",
        sensor_state_hash,
        "sensor state content hash evidence",
    )
}
