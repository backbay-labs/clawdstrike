use super::super::*;

pub(crate) fn provider_degradation_id_from_provider(
    endpoint_id: &str,
    policy_hash: &str,
    provider: &EndpointProviderState,
) -> String {
    let provider_kind = camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str());
    let reasons = provider.degradation_reasons.join("|");
    let dropped_event_count = provider.dropped_event_count.to_string();
    let deadline_miss_count = provider.deadline_miss_count.to_string();
    let full_disk_access =
        endpoint_provider_full_disk_access_evidence_value(provider.full_disk_access);
    let provider_id_hash = sha256(provider.provider_id.as_bytes()).to_hex_prefixed();
    let provider_kind_hash = sha256(provider_kind.as_bytes()).to_hex_prefixed();
    let installed_hash = sha256(provider.installed.to_string().as_bytes()).to_hex_prefixed();
    let active_hash = sha256(provider.active.to_string().as_bytes()).to_hex_prefixed();
    let healthy_hash = sha256(provider.healthy.to_string().as_bytes()).to_hex_prefixed();
    let degraded_hash = sha256(provider.degraded.to_string().as_bytes()).to_hex_prefixed();
    let reasons_hash = sha256(reasons.as_bytes()).to_hex_prefixed();
    let dropped_event_count_hash = sha256(dropped_event_count.as_bytes()).to_hex_prefixed();
    let deadline_miss_count_hash = sha256(deadline_miss_count.as_bytes()).to_hex_prefixed();
    let full_disk_access_hash = sha256(full_disk_access.as_bytes()).to_hex_prefixed();
    provider_degradation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        [
            provider_id_hash.as_str(),
            provider_kind_hash.as_str(),
            installed_hash.as_str(),
            active_hash.as_str(),
            healthy_hash.as_str(),
            degraded_hash.as_str(),
            reasons_hash.as_str(),
            dropped_event_count_hash.as_str(),
            deadline_miss_count_hash.as_str(),
            full_disk_access_hash.as_str(),
        ],
    )
}

pub(crate) fn provider_degradation_id_from_evidence(
    evidence: &[EndpointReceiptEvidence],
    endpoint_id: &str,
    policy_hash: &str,
) -> Result<String> {
    Ok(provider_degradation_id_from_evidence_hashes(
        endpoint_id,
        policy_hash,
        [
            evidence_value_hash(
                evidence,
                "providerId",
                "provider degradation provider id evidence",
            )?,
            evidence_value_hash(
                evidence,
                "providerKind",
                "provider degradation provider kind evidence",
            )?,
            evidence_value_hash(
                evidence,
                "installed",
                "provider degradation installed evidence",
            )?,
            evidence_value_hash(evidence, "active", "provider degradation active evidence")?,
            evidence_value_hash(evidence, "healthy", "provider degradation healthy evidence")?,
            evidence_value_hash(
                evidence,
                "degraded",
                "provider degradation degraded evidence",
            )?,
            evidence_value_hash(
                evidence,
                "degradationReasons",
                "provider degradation reasons evidence",
            )?,
            evidence_value_hash(
                evidence,
                "droppedEventCount",
                "provider degradation dropped-event count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "deadlineMissCount",
                "provider degradation deadline-miss count evidence",
            )?,
            evidence_value_hash(
                evidence,
                "fullDiskAccess",
                "provider degradation full-disk-access evidence",
            )?,
        ],
    ))
}

pub(crate) fn provider_degradation_id_from_evidence_hashes(
    endpoint_id: &str,
    policy_hash: &str,
    evidence_hashes: [&str; 10],
) -> String {
    stable_id(
        "provider_degradation",
        [
            endpoint_id,
            policy_hash,
            evidence_hashes[0],
            evidence_hashes[1],
            evidence_hashes[2],
            evidence_hashes[3],
            evidence_hashes[4],
            evidence_hashes[5],
            evidence_hashes[6],
            evidence_hashes[7],
            evidence_hashes[8],
            evidence_hashes[9],
        ],
    )
}

pub(crate) fn endpoint_provider_full_disk_access_evidence_value(
    value: Option<bool>,
) -> &'static str {
    match value {
        Some(true) => "true",
        Some(false) => "false",
        None => "unknown",
    }
}

pub(crate) fn require_provider_degradation_evidence(
    evidence: &[EndpointReceiptEvidence],
    signed_degradation_id: Option<&str>,
    rule_id: Option<&str>,
    actor: &EndpointDecisionActor,
    policy: &EndpointPolicySnapshot,
    sensor_state: &EndpointSensorState,
) -> Result<()> {
    let signed_degradation_id = signed_degradation_id
        .ok_or_else(|| anyhow!("provider degradation signed id is required"))?;
    let rule_id = rule_id.ok_or_else(|| anyhow!("provider degradation rule id is required"))?;
    let provider_id = rule_id
        .strip_prefix("endpoint.provider_degradation.")
        .ok_or_else(|| anyhow!("provider degradation rule id must include provider id"))?;
    let provider = sensor_state
        .providers
        .iter()
        .find(|provider| provider.provider_id == provider_id)
        .ok_or_else(|| {
            anyhow!("provider degradation provider id is not present in sensor state")
        })?;
    let provider_kind = camel_debug_to_snake(format!("{:?}", provider.provider_kind).as_str());
    let reasons = provider.degradation_reasons.join("|");

    require_evidence_value_hash(
        evidence,
        "providerId",
        provider.provider_id.as_str(),
        "provider degradation provider id evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "providerKind",
        provider_kind.as_str(),
        "provider degradation provider kind evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "installed",
        provider.installed.to_string(),
        "provider degradation installed evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "active",
        provider.active.to_string(),
        "provider degradation active evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "healthy",
        provider.healthy.to_string(),
        "provider degradation healthy evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "degraded",
        provider.degraded.to_string(),
        "provider degradation degraded evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "degradationReasons",
        reasons,
        "provider degradation reasons evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "droppedEventCount",
        provider.dropped_event_count.to_string(),
        "provider degradation dropped-event count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "deadlineMissCount",
        provider.deadline_miss_count.to_string(),
        "provider degradation deadline-miss count evidence",
    )?;
    require_evidence_value_hash(
        evidence,
        "fullDiskAccess",
        endpoint_provider_full_disk_access_evidence_value(provider.full_disk_access),
        "provider degradation full-disk-access evidence",
    )?;
    let expected_degradation_id = provider_degradation_id_from_evidence(
        evidence,
        actor.endpoint_id.as_str(),
        policy.policy_hash.as_str(),
    )?;
    if signed_degradation_id != expected_degradation_id {
        return Err(anyhow!(
            "provider degradation id must match signed endpoint, policy, provider state, reason, and counter evidence"
        ));
    }
    Ok(())
}

pub(crate) fn require_provider_last_seen_consistency(
    provider: &EndpointProviderState,
    captured_at: &DateTime<Utc>,
) -> Result<()> {
    if (provider.active || provider.healthy) && provider.last_seen.is_none() {
        return Err(anyhow!(
            "sensor provider {} last seen timestamp is required when provider is active or healthy",
            provider.provider_id
        ));
    }
    if let Some(last_seen) = provider.last_seen.as_ref() {
        if last_seen > captured_at {
            return Err(anyhow!(
                "sensor provider {} last seen timestamp is after receipt capture time",
                provider.provider_id
            ));
        }
    }
    Ok(())
}

pub(crate) fn require_provider_degradation_consistency(
    provider: &EndpointProviderState,
) -> Result<()> {
    let has_degradation_signal = !provider.installed
        || !provider.active
        || !provider.healthy
        || provider.dropped_event_count > 0
        || provider.deadline_miss_count > 0
        || provider.full_disk_access == Some(false);

    if has_degradation_signal && !provider.degraded {
        return Err(anyhow!(
            "sensor provider {} must be marked degraded when installed, active, healthy, event-loss, deadline, or full-disk-access evidence indicates degraded protection",
            provider.provider_id
        ));
    }
    Ok(())
}
