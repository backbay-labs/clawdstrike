use super::*;

pub(crate) fn receipt_family_allows_multiple_archive_members(family: &str) -> bool {
    family == "response_execution"
}

pub(crate) fn push_archive_receipt_evidence_hash_failure(
    receipt_failures: &mut Vec<String>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    key: &str,
    raw_value: &str,
    failure_key: &str,
) {
    let expected_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
    match receipt_evidence_hash_value(receipt, key) {
        Some(actual) if actual == expected_hash => {}
        Some(actual) => {
            receipt_failures.push(format!("{receipt_label}:{failure_key}_mismatch:{actual}"));
        }
        None => receipt_failures.push(format!("{receipt_label}:missing_{failure_key}")),
    }
}

pub(crate) fn push_archive_response_actor_failures(
    receipt_failures: &mut Vec<String>,
    response_actor_hashes: &mut Vec<(String, String)>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    receipt_family: &str,
    required_hash_keys: &[&str],
) -> Result<()> {
    let actor = match receipt_endpoint_decision_actor(receipt) {
        Ok(actor) => actor,
        Err(reason) => {
            receipt_failures.push(format!("{receipt_label}:actor_decode_failed:{reason}"));
            return Ok(());
        }
    };
    let actor_hash = canonical_json_hash(&actor, "archive response receipt actor")?;
    response_actor_hashes.push((receipt_family.to_string(), actor_hash.clone()));
    for key in required_hash_keys {
        push_archive_receipt_evidence_hash_failure(
            receipt_failures,
            receipt,
            receipt_label,
            key,
            &actor_hash,
            &archive_actor_failure_key(key),
        );
    }
    Ok(())
}

pub(crate) fn push_archive_policy_failures(
    receipt_failures: &mut Vec<String>,
    policy_hashes: &mut Vec<(String, String)>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    receipt_family: &str,
) -> Result<()> {
    let policy = match receipt_endpoint_decision_policy(receipt) {
        Ok(policy) => policy,
        Err(reason) => {
            receipt_failures.push(format!("{receipt_label}:policy_decode_failed:{reason}"));
            return Ok(());
        }
    };
    if policy.policy_version.trim().is_empty() {
        receipt_failures.push(format!("{receipt_label}:invalid_policy_version"));
    }
    if !policy.policy_hash.starts_with("0x") {
        receipt_failures.push(format!(
            "{receipt_label}:invalid_policy_hash:{}",
            policy.policy_hash
        ));
    }
    if policy.policy_epoch == 0 {
        receipt_failures.push(format!("{receipt_label}:invalid_policy_epoch"));
    }
    let policy_hash = canonical_json_hash(&policy, "archive receipt policy snapshot")?;
    policy_hashes.push((receipt_family.to_string(), policy_hash));
    Ok(())
}

pub(crate) fn push_archive_sensor_state_failures(
    receipt_failures: &mut Vec<String>,
    sensor_provider_sets: &mut Vec<(String, BTreeSet<String>)>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    receipt_family: &str,
) -> Result<()> {
    let sensor_state = match receipt_endpoint_decision_sensor_state(receipt) {
        Ok(sensor_state) => sensor_state,
        Err(reason) => {
            receipt_failures.push(format!(
                "{receipt_label}:sensor_state_decode_failed:{reason}"
            ));
            return Ok(());
        }
    };
    if sensor_state.providers.is_empty() {
        receipt_failures.push(format!("{receipt_label}:sensor_state_missing_providers"));
    }
    let mut providers = BTreeSet::new();
    for provider in &sensor_state.providers {
        if provider.provider_id.trim().is_empty() {
            receipt_failures.push(format!("{receipt_label}:sensor_state_missing_provider_id"));
        } else {
            providers.insert(provider.provider_id.clone());
        }
    }
    sensor_provider_sets.push((receipt_family.to_string(), providers));
    Ok(())
}

pub(crate) fn archive_actor_failure_key(key: &str) -> String {
    let mut failure_key = String::new();
    for (index, ch) in key.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                failure_key.push('_');
            }
            failure_key.push(ch.to_ascii_lowercase());
        } else {
            failure_key.push(ch);
        }
    }
    failure_key
}

pub(crate) fn required_archive_receipt_families(bundle_id: &str) -> Option<Vec<&'static str>> {
    if bundle_id.starts_with("evidence_bundle:") {
        Some(vec![
            "response_request",
            "response_execution",
            "evidence_bundle_manifest",
        ])
    } else if bundle_id.starts_with("evidence_bundle-") {
        Some(vec!["graph_slice"])
    } else {
        None
    }
}

pub(crate) fn evidence_bundle_record(
    stored: StoredEndpointEvidenceBundle,
    now: chrono::DateTime<chrono::Utc>,
    protected_bundle_ids: &BTreeSet<String>,
) -> EdrEvidenceBundleRecord {
    let protected_by_active_response = protected_bundle_ids.contains(&stored.bundle.bundle_id);
    EdrEvidenceBundleRecord {
        age_seconds: evidence_bundle_age_seconds(&stored, now),
        bundle: stored.bundle,
        path: stored.path,
        byte_count: stored.byte_count,
        protected_by_active_response,
    }
}

pub(crate) fn evidence_bundle_age_seconds(
    stored: &StoredEndpointEvidenceBundle,
    now: chrono::DateTime<chrono::Utc>,
) -> u64 {
    now.signed_duration_since(stored.bundle.created_at)
        .num_seconds()
        .max(0) as u64
}

pub(crate) fn append_cross_receipt_continuity_failures(
    receipt_failures: &mut Vec<String>,
    response_actor_hashes: &[(String, String)],
    policy_hashes: &[(String, String)],
    sensor_provider_sets: &[(String, BTreeSet<String>)],
) {
    let distinct_response_actor_hashes = response_actor_hashes
        .iter()
        .map(|(_, actor_hash)| actor_hash)
        .collect::<BTreeSet<_>>();
    if distinct_response_actor_hashes.len() > 1 {
        let actor_families = response_actor_hashes
            .iter()
            .map(|(family, _)| family.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        receipt_failures.push(format!(
            "response_actor_continuity_mismatch:{actor_families}"
        ));
    }
    let distinct_policy_hashes = policy_hashes
        .iter()
        .map(|(_, policy_hash)| policy_hash)
        .collect::<BTreeSet<_>>();
    if distinct_policy_hashes.len() > 1 {
        let policy_families = policy_hashes
            .iter()
            .map(|(family, _)| family.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        receipt_failures.push(format!("policy_continuity_mismatch:{policy_families}"));
    }
    if let Some((_, execution_providers)) = sensor_provider_sets
        .iter()
        .find(|(family, _)| family == "response_execution")
    {
        for (family, providers) in sensor_provider_sets {
            if family != "response_execution" && !providers.is_subset(execution_providers) {
                receipt_failures.push(format!("sensor_state_continuity_mismatch:{family}"));
            }
        }
    }
}
