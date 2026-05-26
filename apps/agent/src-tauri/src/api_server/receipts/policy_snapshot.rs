//! Endpoint policy snapshot construction and YAML field extraction.
//!
//! Builds the `EndpointPolicySnapshot` (version, content hash, epoch)
//! used to bind receipts to the policy under which they were produced.

use super::super::*;

const EDR_POLICY_EPOCH_YAML_PATHS: &[&[&str]] = &[
    &["policy_epoch"],
    &["policyEpoch"],
    &["epoch"],
    &["policy", "epoch"],
    &["policy", "policy_epoch"],
    &["policy", "policyEpoch"],
    &["metadata", "policy_epoch"],
    &["metadata", "policyEpoch"],
    &["bundle", "epoch"],
    &["bundle", "policy_epoch"],
    &["bundle", "policyEpoch"],
];

pub(crate) fn endpoint_policy_snapshot_from_settings(
    settings: &Settings,
) -> Result<EndpointPolicySnapshot> {
    let bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for endpoint receipt {}",
            settings.policy_path.display()
        )
    })?;
    endpoint_policy_snapshot_from_policy_bytes(&bytes, &settings.policy_path)
}

pub(crate) fn endpoint_policy_snapshot_from_policy_bytes(
    bytes: &[u8],
    policy_path: &FsPath,
) -> Result<EndpointPolicySnapshot> {
    let policy_hash = sha256(bytes).to_hex_prefixed();
    let policy_version =
        policy_version_from_yaml(bytes).unwrap_or_else(|| format!("local-policy:{policy_hash}"));
    let policy_epoch = policy_epoch_from_yaml(bytes)
        .or_else(|| policy_epoch_from_file(policy_path))
        .unwrap_or(1)
        .max(1);
    Ok(EndpointPolicySnapshot {
        policy_version,
        policy_hash,
        policy_epoch,
    })
}

pub(crate) fn endpoint_policy_snapshot_from_memory_policy_bytes(
    bytes: &[u8],
) -> Result<EndpointPolicySnapshot> {
    let policy_hash = sha256(bytes).to_hex_prefixed();
    let policy_version =
        policy_version_from_yaml(bytes).unwrap_or_else(|| format!("local-policy:{policy_hash}"));
    let policy_epoch = policy_epoch_from_yaml(bytes).ok_or_else(|| {
        anyhow::anyhow!("proposedPolicyYaml must declare a positive policy_epoch")
    })?;
    Ok(EndpointPolicySnapshot {
        policy_version,
        policy_hash,
        policy_epoch,
    })
}

pub(crate) fn policy_version_from_yaml(bytes: &[u8]) -> Option<String> {
    let value = serde_yaml::from_slice::<serde_yaml::Value>(bytes).ok()?;
    value
        .get("version")
        .and_then(serde_yaml::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn policy_epoch_from_yaml(bytes: &[u8]) -> Option<u64> {
    let value = serde_yaml::from_slice::<serde_yaml::Value>(bytes).ok()?;
    EDR_POLICY_EPOCH_YAML_PATHS
        .iter()
        .filter_map(|path| yaml_u64_at_path(&value, path))
        .find(|epoch| *epoch > 0)
}

pub(crate) fn yaml_u64_at_path(value: &serde_yaml::Value, path: &[&str]) -> Option<u64> {
    let mut current = value;
    for segment in path {
        current = current.get(*segment)?;
    }
    yaml_u64_value(current)
}

pub(crate) fn yaml_u64_value(value: &serde_yaml::Value) -> Option<u64> {
    match value {
        serde_yaml::Value::Number(value) => value.as_u64(),
        serde_yaml::Value::String(value) => value.trim().parse::<u64>().ok(),
        _ => None,
    }
}

pub(crate) fn policy_epoch_from_file(path: &FsPath) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let since_epoch = modified.duration_since(std::time::UNIX_EPOCH).ok()?;
    Some(since_epoch.as_secs())
}
