//! Top-level YAML policy-change summarization helpers.

use super::*;

pub(crate) fn top_level_policy_change_summary(
    base_value: Option<&serde_yaml::Value>,
    proposed_value: &serde_yaml::Value,
) -> serde_json::Value {
    let base_keys = yaml_mapping_keys(base_value);
    let proposed_keys = yaml_mapping_keys(Some(proposed_value));

    let added = sorted_difference(&proposed_keys, &base_keys);
    let removed = sorted_difference(&base_keys, &proposed_keys);
    let common = base_keys
        .intersection(&proposed_keys)
        .cloned()
        .collect::<BTreeSet<_>>();
    let changed = common
        .into_iter()
        .filter(|key| {
            yaml_mapping_value(base_value, key) != yaml_mapping_value(Some(proposed_value), key)
        })
        .collect::<Vec<_>>();
    let unchanged_count = proposed_keys
        .iter()
        .filter(|key| {
            base_keys.contains(*key)
                && yaml_mapping_value(base_value, key)
                    == yaml_mapping_value(Some(proposed_value), key)
        })
        .count();

    serde_json::json!({
        "added": added,
        "removed": removed,
        "changed": changed,
        "unchangedCount": unchanged_count,
    })
}

fn yaml_mapping_keys(value: Option<&serde_yaml::Value>) -> BTreeSet<String> {
    let Some(serde_yaml::Value::Mapping(map)) = value else {
        return BTreeSet::new();
    };
    map.keys().map(yaml_key_label).collect()
}

fn yaml_mapping_value<'a>(
    value: Option<&'a serde_yaml::Value>,
    key_label: &str,
) -> Option<&'a serde_yaml::Value> {
    let Some(serde_yaml::Value::Mapping(map)) = value else {
        return None;
    };
    map.iter()
        .find(|(key, _)| yaml_key_label(key) == key_label)
        .map(|(_, value)| value)
}

fn yaml_key_label(key: &serde_yaml::Value) -> String {
    key.as_str()
        .map(str::to_string)
        .unwrap_or_else(|| serde_yaml::to_string(key).unwrap_or_else(|_| format!("{key:?}")))
}

fn sorted_difference(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).cloned().collect()
}
