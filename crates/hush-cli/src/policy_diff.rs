use clawdstrike::{Policy, RuleSet};

use crate::remote_extends::{RemoteExtendsConfig, RemotePolicyResolver};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolvedPolicySource {
    Ruleset { id: String },
    File { path: String },
}

impl ResolvedPolicySource {
    pub fn describe(&self) -> String {
        match self {
            Self::Ruleset { id } => format!("ruleset:clawdstrike:{}", id),
            Self::File { path } => format!("file:{}", path),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LoadedPolicy {
    pub policy: Policy,
    pub source: ResolvedPolicySource,
}

#[derive(Debug)]
pub struct PolicyLoadError {
    pub message: String,
    pub source: clawdstrike::Error,
}

pub fn load_policy_from_arg(
    arg: &str,
    resolve: bool,
    remote_extends: &RemoteExtendsConfig,
) -> Result<LoadedPolicy, PolicyLoadError> {
    let resolver = RemotePolicyResolver::new(remote_extends.clone()).map_err(|e| PolicyLoadError {
        message: format!("Failed to initialize remote extends resolver: {}", e),
        source: e,
    })?;

    match RuleSet::by_name(arg) {
        Ok(Some(rs)) => {
            if !resolve {
                return Ok(LoadedPolicy {
                    policy: rs.policy,
                    source: ResolvedPolicySource::Ruleset { id: rs.id },
                });
            }

            // Resolve `extends` using the same mechanism as file-based policies.
            let yaml = rs.policy.to_yaml().map_err(|e| PolicyLoadError {
                message: format!("Failed to export ruleset as YAML: {}", e),
                source: e,
            })?;

            let policy =
                Policy::from_yaml_with_extends_resolver(&yaml, None, &resolver).map_err(|e| {
                    PolicyLoadError {
                        message: format!("Failed to resolve ruleset extends: {}", e),
                        source: e,
                    }
                })?;

            Ok(LoadedPolicy {
                policy,
                source: ResolvedPolicySource::Ruleset { id: rs.id },
            })
        }
        Ok(None) => {
            let policy = if resolve {
                let path = std::path::Path::new(arg);
                let content = std::fs::read_to_string(path).map_err(|e| PolicyLoadError {
                    message: format!(
                        "{arg:?} is not a known ruleset; failed to read policy file: {}",
                        e
                    ),
                    source: clawdstrike::Error::from(e),
                })?;

                Policy::from_yaml_with_extends_resolver(&content, Some(path), &resolver).map_err(
                    |e| PolicyLoadError {
                        message: format!(
                            "{arg:?} is not a known ruleset; failed to load policy file: {}",
                            e
                        ),
                        source: e,
                    },
                )?
            } else {
                Policy::from_yaml_file(arg).map_err(|e| PolicyLoadError {
                    message: format!(
                        "{arg:?} is not a known ruleset; failed to load policy file: {}",
                        e
                    ),
                    source: e,
                })?
            };

            Ok(LoadedPolicy {
                policy,
                source: ResolvedPolicySource::File {
                    path: arg.to_string(),
                },
            })
        }
        Err(e) => Err(PolicyLoadError {
            message: format!("Failed to load ruleset {arg:?}: {}", e),
            source: e,
        }),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffKind {
    Added,
    Removed,
    Changed,
}

#[derive(Clone, Debug, PartialEq, serde::Serialize)]
pub struct DiffEntry {
    pub path: String,
    pub kind: DiffKind,
    pub old: Option<serde_json::Value>,
    pub new: Option<serde_json::Value>,
}

pub fn diff_values(left: &serde_json::Value, right: &serde_json::Value) -> Vec<DiffEntry> {
    let mut diffs = Vec::new();
    diff_values_inner("", left, right, &mut diffs);
    diffs.sort_by(|a, b| a.path.cmp(&b.path));
    diffs
}

fn diff_values_inner(
    path: &str,
    left: &serde_json::Value,
    right: &serde_json::Value,
    diffs: &mut Vec<DiffEntry>,
) {
    if left == right {
        return;
    }

    match (left, right) {
        (serde_json::Value::Object(left_obj), serde_json::Value::Object(right_obj)) => {
            let mut keys = std::collections::BTreeSet::new();
            keys.extend(left_obj.keys());
            keys.extend(right_obj.keys());

            for key in keys {
                let next_path = format!("{}/{}", path, escape_pointer_segment(key));

                match (left_obj.get(key), right_obj.get(key)) {
                    (Some(lv), Some(rv)) => diff_values_inner(&next_path, lv, rv, diffs),
                    (Some(lv), None) => diffs.push(DiffEntry {
                        path: next_path,
                        kind: DiffKind::Removed,
                        old: Some(lv.clone()),
                        new: None,
                    }),
                    (None, Some(rv)) => diffs.push(DiffEntry {
                        path: next_path,
                        kind: DiffKind::Added,
                        old: None,
                        new: Some(rv.clone()),
                    }),
                    (None, None) => {}
                }
            }
        }

        (serde_json::Value::Array(left_arr), serde_json::Value::Array(right_arr)) => {
            let max_len = std::cmp::max(left_arr.len(), right_arr.len());
            for i in 0..max_len {
                let next_path = format!("{}/{}", path, i);

                match (left_arr.get(i), right_arr.get(i)) {
                    (Some(lv), Some(rv)) => diff_values_inner(&next_path, lv, rv, diffs),
                    (Some(lv), None) => diffs.push(DiffEntry {
                        path: next_path,
                        kind: DiffKind::Removed,
                        old: Some(lv.clone()),
                        new: None,
                    }),
                    (None, Some(rv)) => diffs.push(DiffEntry {
                        path: next_path,
                        kind: DiffKind::Added,
                        old: None,
                        new: Some(rv.clone()),
                    }),
                    (None, None) => {}
                }
            }
        }

        _ => diffs.push(DiffEntry {
            path: path.to_string(),
            kind: DiffKind::Changed,
            old: Some(left.clone()),
            new: Some(right.clone()),
        }),
    }
}

fn escape_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}

pub fn format_compact_value(value: &serde_json::Value, max_len: usize) -> String {
    let s = serde_json::to_string(value).unwrap_or_else(|_| "<unserializable>".to_string());
    if s.chars().count() <= max_len {
        return s;
    }

    let mut out = s
        .chars()
        .take(max_len.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diff_paths_use_json_pointer() {
        let left = serde_json::json!({
            "a/b": 1,
            "arr": [1, 2],
            "nested": {"x": 1}
        });
        let right = serde_json::json!({
            "a/b": 2,
            "arr": [1, 3],
            "nested": {"x": 1}
        });

        let diffs = diff_values(&left, &right);
        assert!(diffs.iter().any(|d| d.path == "/a~1b"));
        assert!(diffs.iter().any(|d| d.path == "/arr/1"));
    }

    #[test]
    fn diff_root_path_is_empty_string() {
        let left = serde_json::json!(1);
        let right = serde_json::json!(2);
        let diffs = diff_values(&left, &right);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].path, "");
    }

    #[test]
    fn load_policy_prefers_ruleset() {
        let loaded = load_policy_from_arg("default", false, &RemoteExtendsConfig::disabled())
            .expect("load default ruleset");
        assert!(matches!(
            loaded.source,
            ResolvedPolicySource::Ruleset { ref id } if id == "default"
        ));
    }

    #[test]
    fn load_policy_falls_back_to_file() {
        let path = std::env::temp_dir().join(format!(
            "hush_cli_policy_diff_{}.yaml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));

        std::fs::write(
            &path,
            r#"
version: "1.1.0"
name: "test-policy"
"#,
        )
        .expect("write policy");

        let loaded = load_policy_from_arg(
            path.to_str().expect("path"),
            false,
            &RemoteExtendsConfig::disabled(),
        )
        .expect("load file");
        assert!(matches!(loaded.source, ResolvedPolicySource::File { .. }));
        assert_eq!(loaded.policy.name, "test-policy");
    }
}
