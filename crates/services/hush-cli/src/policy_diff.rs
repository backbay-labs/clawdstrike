use clawdstrike::policy::PolicyLocation;
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
    pub source_policy: Policy,
    pub source: ResolvedPolicySource,
    pub source_location: PolicyLocation,
    pub original_extends: Option<String>,
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
    let resolver =
        RemotePolicyResolver::new(remote_extends.clone()).map_err(|e| PolicyLoadError {
            message: format!("Failed to initialize remote extends resolver: {}", e),
            source: e,
        })?;

    match RuleSet::yaml_by_name(arg) {
        Some((yaml, id)) => {
            let source = ResolvedPolicySource::Ruleset { id: id.clone() };
            let source_location = PolicyLocation::Ruleset { id };
            let source_policy =
                Policy::from_yaml_without_load_verification(yaml).map_err(|e| PolicyLoadError {
                    message: format!("Failed to load ruleset {:?}: {}", arg, e),
                    source: e,
                })?;
            // Built-in rulesets historically load as effective policies via
            // `RuleSet::by_name()`. Keep that behavior even when callers do not
            // request `--resolve`, while still preserving the raw source policy
            // for inheritance-aware CLI reporting.
            let policy = Policy::from_yaml_with_extends_location_resolver(
                yaml,
                source_location.clone(),
                &resolver,
            )
            .map_err(|e| PolicyLoadError {
                message: format!("Failed to resolve ruleset extends: {}", e),
                source: e,
            })?;
            let original_extends = source_policy.extends.clone();

            Ok(LoadedPolicy {
                policy,
                source_policy,
                source,
                source_location,
                original_extends,
            })
        }
        None => {
            let path = std::path::Path::new(arg);
            let source = ResolvedPolicySource::File {
                path: arg.to_string(),
            };
            let source_location = PolicyLocation::File(path.to_path_buf());

            let (policy, source_policy, original_extends) =
                if resolve {
                    let content = std::fs::read_to_string(path).map_err(|e| PolicyLoadError {
                        message: format!(
                            "{arg:?} is not a known ruleset; failed to read policy file: {}",
                            e
                        ),
                        source: clawdstrike::Error::from(e),
                    })?;

                    let raw_policy = Policy::from_yaml_without_load_verification(&content)
                        .map_err(|e| PolicyLoadError {
                            message: format!(
                                "{arg:?} is not a known ruleset; failed to load policy file: {}",
                                e
                            ),
                            source: e,
                        })?;
                    let original_extends = raw_policy.extends.clone();

                    let policy = Policy::from_yaml_with_extends_location_resolver(
                        &content,
                        source_location.clone(),
                        &resolver,
                    )
                    .map_err(|e| PolicyLoadError {
                        message: format!(
                            "{arg:?} is not a known ruleset; failed to load policy file: {}",
                            e
                        ),
                        source: e,
                    })?;

                    (policy, raw_policy, original_extends)
                } else {
                    let policy = Policy::from_yaml_file(arg).map_err(|e| PolicyLoadError {
                        message: format!(
                            "{arg:?} is not a known ruleset; failed to load policy file: {}",
                            e
                        ),
                        source: e,
                    })?;
                    let original_extends = policy.extends.clone();

                    (policy.clone(), policy, original_extends)
                };

            Ok(LoadedPolicy {
                policy,
                source_policy,
                source,
                source_location,
                original_extends,
            })
        }
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
    use tempfile::tempdir;

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
        assert!(matches!(
            loaded.source_location,
            PolicyLocation::Ruleset { ref id } if id == "default"
        ));
    }

    #[test]
    fn load_resolved_ruleset_keeps_original_extends_metadata() {
        let loaded = load_policy_from_arg(
            "remote-desktop-strict",
            true,
            &RemoteExtendsConfig::disabled(),
        )
        .expect("load resolved ruleset");

        assert_eq!(loaded.original_extends.as_deref(), Some("remote-desktop"));
        assert_eq!(
            loaded.source_policy.extends.as_deref(),
            Some("remote-desktop")
        );
        assert_eq!(loaded.policy.extends, None);
    }

    #[test]
    fn load_unresolved_ruleset_still_returns_effective_policy() {
        let loaded = load_policy_from_arg(
            "remote-desktop-strict",
            false,
            &RemoteExtendsConfig::disabled(),
        )
        .expect("load unresolved ruleset");
        let expected = RuleSet::by_name("remote-desktop-strict")
            .expect("ruleset lookup")
            .expect("ruleset")
            .policy;

        assert_eq!(
            serde_json::to_value(&loaded.policy).expect("serialize loaded policy"),
            serde_json::to_value(&expected).expect("serialize expected policy")
        );
        assert_eq!(loaded.original_extends.as_deref(), Some("remote-desktop"));
        assert_eq!(
            loaded.source_policy.extends.as_deref(),
            Some("remote-desktop")
        );
        assert_eq!(loaded.policy.extends, None);
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
        assert!(matches!(
            loaded.source_location,
            PolicyLocation::File { .. }
        ));
        assert_eq!(loaded.policy.name, "test-policy");
        assert_eq!(loaded.source_policy.name, "test-policy");
    }

    #[test]
    fn load_resolved_file_with_strict_extends_uses_resolver_context() {
        clawdstrike_logos::verifier::install_clawdstrike_policy_load_verifier();

        let dir = tempdir().expect("tempdir");
        let parent = dir.path().join("parent.yaml");
        let child = dir.path().join("child.yaml");

        std::fs::write(
            &parent,
            r#"
version: "1.5.0"
name: "parent"
settings:
  verification:
    enabled: true
    strict: true
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
"#,
        )
        .expect("write parent");

        std::fs::write(
            &child,
            r#"
version: "1.5.0"
name: "child"
extends: "parent.yaml"
settings:
  verification:
    enabled: true
    strict: true
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
"#,
        )
        .expect("write child");

        let loaded = load_policy_from_arg(
            child.to_str().expect("child path"),
            true,
            &RemoteExtendsConfig::disabled(),
        )
        .expect("resolved strict policy should load");

        assert_eq!(loaded.original_extends.as_deref(), Some("parent.yaml"));
        assert_eq!(loaded.source_policy.extends.as_deref(), Some("parent.yaml"));
        assert_eq!(loaded.policy.extends, None);
    }
}
