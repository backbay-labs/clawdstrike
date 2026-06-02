//! Policy loading: YAML parsing, `extends` resolution + cycle detection, and the
//! optional load-time verification hook.

#[cfg(feature = "full")]
use std::collections::BTreeSet;
use std::path::Path;

use super::{
    LocalPolicyResolver, Policy, PolicyLoadVerificationInput, PolicyLocation, PolicyResolver,
    PolicyValidationOptions, RuleSet, POLICY_LOAD_VERIFIER,
};
use crate::error::{Error, Result};

impl Policy {
    /// Create an empty policy
    pub fn new() -> Self {
        Self::default()
    }

    /// Load from YAML file
    pub fn from_yaml_file(path: impl AsRef<Path>) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml(&content)
    }

    /// Parse from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self> {
        let policy = Self::from_yaml_without_load_verification(yaml)?;
        if policy.extends.is_none() {
            maybe_verify_loaded_policy(&policy, Some(&policy), None)?;
        }
        Ok(policy)
    }

    /// Parse from YAML string and validate it without running load-time
    /// verification hooks.
    ///
    /// This is intended for callers that need source metadata before resolving
    /// `extends`, or that will run load-time verification with richer parent
    /// context later in the load pipeline.
    pub fn from_yaml_without_load_verification(yaml: &str) -> Result<Self> {
        let policy = Self::from_yaml_unvalidated(yaml)?;
        policy.validate()?;
        Ok(policy)
    }

    /// Parse from YAML string, auto-detecting HushSpec or Clawdstrike format.
    ///
    /// If the document contains a top-level `hushspec:` key, it is parsed and compiled via
    /// [`compile_hushspec`](crate::hushspec_compiler::compile_hushspec).
    /// Otherwise falls through to
    /// [`from_yaml`](Self::from_yaml).
    pub fn from_yaml_auto(yaml: &str) -> Result<Self> {
        if crate::hushspec_compiler::is_hushspec(yaml) {
            crate::hushspec_compiler::compile_hushspec(yaml)
        } else {
            Self::from_yaml(yaml)
        }
    }

    pub(in crate::policy) fn from_yaml_unvalidated(yaml: &str) -> Result<Self> {
        let policy: Self = serde_yaml::from_str(yaml)?;
        #[cfg(feature = "full")]
        {
            let mut policy = policy;
            policy.guards.spider_sense_present_fields = spider_sense_present_fields_from_yaml(yaml);
            Ok(policy)
        }
        #[cfg(not(feature = "full"))]
        {
            Ok(policy)
        }
    }

    /// Export to YAML string
    pub fn to_yaml(&self) -> Result<String> {
        serde_yaml::to_string(self).map_err(Error::from)
    }

    /// Resolve a base policy by name or path
    ///
    /// Tries built-in ruleset names first,
    /// then falls back to loading from file path.
    pub fn resolve_base(name_or_path: &str) -> Result<Self> {
        // Try built-in rulesets first
        if let Some(ruleset) = RuleSet::by_name(name_or_path)? {
            return Ok(ruleset.policy);
        }

        // Try loading from file
        let path = std::path::Path::new(name_or_path);
        if path.exists() {
            return Self::from_yaml_file(path);
        }

        Err(Error::ConfigError(format!(
            "Unknown ruleset or file not found: {}",
            name_or_path
        )))
    }

    /// Load from YAML string with extends resolution
    ///
    /// If the policy has an `extends` field, loads the base and merges.
    /// Detects circular dependencies.
    pub fn from_yaml_with_extends(yaml: &str, base_path: Option<&Path>) -> Result<Self> {
        let resolver = LocalPolicyResolver::new();
        Self::from_yaml_with_extends_resolver(yaml, base_path, &resolver)
    }

    /// Load from YAML string with extends resolution using a custom resolver.
    ///
    /// This allows callers to support remote `extends` while keeping the default path
    /// filesystem-only.
    pub fn from_yaml_with_extends_resolver(
        yaml: &str,
        base_path: Option<&Path>,
        resolver: &impl PolicyResolver,
    ) -> Result<Self> {
        let location = base_path
            .map(|p| PolicyLocation::File(p.to_path_buf()))
            .unwrap_or(PolicyLocation::None);

        Self::from_yaml_with_extends_location_resolver(yaml, location, resolver)
    }

    /// Like `from_yaml_with_extends` but with an explicit source location.
    pub fn from_yaml_with_extends_location_resolver(
        yaml: &str,
        location: PolicyLocation,
        resolver: &impl PolicyResolver,
    ) -> Result<Self> {
        Self::from_yaml_with_extends_internal_resolver(
            yaml,
            location,
            resolver,
            &mut std::collections::HashSet::new(),
            0,
            PolicyValidationOptions::default(),
        )
    }

    fn from_yaml_with_extends_internal_resolver(
        yaml: &str,
        location: PolicyLocation,
        resolver: &impl PolicyResolver,
        visited: &mut std::collections::HashSet<String>,
        depth: usize,
        validation: PolicyValidationOptions,
    ) -> Result<Self> {
        if depth > crate::core::cycle::MAX_POLICY_EXTENDS_DEPTH {
            return Err(Error::ConfigError(format!(
                "Policy extends depth exceeded (limit: {})",
                crate::core::cycle::MAX_POLICY_EXTENDS_DEPTH
            )));
        }

        let child = Policy::from_yaml_unvalidated(yaml)?;

        if let Some(ref extends) = child.extends {
            let resolved = resolver.resolve(extends, &location)?;

            match crate::core::cycle::check_extends_cycle(&resolved.key, visited, depth + 1) {
                crate::core::cycle::CycleCheckResult::Ok => {}
                crate::core::cycle::CycleCheckResult::DepthExceeded { limit, .. } => {
                    return Err(Error::ConfigError(format!(
                        "Policy extends depth exceeded (limit: {})",
                        limit
                    )));
                }
                crate::core::cycle::CycleCheckResult::CycleDetected { .. } => {
                    return Err(Error::ConfigError(format!(
                        "Circular policy extension detected: {}",
                        extends
                    )));
                }
            }
            visited.insert(resolved.key);

            let base = Self::from_yaml_with_extends_internal_resolver(
                &resolved.yaml,
                resolved.location,
                resolver,
                visited,
                depth + 1,
                validation,
            )?;

            let merged = base.merge(&child);
            merged.validate_with_options(validation)?;
            maybe_verify_loaded_policy(&merged, Some(&child), Some(&base))?;
            Ok(merged)
        } else {
            child.validate_with_options(validation)?;
            maybe_verify_loaded_policy(&child, Some(&child), None)?;
            Ok(child)
        }
    }

    /// Load from YAML string with extends resolution using a custom resolver and validation options.
    pub fn from_yaml_with_extends_resolver_with_validation_options(
        yaml: &str,
        base_path: Option<&Path>,
        resolver: &impl PolicyResolver,
        validation: PolicyValidationOptions,
    ) -> Result<Self> {
        let location = base_path
            .map(|p| PolicyLocation::File(p.to_path_buf()))
            .unwrap_or(PolicyLocation::None);

        Self::from_yaml_with_extends_internal_resolver(
            yaml,
            location,
            resolver,
            &mut std::collections::HashSet::new(),
            0,
            validation,
        )
    }

    /// Load from YAML file with extends resolution
    pub fn from_yaml_file_with_extends(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        Self::from_yaml_with_extends(&content, Some(path))
    }
}

fn maybe_verify_loaded_policy(
    effective_policy: &Policy,
    source_policy: Option<&Policy>,
    parent_policy: Option<&Policy>,
) -> Result<()> {
    let settings = effective_policy.settings.effective_verification();
    if !settings.enabled {
        return Ok(());
    }

    let Some(verifier) = POLICY_LOAD_VERIFIER.get() else {
        let message = "policy.settings.verification is enabled, but no load-time policy verifier is registered";
        if settings.strict {
            return Err(Error::ConfigError(message.to_string()));
        }
        tracing::warn!("{}", message);
        return Ok(());
    };

    verifier(&PolicyLoadVerificationInput {
        effective_policy: effective_policy.clone(),
        source_policy: source_policy.cloned(),
        parent_policy: parent_policy.cloned(),
    })
}

#[cfg(feature = "full")]
fn spider_sense_present_fields_from_yaml(yaml: &str) -> BTreeSet<String> {
    fn mapping_get<'a>(map: &'a serde_yaml::Mapping, key: &str) -> Option<&'a serde_yaml::Value> {
        map.get(serde_yaml::Value::String(key.to_string()))
    }

    let mut fields = BTreeSet::new();
    let root = match serde_yaml::from_str::<serde_yaml::Value>(yaml) {
        Ok(value) => value,
        Err(_) => return fields,
    };
    let Some(root_map) = root.as_mapping() else {
        return fields;
    };
    let Some(guards) = mapping_get(root_map, "guards") else {
        return fields;
    };
    let Some(guards_map) = guards.as_mapping() else {
        return fields;
    };
    let Some(spider_sense) = mapping_get(guards_map, "spider_sense") else {
        return fields;
    };
    let Some(spider_sense_map) = spider_sense.as_mapping() else {
        return fields;
    };

    for key in spider_sense_map.keys() {
        if let Some(name) = key.as_str() {
            fields.insert(name.to_string());
        }
    }
    fields
}
