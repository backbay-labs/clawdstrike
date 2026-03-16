use crate::extensions::{Extensions, OriginsExtension};
use crate::rules::Rules;
use crate::schema::{HushSpec, MergeStrategy};

/// Merge a base HushSpec with a child according to the child's merge strategy.
///
/// Returns a new `HushSpec` combining base and child fields.
#[must_use = "merged spec is returned, not applied in place"]
pub fn merge(base: &HushSpec, child: &HushSpec) -> HushSpec {
    let strategy = child.merge_strategy.unwrap_or_default();
    match strategy {
        MergeStrategy::Replace => child.clone(),
        MergeStrategy::Merge => merge_shallow(base, child),
        MergeStrategy::DeepMerge => merge_deep(base, child),
    }
}

fn merge_shallow(base: &HushSpec, child: &HushSpec) -> HushSpec {
    HushSpec {
        hushspec: child.hushspec.clone(),
        name: child.name.clone().or_else(|| base.name.clone()),
        description: child
            .description
            .clone()
            .or_else(|| base.description.clone()),
        extends: child.extends.clone(),
        merge_strategy: child.merge_strategy,
        rules: match (&base.rules, &child.rules) {
            (_, Some(child_rules)) => {
                // For shallow merge, child rules at the rule-level replace base rules
                let base_rules = base.rules.as_ref().cloned().unwrap_or_default();
                Some(Rules {
                    forbidden_paths: child_rules
                        .forbidden_paths
                        .clone()
                        .or(base_rules.forbidden_paths),
                    path_allowlist: child_rules
                        .path_allowlist
                        .clone()
                        .or(base_rules.path_allowlist),
                    egress: child_rules.egress.clone().or(base_rules.egress),
                    secret_patterns: child_rules
                        .secret_patterns
                        .clone()
                        .or(base_rules.secret_patterns),
                    patch_integrity: child_rules
                        .patch_integrity
                        .clone()
                        .or(base_rules.patch_integrity),
                    shell_commands: child_rules
                        .shell_commands
                        .clone()
                        .or(base_rules.shell_commands),
                    tool_access: child_rules.tool_access.clone().or(base_rules.tool_access),
                    computer_use: child_rules.computer_use.clone().or(base_rules.computer_use),
                    remote_desktop_channels: child_rules
                        .remote_desktop_channels
                        .clone()
                        .or(base_rules.remote_desktop_channels),
                    input_injection: child_rules
                        .input_injection
                        .clone()
                        .or(base_rules.input_injection),
                })
            }
            (Some(base_rules), None) => Some(base_rules.clone()),
            (None, None) => None,
        },
        extensions: merge_extensions(&base.extensions, &child.extensions),
    }
}

fn merge_deep(base: &HushSpec, child: &HushSpec) -> HushSpec {
    // Deep merge is same as shallow merge for v0 since all rule fields
    // use array-replace semantics (not array-append).
    // The difference will matter when extensions add nested objects.
    merge_shallow(base, child)
}

fn merge_extensions(base: &Option<Extensions>, child: &Option<Extensions>) -> Option<Extensions> {
    match (base, child) {
        (_, Some(child_ext)) => {
            let base_ext = base.as_ref().cloned().unwrap_or_default();
            Some(Extensions {
                posture: child_ext.posture.clone().or(base_ext.posture),
                origins: merge_origins(&base_ext.origins, &child_ext.origins),
                detection: child_ext.detection.clone().or(base_ext.detection),
            })
        }
        (Some(base_ext), None) => Some(base_ext.clone()),
        (None, None) => None,
    }
}

fn merge_origins(
    base: &Option<OriginsExtension>,
    child: &Option<OriginsExtension>,
) -> Option<OriginsExtension> {
    match (base, child) {
        (_, Some(child_origins)) => {
            if let Some(base_origins) = base {
                // Merge profiles by id
                let mut merged_profiles = base_origins.profiles.clone();
                for child_profile in &child_origins.profiles {
                    if let Some(pos) = merged_profiles
                        .iter()
                        .position(|p| p.id == child_profile.id)
                    {
                        merged_profiles[pos] = child_profile.clone();
                    } else {
                        merged_profiles.push(child_profile.clone());
                    }
                }
                Some(OriginsExtension {
                    default_behavior: child_origins.default_behavior, // child overrides
                    profiles: merged_profiles,
                })
            } else {
                Some(child_origins.clone())
            }
        }
        (Some(base_origins), None) => Some(base_origins.clone()),
        (None, None) => None,
    }
}
