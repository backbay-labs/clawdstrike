//! Fail-closed policy validation: version gating, glob/regex/placeholder checks,
//! and provider-spec validation.

use globset::GlobBuilder;
use regex::Regex;

use crate::error::{PolicyFieldError, PolicyValidationError, Result};
use crate::placeholders::env_var_for_placeholder;
use crate::posture::validate_posture_config;

use super::{Policy, PolicyValidationOptions};

mod specs;
mod version;

pub use version::{policy_version_supports_broker, policy_version_supports_origins};

use specs::validate_custom_guards;
use version::{policy_version_supports_posture, validate_policy_version};

impl Policy {
    /// Validate policy semantics and guard configs.
    ///
    /// This is a security boundary: invalid regex/glob patterns are treated as errors, not silently ignored.
    pub fn validate(&self) -> Result<()> {
        self.validate_with_options(PolicyValidationOptions::default())
    }

    pub fn validate_with_options(&self, options: PolicyValidationOptions) -> Result<()> {
        validate_policy_version(&self.version)?;

        let mut errors: Vec<PolicyFieldError> = Vec::new();
        let require_env = options.require_env;
        let supports_v1_2_features = policy_version_supports_posture(&self.version);

        if self.posture.is_some() && !supports_v1_2_features {
            errors.push(PolicyFieldError::new(
                "posture",
                "posture requires policy version 1.2.0".to_string(),
            ));
        }

        if self.origins.is_some() && !policy_version_supports_origins(&self.version) {
            errors.push(PolicyFieldError::new(
                "origins",
                format!(
                    "origins block requires schema version >= 1.4.0, got {}",
                    self.version
                ),
            ));
        }

        if self.broker.is_some() && !policy_version_supports_broker(&self.version) {
            errors.push(PolicyFieldError::new(
                "broker",
                format!(
                    "broker block requires schema version >= 1.5.0, got {}",
                    self.version
                ),
            ));
        }

        if let Some(ref broker) = self.broker {
            if broker.enabled && broker.providers.is_empty() {
                errors.push(PolicyFieldError::new(
                    "broker.providers",
                    "broker.providers must contain at least one provider when broker is enabled"
                        .to_string(),
                ));
            }

            let mut seen_provider_names = std::collections::HashSet::new();
            for (index, provider) in broker.providers.iter().enumerate() {
                let prefix = format!("broker.providers[{index}]");
                if provider.name.trim().is_empty() {
                    errors.push(PolicyFieldError::new(
                        format!("{prefix}.name"),
                        "provider name must be non-empty".to_string(),
                    ));
                } else if !seen_provider_names.insert(provider.name.as_str()) {
                    errors.push(PolicyFieldError::new(
                        format!("{prefix}.name"),
                        format!("duplicate broker provider name: {}", provider.name),
                    ));
                }

                if provider.host.trim().is_empty() {
                    errors.push(PolicyFieldError::new(
                        format!("{prefix}.host"),
                        "provider host must be non-empty".to_string(),
                    ));
                }

                if provider.secret_ref.trim().is_empty() {
                    errors.push(PolicyFieldError::new(
                        format!("{prefix}.secret_ref"),
                        "provider secret_ref must be non-empty".to_string(),
                    ));
                }

                if provider.exact_paths.is_empty() {
                    errors.push(PolicyFieldError::new(
                        format!("{prefix}.exact_paths"),
                        "provider exact_paths must contain at least one path".to_string(),
                    ));
                }

                if provider.methods.is_empty() {
                    errors.push(PolicyFieldError::new(
                        format!("{prefix}.methods"),
                        "provider methods must contain at least one method".to_string(),
                    ));
                }

                for (path_index, path) in provider.exact_paths.iter().enumerate() {
                    if !path.starts_with('/') {
                        errors.push(PolicyFieldError::new(
                            format!("{prefix}.exact_paths[{path_index}]"),
                            "broker exact path must start with '/'".to_string(),
                        ));
                    }
                }
            }
        }

        if let Some(ref origins) = self.origins {
            let mut seen_ids = std::collections::HashSet::new();
            for profile in &origins.profiles {
                if !seen_ids.insert(&profile.id) {
                    errors.push(PolicyFieldError::new(
                        "origins.profiles",
                        format!("duplicate origin profile id: {}", profile.id),
                    ));
                }
                // H3 fix: validate posture references at load time
                if let Some(ref posture_ref) = profile.posture {
                    if let Some(ref posture_config) = self.posture {
                        if !posture_config.states.contains_key(posture_ref) {
                            errors.push(PolicyFieldError::new(
                                format!("origins.profiles[{}].posture", profile.id),
                                format!(
                                    "references unknown posture state '{}' (available: {:?})",
                                    posture_ref,
                                    posture_config.states.keys().collect::<Vec<_>>()
                                ),
                            ));
                        }
                    } else {
                        errors.push(PolicyFieldError::new(
                            format!("origins.profiles[{}].posture", profile.id),
                            format!(
                                "references posture state '{}' but no posture config is defined",
                                posture_ref
                            ),
                        ));
                    }
                }
            }
        }

        if self.guards.path_allowlist.is_some() && !supports_v1_2_features {
            errors.push(PolicyFieldError::new(
                "guards.path_allowlist",
                "path_allowlist requires policy version 1.2.0".to_string(),
            ));
        }

        if let Some(posture) = &self.posture {
            validate_posture_config(posture, &mut errors);
        }

        if !self.custom_guards.is_empty() {
            let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
            for (idx, cg) in self.custom_guards.iter().enumerate() {
                if cg.id.trim().is_empty() {
                    errors.push(PolicyFieldError::new(
                        format!("custom_guards[{}].id", idx),
                        "id must be non-empty".to_string(),
                    ));
                }
                if !seen.insert(cg.id.as_str()) {
                    errors.push(PolicyFieldError::new(
                        format!("custom_guards[{}].id", idx),
                        format!("duplicate custom guard id: {}", cg.id),
                    ));
                }
                if !cg.config.is_object() {
                    errors.push(PolicyFieldError::new(
                        format!("custom_guards[{}].config", idx),
                        "config must be a JSON object".to_string(),
                    ));
                }

                validate_placeholders_in_json(
                    &mut errors,
                    &format!("custom_guards[{}].config", idx),
                    &cg.config,
                    cg.enabled,
                    require_env,
                );
            }
        }

        if let Some(cfg) = &self.guards.forbidden_path {
            if let Some(patterns) = cfg.patterns.as_ref() {
                validate_globs(&mut errors, "guards.forbidden_path.patterns", patterns);
                validate_placeholders_in_strings(
                    &mut errors,
                    "guards.forbidden_path.patterns",
                    patterns,
                    cfg.enabled,
                    require_env,
                );
            }
            validate_globs(
                &mut errors,
                "guards.forbidden_path.exceptions",
                &cfg.exceptions,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.forbidden_path.exceptions",
                &cfg.exceptions,
                cfg.enabled,
                require_env,
            );
            validate_globs(
                &mut errors,
                "guards.forbidden_path.additional_patterns",
                &cfg.additional_patterns,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.forbidden_path.additional_patterns",
                &cfg.additional_patterns,
                cfg.enabled,
                require_env,
            );
            validate_globs(
                &mut errors,
                "guards.forbidden_path.remove_patterns",
                &cfg.remove_patterns,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.forbidden_path.remove_patterns",
                &cfg.remove_patterns,
                cfg.enabled,
                require_env,
            );
        }

        if let Some(cfg) = &self.guards.path_allowlist {
            validate_globs(
                &mut errors,
                "guards.path_allowlist.file_access_allow",
                &cfg.file_access_allow,
            );
            validate_globs(
                &mut errors,
                "guards.path_allowlist.file_write_allow",
                &cfg.file_write_allow,
            );
            validate_globs(
                &mut errors,
                "guards.path_allowlist.patch_allow",
                &cfg.patch_allow,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.path_allowlist.file_access_allow",
                &cfg.file_access_allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.path_allowlist.file_write_allow",
                &cfg.file_write_allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.path_allowlist.patch_allow",
                &cfg.patch_allow,
                cfg.enabled,
                require_env,
            );
        }

        if let Some(cfg) = &self.guards.egress_allowlist {
            validate_domain_globs(&mut errors, "guards.egress_allowlist.allow", &cfg.allow);
            validate_domain_globs(&mut errors, "guards.egress_allowlist.block", &cfg.block);
            validate_domain_globs(
                &mut errors,
                "guards.egress_allowlist.additional_allow",
                &cfg.additional_allow,
            );
            validate_domain_globs(
                &mut errors,
                "guards.egress_allowlist.additional_block",
                &cfg.additional_block,
            );
            validate_domain_globs(
                &mut errors,
                "guards.egress_allowlist.remove_allow",
                &cfg.remove_allow,
            );
            validate_domain_globs(
                &mut errors,
                "guards.egress_allowlist.remove_block",
                &cfg.remove_block,
            );

            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.allow",
                &cfg.allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.block",
                &cfg.block,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.additional_allow",
                &cfg.additional_allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.additional_block",
                &cfg.additional_block,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.remove_allow",
                &cfg.remove_allow,
                cfg.enabled,
                require_env,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.egress_allowlist.remove_block",
                &cfg.remove_block,
                cfg.enabled,
                require_env,
            );
        }

        if let Some(cfg) = &self.guards.secret_leak {
            for (idx, p) in cfg.patterns.iter().enumerate() {
                validate_placeholders_in_string(
                    &mut errors,
                    &format!("guards.secret_leak.patterns[{}].name", idx),
                    &p.name,
                    cfg.enabled,
                    require_env,
                );
                validate_placeholders_in_string(
                    &mut errors,
                    &format!("guards.secret_leak.patterns[{}].pattern", idx),
                    &p.pattern,
                    cfg.enabled,
                    require_env,
                );

                if let Err(e) = Regex::new(&p.pattern) {
                    errors.push(PolicyFieldError::new(
                        format!("guards.secret_leak.patterns[{}].pattern", idx),
                        format!("invalid regex ({}): {}", p.name, e),
                    ));
                }
            }
            for (idx, p) in cfg.additional_patterns.iter().enumerate() {
                validate_placeholders_in_string(
                    &mut errors,
                    &format!("guards.secret_leak.additional_patterns[{}].name", idx),
                    &p.name,
                    cfg.enabled,
                    require_env,
                );
                validate_placeholders_in_string(
                    &mut errors,
                    &format!("guards.secret_leak.additional_patterns[{}].pattern", idx),
                    &p.pattern,
                    cfg.enabled,
                    require_env,
                );

                if let Err(e) = Regex::new(&p.pattern) {
                    errors.push(PolicyFieldError::new(
                        format!("guards.secret_leak.additional_patterns[{}].pattern", idx),
                        format!("invalid regex ({}): {}", p.name, e),
                    ));
                }
            }
            validate_globs(
                &mut errors,
                "guards.secret_leak.skip_paths",
                &cfg.skip_paths,
            );
            validate_placeholders_in_strings(
                &mut errors,
                "guards.secret_leak.skip_paths",
                &cfg.skip_paths,
                cfg.enabled,
                require_env,
            );
        }

        if let Some(cfg) = &self.guards.patch_integrity {
            for (idx, pattern) in cfg.forbidden_patterns.iter().enumerate() {
                if let Err(e) = Regex::new(pattern) {
                    errors.push(PolicyFieldError::new(
                        format!("guards.patch_integrity.forbidden_patterns[{}]", idx),
                        format!("invalid regex: {}", e),
                    ));
                }
                validate_placeholders_in_string(
                    &mut errors,
                    &format!("guards.patch_integrity.forbidden_patterns[{}]", idx),
                    pattern,
                    cfg.enabled,
                    require_env,
                );
            }
        }

        if let Some(cfg) = &self.guards.shell_command {
            for (idx, pattern) in cfg.forbidden_patterns.iter().enumerate() {
                if let Err(e) = Regex::new(pattern) {
                    errors.push(PolicyFieldError::new(
                        format!("guards.shell_command.forbidden_patterns[{}]", idx),
                        format!("invalid regex: {}", e),
                    ));
                }
                validate_placeholders_in_string(
                    &mut errors,
                    &format!("guards.shell_command.forbidden_patterns[{}]", idx),
                    pattern,
                    cfg.enabled,
                    require_env,
                );
            }
        }

        if let Some(cfg) = &self.guards.prompt_injection {
            if cfg.max_scan_bytes == 0 {
                errors.push(PolicyFieldError::new(
                    "guards.prompt_injection.max_scan_bytes".to_string(),
                    "max_scan_bytes must be > 0".to_string(),
                ));
            }
            if !cfg.block_at_or_above.at_least(cfg.warn_at_or_above) {
                errors.push(PolicyFieldError::new(
                    "guards.prompt_injection.warn_at_or_above".to_string(),
                    "warn_at_or_above must be <= block_at_or_above".to_string(),
                ));
            }
        }

        if !self.guards.custom.is_empty() {
            validate_custom_guards(&mut errors, &self.guards.custom, require_env);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(PolicyValidationError::new(errors).into())
        }
    }
}

fn validate_globs(errors: &mut Vec<PolicyFieldError>, field: &str, patterns: &[String]) {
    for (idx, pattern) in patterns.iter().enumerate() {
        if let Err(e) = glob::Pattern::new(pattern) {
            errors.push(PolicyFieldError::new(
                format!("{}[{}]", field, idx),
                format!("invalid glob {:?}: {}", pattern, e),
            ));
        }
    }
}

fn validate_domain_globs(errors: &mut Vec<PolicyFieldError>, field: &str, patterns: &[String]) {
    for (idx, pattern) in patterns.iter().enumerate() {
        if let Err(e) = GlobBuilder::new(pattern)
            .case_insensitive(true)
            .literal_separator(true)
            .build()
        {
            errors.push(PolicyFieldError::new(
                format!("{}[{}]", field, idx),
                format!("invalid domain glob {:?}: {}", pattern, e),
            ));
        }
    }
}

pub(in crate::policy) fn validate_placeholders_in_string(
    errors: &mut Vec<PolicyFieldError>,
    field: &str,
    value: &str,
    enabled: bool,
    require_env: bool,
) {
    if !enabled {
        return;
    }

    let mut i = 0usize;
    while let Some(start_rel) = value[i..].find("${") {
        let start = i + start_rel;
        let after = start + 2;

        let Some(end_rel) = value[after..].find('}') else {
            break;
        };
        let end = after + end_rel;

        let raw = &value[after..end];
        let env_name = match env_var_for_placeholder(raw) {
            Ok(v) => v,
            Err(msg) => {
                errors.push(PolicyFieldError::new(field, msg));
                i = end + 1;
                continue;
            }
        };

        if require_env && std::env::var(&env_name).is_err() {
            errors.push(PolicyFieldError::new(
                field,
                format!("missing environment variable {}", env_name),
            ));
        }

        i = end + 1;
    }
}

fn validate_placeholders_in_strings(
    errors: &mut Vec<PolicyFieldError>,
    field: &str,
    values: &[String],
    enabled: bool,
    require_env: bool,
) {
    if !enabled {
        return;
    }

    for (idx, v) in values.iter().enumerate() {
        validate_placeholders_in_string(
            errors,
            &format!("{}[{}]", field, idx),
            v,
            enabled,
            require_env,
        );
    }
}

pub(in crate::policy) fn validate_placeholders_in_json(
    errors: &mut Vec<PolicyFieldError>,
    field: &str,
    value: &serde_json::Value,
    enabled: bool,
    require_env: bool,
) {
    if !enabled {
        return;
    }

    match value {
        serde_json::Value::String(s) => {
            validate_placeholders_in_string(errors, field, s, enabled, require_env);
        }
        serde_json::Value::Array(items) => {
            for (idx, v) in items.iter().enumerate() {
                validate_placeholders_in_json(
                    errors,
                    &format!("{}[{}]", field, idx),
                    v,
                    enabled,
                    require_env,
                );
            }
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                validate_placeholders_in_json(
                    errors,
                    &format!("{}.{}", field, k),
                    v,
                    enabled,
                    require_env,
                );
            }
        }
        _ => {}
    }
}
