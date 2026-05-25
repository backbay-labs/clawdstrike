use crate::schema::HushSpec;
use crate::version;
use regex::Regex;
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    #[error("unsupported hushspec version: {0}")]
    UnsupportedVersion(String),
    #[error("duplicate secret pattern name: {0}")]
    DuplicatePatternName(String),
    /// Regex uses features outside the RE2 subset (backreferences, lookahead, etc.).
    /// The Rust `regex` crate enforces RE2 semantics, ensuring any accepted pattern
    /// is safe from ReDoS across all HushSpec SDKs.
    #[error("{field}: invalid regex pattern {pattern:?}: {message}")]
    InvalidRegex {
        field: String,
        pattern: String,
        message: String,
    },
    #[error("{0}")]
    Custom(String),
}

#[must_use = "validation result should be checked"]
pub fn validate(spec: &HushSpec) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if !version::is_supported(&spec.hushspec) {
        errors.push(ValidationError::UnsupportedVersion(spec.hushspec.clone()));
    }

    if let Some(rules) = &spec.rules {
        validate_rules(rules, &mut errors);

        if rules.forbidden_paths.is_none()
            && rules.path_allowlist.is_none()
            && rules.egress.is_none()
            && rules.secret_patterns.is_none()
            && rules.patch_integrity.is_none()
            && rules.shell_commands.is_none()
            && rules.tool_access.is_none()
            && rules.computer_use.is_none()
            && rules.remote_desktop_channels.is_none()
            && rules.input_injection.is_none()
        {
            warnings.push("no rules configured".to_string());
        }
    } else {
        warnings.push("no rules section present".to_string());
    }

    if let Some(ext) = &spec.extensions {
        validate_posture(ext, &mut errors, &mut warnings);
        validate_origins(ext, &mut errors);
        validate_detection(ext, &mut errors, &mut warnings);
    }

    for gw in crate::governance::validate_governance(spec) {
        warnings.push(gw.message);
    }

    ValidationResult { errors, warnings }
}

fn validate_rules(rules: &crate::rules::Rules, errors: &mut Vec<ValidationError>) {
    if let Some(secret_patterns) = &rules.secret_patterns {
        let mut seen = HashSet::new();
        for pattern in &secret_patterns.patterns {
            if !seen.insert(&pattern.name) {
                errors.push(ValidationError::DuplicatePatternName(pattern.name.clone()));
            }
            validate_regex(
                &pattern.pattern,
                &format!("secret_patterns.patterns.{}", pattern.name),
                errors,
            );
        }
    }

    if let Some(patch_integrity) = &rules.patch_integrity {
        if patch_integrity.max_imbalance_ratio <= 0.0 {
            errors.push(ValidationError::Custom(
                "rules.patch_integrity.max_imbalance_ratio must be > 0".to_string(),
            ));
        }
        for (index, pattern) in patch_integrity.forbidden_patterns.iter().enumerate() {
            validate_regex(
                pattern,
                &format!("rules.patch_integrity.forbidden_patterns[{index}]"),
                errors,
            );
        }
    }

    if let Some(shell_commands) = &rules.shell_commands {
        for (index, pattern) in shell_commands.forbidden_patterns.iter().enumerate() {
            validate_regex(
                pattern,
                &format!("rules.shell_commands.forbidden_patterns[{index}]"),
                errors,
            );
        }
    }

    if let Some(tool_access) = &rules.tool_access
        && matches!(tool_access.max_args_size, Some(0))
    {
        errors.push(ValidationError::Custom(
            "rules.tool_access.max_args_size must be >= 1".to_string(),
        ));
    }
}

fn validate_posture(
    ext: &crate::extensions::Extensions,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<String>,
) {
    if let Some(posture) = &ext.posture {
        if posture.states.is_empty() {
            errors.push(ValidationError::Custom(
                "posture.states must define at least one state".to_string(),
            ));
        }

        if !posture.states.contains_key(&posture.initial) {
            errors.push(ValidationError::Custom(format!(
                "posture.initial '{}' does not reference a defined state",
                posture.initial
            )));
        }

        for (state_name, state) in &posture.states {
            for capability in &state.capabilities {
                if !matches!(
                    capability.as_str(),
                    "file_access"
                        | "file_write"
                        | "egress"
                        | "shell"
                        | "tool_call"
                        | "patch"
                        | "custom"
                ) {
                    warnings.push(format!(
                        "posture.states.{state_name}.capabilities includes unknown capability '{capability}'"
                    ));
                }
            }

            for (budget_key, &value) in &state.budgets {
                if value < 0 {
                    errors.push(ValidationError::Custom(format!(
                        "posture.states.{state_name}.budgets.{budget_key} must be non-negative, got {value}"
                    )));
                }
                if !matches!(
                    budget_key.as_str(),
                    "file_writes"
                        | "egress_calls"
                        | "shell_commands"
                        | "tool_calls"
                        | "patches"
                        | "custom_calls"
                ) {
                    warnings.push(format!(
                        "posture.states.{state_name}.budgets uses unknown budget key '{budget_key}'"
                    ));
                }
            }
        }

        for (index, transition) in posture.transitions.iter().enumerate() {
            if transition.from != "*" && !posture.states.contains_key(&transition.from) {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].from '{}' does not reference a defined state",
                    transition.from
                )));
            }
            if transition.to == "*" {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].to cannot be '*'"
                )));
            } else if !posture.states.contains_key(&transition.to) {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].to '{}' does not reference a defined state",
                    transition.to
                )));
            }

            if transition.on != crate::extensions::TransitionTrigger::Timeout
                && let Some(after) = &transition.after
                && !is_valid_duration(after)
            {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{index}].after must match ^\\d+[smhd]$"
                )));
            }

            if transition.on == crate::extensions::TransitionTrigger::Timeout {
                match transition.after.as_deref() {
                    Some(after) if is_valid_duration(after) => {}
                    Some(_) => errors.push(ValidationError::Custom(format!(
                        "posture.transitions[{index}].after must match ^\\d+[smhd]$"
                    ))),
                    None => errors.push(ValidationError::Custom(format!(
                        "posture.transitions[{index}]: timeout trigger requires 'after' field"
                    ))),
                }
            }
        }
    }
}

fn validate_origins(ext: &crate::extensions::Extensions, errors: &mut Vec<ValidationError>) {
    if let Some(origins) = &ext.origins {
        let mut seen_ids = HashSet::new();
        let posture_states = ext.posture.as_ref().map(|posture| {
            posture
                .states
                .keys()
                .map(String::as_str)
                .collect::<HashSet<_>>()
        });

        for (index, profile) in origins.profiles.iter().enumerate() {
            if !seen_ids.insert(&profile.id) {
                errors.push(ValidationError::Custom(format!(
                    "duplicate origin profile id: '{}'",
                    profile.id
                )));
            }

            if let Some(match_rules) = &profile.match_rules {
                if let Some(space_type) = &match_rules.space_type
                    && !contains_allowed_value(
                        space_type,
                        crate::generated_contract::ORIGIN_SPACE_TYPES,
                    )
                {
                    errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].match.space_type '{space_type}' is not valid"
                    )));
                }

                if let Some(visibility) = &match_rules.visibility
                    && !contains_allowed_value(
                        visibility,
                        crate::generated_contract::ORIGIN_VISIBILITIES,
                    )
                {
                    errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].match.visibility '{visibility}' is not valid"
                    )));
                }
            }

            if let Some(posture_state) = &profile.posture {
                match &posture_states {
                    Some(states) if states.contains(posture_state.as_str()) => {}
                    Some(_) => errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].posture '{}' does not reference a defined posture state",
                        posture_state
                    ))),
                    None => errors.push(ValidationError::Custom(format!(
                        "origins.profiles[{index}].posture requires extensions.posture to be defined"
                    ))),
                }
            }

            if let Some(bridge) = &profile.bridge {
                for (target_index, target) in bridge.allowed_targets.iter().enumerate() {
                    if let Some(space_type) = &target.space_type
                        && !contains_allowed_value(
                            space_type,
                            crate::generated_contract::ORIGIN_SPACE_TYPES,
                        )
                    {
                        errors.push(ValidationError::Custom(format!(
                            "origins.profiles[{index}].bridge.allowed_targets[{target_index}].space_type '{space_type}' is not valid"
                        )));
                    }

                    if let Some(visibility) = &target.visibility
                        && !contains_allowed_value(
                            visibility,
                            crate::generated_contract::ORIGIN_VISIBILITIES,
                        )
                    {
                        errors.push(ValidationError::Custom(format!(
                            "origins.profiles[{index}].bridge.allowed_targets[{target_index}].visibility '{visibility}' is not valid"
                        )));
                    }
                }
            }
        }
    }
}

fn validate_detection(
    ext: &crate::extensions::Extensions,
    errors: &mut Vec<ValidationError>,
    warnings: &mut Vec<String>,
) {
    if let Some(detection) = &ext.detection {
        if let Some(prompt_injection) = &detection.prompt_injection {
            if matches!(prompt_injection.max_scan_bytes, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.prompt_injection.max_scan_bytes must be >= 1".to_string(),
                ));
            }

            let warn_level = prompt_injection
                .warn_at_or_above
                .unwrap_or(crate::extensions::DetectionLevel::Suspicious);
            let block_level = prompt_injection
                .block_at_or_above
                .unwrap_or(crate::extensions::DetectionLevel::High);
            if block_level < warn_level {
                warnings.push(
                    "detection.prompt_injection: block_at_or_above is less strict than warn_at_or_above"
                        .to_string(),
                );
            }
        }

        if let Some(jailbreak) = &detection.jailbreak {
            if matches!(jailbreak.block_threshold, Some(value) if value > 100) {
                errors.push(ValidationError::Custom(
                    "detection.jailbreak.block_threshold must be between 0 and 100".to_string(),
                ));
            }
            if matches!(jailbreak.warn_threshold, Some(value) if value > 100) {
                errors.push(ValidationError::Custom(
                    "detection.jailbreak.warn_threshold must be between 0 and 100".to_string(),
                ));
            }
            if matches!(jailbreak.max_input_bytes, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.jailbreak.max_input_bytes must be >= 1".to_string(),
                ));
            }

            let block_threshold = jailbreak.block_threshold.unwrap_or(80);
            let warn_threshold = jailbreak.warn_threshold.unwrap_or(50);
            if block_threshold < warn_threshold {
                warnings.push(
                    "detection.jailbreak: block_threshold is lower than warn_threshold".to_string(),
                );
            }
        }

        if let Some(threat_intel) = &detection.threat_intel {
            if let Some(similarity_threshold) = threat_intel.similarity_threshold
                && !(0.0..=1.0).contains(&similarity_threshold)
            {
                errors.push(ValidationError::Custom(
                    "detection.threat_intel.similarity_threshold must be between 0.0 and 1.0"
                        .to_string(),
                ));
            }
            if matches!(threat_intel.top_k, Some(0)) {
                errors.push(ValidationError::Custom(
                    "detection.threat_intel.top_k must be >= 1".to_string(),
                ));
            }
        }
    }
}

fn validate_regex(pattern: &str, path: &str, errors: &mut Vec<ValidationError>) {
    if let Err(error) = Regex::new(pattern) {
        errors.push(ValidationError::InvalidRegex {
            field: path.to_string(),
            pattern: pattern.to_string(),
            message: error.to_string(),
        });
    }
}

fn is_valid_duration(value: &str) -> bool {
    matches!(
        value.as_bytes(),
        [b'0'..=b'9', .., b's' | b'm' | b'h' | b'd']
    ) && value[..value.len() - 1]
        .bytes()
        .all(|byte| byte.is_ascii_digit())
}

fn contains_allowed_value(value: &str, allowed: &[&str]) -> bool {
    allowed.contains(&value)
}
