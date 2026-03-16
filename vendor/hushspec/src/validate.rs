use crate::schema::HushSpec;
use crate::version;
use std::collections::HashSet;

/// Result of validating a HushSpec document.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// Errors that make the document invalid.
    pub errors: Vec<ValidationError>,
    /// Non-fatal observations about the document.
    pub warnings: Vec<String>,
}

impl ValidationResult {
    /// Returns `true` if no validation errors were found.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }
}

/// A validation error found in a HushSpec document.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ValidationError {
    /// The `hushspec` version string is not recognized.
    #[error("unsupported hushspec version: {0}")]
    UnsupportedVersion(String),
    /// Two secret patterns share the same name.
    #[error("duplicate secret pattern name: {0}")]
    DuplicatePatternName(String),
    /// A structural constraint was violated.
    #[error("{0}")]
    Custom(String),
}

/// Validate a parsed HushSpec document for structural correctness.
///
/// Checks version support, field constraints, and extension validity.
/// Regex pattern validation is left to engines at load time.
#[must_use = "validation result should be checked"]
pub fn validate(spec: &HushSpec) -> ValidationResult {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    // Check version
    if !version::is_supported(&spec.hushspec) {
        errors.push(ValidationError::UnsupportedVersion(spec.hushspec.clone()));
    }

    // Validate rules if present
    if let Some(rules) = &spec.rules {
        // Check secret pattern name uniqueness
        if let Some(sp) = &rules.secret_patterns {
            let mut seen = HashSet::new();
            for p in &sp.patterns {
                if !seen.insert(&p.name) {
                    errors.push(ValidationError::DuplicatePatternName(p.name.clone()));
                }
            }
        }

        // Warn if no rules are configured
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

    // Validate extensions if present
    if let Some(ext) = &spec.extensions {
        validate_posture(ext, &mut errors);
        validate_origins(ext, &mut errors);
        validate_detection(ext, &mut errors, &mut warnings);
    }

    ValidationResult { errors, warnings }
}

fn validate_posture(ext: &crate::extensions::Extensions, errors: &mut Vec<ValidationError>) {
    if let Some(posture) = &ext.posture {
        // initial must reference a state
        if !posture.states.contains_key(&posture.initial) {
            errors.push(ValidationError::Custom(format!(
                "posture.initial '{}' does not reference a defined state",
                posture.initial
            )));
        }
        // transitions must reference valid states
        for (i, t) in posture.transitions.iter().enumerate() {
            if t.from != "*" && !posture.states.contains_key(&t.from) {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{i}].from '{}' does not reference a defined state",
                    t.from
                )));
            }
            if !posture.states.contains_key(&t.to) {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{i}].to '{}' does not reference a defined state",
                    t.to
                )));
            }
            if t.to == "*" {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{i}].to cannot be '*'"
                )));
            }
            // timeout requires after
            if t.on == crate::extensions::TransitionTrigger::Timeout && t.after.is_none() {
                errors.push(ValidationError::Custom(format!(
                    "posture.transitions[{i}]: timeout trigger requires 'after' field"
                )));
            }
        }
        // budgets must be non-negative
        for (state_name, state) in &posture.states {
            for (key, &value) in &state.budgets {
                if value < 0 {
                    errors.push(ValidationError::Custom(format!(
                        "posture.states.{state_name}.budgets.{key} must be non-negative, got {value}"
                    )));
                }
            }
        }
    }
}

fn validate_origins(ext: &crate::extensions::Extensions, errors: &mut Vec<ValidationError>) {
    if let Some(origins) = &ext.origins {
        let mut seen_ids = HashSet::new();
        for profile in &origins.profiles {
            if !seen_ids.insert(&profile.id) {
                errors.push(ValidationError::Custom(format!(
                    "duplicate origin profile id: '{}'",
                    profile.id
                )));
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
        if let Some(pi) = &detection.prompt_injection
            && pi.block_at_or_above < pi.warn_at_or_above
        {
            warnings.push(
                "detection.prompt_injection: block_at_or_above is less strict than warn_at_or_above"
                    .to_string(),
            );
        }
        if let Some(jb) = &detection.jailbreak
            && jb.block_threshold < jb.warn_threshold
        {
            warnings.push(
                "detection.jailbreak: block_threshold is lower than warn_threshold".to_string(),
            );
        }
        if let Some(ti) = &detection.threat_intel
            && !(0.0..=1.0).contains(&ti.similarity_threshold)
        {
            errors.push(ValidationError::Custom(
                "detection.threat_intel.similarity_threshold must be between 0.0 and 1.0"
                    .to_string(),
            ));
        }
    }
}
