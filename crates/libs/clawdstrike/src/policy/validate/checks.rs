//! Field/format validators: glob, domain-glob, and placeholder checks.

use globset::GlobBuilder;

use crate::error::PolicyFieldError;
use crate::placeholders::env_var_for_placeholder;

pub(super) fn validate_globs(errors: &mut Vec<PolicyFieldError>, field: &str, patterns: &[String]) {
    for (idx, pattern) in patterns.iter().enumerate() {
        if let Err(e) = glob::Pattern::new(pattern) {
            errors.push(PolicyFieldError::new(
                format!("{}[{}]", field, idx),
                format!("invalid glob {:?}: {}", pattern, e),
            ));
        }
    }
}

pub(super) fn validate_domain_globs(
    errors: &mut Vec<PolicyFieldError>,
    field: &str,
    patterns: &[String],
) {
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

pub(super) fn validate_placeholders_in_strings(
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
