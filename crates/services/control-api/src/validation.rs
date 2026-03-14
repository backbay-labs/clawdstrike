//! Input length validation helpers for API route handlers.
//!
//! All string fields accepted from clients must be bounded to prevent storage
//! abuse.  These helpers return `ApiError::BadRequest` with a descriptive
//! message on validation failure.

use crate::error::ApiError;

/// Maximum byte length for general string fields (name, external_id, policy_name, etc.).
const MAX_STRING_LEN: usize = 255;

/// Maximum byte length for Ed25519 public key hex strings.
/// Ed25519 hex-encoded public keys are 64 characters; we allow some headroom.
const MAX_PUBLIC_KEY_LEN: usize = 128;

/// Maximum byte length for trust_level values.
const MAX_TRUST_LEVEL_LEN: usize = 32;

/// Maximum byte length for serialized metadata JSON.
const MAX_METADATA_BYTES: usize = 65_536;

/// Known valid trust level values.
const KNOWN_TRUST_LEVELS: &[&str] = &["untrusted", "low", "medium", "high", "system"];

/// Validate that a required string field does not exceed `max_len` bytes.
pub fn validate_string_length(
    field_name: &str,
    value: &str,
    max_len: usize,
) -> Result<(), ApiError> {
    if value.len() > max_len {
        return Err(ApiError::BadRequest(format!(
            "{field_name} exceeds maximum length of {max_len} characters"
        )));
    }
    Ok(())
}

/// Validate an optional string field's length when present.
pub fn validate_optional_string_length(
    field_name: &str,
    value: Option<&str>,
    max_len: usize,
) -> Result<(), ApiError> {
    if let Some(v) = value {
        validate_string_length(field_name, v, max_len)?;
    }
    Ok(())
}

/// Validate a `name` field (max 255 characters).
pub fn validate_name(value: &str) -> Result<(), ApiError> {
    validate_string_length("name", value, MAX_STRING_LEN)
}

/// Validate an `external_id` field (max 255 characters).
pub fn validate_external_id(value: Option<&str>) -> Result<(), ApiError> {
    validate_optional_string_length("external_id", value, MAX_STRING_LEN)
}

/// Validate a `policy_name` field (max 255 characters).
pub fn validate_policy_name(value: Option<&str>) -> Result<(), ApiError> {
    validate_optional_string_length("policy_name", value, MAX_STRING_LEN)
}

/// Validate a `public_key` field (max 128 characters).
pub fn validate_public_key_length(value: &str) -> Result<(), ApiError> {
    validate_string_length("public_key", value, MAX_PUBLIC_KEY_LEN)
}

/// Validate a `trust_level` field (max 32 characters, must be a known value).
pub fn validate_trust_level(value: Option<&str>) -> Result<(), ApiError> {
    if let Some(v) = value {
        validate_string_length("trust_level", v, MAX_TRUST_LEVEL_LEN)?;
        if !KNOWN_TRUST_LEVELS.contains(&v) {
            return Err(ApiError::BadRequest(format!(
                "trust_level must be one of: {}",
                KNOWN_TRUST_LEVELS.join(", ")
            )));
        }
    }
    Ok(())
}

/// Clamp legacy trust levels to the directory contract.
pub fn sanitize_trust_level(value: &str) -> &str {
    if KNOWN_TRUST_LEVELS.contains(&value) {
        value
    } else {
        "medium"
    }
}

/// Validate that serialized metadata JSON does not exceed 64 KiB.
pub fn validate_metadata(value: Option<&serde_json::Value>) -> Result<(), ApiError> {
    if let Some(v) = value {
        let serialized = serde_json::to_string(v).unwrap_or_default();
        if serialized.len() > MAX_METADATA_BYTES {
            return Err(ApiError::BadRequest(format!(
                "metadata exceeds maximum size of {MAX_METADATA_BYTES} bytes"
            )));
        }
    }
    Ok(())
}

/// Validate an `agent_id` field (max 255 characters).
pub fn validate_agent_id(value: &str) -> Result<(), ApiError> {
    validate_string_length("agent_id", value, MAX_STRING_LEN)
}

/// Validate a `runtime_name` / display name field (max 255 characters).
pub fn validate_runtime_name(value: &str) -> Result<(), ApiError> {
    validate_string_length("runtime_name", value, MAX_STRING_LEN)
}

/// Validate a `hostname` field (max 255 characters).
pub fn validate_hostname(value: &str) -> Result<(), ApiError> {
    validate_string_length("hostname", value, MAX_STRING_LEN)
}

/// Validate a `version` field (max 255 characters).
pub fn validate_version(value: &str) -> Result<(), ApiError> {
    validate_string_length("version", value, MAX_STRING_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_string_length() {
        assert!(validate_string_length("test", "hello", 255).is_ok());
        assert!(validate_string_length("test", "", 255).is_ok());
    }

    #[test]
    fn rejects_oversized_string() {
        let long = "a".repeat(256);
        let err = validate_string_length("name", &long, 255).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(msg) if msg.contains("name")));
    }

    #[test]
    fn accepts_string_at_exact_limit() {
        let exact = "a".repeat(255);
        assert!(validate_string_length("name", &exact, 255).is_ok());
    }

    #[test]
    fn optional_none_passes() {
        assert!(validate_optional_string_length("field", None, 10).is_ok());
    }

    #[test]
    fn optional_some_validates() {
        assert!(validate_optional_string_length("field", Some("ok"), 10).is_ok());
        assert!(validate_optional_string_length("field", Some("too-long-value"), 5).is_err());
    }

    #[test]
    fn validate_name_enforces_limit() {
        assert!(validate_name("my-node").is_ok());
        assert!(validate_name(&"x".repeat(256)).is_err());
    }

    #[test]
    fn validate_public_key_length_enforces_limit() {
        // Valid Ed25519 hex key is 64 chars
        let valid = "a".repeat(64);
        assert!(validate_public_key_length(&valid).is_ok());
        // Over 128 chars rejected
        let too_long = "b".repeat(129);
        assert!(validate_public_key_length(&too_long).is_err());
    }

    #[test]
    fn validate_trust_level_accepts_known_values() {
        assert!(validate_trust_level(Some("untrusted")).is_ok());
        assert!(validate_trust_level(Some("low")).is_ok());
        assert!(validate_trust_level(Some("medium")).is_ok());
        assert!(validate_trust_level(Some("high")).is_ok());
        assert!(validate_trust_level(Some("system")).is_ok());
        assert!(validate_trust_level(None).is_ok());
    }

    #[test]
    fn validate_trust_level_rejects_unknown_values() {
        let err = validate_trust_level(Some("ultra")).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(msg) if msg.contains("trust_level")));
        assert!(validate_trust_level(Some("standard")).is_err());
    }

    #[test]
    fn validate_trust_level_rejects_oversized_values() {
        let long = "a".repeat(33);
        assert!(validate_trust_level(Some(&long)).is_err());
    }

    #[test]
    fn sanitize_trust_level_preserves_known_values() {
        assert_eq!(sanitize_trust_level("untrusted"), "untrusted");
        assert_eq!(sanitize_trust_level("low"), "low");
        assert_eq!(sanitize_trust_level("medium"), "medium");
        assert_eq!(sanitize_trust_level("high"), "high");
        assert_eq!(sanitize_trust_level("system"), "system");
    }

    #[test]
    fn sanitize_trust_level_clamps_legacy_values() {
        assert_eq!(sanitize_trust_level("verified"), "medium");
        assert_eq!(sanitize_trust_level("custom"), "medium");
    }

    #[test]
    fn validate_metadata_accepts_small_json() {
        let small = serde_json::json!({"key": "value"});
        assert!(validate_metadata(Some(&small)).is_ok());
    }

    #[test]
    fn validate_metadata_rejects_oversized_json() {
        let large_string = "x".repeat(70_000);
        let large = serde_json::json!({"data": large_string});
        let err = validate_metadata(Some(&large)).unwrap_err();
        assert!(matches!(err, ApiError::BadRequest(msg) if msg.contains("metadata")));
    }

    #[test]
    fn validate_metadata_accepts_none() {
        assert!(validate_metadata(None).is_ok());
    }
}
