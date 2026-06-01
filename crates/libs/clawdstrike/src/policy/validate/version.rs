//! Schema-version parsing and feature-gating helpers.

use crate::error::{Error, Result};

use super::super::POLICY_SUPPORTED_SCHEMA_VERSIONS;

pub(in crate::policy) fn validate_policy_version(version: &str) -> Result<()> {
    if parse_semver_strict(version).is_none() {
        return Err(Error::InvalidPolicyVersion {
            version: version.to_string(),
        });
    }

    if !POLICY_SUPPORTED_SCHEMA_VERSIONS.contains(&version) {
        return Err(Error::UnsupportedPolicyVersion {
            found: version.to_string(),
            supported: POLICY_SUPPORTED_SCHEMA_VERSIONS.join(", "),
        });
    }

    Ok(())
}

fn parse_semver_strict(version: &str) -> Option<(u64, u64, u64)> {
    let mut parts = version.split('.');
    let major = parse_semver_part(parts.next()?)?;
    let minor = parse_semver_part(parts.next()?)?;
    let patch = parse_semver_part(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }

    Some((major, minor, patch))
}

fn semver_at_least(version: &str, minimum: (u64, u64, u64)) -> bool {
    let Some(found) = parse_semver_strict(version) else {
        return false;
    };
    found >= minimum
}

pub(in crate::policy) fn policy_version_supports_posture(version: &str) -> bool {
    semver_at_least(version, (1, 2, 0))
}

/// Returns true if the given schema version supports origin-aware enforcement.
pub fn policy_version_supports_origins(version: &str) -> bool {
    semver_at_least(version, (1, 4, 0))
}

/// Returns true if the given schema version supports brokered egress policy.
pub fn policy_version_supports_broker(version: &str) -> bool {
    semver_at_least(version, (1, 5, 0))
}

fn parse_semver_part(part: &str) -> Option<u64> {
    if part.is_empty() {
        return None;
    }
    if part.len() > 1 && part.starts_with('0') {
        return None;
    }
    if !part.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    part.parse().ok()
}
