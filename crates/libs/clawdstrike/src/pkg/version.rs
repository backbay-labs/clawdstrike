//! Semver version constraint parsing and matching for package dependencies.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// A parsed semver version requirement (e.g. `^1.2.3`, `~1.0`, `>=1.0.0, <2.0.0`).
///
/// Wraps the `semver::VersionReq` type and provides convenience methods for
/// matching against version strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionReq {
    inner: semver::VersionReq,
    /// The original string representation, preserved for deterministic serialization.
    raw: String,
}

impl VersionReq {
    /// Parse a version constraint string.
    ///
    /// Supported formats:
    /// - `^1.2.3` (caret / compatible)
    /// - `~1.2.0` (tilde / patch-level)
    /// - `>=1.0.0, <2.0.0` (range)
    /// - `=1.2.3` (exact)
    /// - `*` (any version)
    pub fn parse(s: &str) -> Result<Self> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(Error::PkgError("empty version constraint".to_string()));
        }
        let inner = semver::VersionReq::parse(trimmed).map_err(|e| {
            Error::PkgError(format!("invalid version constraint '{}': {}", trimmed, e))
        })?;
        Ok(Self {
            inner,
            raw: trimmed.to_string(),
        })
    }

    /// Check whether a version string satisfies this constraint.
    pub fn matches(&self, version: &str) -> bool {
        match semver::Version::parse(version) {
            Ok(v) => self.inner.matches(&v),
            Err(_) => false,
        }
    }

    /// Check whether a parsed `semver::Version` satisfies this constraint.
    pub fn matches_version(&self, version: &semver::Version) -> bool {
        self.inner.matches(version)
    }

    /// Return the underlying `semver::VersionReq`.
    pub fn inner(&self) -> &semver::VersionReq {
        &self.inner
    }
}

impl fmt::Display for VersionReq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for VersionReq {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for VersionReq {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for VersionReq {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// Parse a version constraint string. Convenience function wrapping `VersionReq::parse`.
pub fn parse_version_req(s: &str) -> Result<VersionReq> {
    VersionReq::parse(s)
}

/// Parse a strict semver version string into a `semver::Version`.
pub fn parse_version(s: &str) -> Result<semver::Version> {
    semver::Version::parse(s)
        .map_err(|e| Error::PkgError(format!("invalid version '{}': {}", s, e)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_caret() {
        let req = VersionReq::parse("^1.2.3").unwrap();
        assert!(req.matches("1.2.3"));
        assert!(req.matches("1.2.4"));
        assert!(req.matches("1.9.0"));
        assert!(!req.matches("2.0.0"));
        assert!(!req.matches("1.2.2"));
    }

    #[test]
    fn parse_tilde() {
        let req = VersionReq::parse("~1.2.0").unwrap();
        assert!(req.matches("1.2.0"));
        assert!(req.matches("1.2.9"));
        assert!(!req.matches("1.3.0"));
        assert!(!req.matches("1.1.0"));
    }

    #[test]
    fn parse_range() {
        let req = VersionReq::parse(">=1.0.0, <2.0.0").unwrap();
        assert!(req.matches("1.0.0"));
        assert!(req.matches("1.5.0"));
        assert!(req.matches("1.99.99"));
        assert!(!req.matches("2.0.0"));
        assert!(!req.matches("0.9.9"));
    }

    #[test]
    fn parse_exact() {
        let req = VersionReq::parse("=1.2.3").unwrap();
        assert!(req.matches("1.2.3"));
        assert!(!req.matches("1.2.4"));
        assert!(!req.matches("1.2.2"));
    }

    #[test]
    fn parse_wildcard() {
        let req = VersionReq::parse("*").unwrap();
        assert!(req.matches("0.0.1"));
        assert!(req.matches("1.0.0"));
        assert!(req.matches("99.99.99"));
    }

    #[test]
    fn parse_greater_equal() {
        let req = VersionReq::parse(">=2.0.0").unwrap();
        assert!(req.matches("2.0.0"));
        assert!(req.matches("3.0.0"));
        assert!(!req.matches("1.9.9"));
    }

    #[test]
    fn parse_less_than() {
        let req = VersionReq::parse("<1.0.0").unwrap();
        assert!(req.matches("0.9.9"));
        assert!(!req.matches("1.0.0"));
    }

    #[test]
    fn parse_caret_partial() {
        // ^1.2 should match 1.2.0 through <2.0.0
        let req = VersionReq::parse("^1.2").unwrap();
        assert!(req.matches("1.2.0"));
        assert!(req.matches("1.9.0"));
        assert!(!req.matches("2.0.0"));
    }

    #[test]
    fn rejects_empty() {
        let err = VersionReq::parse("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn rejects_garbage() {
        let err = VersionReq::parse("not-a-version").unwrap_err();
        assert!(err.to_string().contains("invalid version constraint"));
    }

    #[test]
    fn invalid_version_does_not_match() {
        let req = VersionReq::parse("^1.0.0").unwrap();
        assert!(!req.matches("not-a-version"));
        assert!(!req.matches(""));
    }

    #[test]
    fn display_preserves_original() {
        let req = VersionReq::parse("^1.2.3").unwrap();
        assert_eq!(req.to_string(), "^1.2.3");

        let req2 = VersionReq::parse(">=1.0.0, <2.0.0").unwrap();
        assert_eq!(req2.to_string(), ">=1.0.0, <2.0.0");
    }

    #[test]
    fn serde_roundtrip() {
        let req = VersionReq::parse("^1.2.3").unwrap();
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, "\"^1.2.3\"");
        let parsed: VersionReq = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn from_str() {
        let req: VersionReq = "~2.0.0".parse().unwrap();
        assert!(req.matches("2.0.5"));
        assert!(!req.matches("2.1.0"));
    }

    #[test]
    fn parse_version_ok() {
        let v = parse_version("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn parse_version_invalid() {
        let err = parse_version("1.2").unwrap_err();
        assert!(err.to_string().contains("invalid version"));
    }
}
