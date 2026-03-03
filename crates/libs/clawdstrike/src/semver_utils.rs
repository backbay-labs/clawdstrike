/// Parse a strict `major.minor.patch` semantic version where all components are
/// unsigned decimal integers.
pub(crate) fn parse_strict_semver(value: &str) -> Option<[u32; 3]> {
    let parsed = semver::Version::parse(value).ok()?;

    // Strict in this codebase means exactly major.minor.patch without
    // pre-release or build metadata suffixes.
    if !parsed.pre.is_empty() || !parsed.build.is_empty() {
        return None;
    }

    let major = u32::try_from(parsed.major).ok()?;
    let minor = u32::try_from(parsed.minor).ok()?;
    let patch = u32::try_from(parsed.patch).ok()?;
    Some([major, minor, patch])
}

pub(crate) fn is_strict_semver(value: &str) -> bool {
    parse_strict_semver(value).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_strict_semver_accepts_plain_numeric_triplets() {
        assert_eq!(parse_strict_semver("0.0.0"), Some([0, 0, 0]));
        assert_eq!(parse_strict_semver("1.2.3"), Some([1, 2, 3]));
        assert_eq!(
            parse_strict_semver("4294967295.1.2"),
            Some([u32::MAX, 1, 2])
        );
    }

    #[test]
    fn parse_strict_semver_rejects_leading_zero_components() {
        assert_eq!(parse_strict_semver("01.2.3"), None);
        assert_eq!(parse_strict_semver("1.02.3"), None);
        assert_eq!(parse_strict_semver("1.2.03"), None);
    }

    #[test]
    fn parse_strict_semver_rejects_prerelease_or_build_suffixes() {
        assert_eq!(parse_strict_semver("1.2.3-alpha"), None);
        assert_eq!(parse_strict_semver("1.2.3+build"), None);
        assert_eq!(parse_strict_semver("1.2.3-alpha+build"), None);
    }

    #[test]
    fn parse_strict_semver_rejects_values_outside_u32_range() {
        assert_eq!(parse_strict_semver("4294967296.0.0"), None);
        assert_eq!(parse_strict_semver("0.4294967296.0"), None);
        assert_eq!(parse_strict_semver("0.0.4294967296"), None);
    }
}
