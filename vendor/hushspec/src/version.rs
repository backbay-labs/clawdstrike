/// Current HushSpec specification version.
pub const HUSHSPEC_VERSION: &str = "0.1.0";

/// All supported HushSpec specification versions.
pub const HUSHSPEC_SUPPORTED_VERSIONS: &[&str] = &["0.1.0"];

/// Returns true if the given version string is supported.
#[must_use]
pub fn is_supported(version: &str) -> bool {
    HUSHSPEC_SUPPORTED_VERSIONS.contains(&version)
}
