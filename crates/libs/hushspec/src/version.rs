pub const HUSHSPEC_VERSION: &str = "0.1.0";

pub const HUSHSPEC_SUPPORTED_VERSIONS: &[&str] = &["0.1.0"];

#[must_use]
pub fn is_supported(version: &str) -> bool {
    HUSHSPEC_SUPPORTED_VERSIONS.contains(&version)
}
