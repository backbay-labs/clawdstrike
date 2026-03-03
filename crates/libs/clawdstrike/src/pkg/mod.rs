//! Package manager core library for `.cpkg` packages.
//!
//! Provides manifest parsing, archive creation/extraction, a local package
//! store, lockfile management, and cryptographic integrity verification.

use std::path::Path;

pub mod archive;
pub mod index;
pub mod integrity;
pub mod lockfile;
pub mod manifest;
pub mod merkle;
pub mod resolver;
pub mod resolver_deps;
pub mod store;
#[cfg(feature = "wasm-plugin-runtime")]
pub mod test_runner;
pub mod trust;
pub mod version;

/// Normalize package names for filesystem/cache keys.
///
/// Uses collision-free prefixes for scoped vs unscoped names.
///
/// - `@scope/name` -> `s--scope%2Fname`
/// - `plain-name`  -> `u--plain-name`
pub(crate) fn normalize_package_name(name: &str) -> String {
    if let Some(rest) = name.strip_prefix('@') {
        // Encode the scoped path separator so distinct scoped names cannot
        // collide on the same filesystem key.
        format!("s--{}", encode_url_path_segment(rest))
    } else {
        format!("u--{}", encode_url_path_segment(name))
    }
}

/// Percent-encode a package name for use in a single URL path segment.
pub(crate) fn encode_url_path_segment(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &byte in name.as_bytes() {
        if matches!(
            byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
        ) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0F) as usize] as char);
        }
    }
    out
}

/// Normalize a relative path into a stable forward-slash separated key form.
pub(crate) fn normalize_relative_path_for_key(path: &Path) -> String {
    path.components()
        .map(|c| c.as_os_str().to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join("/")
}

pub use archive::{content_hash, pack, unpack};
pub use index::{
    IndexVersion, MockRegistryIndex, PackageIndexEntry, RegistryIndex, DEFAULT_REGISTRY_URL,
};
pub use integrity::{sign_package, verify_package, PackageSignature};
pub use lockfile::{LockedDependency, LockedPackage, Lockfile};
pub use manifest::{parse_pkg_manifest_toml, PkgManifest, PkgType};
pub use resolver::PackagePolicyResolver;
pub use resolver_deps::{
    lockfile_from_resolution, DependencyResolver, PkgId, ResolvedPackage, ResolverError,
};
pub use store::{InstalledPackage, PackageStore, StoreMetadata};
#[cfg(feature = "wasm-plugin-runtime")]
pub use test_runner::{
    parse_guard_test_file, parse_guard_test_suite, run_guard_tests, GuardTestFixture,
    GuardTestResult, GuardTestSuite,
};
pub use trust::{check_trust, compute_trust_level, TrustError, TrustLevel, TrustRequirement};
pub use version::{parse_version, parse_version_req, VersionReq};

#[cfg(test)]
mod tests {
    use super::{encode_url_path_segment, normalize_package_name};

    #[test]
    fn encode_url_path_segment_encodes_all_non_unreserved_bytes() {
        assert_eq!(
            encode_url_path_segment("@acme/firewall"),
            "%40acme%2Ffirewall"
        );
        assert_eq!(
            encode_url_path_segment("name with?#[]"),
            "name%20with%3F%23%5B%5D"
        );
        assert_eq!(encode_url_path_segment("pkg%v1"), "pkg%25v1");
    }

    #[test]
    fn encode_url_path_segment_encodes_utf8_bytes() {
        assert_eq!(encode_url_path_segment("caf\u{00e9}"), "caf%C3%A9");
    }

    #[test]
    fn normalize_package_name_encodes_unscoped_names_too() {
        assert_eq!(normalize_package_name("simple-name"), "u--simple-name");
        assert_eq!(normalize_package_name("pkg%v1"), "u--pkg%25v1");
    }
}
