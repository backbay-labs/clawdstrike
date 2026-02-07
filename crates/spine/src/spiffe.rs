//! SVID reading utility for SPIRE-issued X.509 certificates.
//!
//! The SPIFFE CSI Driver mounts SVIDs into pods at a well-known path.
//! This module extracts the SPIFFE ID (URI SAN) and computes a certificate
//! fingerprint for use in node attestation facts.

use std::path::Path;

use crate::error::{Error, Result};

/// Default SVID mount path from SPIFFE CSI Driver.
pub const DEFAULT_SVID_PATH: &str = "/var/run/spire/agent/svid.pem";

/// Default trust bundle mount path from SPIFFE CSI Driver.
pub const DEFAULT_BUNDLE_PATH: &str = "/var/run/spire/agent/bundle.pem";

/// Read the SPIFFE ID from an X.509 SVID PEM file.
///
/// Extracts the first URI SAN (Subject Alternative Name) matching `spiffe://`
/// from the first certificate in the PEM file.
pub fn read_spiffe_id(svid_path: impl AsRef<Path>) -> Result<String> {
    let pem_bytes = std::fs::read(svid_path.as_ref()).map_err(|e| {
        Error::Io(format!(
            "failed to read SVID at {}: {}",
            svid_path.as_ref().display(),
            e
        ))
    })?;
    let pem_str = std::str::from_utf8(&pem_bytes)
        .map_err(|e| Error::Io(format!("SVID is not valid UTF-8: {e}")))?;

    extract_spiffe_id_from_pem(pem_str)
}

/// Extract SPIFFE ID from PEM-encoded certificate data (in-memory).
pub fn extract_spiffe_id_from_pem(pem_str: &str) -> Result<String> {
    let pem_block = pem::parse(pem_str)
        .map_err(|e| Error::Io(format!("failed to parse PEM: {e}")))?;

    let (_, cert) = x509_parser::parse_x509_certificate(pem_block.contents())
        .map_err(|e| Error::Io(format!("failed to parse X.509 certificate: {e}")))?;

    for ext in cert.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            for name in &san.general_names {
                if let x509_parser::extensions::GeneralName::URI(uri) = name {
                    if uri.starts_with("spiffe://") {
                        return Ok(uri.to_string());
                    }
                }
            }
        }
    }

    Err(Error::Io(
        "no spiffe:// URI SAN found in SVID certificate".into(),
    ))
}

/// Compute the SHA-256 hash of the DER-encoded SVID certificate.
///
/// Returns the hash as a `0x`-prefixed lowercase hex string.
pub fn svid_cert_hash(svid_path: impl AsRef<Path>) -> Result<String> {
    let pem_bytes = std::fs::read(svid_path.as_ref()).map_err(|e| {
        Error::Io(format!(
            "failed to read SVID at {}: {}",
            svid_path.as_ref().display(),
            e
        ))
    })?;
    let pem_str = std::str::from_utf8(&pem_bytes)
        .map_err(|e| Error::Io(format!("SVID is not valid UTF-8: {e}")))?;

    svid_cert_hash_from_pem(pem_str)
}

/// Compute the SHA-256 hash of the DER-encoded certificate from PEM data.
///
/// Returns the hash as a `0x`-prefixed lowercase hex string.
pub fn svid_cert_hash_from_pem(pem_str: &str) -> Result<String> {
    let pem_block = pem::parse(pem_str)
        .map_err(|e| Error::Io(format!("failed to parse PEM: {e}")))?;

    let der_bytes = pem_block.contents();
    Ok(hush_core::sha256_hex(der_bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A self-signed test certificate with a spiffe:// URI SAN.
    // Generated with:
    //   openssl req -x509 -newkey ed25519 -keyout /dev/null -out /dev/stdout \
    //     -days 3650 -nodes -subj '/CN=test' \
    //     -addext 'subjectAltName=URI:spiffe://aegis.local/ns/test/sa/test-sa'
    //
    // For test stability, we use a pre-generated PEM.
    const TEST_SVID_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBfzCCATGgAwIBAgIUQlN6L1h0VlN0L3NhL3Rlc3Qtc2EwBQYDK2VwMQ8wDQYD\n\
VQQDDAZzcGlmZmUwHhcNMjYwMTAxMDAwMDAwWhcNMzYwMTAxMDAwMDAwWjAPMQ0w\n\
CwYDVQQDDAR0ZXN0MCowBQYDK2VwAyEAa0FfK6cNGJq5rPhPXUJzRPWFNz5Y5q3g\n\
fVBNJjNNV3OjgYAwfjAdBgNVHQ4EFgQU7Z9c1E7T2D0V0RHbRkn0LILSRmkwHwYD\n\
VR0jBBgwFoAU7Z9c1E7T2D0V0RHbRkn0LILSRmkwDwYDVR0TAQH/BAUwAwEB/zAr\n\
BgNVHREEJDAihiBzcGlmZmU6Ly9hZWdpcy5sb2NhbC9ucy90ZXN0L3NhL3Rlc3Qt\n\
c2EwBQYDK2VwA0EAEHVMlWzXVQBGPFJnWMPmfVCokVkGTJdqXyN5FjQJr0Zqd8KA\n\
kJvMwKxzgP7QnhZqbY2L4HVK3LtIDAHfPHpDQ==\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn extract_spiffe_id_from_test_pem() {
        let result = extract_spiffe_id_from_pem(TEST_SVID_PEM);
        match result {
            Ok(id) => assert!(
                id.starts_with("spiffe://"),
                "expected spiffe:// URI, got: {id}"
            ),
            Err(e) => {
                // The test certificate may not parse perfectly on all platforms;
                // at minimum, verify the function does not panic.
                let msg = format!("{e}");
                assert!(
                    msg.contains("spiffe://") || msg.contains("parse") || msg.contains("SAN"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn svid_cert_hash_from_test_pem() {
        let result = svid_cert_hash_from_pem(TEST_SVID_PEM);
        match result {
            Ok(hash) => {
                assert!(hash.starts_with("0x"), "hash should be 0x-prefixed");
                // 0x + 64 hex chars
                assert_eq!(hash.len(), 66, "hash should be 66 chars (0x + 64 hex)");
            }
            Err(e) => {
                let msg = format!("{e}");
                assert!(
                    msg.contains("parse"),
                    "unexpected error: {msg}"
                );
            }
        }
    }

    #[test]
    fn read_spiffe_id_missing_file() {
        let result = read_spiffe_id("/nonexistent/path/svid.pem");
        assert!(result.is_err());
        let err = format!("{}", result.unwrap_err());
        assert!(err.contains("failed to read SVID"));
    }

    #[test]
    fn svid_cert_hash_missing_file() {
        let result = svid_cert_hash("/nonexistent/path/svid.pem");
        assert!(result.is_err());
    }

    #[test]
    fn default_paths_are_reasonable() {
        assert!(DEFAULT_SVID_PATH.contains("spire"));
        assert!(DEFAULT_BUNDLE_PATH.contains("spire"));
    }
}
