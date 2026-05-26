use super::manifest::{is_update_available, verify_manifest_signature};
use super::types::{OtaManifest, OTA_SCHEMA_VERSION};
use hush_core::canonical::canonicalize;
use hush_core::Keypair;

#[test]
fn update_availability_uses_semver() {
    assert!(matches!(
        is_update_available(Some("0.1.0"), "0.1.1"),
        Ok(true)
    ));
    assert!(matches!(
        is_update_available(Some("0.1.1"), "0.1.1"),
        Ok(false)
    ));
    assert!(matches!(
        is_update_available(Some("0.2.0"), "0.1.9"),
        Ok(false)
    ));
}

#[test]
fn verify_manifest_signature_accepts_trusted_embedded_key() {
    let keypair = Keypair::generate();
    let mut manifest = serde_json::json!({
        "schema_version": OTA_SCHEMA_VERSION,
        "release_version": "1.2.3",
        "published_at": "2026-01-01T00:00:00Z",
        "channel": "stable",
        "artifacts": [{
            "platform": "darwin-aarch64",
            "url": "https://example.com/hushd",
            "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "size": 123
        }],
        "public_key": keypair.public_key().to_hex()
    });
    let canonical = match canonicalize(&manifest) {
        Ok(value) => value,
        Err(err) => panic!("manifest canonicalization should succeed: {err}"),
    };
    let signature = keypair.sign(canonical.as_bytes()).to_hex();
    manifest["signature"] = serde_json::Value::String(signature);

    let parsed: OtaManifest = match serde_json::from_value(manifest.clone()) {
        Ok(value) => value,
        Err(err) => panic!("manifest parse should succeed: {err}"),
    };
    let signer = match verify_manifest_signature(&manifest, &parsed, &[keypair.public_key()]) {
        Ok(value) => value,
        Err(err) => panic!("signature verification should succeed: {err}"),
    };
    assert_eq!(signer.to_hex(), keypair.public_key().to_hex());
}
