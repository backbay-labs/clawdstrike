//! GET /api/v1/packages/{name}/{version}/attestation
//!
//! Returns the publish attestation for a specific package version, including
//! the publisher signature, registry counter-signature, and content checksum.

use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;

use crate::error::RegistryError;
use crate::state::AppState;

/// Attestation response for a published package version.
#[derive(Clone, Debug, Serialize)]
pub struct AttestationResponse {
    /// Package name.
    pub name: String,
    /// Package version.
    pub version: String,
    /// SHA-256 checksum of the `.cpkg` archive.
    pub checksum: String,
    /// Hex-encoded publisher Ed25519 public key.
    pub publisher_key: String,
    /// Hex-encoded publisher Ed25519 signature over the checksum.
    pub publisher_sig: String,
    /// Hex-encoded registry counter-signature (if available).
    pub registry_sig: Option<String>,
    /// Key ID of the registry key used to counter-sign.
    pub key_id: Option<String>,
    /// Hex-encoded registry public key used for `registry_sig` verification.
    pub registry_key: Option<String>,
    /// ISO-8601 publish timestamp.
    pub published_at: String,
}

/// GET /api/v1/packages/{name}/{version}/attestation
pub async fn get_attestation(
    State(state): State<AppState>,
    Path((name, version)): Path<(String, String)>,
) -> Result<Json<AttestationResponse>, RegistryError> {
    let db = state
        .db
        .lock()
        .map_err(|e| RegistryError::Internal(format!("db lock poisoned: {e}")))?;

    let v = db
        .get_version(&name, &version)?
        .ok_or_else(|| RegistryError::NotFound(format!("version {version} of {name} not found")))?;

    let registry_key = if v.registry_sig.is_some() {
        if let Some(ref key_id) = v.key_id {
            if let Some(key) = db.get_registry_key(key_id)? {
                Some(key.public_key)
            } else {
                let key_mgr = state.key_manager.lock().map_err(|e| {
                    RegistryError::Internal(format!("key_manager lock poisoned: {e}"))
                })?;
                key_mgr
                    .all_keys()
                    .into_iter()
                    .find(|k| k.key_id == *key_id)
                    .map(|k| k.public_key.clone())
            }
        } else {
            Some(state.registry_keypair.public_key().to_hex())
        }
    } else {
        None
    };

    Ok(Json(AttestationResponse {
        name: v.name,
        version: v.version,
        checksum: v.checksum,
        publisher_key: v.publisher_key,
        publisher_sig: v.publisher_sig,
        registry_sig: v.registry_sig,
        key_id: v.key_id,
        registry_key,
        published_at: v.published_at,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attestation_response_serializes() {
        let resp = AttestationResponse {
            name: "@acme/guard".into(),
            version: "1.0.0".into(),
            checksum: "abc123".into(),
            publisher_key: "pub_hex".into(),
            publisher_sig: "sig_hex".into(),
            registry_sig: Some("reg_sig_hex".into()),
            key_id: Some("kid1".into()),
            registry_key: Some("pk1".into()),
            published_at: "2026-02-25T10:30:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["name"], "@acme/guard");
        assert_eq!(json["registry_sig"], "reg_sig_hex");
    }

    #[test]
    fn attestation_response_without_registry_sig() {
        let resp = AttestationResponse {
            name: "test".into(),
            version: "0.1.0".into(),
            checksum: "abc".into(),
            publisher_key: "pk".into(),
            publisher_sig: "sig".into(),
            registry_sig: None,
            key_id: None,
            registry_key: None,
            published_at: "2026-01-01T00:00:00Z".into(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert!(json["registry_sig"].is_null());
    }
}
