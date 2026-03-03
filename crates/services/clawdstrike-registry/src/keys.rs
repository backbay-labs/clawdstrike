//! Registry key management and rotation.
//!
//! The registry uses Ed25519 keypairs for counter-signing publish attestations.
//! Key rotation creates overlapping validity windows so that old signatures
//! remain verifiable during the transition period.

use hush_core::{sha256, Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::RegistryError;

/// Status of a registry signing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    /// The key is actively used for signing new attestations.
    Active,
    /// The key has been superseded but signatures made with it are still valid
    /// until `valid_until`.
    Deprecated,
    /// The key has been compromised or administratively revoked. Signatures
    /// made with this key should be treated as untrusted.
    Revoked,
}

impl std::fmt::Display for KeyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyStatus::Active => write!(f, "active"),
            KeyStatus::Deprecated => write!(f, "deprecated"),
            KeyStatus::Revoked => write!(f, "revoked"),
        }
    }
}

/// Metadata about a registry signing key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryKeyInfo {
    /// Short key identifier: first 16 hex chars of SHA-256(public_key_hex).
    pub key_id: String,
    /// Hex-encoded Ed25519 public key.
    pub public_key: String,
    /// ISO-8601 creation timestamp.
    pub created_at: String,
    /// ISO-8601 timestamp after which this key should not be used for
    /// verification (only set for deprecated keys).
    pub valid_until: Option<String>,
    /// Current key status.
    pub status: KeyStatus,
}

/// A key rotation event, signed by both the old and new keys for
/// non-repudiation.
#[allow(dead_code)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyRotationEvent {
    pub old_key_id: String,
    pub new_key_id: String,
    pub old_key: String,
    pub new_key: String,
    /// ISO-8601 timestamp when the old key stops being valid.
    pub valid_until_old: String,
    /// Hex-encoded signature by the old key over the rotation payload.
    pub signed_by_old: String,
    /// Hex-encoded signature by the new key over the rotation payload.
    pub signed_by_new: String,
}

/// Generate a deterministic key ID from a public key.
///
/// `key_id = SHA-256(public_key_hex)[..16]` (first 16 hex characters = 8 bytes).
pub fn generate_key_id(pubkey: &PublicKey) -> String {
    let hex_str = pubkey.to_hex();
    let hash = sha256(hex_str.as_bytes());
    hash.to_hex()[..16].to_string()
}

/// Manages registry signing keys and rotation.
pub struct RegistryKeyManager {
    /// All known keys, ordered newest-first.
    keys: Vec<ManagedKey>,
}

/// A key together with its private material (if available).
struct ManagedKey {
    info: RegistryKeyInfo,
    keypair: Option<Keypair>,
}

impl RegistryKeyManager {
    /// Create a new key manager with a single initial keypair.
    pub fn new(keypair: Keypair) -> Self {
        let pubkey = keypair.public_key();
        let key_id = generate_key_id(&pubkey);
        let now = chrono::Utc::now().to_rfc3339();
        let info = RegistryKeyInfo {
            key_id,
            public_key: pubkey.to_hex(),
            created_at: now,
            valid_until: None,
            status: KeyStatus::Active,
        };
        Self {
            keys: vec![ManagedKey {
                info,
                keypair: Some(keypair),
            }],
        }
    }

    /// Get info about the current (active) signing key.
    ///
    /// # Panics
    ///
    /// Panics if no active key exists. This is a class invariant: the
    /// constructor and `rotate` always maintain an active key.
    #[allow(clippy::expect_used)]
    pub fn current_key(&self) -> &RegistryKeyInfo {
        self.keys
            .iter()
            .find(|k| k.info.status == KeyStatus::Active)
            .map(|k| &k.info)
            .expect("RegistryKeyManager must always have an active key")
    }

    /// Get the active keypair for signing.
    ///
    /// # Panics
    ///
    /// Panics if no active key with private material exists.
    #[allow(clippy::expect_used)]
    pub fn current_keypair(&self) -> &Keypair {
        self.keys
            .iter()
            .find(|k| k.info.status == KeyStatus::Active)
            .and_then(|k| k.keypair.as_ref())
            .expect("RegistryKeyManager must always have an active keypair")
    }

    /// Get a signing keypair by key id, if private material is present.
    pub fn keypair_for_key_id(&self, key_id: &str) -> Option<&Keypair> {
        self.keys
            .iter()
            .find(|k| k.info.key_id == key_id)
            .and_then(|k| k.keypair.as_ref())
    }

    /// List all key infos (including deprecated/revoked).
    #[allow(dead_code)]
    pub fn all_keys(&self) -> Vec<&RegistryKeyInfo> {
        self.keys.iter().map(|k| &k.info).collect()
    }

    /// Rotate to a new keypair, deprecating the current active key.
    ///
    /// `overlap_days` controls how long the old key remains valid for
    /// verification after rotation.
    #[allow(dead_code)]
    pub fn rotate(
        &mut self,
        new_keypair: Keypair,
        overlap_days: u32,
    ) -> Result<KeyRotationEvent, RegistryError> {
        let old_managed = self
            .keys
            .iter_mut()
            .find(|k| k.info.status == KeyStatus::Active)
            .ok_or_else(|| RegistryError::Internal("no active key to rotate from".into()))?;

        let old_keypair = old_managed.keypair.as_ref().ok_or_else(|| {
            RegistryError::Internal("active key has no private material for rotation".into())
        })?;

        let new_pubkey = new_keypair.public_key();
        let new_key_id = generate_key_id(&new_pubkey);
        let now = chrono::Utc::now();
        let valid_until = now + chrono::Duration::days(i64::from(overlap_days));
        let valid_until_str = valid_until.to_rfc3339();

        // Build the rotation payload for dual signing.
        let payload = format!(
            "rotate:{}:{}:{}",
            old_managed.info.key_id, new_key_id, valid_until_str
        );
        let payload_bytes = payload.as_bytes();

        let signed_by_old = old_keypair.sign(payload_bytes).to_hex();
        let signed_by_new = new_keypair.sign(payload_bytes).to_hex();

        let event = KeyRotationEvent {
            old_key_id: old_managed.info.key_id.clone(),
            new_key_id: new_key_id.clone(),
            old_key: old_managed.info.public_key.clone(),
            new_key: new_pubkey.to_hex(),
            valid_until_old: valid_until_str.clone(),
            signed_by_old,
            signed_by_new,
        };

        // Mark old key as deprecated.
        old_managed.info.status = KeyStatus::Deprecated;
        old_managed.info.valid_until = Some(valid_until_str);

        // Insert new key at front.
        let new_info = RegistryKeyInfo {
            key_id: new_key_id,
            public_key: new_pubkey.to_hex(),
            created_at: now.to_rfc3339(),
            valid_until: None,
            status: KeyStatus::Active,
        };
        self.keys.insert(
            0,
            ManagedKey {
                info: new_info,
                keypair: Some(new_keypair),
            },
        );

        Ok(event)
    }

    /// Verify a signature against any key that is currently valid
    /// (Active or Deprecated with a future `valid_until`).
    ///
    /// Returns the key info of the key that verified the signature, or an
    /// error if no valid key could verify it.
    #[allow(dead_code)]
    pub fn verify_with_any_valid_key(
        &self,
        data: &[u8],
        sig_hex: &str,
    ) -> Result<RegistryKeyInfo, RegistryError> {
        let signature = Signature::from_hex(sig_hex)
            .map_err(|e| RegistryError::Integrity(format!("invalid signature hex: {e}")))?;

        let now = chrono::Utc::now();

        for managed in &self.keys {
            // Skip revoked keys.
            if managed.info.status == KeyStatus::Revoked {
                continue;
            }

            // Skip deprecated keys past their validity window.
            if managed.info.status == KeyStatus::Deprecated {
                if let Some(ref until) = managed.info.valid_until {
                    let until_ts = match chrono::DateTime::parse_from_rfc3339(until) {
                        Ok(ts) => ts.with_timezone(&chrono::Utc),
                        // Fail closed for malformed external timestamp values.
                        Err(_) => continue,
                    };
                    if now > until_ts {
                        continue;
                    }
                }
            }

            let pubkey = match PublicKey::from_hex(&managed.info.public_key) {
                Ok(pk) => pk,
                Err(_) => continue,
            };

            if pubkey.verify(data, &signature) {
                return Ok(managed.info.clone());
            }
        }

        Err(RegistryError::Integrity(
            "no valid registry key could verify the signature".into(),
        ))
    }

    /// Revoke a key by its key ID.
    #[allow(dead_code)]
    pub fn revoke(&mut self, key_id: &str) -> Result<(), RegistryError> {
        let managed = self
            .keys
            .iter_mut()
            .find(|k| k.info.key_id == key_id)
            .ok_or_else(|| RegistryError::NotFound(format!("key {key_id} not found")))?;

        if managed.info.status == KeyStatus::Active {
            return Err(RegistryError::BadRequest(
                "cannot revoke the active key; rotate first".into(),
            ));
        }

        managed.info.status = KeyStatus::Revoked;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_key_id_is_deterministic() {
        let kp = Keypair::from_seed(&[1u8; 32]);
        let id1 = generate_key_id(&kp.public_key());
        let id2 = generate_key_id(&kp.public_key());
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16);
    }

    #[test]
    fn new_manager_has_active_key() {
        let kp = Keypair::generate();
        let mgr = RegistryKeyManager::new(kp);
        assert_eq!(mgr.current_key().status, KeyStatus::Active);
        assert_eq!(mgr.all_keys().len(), 1);
    }

    #[test]
    fn rotate_creates_event_signed_by_both_keys() {
        let old_kp = Keypair::from_seed(&[1u8; 32]);
        let new_kp = Keypair::from_seed(&[2u8; 32]);

        let old_pubkey = old_kp.public_key();
        let new_pubkey = new_kp.public_key();

        let mut mgr = RegistryKeyManager::new(old_kp);
        let event = mgr.rotate(new_kp, 30).unwrap();

        // Verify both signatures over the rotation payload.
        let payload = format!(
            "rotate:{}:{}:{}",
            event.old_key_id, event.new_key_id, event.valid_until_old
        );
        let payload_bytes = payload.as_bytes();

        let old_sig = Signature::from_hex(&event.signed_by_old).unwrap();
        let new_sig = Signature::from_hex(&event.signed_by_new).unwrap();

        assert!(old_pubkey.verify(payload_bytes, &old_sig));
        assert!(new_pubkey.verify(payload_bytes, &new_sig));
    }

    #[test]
    fn old_key_is_deprecated_after_rotation() {
        let old_kp = Keypair::from_seed(&[1u8; 32]);
        let new_kp = Keypair::from_seed(&[2u8; 32]);

        let old_key_id = generate_key_id(&old_kp.public_key());

        let mut mgr = RegistryKeyManager::new(old_kp);
        mgr.rotate(new_kp, 30).unwrap();

        // New key is active.
        assert_eq!(mgr.current_key().status, KeyStatus::Active);
        assert_ne!(mgr.current_key().key_id, old_key_id);

        // Old key is deprecated.
        let all = mgr.all_keys();
        assert_eq!(all.len(), 2);
        let old = all.iter().find(|k| k.key_id == old_key_id).unwrap();
        assert_eq!(old.status, KeyStatus::Deprecated);
        assert!(old.valid_until.is_some());
    }

    #[test]
    fn verify_with_deprecated_key_within_overlap() {
        let old_kp = Keypair::from_seed(&[1u8; 32]);
        let new_kp = Keypair::from_seed(&[2u8; 32]);

        let data = b"test message";
        let sig = old_kp.sign(data);

        let mut mgr = RegistryKeyManager::new(old_kp);
        mgr.rotate(new_kp, 30).unwrap();

        // Should verify with the deprecated key (within overlap window).
        let key_info = mgr.verify_with_any_valid_key(data, &sig.to_hex()).unwrap();
        assert_eq!(key_info.status, KeyStatus::Deprecated);
    }

    #[test]
    fn verify_with_any_valid_key_parses_rfc3339_offsets_for_expiry() {
        let old_kp = Keypair::from_seed(&[1u8; 32]);
        let new_kp = Keypair::from_seed(&[2u8; 32]);
        let data = b"test message";
        let sig = old_kp.sign(data);

        let mut mgr = RegistryKeyManager::new(old_kp);
        mgr.rotate(new_kp, 30).unwrap();

        // Use an expired instant represented with a non-UTC offset. String
        // comparison can mis-order this; parsed datetime comparison must not.
        let expired_instant = chrono::Utc::now() - chrono::Duration::minutes(30);
        let offset = chrono::FixedOffset::east_opt(3600).unwrap();
        mgr.keys[1].info.valid_until = Some(expired_instant.with_timezone(&offset).to_rfc3339());

        let result = mgr.verify_with_any_valid_key(data, &sig.to_hex());
        assert!(
            result.is_err(),
            "deprecated key past expiry must be rejected"
        );
    }

    #[test]
    fn verify_with_active_key() {
        let kp = Keypair::from_seed(&[1u8; 32]);
        let data = b"test message";
        let sig = kp.sign(data);

        let mgr = RegistryKeyManager::new(kp);
        let key_info = mgr.verify_with_any_valid_key(data, &sig.to_hex()).unwrap();
        assert_eq!(key_info.status, KeyStatus::Active);
    }

    #[test]
    fn verify_fails_with_revoked_key() {
        let old_kp = Keypair::from_seed(&[1u8; 32]);
        let new_kp = Keypair::from_seed(&[2u8; 32]);

        let data = b"test message";
        let sig = old_kp.sign(data);

        let old_key_id = generate_key_id(&old_kp.public_key());

        let mut mgr = RegistryKeyManager::new(old_kp);
        mgr.rotate(new_kp, 30).unwrap();
        mgr.revoke(&old_key_id).unwrap();

        // Should fail — revoked key is not usable.
        let result = mgr.verify_with_any_valid_key(data, &sig.to_hex());
        assert!(result.is_err());
    }

    #[test]
    fn cannot_revoke_active_key() {
        let kp = Keypair::from_seed(&[1u8; 32]);
        let key_id = generate_key_id(&kp.public_key());
        let mut mgr = RegistryKeyManager::new(kp);

        let err = mgr.revoke(&key_id).unwrap_err();
        assert!(err.to_string().contains("rotate first"));
    }

    #[test]
    fn verify_rejects_invalid_signature() {
        let kp = Keypair::generate();
        let mgr = RegistryKeyManager::new(kp);

        let other = Keypair::generate();
        let sig = other.sign(b"hello");

        let result = mgr.verify_with_any_valid_key(b"hello", &sig.to_hex());
        assert!(result.is_err());
    }

    #[test]
    fn key_status_display() {
        assert_eq!(KeyStatus::Active.to_string(), "active");
        assert_eq!(KeyStatus::Deprecated.to_string(), "deprecated");
        assert_eq!(KeyStatus::Revoked.to_string(), "revoked");
    }

    #[test]
    fn key_rotation_event_serde_roundtrip() {
        let old_kp = Keypair::from_seed(&[1u8; 32]);
        let new_kp = Keypair::from_seed(&[2u8; 32]);

        let mut mgr = RegistryKeyManager::new(old_kp);
        let event = mgr.rotate(new_kp, 30).unwrap();

        let json = serde_json::to_string(&event).unwrap();
        let restored: KeyRotationEvent = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.old_key_id, event.old_key_id);
        assert_eq!(restored.new_key_id, event.new_key_id);
        assert_eq!(restored.signed_by_old, event.signed_by_old);
        assert_eq!(restored.signed_by_new, event.signed_by_new);
    }
}
