//! Signed marketplace feed for distributing policy bundles.

use hush_core::canonical::canonicalize;
use hush_core::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::curator_config::{CuratorConfig, ValidatedCurator};
use crate::error::{Error, Result};
use hush_core::Hash;

pub const MARKETPLACE_FEED_SCHEMA_VERSION: &str = "clawdstrike-marketplace-feed-v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceFeed {
    /// Feed schema version.
    pub version: String,
    /// Stable identifier for the feed (e.g., "clawdstrike-official").
    pub feed_id: String,
    /// ISO-8601 timestamp.
    pub published_at: String,
    /// Monotonic sequence number.
    pub seq: u64,
    /// Marketplace entries.
    pub entries: Vec<MarketplaceEntry>,
    /// Optional metadata (publisher info, etc).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl MarketplaceFeed {
    pub fn validate_version(&self) -> Result<()> {
        if self.version != MARKETPLACE_FEED_SCHEMA_VERSION {
            return Err(Error::ConfigError(format!(
                "Unsupported marketplace feed version: {} (expected {})",
                self.version, MARKETPLACE_FEED_SCHEMA_VERSION
            )));
        }
        Ok(())
    }

    pub fn to_canonical_json(&self) -> Result<String> {
        self.validate_version()?;
        let value = serde_json::to_value(self)?;
        Ok(canonicalize(&value)?)
    }
}

/// Content identifiers for verifiable fetching (dual-CID: IPFS + SHA-256).
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContentIds {
    /// IPFS CIDv1 (base32, typically SHA-256 under the hood).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipfs_cid: Option<String>,
    /// SHA-256 of the canonical JSON of the signed bundle.
    pub sha256: Hash,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceEntry {
    /// Stable entry identifier (unique within the feed).
    pub entry_id: String,
    /// Location of a signed policy bundle (`https://...` / `ipfs://...` / `builtin://...`).
    pub bundle_uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Optional provenance info (e.g., Notary/EAS attestation pointers).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance: Option<MarketplaceProvenance>,
    /// Optional curator public key that added this entry (hex-encoded).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub curator_public_key: Option<String>,
    /// Content identifiers for verifiable fetching.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_ids: Option<ContentIds>,
    /// Ordered list of IPFS gateway base URLs for fallback fetching.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub gateway_hints: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceProvenance {
    /// Verification type: `"notary"`, `"spine"`, `"eas"`.
    /// When absent, inferred from which fields are populated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    /// Optional attestation UID (e.g., EAS UID) that can be verified via a notary service.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_uid: Option<String>,
    /// Optional notary base URL (e.g., `https://notary.example.com`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notary_url: Option<String>,
    /// Optional Spine envelope hash for provenance tracing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spine_envelope_hash: Option<String>,
    /// Log operator ID for Spine verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_id: Option<String>,
    /// Checkpoint sequence for Spine verification (pin to a specific checkpoint).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_seq: Option<u64>,
    /// Pre-computed inclusion proof for offline verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inclusion_proof: Option<InclusionProofBundle>,
}

impl MarketplaceProvenance {
    /// Determine the effective provenance verification type.
    ///
    /// If `type` is explicitly set, returns that. Otherwise, infers from
    /// which fields are populated: `spine_envelope_hash` -> `"spine"`,
    /// `attestation_uid` + `notary_url` -> `"notary"`.
    pub fn effective_type(&self) -> Option<&str> {
        if let Some(t) = &self.r#type {
            return Some(t.as_str());
        }
        if self.spine_envelope_hash.is_some() {
            return Some("spine");
        }
        if self.attestation_uid.is_some() && self.notary_url.is_some() {
            return Some("notary");
        }
        None
    }
}

/// Pre-computed inclusion proof for offline Spine verification.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProofBundle {
    /// RFC 6962 Merkle audit path (hex-encoded hashes).
    pub audit_path: Vec<String>,
    pub checkpoint_seq: u64,
    pub tree_size: u64,
    pub log_index: u64,
    pub merkle_root: String,
    /// Witness signatures on the checkpoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_signatures: Vec<WitnessSignatureRef>,
}

/// Reference to a witness co-signature on a checkpoint.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessSignatureRef {
    pub witness_node_id: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMarketplaceFeed {
    pub feed: MarketplaceFeed,
    pub signature: Signature,
    /// Optional embedded signer key (useful for distribution).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
}

impl SignedMarketplaceFeed {
    pub fn sign(feed: MarketplaceFeed, keypair: &Keypair) -> Result<Self> {
        feed.validate_version()?;
        let canonical = feed.to_canonical_json()?;
        let signature = keypair.sign(canonical.as_bytes());
        Ok(Self {
            feed,
            signature,
            public_key: None,
        })
    }

    pub fn sign_with_public_key(feed: MarketplaceFeed, keypair: &Keypair) -> Result<Self> {
        let mut signed = Self::sign(feed, keypair)?;
        signed.public_key = Some(keypair.public_key());
        Ok(signed)
    }

    pub fn verify(&self, public_key: &PublicKey) -> Result<bool> {
        self.feed.validate_version()?;
        let canonical = self.feed.to_canonical_json()?;
        Ok(public_key.verify(canonical.as_bytes(), &self.signature))
    }

    pub fn verify_embedded(&self) -> Result<bool> {
        match &self.public_key {
            Some(pk) => self.verify(pk),
            None => Err(Error::ConfigError(
                "No public_key embedded in marketplace feed".to_string(),
            )),
        }
    }

    pub fn verify_trusted(&self, trusted_public_keys: &[PublicKey]) -> Result<PublicKey> {
        if trusted_public_keys.is_empty() {
            return Err(Error::ConfigError(
                "No trusted marketplace feed keys configured".to_string(),
            ));
        }

        self.feed.validate_version()?;
        let canonical = self.feed.to_canonical_json()?;

        if let Some(pk) = &self.public_key {
            if !trusted_public_keys.iter().any(|t| t == pk) {
                return Err(Error::ConfigError(
                    "Marketplace feed embedded public_key is not trusted".to_string(),
                ));
            }
            if pk.verify(canonical.as_bytes(), &self.signature) {
                return Ok(pk.clone());
            }
            return Err(Error::ConfigError(
                "Marketplace feed signature verification failed".to_string(),
            ));
        }

        for pk in trusted_public_keys {
            if pk.verify(canonical.as_bytes(), &self.signature) {
                return Ok(pk.clone());
            }
        }

        Err(Error::ConfigError(
            "Marketplace feed signature verification failed (no trusted key matched)".to_string(),
        ))
    }

    /// Verify against a curator config, returning the matching curator entry.
    ///
    /// This combines feed-scoped key filtering with signature verification and
    /// returns the full [`ValidatedCurator`] so the caller knows the trust level.
    pub fn verify_with_config<'a>(
        &self,
        config: &'a CuratorConfig,
    ) -> Result<&'a ValidatedCurator> {
        let feed_keys = config.public_keys_for_feed(&self.feed.feed_id);
        let matching_key = self.verify_trusted(&feed_keys)?;
        config.find_curator(&matching_key).ok_or_else(|| {
            Error::ConfigError("Verified key not found in curator config".to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signed_feed_round_trip_verifies() {
        let keypair = Keypair::generate();
        let feed = MarketplaceFeed {
            version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
            feed_id: "test".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            seq: 1,
            entries: vec![MarketplaceEntry {
                entry_id: "policy-1".to_string(),
                bundle_uri: "https://example.com/policy.bundle.json".to_string(),
                title: Some("Policy 1".to_string()),
                description: None,
                category: None,
                tags: vec!["test".to_string()],
                author: None,
                author_url: None,
                icon: None,
                created_at: None,
                updated_at: None,
                provenance: None,
                curator_public_key: None,
                content_ids: None,
                gateway_hints: Vec::new(),
            }],
            metadata: None,
        };

        let signed = SignedMarketplaceFeed::sign_with_public_key(feed, &keypair).unwrap();
        assert!(signed.verify_embedded().unwrap());
    }

    #[test]
    fn feed_rejects_wrong_version() {
        let keypair = Keypair::generate();
        let feed = MarketplaceFeed {
            version: "wrong".to_string(),
            feed_id: "test".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            seq: 1,
            entries: Vec::new(),
            metadata: None,
        };

        let err = SignedMarketplaceFeed::sign(feed, &keypair).expect_err("should reject version");
        assert!(err
            .to_string()
            .contains("Unsupported marketplace feed version"));
    }

    #[test]
    fn wrong_public_key_does_not_verify() {
        let kp1 = Keypair::generate();
        let kp2 = Keypair::generate();
        let feed = MarketplaceFeed {
            version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
            feed_id: "test".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            seq: 1,
            entries: Vec::new(),
            metadata: None,
        };
        let signed = SignedMarketplaceFeed::sign(feed, &kp1).unwrap();
        assert!(!signed.verify(&kp2.public_key()).unwrap());
    }

    #[test]
    fn trusted_verification_requires_trusted_key() {
        let keypair = Keypair::generate();
        let other = Keypair::generate();

        let feed = MarketplaceFeed {
            version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
            feed_id: "test".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            seq: 1,
            entries: Vec::new(),
            metadata: None,
        };
        let signed = SignedMarketplaceFeed::sign_with_public_key(feed, &keypair).unwrap();

        let err = signed
            .verify_trusted(&[other.public_key()])
            .expect_err("key should not be trusted");
        assert!(err.to_string().contains("not trusted"));
    }

    #[test]
    fn key_ordering_in_feed_json_does_not_break_verification() {
        let keypair = Keypair::generate();
        let feed = MarketplaceFeed {
            version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
            feed_id: "test".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            seq: 1,
            entries: vec![MarketplaceEntry {
                entry_id: "policy-1".to_string(),
                bundle_uri: "https://example.com/policy.bundle.json".to_string(),
                title: None,
                description: None,
                category: None,
                tags: Vec::new(),
                author: None,
                author_url: None,
                icon: None,
                created_at: None,
                updated_at: None,
                provenance: None,
                curator_public_key: None,
                content_ids: None,
                gateway_hints: Vec::new(),
            }],
            metadata: Some(serde_json::json!({ "b": 1, "a": 2 })),
        };

        let signed = SignedMarketplaceFeed::sign_with_public_key(feed, &keypair).unwrap();
        let json = serde_json::to_value(&signed).unwrap();

        // Rebuild the `feed` object with a different key insertion order.
        let mut root = json.as_object().unwrap().clone();
        let feed_value = root.get("feed").unwrap().clone();
        let feed_obj = feed_value.as_object().unwrap();

        let mut shuffled_feed = serde_json::Map::new();
        shuffled_feed.insert(
            "entries".to_string(),
            feed_obj.get("entries").unwrap().clone(),
        );
        shuffled_feed.insert("seq".to_string(), feed_obj.get("seq").unwrap().clone());
        shuffled_feed.insert(
            "published_at".to_string(),
            feed_obj.get("published_at").unwrap().clone(),
        );
        shuffled_feed.insert(
            "feed_id".to_string(),
            feed_obj.get("feed_id").unwrap().clone(),
        );
        shuffled_feed.insert(
            "version".to_string(),
            feed_obj.get("version").unwrap().clone(),
        );
        shuffled_feed.insert(
            "metadata".to_string(),
            feed_obj.get("metadata").unwrap().clone(),
        );

        root.insert("feed".to_string(), serde_json::Value::Object(shuffled_feed));
        let shuffled_json = serde_json::Value::Object(root);
        let shuffled_str = serde_json::to_string(&shuffled_json).unwrap();

        let parsed: SignedMarketplaceFeed = serde_json::from_str(&shuffled_str).unwrap();
        let verified = parsed
            .verify_trusted(&[keypair.public_key()])
            .expect("should verify with trusted key");
        assert_eq!(verified, keypair.public_key());
    }

    #[test]
    fn verify_feed_with_curator_config() {
        use crate::curator_config::{CuratorConfig, TrustLevel};

        let kp = Keypair::generate();
        let config_toml = format!(
            r#"
[[curator]]
name = "test"
public_key = "{}"
trust_level = "full"
feed_ids = ["test-feed"]
"#,
            kp.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&config_toml).unwrap();

        let feed = MarketplaceFeed {
            version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
            feed_id: "test-feed".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            seq: 1,
            entries: Vec::new(),
            metadata: None,
        };
        let signed = SignedMarketplaceFeed::sign(feed, &kp).unwrap();
        let curator = signed.verify_with_config(&config).unwrap();
        assert_eq!(curator.name, "test");
        assert_eq!(curator.trust_level, TrustLevel::Full);
    }

    #[test]
    fn verify_with_config_feed_id_mismatch() {
        use crate::curator_config::CuratorConfig;

        let kp = Keypair::generate();
        let config_toml = format!(
            r#"
[[curator]]
name = "scoped"
public_key = "{}"
trust_level = "full"
feed_ids = ["feed-a"]
"#,
            kp.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&config_toml).unwrap();

        let feed = MarketplaceFeed {
            version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
            feed_id: "feed-b".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            seq: 1,
            entries: Vec::new(),
            metadata: None,
        };
        let signed = SignedMarketplaceFeed::sign(feed, &kp).unwrap();
        let err = signed
            .verify_with_config(&config)
            .expect_err("should fail for wrong feed id");
        assert!(err
            .to_string()
            .contains("No trusted marketplace feed keys configured"));
    }

    #[test]
    fn verify_with_config_trust_level_propagation() {
        use crate::curator_config::{CuratorConfig, TrustLevel};

        let kp = Keypair::generate();
        let config_toml = format!(
            r#"
[[curator]]
name = "auditor"
public_key = "{}"
trust_level = "audit-only"
"#,
            kp.public_key().to_hex()
        );
        let config = CuratorConfig::parse(&config_toml).unwrap();

        let feed = MarketplaceFeed {
            version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
            feed_id: "any-feed".to_string(),
            published_at: "2026-01-01T00:00:00Z".to_string(),
            seq: 1,
            entries: Vec::new(),
            metadata: None,
        };
        let signed = SignedMarketplaceFeed::sign(feed, &kp).unwrap();
        let curator = signed.verify_with_config(&config).unwrap();
        assert_eq!(curator.trust_level, TrustLevel::AuditOnly);
    }

    #[test]
    fn content_ids_serde_round_trip() {
        let ids = ContentIds {
            ipfs_cid: Some(
                "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi".to_string(),
            ),
            sha256: hush_core::sha256(b"test content"),
        };
        let json = serde_json::to_string(&ids).unwrap();
        let parsed: ContentIds = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.ipfs_cid, ids.ipfs_cid);
        assert_eq!(parsed.sha256, ids.sha256);
    }

    #[test]
    fn content_ids_without_ipfs_cid() {
        let ids = ContentIds {
            ipfs_cid: None,
            sha256: hush_core::sha256(b"test"),
        };
        let json = serde_json::to_string(&ids).unwrap();
        assert!(!json.contains("ipfs_cid"));
        let parsed: ContentIds = serde_json::from_str(&json).unwrap();
        assert!(parsed.ipfs_cid.is_none());
    }

    #[test]
    fn entry_with_content_ids_and_gateway_hints() {
        let entry = MarketplaceEntry {
            entry_id: "test-1".to_string(),
            bundle_uri: "ipfs://bafytest123".to_string(),
            title: None,
            description: None,
            category: None,
            tags: Vec::new(),
            author: None,
            author_url: None,
            icon: None,
            created_at: None,
            updated_at: None,
            provenance: None,
            curator_public_key: None,
            content_ids: Some(ContentIds {
                ipfs_cid: Some("bafytest123".to_string()),
                sha256: hush_core::sha256(b"bundle data"),
            }),
            gateway_hints: vec!["https://my-gw.example.com/ipfs/".to_string()],
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("content_ids"));
        assert!(json.contains("gateway_hints"));
        let parsed: MarketplaceEntry = serde_json::from_str(&json).unwrap();
        assert!(parsed.content_ids.is_some());
        assert_eq!(parsed.gateway_hints.len(), 1);
    }

    #[test]
    fn entry_without_content_ids_backward_compat() {
        // Existing feeds without the new fields should still deserialize
        let json = r#"{
            "entry_id": "legacy-1",
            "bundle_uri": "https://example.com/bundle.json"
        }"#;
        let parsed: MarketplaceEntry = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.entry_id, "legacy-1");
        assert!(parsed.content_ids.is_none());
        assert!(parsed.gateway_hints.is_empty());
    }

    #[test]
    fn signed_feed_with_content_ids_round_trip() {
        let keypair = Keypair::generate();
        let feed = MarketplaceFeed {
            version: MARKETPLACE_FEED_SCHEMA_VERSION.to_string(),
            feed_id: "ipfs-test".to_string(),
            published_at: "2026-02-07T00:00:00Z".to_string(),
            seq: 1,
            entries: vec![MarketplaceEntry {
                entry_id: "ipfs-bundle-1".to_string(),
                bundle_uri: "ipfs://bafytest".to_string(),
                title: Some("IPFS Bundle".to_string()),
                description: None,
                category: None,
                tags: Vec::new(),
                author: None,
                author_url: None,
                icon: None,
                created_at: None,
                updated_at: None,
                provenance: None,
                curator_public_key: None,
                content_ids: Some(ContentIds {
                    ipfs_cid: Some("bafytest".to_string()),
                    sha256: hush_core::sha256(b"test"),
                }),
                gateway_hints: vec!["https://gw.example.com/ipfs/".to_string()],
            }],
            metadata: None,
        };

        let signed = SignedMarketplaceFeed::sign_with_public_key(feed, &keypair).unwrap();
        assert!(signed.verify_embedded().unwrap());

        // Round-trip through JSON
        let json = serde_json::to_string(&signed).unwrap();
        let parsed: SignedMarketplaceFeed = serde_json::from_str(&json).unwrap();
        assert!(parsed.verify(&keypair.public_key()).unwrap());
        assert_eq!(parsed.feed.entries[0].gateway_hints.len(), 1);
        assert!(parsed.feed.entries[0].content_ids.is_some());
    }
}
