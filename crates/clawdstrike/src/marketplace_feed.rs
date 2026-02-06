//! Signed marketplace feed for distributing policy bundles.

use hush_core::canonical::canonicalize;
use hush_core::{Keypair, PublicKey, Signature};
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MarketplaceProvenance {
    /// Optional attestation UID (e.g., EAS UID) that can be verified via a notary service.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_uid: Option<String>,
    /// Optional notary base URL (e.g., `https://notary.example.com`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notary_url: Option<String>,
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
}
