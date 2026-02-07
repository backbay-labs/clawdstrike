//! Spine fact schemas for marketplace-to-Spine protocol unification.
//!
//! Defines typed facts for wrapping marketplace objects (feed entries, head
//! announcements) as Spine envelopes, plus sync request/response types for
//! catching up on missed envelopes.
//!
//! This module implements the "marketplace as a native Spine application"
//! model: policy bundles become Spine envelope facts, feed updates become
//! Spine head announcements, and peers synchronize via envelope range
//! requests.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Schema identifier for marketplace feed entry facts.
pub const FEED_ENTRY_FACT_SCHEMA: &str = "clawdstrike.marketplace.feed_entry.v1";

/// Schema identifier for marketplace head announcement facts.
pub const HEAD_ANNOUNCEMENT_SCHEMA: &str = "clawdstrike.marketplace.head_announcement.v1";

/// Schema identifier for marketplace policy bundle facts.
pub const POLICY_BUNDLE_FACT_SCHEMA: &str = "clawdstrike.marketplace.policy_bundle.v1";

/// Maximum number of envelopes per sync response.
pub const MAX_SYNC_RANGE: u64 = 100;

/// A marketplace feed entry wrapped as a Spine fact.
///
/// Replaces the standalone `MarketplaceEntry` when running in Spine-unified
/// mode. The entry content is identical; only the wrapping changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FeedEntryFact {
    pub schema: String,
    pub fact_id: String,
    /// Feed identifier (e.g., "clawdstrike-official").
    pub feed_id: String,
    /// Feed sequence at time of publication.
    pub feed_seq: u64,
    /// Entry identifier within the feed.
    pub entry_id: String,
    /// Location of the policy bundle (URI).
    pub bundle_uri: String,
    /// SHA-256 hash of the canonical policy bundle.
    pub bundle_hash: String,
    /// SHA-256 hash of the canonical policy JSON.
    pub policy_hash: String,
    /// Entry title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Entry description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Entry category.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Tags for discovery and search.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Entry author.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
}

/// Head announcement fact for a marketplace curator feed.
///
/// Published when a curator updates their feed. Peers compare their local
/// `(issuer, seq)` state against announced heads and initiate sync for
/// missing ranges.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadAnnouncement {
    pub schema: String,
    pub fact_id: String,
    /// Feed identifier.
    pub feed_id: String,
    /// Curator's Spine issuer (redundant with envelope issuer, explicit for clarity).
    pub curator_issuer: String,
    /// Current head sequence number.
    pub head_seq: u64,
    /// Envelope hash of the head envelope.
    pub head_envelope_hash: String,
    /// Number of entries in the feed at this head.
    pub entry_count: u64,
    /// Checkpoint reference for verifiable freshness.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_ref: Option<CheckpointRef>,
}

/// Reference to a Spine checkpoint for verifiable freshness.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRef {
    pub log_id: String,
    pub checkpoint_seq: u64,
    pub envelope_hash: String,
}

/// Sync request from a peer that is behind on a curator's feed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRequest {
    pub schema: String,
    /// Curator issuer to sync.
    pub curator_issuer: String,
    /// Inclusive start of the missing range.
    pub from_seq: u64,
    /// Inclusive end of the missing range.
    pub to_seq: u64,
}

/// Sync response containing a batch of envelopes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncResponse {
    pub schema: String,
    pub curator_issuer: String,
    /// Envelopes in the requested range, ordered by seq.
    pub envelopes: Vec<Value>,
}

impl FeedEntryFact {
    /// Convert to a `serde_json::Value` for embedding in a Spine envelope fact.
    pub fn to_fact_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl HeadAnnouncement {
    /// Convert to a `serde_json::Value` for embedding in a Spine envelope fact.
    pub fn to_fact_value(&self) -> Result<Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}

impl SyncRequest {
    /// Validate that the sync range is well-formed and within limits.
    pub fn validate(&self) -> Result<(), String> {
        if self.from_seq == 0 {
            return Err("from_seq must be >= 1".to_string());
        }
        if self.to_seq < self.from_seq {
            return Err("to_seq must be >= from_seq".to_string());
        }
        let range = self.to_seq - self.from_seq + 1;
        if range > MAX_SYNC_RANGE {
            return Err(format!(
                "sync range too large ({range}), max is {MAX_SYNC_RANGE}"
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_feed_entry() -> FeedEntryFact {
        FeedEntryFact {
            schema: FEED_ENTRY_FACT_SCHEMA.to_string(),
            fact_id: "fe_test_001".to_string(),
            feed_id: "clawdstrike-official".to_string(),
            feed_seq: 10,
            entry_id: "strict-security-v2".to_string(),
            bundle_uri: "ipfs://QmTestHash".to_string(),
            bundle_hash:
                "0xaabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233".to_string(),
            policy_hash:
                "0x1122334455667788112233445566778811223344556677881122334455667788".to_string(),
            title: Some("Strict Security Policy".to_string()),
            description: Some("A strict security policy for production".to_string()),
            category: Some("security".to_string()),
            tags: vec!["production".to_string(), "strict".to_string()],
            author: Some("clawdstrike-team".to_string()),
        }
    }

    fn sample_head_announcement() -> HeadAnnouncement {
        HeadAnnouncement {
            schema: HEAD_ANNOUNCEMENT_SCHEMA.to_string(),
            fact_id: "ha_test_001".to_string(),
            feed_id: "clawdstrike-official".to_string(),
            curator_issuer:
                "aegis:ed25519:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
                    .to_string(),
            head_seq: 10,
            head_envelope_hash:
                "0xdeadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233".to_string(),
            entry_count: 5,
            checkpoint_ref: Some(CheckpointRef {
                log_id:
                    "aegis:ed25519:1122334455667788112233445566778811223344556677881122334455667788"
                        .to_string(),
                checkpoint_seq: 42,
                envelope_hash:
                    "0xcafebabe00112233cafebabe00112233cafebabe00112233cafebabe00112233"
                        .to_string(),
            }),
        }
    }

    #[test]
    fn feed_entry_fact_serde_roundtrip() {
        let fe = sample_feed_entry();
        let json = serde_json::to_string(&fe).unwrap();
        let restored: FeedEntryFact = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.schema, FEED_ENTRY_FACT_SCHEMA);
        assert_eq!(restored.feed_id, "clawdstrike-official");
        assert_eq!(restored.feed_seq, 10);
        assert_eq!(restored.tags.len(), 2);
    }

    #[test]
    fn head_announcement_serde_roundtrip() {
        let ha = sample_head_announcement();
        let json = serde_json::to_string(&ha).unwrap();
        let restored: HeadAnnouncement = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.schema, HEAD_ANNOUNCEMENT_SCHEMA);
        assert_eq!(restored.head_seq, 10);
        assert_eq!(restored.entry_count, 5);
        assert!(restored.checkpoint_ref.is_some());
        assert_eq!(restored.checkpoint_ref.unwrap().checkpoint_seq, 42);
    }

    #[test]
    fn feed_entry_fact_rejects_unknown_fields() {
        let fe = sample_feed_entry();
        let mut value = serde_json::to_value(&fe).unwrap();
        value["rogue_field"] = serde_json::json!("bad");
        let result = serde_json::from_value::<FeedEntryFact>(value);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn head_announcement_rejects_unknown_fields() {
        let ha = sample_head_announcement();
        let mut value = serde_json::to_value(&ha).unwrap();
        value["rogue_field"] = serde_json::json!("bad");
        let result = serde_json::from_value::<HeadAnnouncement>(value);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn checkpoint_ref_rejects_unknown_fields() {
        let cr = CheckpointRef {
            log_id: "test".to_string(),
            checkpoint_seq: 1,
            envelope_hash: "0xabcd".to_string(),
        };
        let mut value = serde_json::to_value(&cr).unwrap();
        value["rogue_field"] = serde_json::json!("bad");
        let result = serde_json::from_value::<CheckpointRef>(value);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn feed_entry_fact_optional_fields_omitted() {
        let fe = FeedEntryFact {
            title: None,
            description: None,
            category: None,
            tags: vec![],
            author: None,
            ..sample_feed_entry()
        };
        let json = serde_json::to_string(&fe).unwrap();
        assert!(!json.contains("title"));
        assert!(!json.contains("description"));
        assert!(!json.contains("category"));
        assert!(!json.contains("tags"));
        assert!(!json.contains("author"));
    }

    #[test]
    fn head_announcement_without_checkpoint_ref() {
        let ha = HeadAnnouncement {
            checkpoint_ref: None,
            ..sample_head_announcement()
        };
        let json = serde_json::to_string(&ha).unwrap();
        assert!(!json.contains("checkpoint_ref"));
        let restored: HeadAnnouncement = serde_json::from_str(&json).unwrap();
        assert!(restored.checkpoint_ref.is_none());
    }

    #[test]
    fn feed_entry_to_fact_value() {
        let fe = sample_feed_entry();
        let val = fe.to_fact_value().unwrap();
        assert_eq!(
            val.get("schema").and_then(|v| v.as_str()).unwrap(),
            FEED_ENTRY_FACT_SCHEMA
        );
    }

    #[test]
    fn head_announcement_to_fact_value() {
        let ha = sample_head_announcement();
        let val = ha.to_fact_value().unwrap();
        assert_eq!(
            val.get("schema").and_then(|v| v.as_str()).unwrap(),
            HEAD_ANNOUNCEMENT_SCHEMA
        );
    }

    #[test]
    fn sync_request_serde_roundtrip() {
        let sr = SyncRequest {
            schema: "clawdstrike.marketplace.sync_request.v1".to_string(),
            curator_issuer:
                "aegis:ed25519:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
                    .to_string(),
            from_seq: 5,
            to_seq: 10,
        };
        let json = serde_json::to_string(&sr).unwrap();
        let restored: SyncRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.from_seq, 5);
        assert_eq!(restored.to_seq, 10);
    }

    #[test]
    fn sync_request_rejects_unknown_fields() {
        let sr = SyncRequest {
            schema: "test".to_string(),
            curator_issuer: "test".to_string(),
            from_seq: 1,
            to_seq: 5,
        };
        let mut value = serde_json::to_value(&sr).unwrap();
        value["rogue_field"] = serde_json::json!("bad");
        let result = serde_json::from_value::<SyncRequest>(value);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn sync_response_serde_roundtrip() {
        let sr = SyncResponse {
            schema: "clawdstrike.marketplace.sync_response.v1".to_string(),
            curator_issuer: "test".to_string(),
            envelopes: vec![serde_json::json!({"test": true})],
        };
        let json = serde_json::to_string(&sr).unwrap();
        let restored: SyncResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.envelopes.len(), 1);
    }

    #[test]
    fn sync_response_rejects_unknown_fields() {
        let sr = SyncResponse {
            schema: "test".to_string(),
            curator_issuer: "test".to_string(),
            envelopes: vec![],
        };
        let mut value = serde_json::to_value(&sr).unwrap();
        value["rogue_field"] = serde_json::json!("bad");
        let result = serde_json::from_value::<SyncResponse>(value);
        assert!(result.is_err(), "should reject unknown fields");
    }

    #[test]
    fn sync_request_validate_accepts_valid_range() {
        let sr = SyncRequest {
            schema: "test".to_string(),
            curator_issuer: "test".to_string(),
            from_seq: 1,
            to_seq: 50,
        };
        assert!(sr.validate().is_ok());
    }

    #[test]
    fn sync_request_validate_rejects_zero_from() {
        let sr = SyncRequest {
            schema: "test".to_string(),
            curator_issuer: "test".to_string(),
            from_seq: 0,
            to_seq: 5,
        };
        assert!(sr.validate().is_err());
    }

    #[test]
    fn sync_request_validate_rejects_reversed_range() {
        let sr = SyncRequest {
            schema: "test".to_string(),
            curator_issuer: "test".to_string(),
            from_seq: 10,
            to_seq: 5,
        };
        assert!(sr.validate().is_err());
    }

    #[test]
    fn sync_request_validate_rejects_oversized_range() {
        let sr = SyncRequest {
            schema: "test".to_string(),
            curator_issuer: "test".to_string(),
            from_seq: 1,
            to_seq: 200,
        };
        assert!(sr.validate().is_err());
    }
}
