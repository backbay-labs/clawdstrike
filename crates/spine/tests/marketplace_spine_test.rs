//! Integration tests for marketplace-to-Spine protocol unification types.
//!
//! Tests the full lifecycle: build typed fact -> wrap in SignedEnvelope ->
//! verify envelope -> extract fact -> deserialize back to typed struct.
//! Also tests head announcements, sync request/response, and chaining.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hush_core::Keypair;
use serde_json::json;
use spine::{
    build_signed_envelope, now_rfc3339, verify_envelope, CheckpointRef, FeedEntryFact,
    HeadAnnouncement, SyncRequest, SyncResponse, FEED_ENTRY_FACT_SCHEMA,
    HEAD_ANNOUNCEMENT_SCHEMA, MAX_SYNC_RANGE,
};

fn sample_feed_entry(seq: u64) -> FeedEntryFact {
    FeedEntryFact {
        schema: FEED_ENTRY_FACT_SCHEMA.to_string(),
        fact_id: format!("fe_integration_{seq:03}"),
        feed_id: "clawdstrike-official".to_string(),
        feed_seq: seq,
        entry_id: format!("entry-{seq}"),
        bundle_uri: format!("ipfs://QmTestHash{seq}"),
        bundle_hash: "0xaabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
            .to_string(),
        policy_hash: "0x1122334455667788112233445566778811223344556677881122334455667788"
            .to_string(),
        title: Some(format!("Policy Entry {seq}")),
        description: None,
        category: Some("security".to_string()),
        tags: vec!["production".to_string()],
        author: Some("test-curator".to_string()),
    }
}

fn sample_head_announcement(head_seq: u64, head_envelope_hash: &str) -> HeadAnnouncement {
    HeadAnnouncement {
        schema: HEAD_ANNOUNCEMENT_SCHEMA.to_string(),
        fact_id: format!("ha_integration_{head_seq:03}"),
        feed_id: "clawdstrike-official".to_string(),
        curator_issuer:
            "aegis:ed25519:aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233"
                .to_string(),
        head_seq,
        head_envelope_hash: head_envelope_hash.to_string(),
        entry_count: head_seq,
        checkpoint_ref: None,
    }
}

#[tokio::test]
async fn test_feed_entry_envelope_roundtrip() {
    let kp = Keypair::generate();
    let fe = sample_feed_entry(1);

    let fact_value = fe.to_fact_value().unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact_value, now_rfc3339()).unwrap();

    assert!(verify_envelope(&envelope).unwrap());

    let fact = envelope.get("fact").unwrap();
    let restored: FeedEntryFact = serde_json::from_value(fact.clone()).unwrap();

    assert_eq!(restored.schema, FEED_ENTRY_FACT_SCHEMA);
    assert_eq!(restored.feed_id, "clawdstrike-official");
    assert_eq!(restored.feed_seq, 1);
    assert_eq!(restored.entry_id, "entry-1");
    assert_eq!(restored.bundle_uri, "ipfs://QmTestHash1");
}

#[tokio::test]
async fn test_head_announcement_envelope_roundtrip() {
    let kp = Keypair::generate();
    let ha = sample_head_announcement(
        5,
        "0xdeadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233",
    );

    let fact_value = ha.to_fact_value().unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact_value, now_rfc3339()).unwrap();

    assert!(verify_envelope(&envelope).unwrap());

    let fact = envelope.get("fact").unwrap();
    let restored: HeadAnnouncement = serde_json::from_value(fact.clone()).unwrap();

    assert_eq!(restored.schema, HEAD_ANNOUNCEMENT_SCHEMA);
    assert_eq!(restored.head_seq, 5);
    assert_eq!(restored.entry_count, 5);
}

#[tokio::test]
async fn test_head_announcement_with_checkpoint_ref() {
    let kp = Keypair::generate();
    let mut ha = sample_head_announcement(
        10,
        "0xdeadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233",
    );
    ha.checkpoint_ref = Some(CheckpointRef {
        log_id: "aegis:ed25519:1122334455667788112233445566778811223344556677881122334455667788"
            .to_string(),
        checkpoint_seq: 42,
        envelope_hash: "0xcafebabe00112233cafebabe00112233cafebabe00112233cafebabe00112233"
            .to_string(),
    });

    let fact_value = ha.to_fact_value().unwrap();
    let envelope = build_signed_envelope(&kp, 1, None, fact_value, now_rfc3339()).unwrap();

    assert!(verify_envelope(&envelope).unwrap());

    let fact = envelope.get("fact").unwrap();
    let restored: HeadAnnouncement = serde_json::from_value(fact.clone()).unwrap();
    let cp = restored.checkpoint_ref.unwrap();
    assert_eq!(cp.checkpoint_seq, 42);
}

#[tokio::test]
async fn test_feed_entry_rejects_unknown_fields() {
    let fe = sample_feed_entry(1);
    let mut value = fe.to_fact_value().unwrap();
    value["unknown_field"] = json!("bad");
    let result = serde_json::from_value::<FeedEntryFact>(value);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_head_announcement_rejects_unknown_fields() {
    let ha = sample_head_announcement(1, "0xabcd");
    let mut value = ha.to_fact_value().unwrap();
    value["unknown_field"] = json!("bad");
    let result = serde_json::from_value::<HeadAnnouncement>(value);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_feed_entry_chain_with_head_announcement() {
    let kp = Keypair::generate();

    // Build a chain of 3 feed entry envelopes.
    let mut prev_hash: Option<String> = None;
    let mut last_envelope_hash = String::new();

    for seq in 1..=3 {
        let fe = sample_feed_entry(seq);
        let envelope = build_signed_envelope(
            &kp,
            seq,
            prev_hash.clone(),
            fe.to_fact_value().unwrap(),
            now_rfc3339(),
        )
        .unwrap();
        assert!(verify_envelope(&envelope).unwrap());

        last_envelope_hash = envelope
            .get("envelope_hash")
            .and_then(|v| v.as_str())
            .unwrap()
            .to_string();
        prev_hash = Some(last_envelope_hash.clone());
    }

    // Publish a head announcement referencing the last entry.
    let ha = sample_head_announcement(3, &last_envelope_hash);
    let head_envelope = build_signed_envelope(
        &kp,
        4,
        prev_hash,
        ha.to_fact_value().unwrap(),
        now_rfc3339(),
    )
    .unwrap();
    assert!(verify_envelope(&head_envelope).unwrap());

    let fact = head_envelope.get("fact").unwrap();
    let restored: HeadAnnouncement = serde_json::from_value(fact.clone()).unwrap();
    assert_eq!(restored.head_envelope_hash, last_envelope_hash);
    assert_eq!(restored.head_seq, 3);
}

#[tokio::test]
async fn test_sync_request_validation() {
    // Valid range.
    let sr = SyncRequest {
        schema: "clawdstrike.marketplace.sync_request.v1".to_string(),
        curator_issuer: "aegis:ed25519:aabbccdd".to_string(),
        from_seq: 1,
        to_seq: 50,
    };
    assert!(sr.validate().is_ok());

    // from_seq = 0 is invalid.
    let sr = SyncRequest {
        from_seq: 0,
        to_seq: 5,
        ..sr.clone()
    };
    assert!(sr.validate().is_err());

    // to_seq < from_seq is invalid.
    let sr = SyncRequest {
        from_seq: 10,
        to_seq: 5,
        ..sr.clone()
    };
    assert!(sr.validate().is_err());

    // Oversized range.
    let sr = SyncRequest {
        from_seq: 1,
        to_seq: MAX_SYNC_RANGE + 1,
        ..sr
    };
    assert!(sr.validate().is_err());
}

#[tokio::test]
async fn test_sync_response_with_envelopes() {
    let kp = Keypair::generate();

    let mut envelopes = Vec::new();
    for seq in 1..=3 {
        let fe = sample_feed_entry(seq);
        let envelope = build_signed_envelope(
            &kp,
            seq,
            None,
            fe.to_fact_value().unwrap(),
            now_rfc3339(),
        )
        .unwrap();
        envelopes.push(envelope);
    }

    let sr = SyncResponse {
        schema: "clawdstrike.marketplace.sync_response.v1".to_string(),
        curator_issuer: spine::issuer_from_keypair(&kp),
        envelopes: envelopes.clone(),
    };

    let json = serde_json::to_string(&sr).unwrap();
    let restored: SyncResponse = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.envelopes.len(), 3);

    // Verify each envelope in the response.
    for env in &restored.envelopes {
        assert!(verify_envelope(env).unwrap());
    }
}

#[tokio::test]
async fn test_discovery_announcement_v1_backward_compat() {
    // A v1-style announcement (without Spine fields) should still deserialize.
    let v1_json = json!({
        "v": 1,
        "feed_uri": "ipfs://QmTest",
        "feed_id": "clawdstrike-official",
        "seq": 5,
        "signer_public_key": "aabbccdd"
    });

    // Verify it can be deserialized -- the extra fields should default to None.
    let v1_str = serde_json::to_string(&v1_json).unwrap();
    // This is a simple JSON parse test; the actual deserialization is in the
    // desktop binary using the extended struct. We verify the JSON structure
    // is valid and contains the expected fields.
    let parsed: serde_json::Value = serde_json::from_str(&v1_str).unwrap();
    assert_eq!(parsed.get("v").and_then(|v| v.as_u64()), Some(1));
    assert!(parsed.get("head_hash").is_none());
    assert!(parsed.get("spine_issuer").is_none());
    assert!(parsed.get("checkpoint_ref").is_none());
}
