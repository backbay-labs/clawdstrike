//! Integration tests for per-issuer hash chain verification.
//!
//! Tests the library-level chain verification logic from `spine::chain`.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use hush_core::Keypair;
use serde_json::json;
use spine::{
    build_signed_envelope, chain_head_from_envelope, now_rfc3339, verify_chain_link,
    ChainLinkVerdict, IssuerChainHead,
};

fn make_envelope(
    kp: &Keypair,
    seq: u64,
    prev: Option<String>,
    fact: serde_json::Value,
) -> serde_json::Value {
    build_signed_envelope(kp, seq, prev, fact, now_rfc3339()).unwrap()
}

/// Full 5-envelope chain: verify each link passes.
#[test]
fn five_envelope_chain_verification() {
    let kp = Keypair::generate();
    let mut head: Option<IssuerChainHead> = None;

    for seq in 1..=5 {
        let prev = head.as_ref().map(|h| h.envelope_hash.clone());
        let envelope = make_envelope(&kp, seq, prev, json!({"step": seq}));

        let verdict = verify_chain_link(&envelope, head.as_ref()).unwrap();
        if seq == 1 {
            assert_eq!(verdict, ChainLinkVerdict::NewChain);
        } else {
            assert_eq!(verdict, ChainLinkVerdict::ValidContinuation);
        }
        assert!(verdict.is_valid());

        head = Some(chain_head_from_envelope(&envelope).unwrap());
    }

    // Final head should be at seq=5.
    assert_eq!(head.unwrap().seq, 5);
}

/// Fork detection: correct seq but wrong prev_hash.
#[test]
fn fork_detection_correct_seq_wrong_prev_hash() {
    let kp = Keypair::generate();

    let e1 = make_envelope(&kp, 1, None, json!({"type": "init"}));
    let head = chain_head_from_envelope(&e1).unwrap();

    // Fork: seq=2 but prev_envelope_hash points to a different envelope.
    let fork = make_envelope(
        &kp,
        2,
        Some("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string()),
        json!({"type": "fork"}),
    );

    let verdict = verify_chain_link(&fork, Some(&head)).unwrap();
    assert!(matches!(verdict, ChainLinkVerdict::HashMismatch { .. }));
    assert!(!verdict.is_valid());

    // into_result should produce ChainIntegrityViolation
    let issuer = spine::issuer_from_keypair(&kp);
    let err = verdict.into_result(&issuer).unwrap_err();
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("chain integrity violation"),
        "expected chain integrity violation, got: {err_msg}"
    );
    assert!(err_msg.contains("prev_envelope_hash mismatch"));
}

/// IssuerChainHead serde roundtrip.
#[test]
fn issuer_chain_head_serde_roundtrip() {
    let head = IssuerChainHead {
        issuer: "aegis:ed25519:aabbccddee001122aabbccddee001122aabbccddee001122aabbccddee001122"
            .to_string(),
        seq: 42,
        envelope_hash: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            .to_string(),
    };

    let json = serde_json::to_string_pretty(&head).unwrap();
    let restored: IssuerChainHead = serde_json::from_str(&json).unwrap();
    assert_eq!(head, restored);

    // Verify deny_unknown_fields
    let bad_json = r#"{"issuer":"x","seq":1,"envelope_hash":"y","rogue":"z"}"#;
    assert!(
        serde_json::from_str::<IssuerChainHead>(bad_json).is_err(),
        "should reject unknown fields"
    );
}

/// ChainLinkVerdict::into_result() converts valid verdicts to Ok.
#[test]
fn verdict_into_result_valid() {
    assert!(ChainLinkVerdict::NewChain
        .into_result("test-issuer")
        .is_ok());
    assert!(ChainLinkVerdict::ValidContinuation
        .into_result("test-issuer")
        .is_ok());
}

/// ChainLinkVerdict::into_result() converts rejection verdicts to Err.
#[test]
fn verdict_into_result_rejection() {
    let hash_err = ChainLinkVerdict::HashMismatch {
        expected_prev_hash: "0xaaa".to_string(),
        actual_prev_hash: "0xbbb".to_string(),
    }
    .into_result("test-issuer");
    assert!(hash_err.is_err());

    let seq_err = ChainLinkVerdict::SequenceMismatch {
        expected_seq: 3,
        actual_seq: 5,
    }
    .into_result("test-issuer");
    assert!(seq_err.is_err());

    let head_err = ChainLinkVerdict::InvalidChainHead {
        reason: "bad".to_string(),
    }
    .into_result("test-issuer");
    assert!(head_err.is_err());
}

/// Two issuers maintain independent chains that don't interfere.
#[test]
fn multi_issuer_independent_chains() {
    let kp_a = Keypair::generate();
    let kp_b = Keypair::generate();

    // Issuer A: 3 envelopes
    let mut head_a: Option<IssuerChainHead> = None;
    for seq in 1..=3 {
        let prev = head_a.as_ref().map(|h| h.envelope_hash.clone());
        let env = make_envelope(&kp_a, seq, prev, json!({"issuer": "a", "seq": seq}));
        let v = verify_chain_link(&env, head_a.as_ref()).unwrap();
        assert!(v.is_valid());
        head_a = Some(chain_head_from_envelope(&env).unwrap());
    }

    // Issuer B: 2 envelopes (completely independent)
    let mut head_b: Option<IssuerChainHead> = None;
    for seq in 1..=2 {
        let prev = head_b.as_ref().map(|h| h.envelope_hash.clone());
        let env = make_envelope(&kp_b, seq, prev, json!({"issuer": "b", "seq": seq}));
        let v = verify_chain_link(&env, head_b.as_ref()).unwrap();
        assert!(v.is_valid());
        head_b = Some(chain_head_from_envelope(&env).unwrap());
    }

    // Issuer A continues at seq=4 (not affected by B)
    let env_a4 = make_envelope(
        &kp_a,
        4,
        Some(head_a.as_ref().unwrap().envelope_hash.clone()),
        json!({"issuer": "a", "seq": 4}),
    );
    let v = verify_chain_link(&env_a4, head_a.as_ref()).unwrap();
    assert_eq!(v, ChainLinkVerdict::ValidContinuation);

    // Using B's head to verify A's envelope should fail (seq mismatch)
    let v_cross = verify_chain_link(&env_a4, head_b.as_ref()).unwrap();
    assert!(!v_cross.is_valid());
}
