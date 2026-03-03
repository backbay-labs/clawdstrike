//! Per-issuer hash chain verification.
//!
//! Verifies that envelopes from each issuer form a contiguous, hash-linked
//! chain. Reusable by the checkpointer, control-api, or any future consumer.
//!
//! No async, no NATS — pure library types and verification logic.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::{Error, Result};

/// Persisted state for the head of an issuer's envelope chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IssuerChainHead {
    /// Issuer identifier (`aegis:ed25519:<hex>`).
    pub issuer: String,
    /// Sequence number of the head envelope.
    pub seq: u64,
    /// Hash of the head envelope (`0x`-prefixed hex).
    pub envelope_hash: String,
}

/// Result of verifying an envelope against its issuer's known chain head.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ChainLinkVerdict {
    /// First envelope from this issuer; chain established.
    NewChain,
    /// Envelope correctly continues the existing chain.
    ValidContinuation,
    /// Envelope has the expected seq but `prev_envelope_hash` does not match
    /// the known head's `envelope_hash`.
    HashMismatch {
        expected_prev_hash: String,
        actual_prev_hash: String,
    },
    /// Envelope sequence is not `known_head.seq + 1`.
    SequenceMismatch { expected_seq: u64, actual_seq: u64 },
    /// First envelope from an issuer (no known head) but chain-start
    /// invariants are violated (seq != 1 or prev_envelope_hash is non-null).
    InvalidChainHead { reason: String },
}

fn normalize_issuer_for_compare(issuer: &str) -> String {
    crate::parse_issuer_pubkey_hex(issuer)
        .map(|hex| hex.to_ascii_lowercase())
        .unwrap_or_else(|_| issuer.to_ascii_lowercase())
}

impl ChainLinkVerdict {
    /// Returns `true` if the verdict indicates a valid chain link.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::NewChain | Self::ValidContinuation)
    }

    /// Convert to a `Result`, mapping rejection variants to
    /// [`Error::ChainIntegrityViolation`].
    pub fn into_result(self, issuer: &str) -> Result<()> {
        match self {
            Self::NewChain | Self::ValidContinuation => Ok(()),
            Self::HashMismatch {
                expected_prev_hash,
                actual_prev_hash,
            } => Err(Error::ChainIntegrityViolation {
                issuer: issuer.to_string(),
                reason: format!(
                    "prev_envelope_hash mismatch: expected {expected_prev_hash}, got {actual_prev_hash}"
                ),
            }),
            Self::SequenceMismatch {
                expected_seq,
                actual_seq,
            } => Err(Error::ChainIntegrityViolation {
                issuer: issuer.to_string(),
                reason: format!("sequence mismatch: expected {expected_seq}, got {actual_seq}"),
            }),
            Self::InvalidChainHead { reason } => Err(Error::ChainIntegrityViolation {
                issuer: issuer.to_string(),
                reason,
            }),
        }
    }
}

/// Verify that `envelope` correctly continues the chain for its issuer.
///
/// - If `known_head` is `None`, the envelope must have `seq = 1` and
///   `prev_envelope_hash` must be `null`.
/// - If `known_head` is `Some`, the envelope must have `seq = head.seq + 1`
///   and `prev_envelope_hash` must equal `head.envelope_hash`.
/// - If `known_head` is `Some`, `envelope.issuer` must match `head.issuer`.
pub fn verify_chain_link(
    envelope: &Value,
    known_head: Option<&IssuerChainHead>,
) -> Result<ChainLinkVerdict> {
    let envelope_issuer = envelope
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or(Error::MissingField("issuer"))?;

    let seq = envelope
        .get("seq")
        .and_then(|v| v.as_u64())
        .ok_or(Error::MissingField("seq"))?;

    let prev_hash = envelope
        .get("prev_envelope_hash")
        .ok_or(Error::MissingField("prev_envelope_hash"))?;

    let prev_hash_str = if prev_hash.is_null() {
        None
    } else {
        Some(
            prev_hash
                .as_str()
                .ok_or(Error::MissingField("prev_envelope_hash"))?,
        )
    };

    match known_head {
        None => {
            if seq != 1 {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: format!("first envelope must have seq=1, got seq={seq}"),
                });
            }
            if prev_hash_str.is_some() {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: "first envelope must have null prev_envelope_hash".to_string(),
                });
            }
            Ok(ChainLinkVerdict::NewChain)
        }
        Some(head) => {
            let envelope_issuer_norm = normalize_issuer_for_compare(envelope_issuer);
            let head_issuer_norm = normalize_issuer_for_compare(&head.issuer);
            if envelope_issuer_norm != head_issuer_norm {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: format!(
                        "issuer mismatch: envelope issuer {envelope_issuer} does not match head issuer {}",
                        head.issuer
                    ),
                });
            }

            let Some(expected_seq) = head.seq.checked_add(1) else {
                return Ok(ChainLinkVerdict::InvalidChainHead {
                    reason: format!("known head sequence overflow for issuer {}", head.issuer),
                });
            };
            if seq != expected_seq {
                return Ok(ChainLinkVerdict::SequenceMismatch {
                    expected_seq,
                    actual_seq: seq,
                });
            }

            let actual_prev = prev_hash_str.unwrap_or("");
            if actual_prev != head.envelope_hash {
                return Ok(ChainLinkVerdict::HashMismatch {
                    expected_prev_hash: head.envelope_hash.clone(),
                    actual_prev_hash: actual_prev.to_string(),
                });
            }

            Ok(ChainLinkVerdict::ValidContinuation)
        }
    }
}

/// Extract an [`IssuerChainHead`] from a verified envelope.
///
/// The envelope must contain `issuer`, `seq`, and `envelope_hash` fields.
pub fn chain_head_from_envelope(envelope: &Value) -> Result<IssuerChainHead> {
    let issuer = envelope
        .get("issuer")
        .and_then(|v| v.as_str())
        .ok_or(Error::MissingField("issuer"))?
        .to_string();

    let seq = envelope
        .get("seq")
        .and_then(|v| v.as_u64())
        .ok_or(Error::MissingField("seq"))?;

    let envelope_hash = envelope
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .ok_or(Error::MissingField("envelope_hash"))?
        .to_string();

    Ok(IssuerChainHead {
        issuer,
        seq,
        envelope_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::Keypair;
    use serde_json::json;

    fn make_envelope(kp: &Keypair, seq: u64, prev: Option<String>) -> Value {
        crate::build_signed_envelope(
            kp,
            seq,
            prev,
            json!({"type": "chain_test", "seq": seq}),
            crate::now_rfc3339(),
        )
        .expect("build_signed_envelope should succeed")
    }

    #[test]
    fn new_chain() {
        let kp = Keypair::generate();
        let e1 = make_envelope(&kp, 1, None);
        let verdict = verify_chain_link(&e1, None).unwrap();
        assert_eq!(verdict, ChainLinkVerdict::NewChain);
        assert!(verdict.is_valid());
    }

    #[test]
    fn valid_continuation() {
        let kp = Keypair::generate();
        let e1 = make_envelope(&kp, 1, None);
        let head = chain_head_from_envelope(&e1).unwrap();

        let e2 = make_envelope(&kp, 2, Some(head.envelope_hash.clone()));
        let verdict = verify_chain_link(&e2, Some(&head)).unwrap();
        assert_eq!(verdict, ChainLinkVerdict::ValidContinuation);
        assert!(verdict.is_valid());
    }

    #[test]
    fn hash_mismatch() {
        let kp = Keypair::generate();
        let e1 = make_envelope(&kp, 1, None);
        let head = chain_head_from_envelope(&e1).unwrap();

        // Build e2 with wrong prev_envelope_hash.
        let e2 = make_envelope(&kp, 2, Some("0xdeadbeef".to_string()));
        let verdict = verify_chain_link(&e2, Some(&head)).unwrap();
        assert!(matches!(verdict, ChainLinkVerdict::HashMismatch { .. }));
        assert!(!verdict.is_valid());
    }

    #[test]
    fn seq_gap() {
        let kp = Keypair::generate();
        let e1 = make_envelope(&kp, 1, None);
        let head = chain_head_from_envelope(&e1).unwrap();

        // Skip seq 2, go straight to 3.
        let e3 = make_envelope(&kp, 3, Some(head.envelope_hash.clone()));
        let verdict = verify_chain_link(&e3, Some(&head)).unwrap();
        assert!(matches!(
            verdict,
            ChainLinkVerdict::SequenceMismatch {
                expected_seq: 2,
                actual_seq: 3,
            }
        ));
        assert!(!verdict.is_valid());
    }

    #[test]
    fn seq_regression() {
        let kp = Keypair::generate();
        let e1 = make_envelope(&kp, 1, None);
        let head1 = chain_head_from_envelope(&e1).unwrap();

        let e2 = make_envelope(&kp, 2, Some(head1.envelope_hash.clone()));
        let head2 = chain_head_from_envelope(&e2).unwrap();

        // Replay seq=2 against head at seq=2 (expects seq=3).
        let e2_replay = make_envelope(&kp, 2, Some(head2.envelope_hash.clone()));
        let verdict = verify_chain_link(&e2_replay, Some(&head2)).unwrap();
        assert!(matches!(
            verdict,
            ChainLinkVerdict::SequenceMismatch {
                expected_seq: 3,
                actual_seq: 2,
            }
        ));
    }

    #[test]
    fn invalid_chain_head_wrong_seq() {
        let kp = Keypair::generate();
        // First envelope with seq=5 (should be 1).
        let e = make_envelope(&kp, 5, None);
        let verdict = verify_chain_link(&e, None).unwrap();
        assert!(matches!(verdict, ChainLinkVerdict::InvalidChainHead { .. }));
        assert!(!verdict.is_valid());
    }

    #[test]
    fn invalid_chain_head_non_null_prev() {
        let kp = Keypair::generate();
        // First envelope with seq=1 but non-null prev.
        let e = make_envelope(&kp, 1, Some("0xabc123".to_string()));
        let verdict = verify_chain_link(&e, None).unwrap();
        assert!(matches!(verdict, ChainLinkVerdict::InvalidChainHead { .. }));
        assert!(!verdict.is_valid());
    }

    #[test]
    fn per_issuer_isolation() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        // Issuer A: seq=1
        let a1 = make_envelope(&kp_a, 1, None);
        let head_a = chain_head_from_envelope(&a1).unwrap();

        // Issuer B: seq=1 (independent chain)
        let b1 = make_envelope(&kp_b, 1, None);
        let verdict_b = verify_chain_link(&b1, None).unwrap();
        assert_eq!(verdict_b, ChainLinkVerdict::NewChain);

        // Issuer A: seq=2 (continues A's chain, not affected by B)
        let a2 = make_envelope(&kp_a, 2, Some(head_a.envelope_hash.clone()));
        let verdict_a2 = verify_chain_link(&a2, Some(&head_a)).unwrap();
        assert_eq!(verdict_a2, ChainLinkVerdict::ValidContinuation);
    }

    #[test]
    fn issuer_mismatch_rejected_even_when_seq_and_prev_match() {
        let kp_a = Keypair::generate();
        let kp_b = Keypair::generate();

        let b1 = make_envelope(&kp_b, 1, None);
        let head_b = chain_head_from_envelope(&b1).unwrap();

        let a2 = make_envelope(&kp_a, 2, Some(head_b.envelope_hash.clone()));
        let verdict = verify_chain_link(&a2, Some(&head_b)).unwrap();
        assert!(matches!(verdict, ChainLinkVerdict::InvalidChainHead { .. }));
        assert!(!verdict.is_valid());
    }

    #[test]
    fn max_sequence_head_rejected_without_overflow() {
        let kp = Keypair::generate();
        let issuer = crate::issuer_from_keypair(&kp);
        let head = IssuerChainHead {
            issuer,
            seq: u64::MAX,
            envelope_hash: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
        };

        let env = make_envelope(&kp, u64::MAX, Some(head.envelope_hash.clone()));
        let verdict = verify_chain_link(&env, Some(&head)).unwrap();
        assert!(matches!(verdict, ChainLinkVerdict::InvalidChainHead { .. }));
        assert!(!verdict.is_valid());
    }

    #[test]
    fn chain_head_from_envelope_extracts_fields() {
        let kp = Keypair::generate();
        let e = make_envelope(&kp, 42, Some("0xprevhash".to_string()));
        let head = chain_head_from_envelope(&e).unwrap();

        assert_eq!(head.issuer, crate::issuer_from_keypair(&kp));
        assert_eq!(head.seq, 42);
        assert!(!head.envelope_hash.is_empty());
    }

    #[test]
    fn issuer_chain_head_serde_roundtrip() {
        let head = IssuerChainHead {
            issuer:
                "aegis:ed25519:aabbccddee001122aabbccddee001122aabbccddee001122aabbccddee001122"
                    .to_string(),
            seq: 7,
            envelope_hash: "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
                .to_string(),
        };
        let json = serde_json::to_string(&head).unwrap();
        let restored: IssuerChainHead = serde_json::from_str(&json).unwrap();
        assert_eq!(head, restored);
    }
}
