//! Bridge between ClawdStrike policy bundles and Spine envelopes.
//!
//! Provides conversion from [`SignedPolicyBundle`] to Spine signed envelopes,
//! allowing policies to be published as attestable facts on the Spine log.

use hush_core::Keypair;
use serde_json::{json, Value};

use crate::error::Result;
use crate::policy_bundle::SignedPolicyBundle;

/// Fact type used when publishing a policy bundle as a Spine envelope.
pub const POLICY_BUNDLE_FACT_TYPE: &str = "clawdstrike.policy.bundle";

/// Convert a [`SignedPolicyBundle`] into a Spine signed envelope.
///
/// The bundle's canonical JSON hash and signature are embedded in the fact
/// payload so that a verifier can cross-check the Spine envelope against
/// the original bundle signature.
///
/// # Arguments
/// * `signed_bundle` - The signed policy bundle to convert.
/// * `keypair` - The Spine issuer keypair (may differ from the bundle signer).
/// * `seq` - Sequence number for the envelope chain.
/// * `prev_envelope_hash` - Hash of the previous envelope (for chaining).
pub fn policy_bundle_to_spine_envelope(
    signed_bundle: &SignedPolicyBundle,
    keypair: &Keypair,
    seq: u64,
    prev_envelope_hash: Option<String>,
) -> Result<Value> {
    let bundle_hash = signed_bundle.bundle.hash_sha256()?;

    let fact = json!({
        "type": POLICY_BUNDLE_FACT_TYPE,
        "bundle_id": signed_bundle.bundle.bundle_id,
        "bundle_version": signed_bundle.bundle.version,
        "policy_name": signed_bundle.bundle.policy.name,
        "policy_hash": signed_bundle.bundle.policy_hash.to_hex(),
        "bundle_hash": bundle_hash.to_hex(),
        "bundle_signature": signed_bundle.signature.to_hex(),
        "bundle_signer": signed_bundle.public_key.as_ref().map(|pk| pk.to_hex()),
        "compiled_at": signed_bundle.bundle.compiled_at,
    });

    let envelope = spine::build_signed_envelope(
        keypair,
        seq,
        prev_envelope_hash,
        fact,
        spine::now_rfc3339(),
    )?;

    Ok(envelope)
}

/// Extract the `envelope_hash` from a Spine envelope value.
pub fn extract_spine_envelope_hash(envelope: &Value) -> Option<String> {
    envelope
        .get("envelope_hash")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Policy;
    use crate::policy_bundle::PolicyBundle;

    #[test]
    fn policy_bundle_converts_to_spine_envelope() {
        let bundle_kp = Keypair::generate();
        let spine_kp = Keypair::generate();

        let bundle = PolicyBundle::new(Policy::default()).expect("bundle");
        let signed = SignedPolicyBundle::sign_with_public_key(bundle, &bundle_kp).expect("sign");

        let envelope =
            policy_bundle_to_spine_envelope(&signed, &spine_kp, 1, None).expect("convert");

        // Envelope should be verifiable
        assert!(spine::verify_envelope(&envelope).expect("verify"));

        // Fact should contain the bundle metadata
        let fact = envelope.get("fact").expect("fact");
        assert_eq!(
            fact.get("type").and_then(|v| v.as_str()),
            Some(POLICY_BUNDLE_FACT_TYPE)
        );
        assert_eq!(
            fact.get("bundle_id").and_then(|v| v.as_str()),
            Some(signed.bundle.bundle_id.as_str())
        );
        assert!(fact.get("bundle_hash").is_some());

        // Envelope hash should be extractable
        let hash = extract_spine_envelope_hash(&envelope);
        assert!(hash.is_some());
    }

    #[test]
    fn spine_envelope_chains() {
        let bundle_kp = Keypair::generate();
        let spine_kp = Keypair::generate();

        let bundle1 = PolicyBundle::new(Policy::default()).expect("bundle1");
        let signed1 =
            SignedPolicyBundle::sign_with_public_key(bundle1, &bundle_kp).expect("sign1");

        let e1 =
            policy_bundle_to_spine_envelope(&signed1, &spine_kp, 1, None).expect("envelope1");
        let h1 = extract_spine_envelope_hash(&e1).expect("hash1");

        let bundle2 = PolicyBundle::new(Policy::default()).expect("bundle2");
        let signed2 =
            SignedPolicyBundle::sign_with_public_key(bundle2, &bundle_kp).expect("sign2");

        let e2 = policy_bundle_to_spine_envelope(&signed2, &spine_kp, 2, Some(h1.clone()))
            .expect("envelope2");

        assert!(spine::verify_envelope(&e2).expect("verify e2"));
        assert_eq!(
            e2.get("prev_envelope_hash")
                .and_then(|v| v.as_str())
                .expect("prev"),
            h1
        );
    }
}
