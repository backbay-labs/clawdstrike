use anyhow::{anyhow, Context, Result};
use hush_core::{
    canonicalize_json, sha256, Hash, Provenance, Receipt, SignedReceipt, Signer, Verdict,
};

use super::super::stable_id;
use super::{camel_debug_to_snake, hex_strings_match, EndpointDecisionReceipt};

impl EndpointDecisionReceipt {
    pub fn to_receipt(&self) -> Result<Receipt> {
        self.validate()?;
        let endpoint_metadata =
            serde_json::to_value(self).context("serialize endpoint decision receipt metadata")?;
        let canonical = canonicalize_json(&endpoint_metadata)
            .context("canonicalize endpoint decision receipt metadata")?;
        let content_hash = sha256(canonical.as_bytes());
        let policy_hash = Hash::from_hex(self.policy.policy_hash.as_str())
            .with_context(|| "policy hash must be a 32-byte hex hash")?;

        Ok(Receipt::new(content_hash, self.to_verdict())
            .with_id(self.receipt_id())
            .with_provenance(Provenance {
                clawdstrike_version: Some(env!("CARGO_PKG_VERSION").to_string()),
                provider: Some("clawdstrike.endpoint_decision_engine".to_string()),
                policy_hash: Some(policy_hash),
                ruleset: Some(self.policy.policy_version.clone()),
                violations: Vec::new(),
            })
            .with_metadata(serde_json::json!({
                "endpointDecision": endpoint_metadata,
            })))
    }

    pub fn sign_with(&self, signer: &dyn Signer) -> Result<SignedReceipt> {
        let actual_public_key = signer.public_key().to_hex();
        if let Some(expected_public_key) = self.signer.signer_public_key.as_deref() {
            if !hex_strings_match(expected_public_key, actual_public_key.as_str()) {
                return Err(anyhow!(
                    "endpoint receipt signer public key does not match signer identity metadata"
                ));
            }
        }

        let mut receipt = self.clone();
        if receipt.signer.signer_public_key.is_none() {
            receipt.signer.signer_public_key = Some(actual_public_key);
        }

        SignedReceipt::sign_with(receipt.to_receipt()?, signer)
            .context("sign endpoint decision receipt")
    }

    #[must_use]
    pub fn receipt_id(&self) -> String {
        let family = format!("{:?}", self.receipt_family);
        let sequence = self.local_sequence.to_string();
        let observation_id = self.decision.observation_id.as_deref().unwrap_or_default();
        let finding_id = self.decision.finding_id.as_deref().unwrap_or_default();
        stable_id(
            "endpoint_receipt",
            [
                self.schema_version.as_str(),
                self.actor.endpoint_id.as_str(),
                family.as_str(),
                sequence.as_str(),
                observation_id,
                finding_id,
            ],
        )
    }

    fn to_verdict(&self) -> Verdict {
        Verdict {
            passed: self.decision.passed,
            gate_id: self.decision.rule_id.clone().or_else(|| {
                Some(camel_debug_to_snake(
                    format!("{:?}", self.receipt_family).as_str(),
                ))
            }),
            scores: self.decision.confidence.map(|confidence| {
                serde_json::json!({
                    "confidence": confidence,
                })
            }),
            threshold: None,
        }
    }
}
