//! Receipt construction and session statistics for [`HushEngine`].

use tracing::info;

use hush_core::receipt::{Provenance, Verdict};
use hush_core::{Hash, Receipt, SignedReceipt};

use crate::error::{Error, Result};

use super::types::{EngineStats, GuardEvaluationMetadata, GuardReport};
use super::{EngineState, HushEngine};

impl HushEngine {
    /// Create a receipt for the current session
    pub async fn create_receipt(&self, content_hash: Hash) -> Result<Receipt> {
        let state = self.state.read().await;

        let verdict = if state.violation_count == 0 {
            Verdict::pass()
        } else {
            Verdict::fail()
        };

        let provenance = Provenance {
            clawdstrike_version: Some(env!("CARGO_PKG_VERSION").to_string()),
            provider: None,
            policy_hash: Some(self.policy_hash()?),
            ruleset: Some(self.policy.name.clone()),
            violations: state.violations.clone(),
        };

        let mut receipt = Receipt::new(content_hash, verdict).with_provenance(provenance);

        if let Some(path) = state.last_evaluation_path.as_ref() {
            let observed_paths = state.evaluation_path_counts.clone();
            receipt = receipt.merge_metadata(serde_json::json!({
                "clawdstrike": {
                    "evaluation": {
                        "last_path": path.path_string(),
                        "last": path,
                        "observed_paths": observed_paths,
                    }
                }
            }));
        }

        if !self.extra_guards.is_empty() {
            let extra_guards: Vec<&str> = self.extra_guards.iter().map(|g| g.name()).collect();
            receipt = receipt.merge_metadata(serde_json::json!({
                "clawdstrike": {
                    "extra_guards": extra_guards,
                }
            }));
        }

        Ok(receipt)
    }

    /// Create a receipt enriched with the origin/enclave metadata from a guard report.
    pub async fn create_receipt_for_report(
        &self,
        content_hash: Hash,
        report: &GuardReport,
    ) -> Result<Receipt> {
        let receipt = self.create_receipt(content_hash).await?;
        Ok(merge_report_metadata_into_receipt(
            receipt,
            report.metadata.as_ref(),
        ))
    }

    /// Create and sign a receipt
    pub async fn create_signed_receipt(&self, content_hash: Hash) -> Result<SignedReceipt> {
        let keypair = self
            .keypair
            .as_ref()
            .ok_or_else(|| Error::ConfigError("No signing keypair configured".into()))?;

        let receipt = self.create_receipt(content_hash).await?;
        SignedReceipt::sign(receipt, keypair).map_err(Error::from)
    }

    /// Create and sign a receipt enriched with per-report origin metadata.
    pub async fn create_signed_receipt_for_report(
        &self,
        content_hash: Hash,
        report: &GuardReport,
    ) -> Result<SignedReceipt> {
        let keypair = self
            .keypair
            .as_ref()
            .ok_or_else(|| Error::ConfigError("No signing keypair configured".into()))?;

        let receipt = self.create_receipt_for_report(content_hash, report).await?;
        SignedReceipt::sign(receipt, keypair).map_err(Error::from)
    }

    /// Get session statistics
    pub async fn stats(&self) -> EngineStats {
        let state = self.state.read().await;
        EngineStats {
            action_count: state.action_count,
            violation_count: state.violation_count,
        }
    }

    /// Reset session state
    pub async fn reset(&self) {
        let mut state = self.state.write().await;
        *state = EngineState::default();
        info!("Engine state reset");
    }
}

pub(super) fn merge_report_metadata_into_receipt(
    mut receipt: Receipt,
    metadata: Option<&GuardEvaluationMetadata>,
) -> Receipt {
    let Some(metadata) = metadata else {
        return receipt;
    };

    if let Some(origin) = metadata.origin.as_ref() {
        if let Ok(origin_json) = serde_json::to_value(origin) {
            receipt = receipt.merge_metadata(serde_json::json!({
                "clawdstrike": {
                    "origin": origin_json,
                }
            }));
        }
    }

    if let Some(enclave) = metadata.enclave.as_ref() {
        receipt = receipt.merge_metadata(serde_json::json!({
            "clawdstrike": {
                "enclave": {
                    "profile_id": enclave.profile_id,
                    "resolution_path": enclave.resolution_path,
                }
            }
        }));
    }

    receipt
}
