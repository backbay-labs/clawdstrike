//! Evidence bundle archive, query, compaction, and flight-recorder DTOs.
//!
//! `EdrEvidenceBundleArtifact::from_stored` references the agent-private
//! `StoredEndpointEvidenceBundle` type; that ctor lives in the agent's
//! `edr/dto.rs`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::edr::{
    CausalGraph, EndpointEvidenceBundleReference, EndpointFlightRecorderCompactionRecord,
};
use hush_core::SignedReceipt;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrEvidenceBundleArtifact {
    pub bundle_id: String,
    pub path: Option<String>,
    pub byte_count: usize,
    pub content_hash: String,
}

#[derive(Debug, Serialize)]
pub struct EdrEvidenceBundleResponse {
    pub bundle: EndpointEvidenceBundleReference,
    pub path: Option<String>,
    pub byte_count: usize,
    pub graph: CausalGraph,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrEvidenceBundleArchive {
    pub bundle: EndpointEvidenceBundleReference,
    pub artifact: EdrEvidenceBundleArtifact,
    pub graph: CausalGraph,
    pub receipts: Vec<SignedReceipt>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrEvidenceBundleArchiveResponse {
    pub archive_id: String,
    pub generated_at: chrono::DateTime<chrono::Utc>,
    pub archive_hash: String,
    pub receipt_count: usize,
    pub verification: EdrEvidenceBundleArchiveVerification,
    pub archive: EdrEvidenceBundleArchive,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrEvidenceBundleArchiveVerification {
    pub verified: bool,
    pub graph_content_hash: String,
    pub content_hash_matches: bool,
    pub artifact_matches_bundle: bool,
    #[serde(default)]
    pub artifact_byte_count_matches: bool,
    #[serde(default)]
    pub receipts_bind_bundle_id: bool,
    #[serde(default)]
    pub receipts_bind_actor: bool,
    #[serde(default)]
    pub receipts_bind_policy: bool,
    #[serde(default)]
    pub receipts_bind_sensor_state: bool,
    #[serde(default)]
    pub receipts_bind_endpoint_decision: bool,
    #[serde(default)]
    pub receipt_endpoint_ids: Vec<String>,
    #[serde(default)]
    pub receipts_bind_endpoint_identity: bool,
    #[serde(default)]
    pub receipt_root_node_ids: Vec<String>,
    #[serde(default)]
    pub receipts_bind_root_node: bool,
    pub graph_counts_match: bool,
    pub receipt_count: usize,
    #[serde(default)]
    pub receipt_ids_unique: bool,
    #[serde(default)]
    pub receipt_local_sequences: Vec<u64>,
    #[serde(default)]
    pub receipt_local_sequences_present: bool,
    #[serde(default)]
    pub receipt_local_sequences_unique: bool,
    #[serde(default)]
    pub receipt_timestamps_parse: bool,
    #[serde(default)]
    pub receipt_chronology_consistent: bool,
    pub receipt_families_valid: bool,
    #[serde(default)]
    pub present_receipt_families: Vec<String>,
    #[serde(default)]
    pub receipt_family_counts: BTreeMap<String, usize>,
    #[serde(default)]
    pub receipt_family_cardinality_valid: bool,
    #[serde(default)]
    pub required_receipt_families: Vec<String>,
    #[serde(default)]
    pub required_receipt_families_present: bool,
    #[serde(default)]
    pub missing_required_receipt_families: Vec<String>,
    pub receipt_signatures_valid: bool,
    #[serde(default)]
    pub receipt_signers_consistent: bool,
    pub receipts_bind_graph_slice: bool,
    pub receipts_bind_content_hash: bool,
    pub receipt_failure_count: usize,
    pub receipt_failures: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EdrEvidenceBundleArchiveVerifyInput {
    #[serde(default)]
    pub archive_id: Option<String>,
    #[serde(default)]
    pub generated_at: Option<chrono::DateTime<chrono::Utc>>,
    pub archive_hash: String,
    #[serde(default)]
    pub receipt_count: Option<usize>,
    #[serde(default)]
    pub verification: Option<EdrEvidenceBundleArchiveVerification>,
    #[serde(default)]
    pub trusted_signer_public_key: Option<String>,
    pub archive: EdrEvidenceBundleArchive,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrEvidenceBundleArchiveVerifyResponse {
    pub verified: bool,
    pub expected_archive_id: String,
    pub archive_id_matches: bool,
    pub expected_archive_hash: String,
    pub archive_hash: String,
    pub archive_hash_matches: bool,
    pub receipt_count_matches: bool,
    pub verification_matches: bool,
    pub generated_at_covers_receipts: bool,
    pub newest_receipt_timestamp: Option<chrono::DateTime<chrono::Utc>>,
    pub trusted_signer_public_key: Option<String>,
    pub signer_trust_matches: bool,
    pub verification: EdrEvidenceBundleArchiveVerification,
}

#[derive(Debug, Deserialize)]
pub struct EdrEvidenceBundleQuery {
    #[serde(default)]
    pub limit: Option<usize>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrEvidenceBundleRecord {
    pub bundle: EndpointEvidenceBundleReference,
    pub path: Option<String>,
    pub byte_count: usize,
    pub age_seconds: u64,
    pub protected_by_active_response: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrEvidenceBundlesResponse {
    pub root: Option<String>,
    pub bundle_count: usize,
    pub protected_count: usize,
    pub bundles: Vec<EdrEvidenceBundleRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrEvidenceBundleCompactionInput {
    #[serde(default, alias = "maxBundles")]
    pub max_bundles: Option<usize>,
    #[serde(default, alias = "minAgeSeconds")]
    pub min_age_seconds: Option<u64>,
    #[serde(default, alias = "dryRun")]
    pub dry_run: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrEvidenceBundleCompactionRecord {
    pub bundle_id: String,
    pub graph_slice_id: String,
    pub path: Option<String>,
    pub byte_count: usize,
    pub age_seconds: u64,
    pub protected_by_active_response: bool,
    pub removed: bool,
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrEvidenceBundleCompactionResponse {
    pub root: Option<String>,
    pub dry_run: bool,
    pub max_bundles: Option<usize>,
    pub min_age_seconds: u64,
    pub bundle_count: usize,
    pub candidate_count: usize,
    pub removed_count: usize,
    pub protected_count: usize,
    pub records: Vec<EdrEvidenceBundleCompactionRecord>,
}

#[derive(Debug, Serialize)]
pub struct EdrFlightRecorderResponse {
    pub path: Option<String>,
    pub observation_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EdrFlightRecorderCompactionInput {
    #[serde(default, alias = "maxObservations")]
    pub max_observations: Option<usize>,
    #[serde(default, alias = "minAgeSeconds")]
    pub min_age_seconds: Option<u64>,
    #[serde(default, alias = "dryRun")]
    pub dry_run: Option<bool>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EdrFlightRecorderCompactionResponse {
    pub path: Option<String>,
    pub dry_run: bool,
    pub max_observations: Option<usize>,
    pub min_age_seconds: u64,
    pub observation_count: usize,
    pub candidate_count: usize,
    pub removed_count: usize,
    pub retained_count: usize,
    pub protected_count: usize,
    pub node_count: usize,
    pub edge_count: usize,
    pub records: Vec<EndpointFlightRecorderCompactionRecord>,
}
