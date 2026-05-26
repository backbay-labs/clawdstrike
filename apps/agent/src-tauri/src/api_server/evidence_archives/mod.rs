use super::*;

mod helpers;
mod response;
mod verify;

// Internal-only re-exports so sibling submodules can resolve each other via
// `use super::*`. These names stay private to the `evidence_archives` module.
use helpers::*;
use response::*;
use verify::*;

// External surface: only the symbols consumed outside the module are
// re-exported up to `crate::api_server::*`.
pub(crate) use helpers::{
    evidence_bundle_age_seconds, evidence_bundle_record,
    receipt_family_allows_multiple_archive_members,
};
pub(crate) use response::{
    active_response_evidence_bundle_ids, archive_newest_receipt_timestamp,
    evidence_bundle_archive_receipts, evidence_bundle_archive_response,
};
pub(crate) use verify::evidence_bundle_archive_verification;
