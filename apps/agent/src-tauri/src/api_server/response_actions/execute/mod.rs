//! Per-action execution paths for live response actions.
//!
//! Each sub-file owns the side effects for one `EndpointDecisionAction`
//! variant: collect_evidence, restrict_egress, quarantine_file,
//! disable_persistence, revoke_grant, suspend_process_tree.

mod collect_evidence;
mod disable_persistence;
mod quarantine_file;
mod restrict_egress;
mod revoke_grant;
mod suspend_process_tree;

pub(crate) use collect_evidence::*;
pub(crate) use disable_persistence::*;
pub(crate) use quarantine_file::*;
pub(crate) use restrict_egress::*;
pub(crate) use revoke_grant::*;
pub(crate) use suspend_process_tree::*;
