//! Per-action rollback paths plus the shared TTL-expiration dispatcher.
//!
//! Each sub-file owns the reverse side effects for one rollback-capable
//! `EndpointDecisionAction`: restrict_egress, quarantine_file,
//! disable_persistence, suspend_process_tree. `expiration` dispatches to the
//! correct rollback based on the original action when an execution's TTL is
//! reached.

mod disable_persistence;
mod expiration;
mod quarantine_file;
mod restrict_egress;
mod suspend_process_tree;

pub(crate) use disable_persistence::*;
pub(crate) use expiration::*;
pub(crate) use quarantine_file::*;
pub(crate) use restrict_egress::*;
pub(crate) use suspend_process_tree::*;
