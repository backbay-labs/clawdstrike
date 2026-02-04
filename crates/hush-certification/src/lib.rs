//! Certification + compliance primitives for hushd-based deployments.
//!
//! This crate intentionally focuses on:
//! - Audit ledger v2 (hash-chained, export-friendly)
//! - Certification authority records (issue/verify/revoke)
//! - Evidence bundle generation (ZIP + signed manifest)

pub mod audit;
pub mod badge;
pub mod certification;
pub mod evidence;
pub mod error;
pub mod webhooks;

pub use error::{Error, Result};
