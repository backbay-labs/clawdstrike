#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! Hush Proxy - Network proxy utilities for clawdstrike
//!
//! This crate provides DNS and SNI inspection/filtering utilities
//! for implementing network egress controls.

pub mod dns;
pub mod error;
pub mod policy;
pub mod sni;

pub use error::{Error, Result};
