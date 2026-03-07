#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! Hunt Query — structured querying and timeline reconstruction for clawdstrike hunt.
//!
//! OCSF projection is part of the crate's baseline surface. The legacy `ocsf`
//! cargo feature remains as a no-op compatibility shim for downstream manifests
//! that still enable it.

pub mod error;
mod fleet_projection;
pub mod local;
pub mod nl;
pub mod query;
pub mod render;
pub mod replay;
pub mod service;
pub mod timeline;

pub mod ocsf;
