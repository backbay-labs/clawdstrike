#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! OCSF v1.4.0 compliant event types and converters for ClawdStrike.
//!
//! This crate provides strongly-typed OCSF event classes, objects, and conversion
//! utilities. It has **no dependency** on the `clawdstrike` engine crate to keep it
//! lightweight and avoid circular dependencies. Wiring code in `hushd` or `hunt-query`
//! maps internal types to these OCSF structures.
//!
//! # Supported OCSF classes
//!
//! | Class              | `class_uid` | Category          |
//! |--------------------|-------------|-------------------|
//! | Detection Finding  | 2004        | Findings (2)      |
//! | Process Activity   | 1007        | System Activity (1) |
//! | File Activity      | 1001        | System Activity (1) |
//! | Network Activity   | 4001        | Network Activity (4) |

pub mod base;
pub mod classes;
pub mod convert;
pub mod decision;
pub mod fleet;
pub mod objects;
pub mod severity;
pub mod validate;

/// OCSF schema version this crate targets.
pub const OCSF_VERSION: &str = "1.4.0";

// Re-exports for convenience.
pub use base::{ActionId, CategoryUid, ClassUid, DispositionId, SeverityId, StatusId};
pub use classes::detection_finding::DetectionFinding;
pub use classes::file_activity::FileActivity;
pub use classes::network_activity::NetworkActivity;
pub use classes::process_activity::ProcessActivity;
pub use objects::metadata::{Metadata, Product};
pub use severity::map_severity;
pub use validate::{validate_ocsf_json, OcsfValidationError};
