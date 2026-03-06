//! Conversion functions from ClawdStrike internal types to OCSF events.
//!
//! These converters take primitive / `serde_json::Value` inputs so the OCSF crate
//! does not depend on the `clawdstrike` engine crate.

pub mod from_detection_record;
pub mod from_guard_result;
pub mod from_hubble_fact;
pub mod from_security_event;
pub mod from_tetragon_fact;
pub mod from_timeline_event;
