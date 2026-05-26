//! Shared on-disk DTOs for the hushd runtime configuration file.
//!
//! The desktop agent at `apps/agent/src-tauri/src/daemon.rs` writes a YAML
//! runtime config that the `hushd` daemon at `crates/services/hushd/src/config.rs`
//! must read. Historically the two sides defined their own private structs
//! with the same field names. If they drifted (e.g. the writer added a field
//! the reader didn't expect, or the reader added `#[serde(deny_unknown_fields)]`
//! to a struct the writer omitted a key from), the result was a silent runtime
//! failure: the agent would spawn `hushd` with a config it could not parse and
//! the daemon would refuse to start.
//!
//! This crate is the single source of truth for that wire format. The DTOs
//! here cover exactly the subset of `hushd`'s configuration schema that the
//! desktop agent writes. Every field uses `#[serde(default)]` (or
//! `skip_serializing_if`) so that the resulting YAML deserializes cleanly into
//! either:
//!
//! * `clawdstrike_hushd_config::RuntimeConfig` (this crate's roundtrip target).
//! * `hushd::config::Config` (the daemon's full reader, which is a strict
//!   superset of the writer's schema).
//!
//! The crate is intentionally tiny: no async, no I/O, no implementation deps.
//! It is shared between the desktop agent (excluded from the workspace) and
//! `hushd` (a workspace member). Both sides should depend on this crate via
//! path so that any future shape change must be expressed here once and is
//! visible in both PRs.

#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod runtime;
pub mod siem;
pub mod spine;
pub mod webhook;

pub use runtime::RuntimeConfig;
pub use siem::{
    DatadogExporterConfig, ElasticAuthConfig, ElasticExporterConfig, ExporterSettings,
    ExportersConfig, SiemConfig, SplunkExporterConfig, SumoLogicExporterConfig,
    WebhookExporterConfig,
};
pub use spine::SpineConfig;
pub use webhook::{GenericWebhookConfig, WebhookAuthConfig};
