//! HTTP route handlers grouped by feature area.
//!
//! Each submodule owns the handlers for a single endpoint family. EDR-specific
//! handlers live in sibling api_server submodules (receipts, response_actions,
//! observations, ...) — these `routes/*` files own the "agent control plane"
//! endpoints: settings, integrations, OTA, policy check, health, diagnostics,
//! OpenClaw, approvals, enrollment, and token rotation.

pub(crate) mod approvals;
pub(crate) mod auth;
pub(crate) mod diagnostics;
pub(crate) mod enrollment;
pub(crate) mod health;
pub(crate) mod integrations;
pub(crate) mod openclaw;
pub(crate) mod ota;
pub(crate) mod policy_check;
pub(crate) mod settings;
pub(crate) mod settings_dto;
pub(crate) mod token_rotation;

pub(crate) use approvals::*;
pub(crate) use diagnostics::*;
pub(crate) use enrollment::*;
pub(crate) use health::*;
pub(crate) use integrations::*;
pub(crate) use openclaw::*;
pub(crate) use ota::*;
pub(crate) use policy_check::*;
pub(crate) use settings::*;
pub(crate) use settings_dto::*;
pub(crate) use token_rotation::*;
