//! Unit tests for the policy module (extracted from the inline test module).
#![allow(clippy::expect_used, clippy::unwrap_used)]

pub(super) use super::*;
pub(super) use crate::error::Error;
pub(super) use crate::guards::{ForbiddenPathConfig, SecretLeakConfig};
pub(super) use crate::origin::{OriginProvider, ProvenanceConfidence, SpaceType, Visibility};
pub(super) use tempfile::tempdir;

mod merge_extends;
mod origins;
mod rulesets_and_verifier;
mod schema_validation;
mod spider_sense_merge;
