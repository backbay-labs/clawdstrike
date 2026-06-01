//! Policy verification via formula inspection and optional Z3 checking.
//!
//! The formula-only API intentionally stays lightweight and conservative.
//! Policy-aware verification goes further by using guard semantics for
//! inheritance checks, because compiled formulas alone do not carry enough
//! information to model guard-specific override behavior soundly.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::{Once, OnceLock};
use std::time::Instant;

use clawdstrike::guards::{
    EgressAllowlistConfig, ForbiddenPathConfig, ForbiddenPathGuard, McpDefaultAction,
    McpToolConfig, McpToolGuard, PathAllowlistConfig, PathAllowlistGuard, ShellCommandConfig,
};
use clawdstrike::policy::{LocalPolicyResolver, Policy, PolicyLocation, PolicyResolver};
use glob::Pattern;
use hush_proxy::policy::{DomainPolicy, PolicyAction};
#[cfg(feature = "z3")]
use logos_ffi::ProofResult;
use logos_ffi::{AgentId, Formula};
#[cfg(feature = "z3")]
use logos_z3::Z3Checker;
use regex::Regex;
use regex_syntax::hir::{Class, Hir, HirKind, Look};
use regex_syntax::Parser;
use serde::{Deserialize, Serialize};

use crate::compiler::{DefaultPolicyCompiler, PolicyCompiler};

mod analysis;
mod inheritance;
mod load_time;
mod report;
mod verifier_core;
mod witness;

// Public surface: re-exported so external callers keep using
// `clawdstrike_logos::verifier::<Item>` regardless of the submodule layout.
pub use load_time::{
    enrich_receipt, install_clawdstrike_policy_load_verifier, verify_policy_at_load_time,
    verify_policy_at_load_time_with_resolver, LoadTimeVerificationResult, VerificationCache,
};
pub use report::{
    AttestationLevel, CheckOutcome, CompletenessResult, Conflict, ConsistencyResult,
    InheritanceResult, VerificationBackend, VerificationReport, WeakenedProhibition,
    DEFAULT_EXPECTED_ACTION_TYPES,
};
pub use verifier_core::PolicyVerifier;

// Internal cross-module resolution: each submodule reaches the others' private
// helpers through these globs + its own `use super::*`.
pub(crate) use analysis::*;
pub(crate) use inheritance::*;
// `load_time`'s pub(crate) helpers (e.g. `verify_policy_at_load_time_with_parent`)
// are reached only from `mod tests { use super::* }`; nothing in a non-test build
// calls into them across modules, so the glob is unused without `cfg(test)`.
#[allow(unused_imports)]
pub(crate) use load_time::*;
pub(crate) use report::*;
// `verifier_core` now exposes only the `PolicyVerifier` struct (re-exported
// above); its former free helpers moved to `analysis`. The glob carries no
// names today but is kept for symmetry and future additions, so it is unused
// in non-test builds.
#[allow(unused_imports)]
pub(crate) use verifier_core::*;
pub(crate) use witness::*;

#[cfg(test)]
fn expected_action_types_for_policy_set(policy: &Policy) -> BTreeSet<String> {
    expected_action_types_for_policy(policy)
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests;
