//! Bridge between ClawdStrike policy types and Logos modal-temporal logic.
//!
//! This crate translates ClawdStrike security policies into Logos Layer 3
//! (normative) formulas, enabling static verification of policy properties
//! such as consistency, completeness, and deny monotonicity.
//!
//! # Overview
//!
//! ClawdStrike policies are declarative YAML documents that define finite sets of
//! permissions, prohibitions, and obligations. These map directly onto Logos
//! normative operators:
//!
//! - **Prohibition** (`F_agent(action)`) -- the agent is forbidden from performing the action
//! - **Permission** (`P_agent(action)`) -- the agent is permitted to perform the action
//! - **Obligation** (`O_agent(action)`) -- the agent is obligated to perform a check
//!
//! # Example
//!
//! ```rust
//! use clawdstrike_logos::compiler::{DefaultPolicyCompiler, PolicyCompiler};
//! use clawdstrike::policy::Policy;
//! use logos_ffi::AgentId;
//!
//! let policy = Policy::default();
//! let agent = AgentId::new("my-agent");
//! let compiler = DefaultPolicyCompiler::new(agent);
//! let formulas = compiler.compile_policy(&policy);
//! // Each formula encodes a normative constraint from the policy
//! ```

pub mod atoms;
pub mod compiler;
pub mod guards;
pub mod verifier;

pub use logos_ffi;
