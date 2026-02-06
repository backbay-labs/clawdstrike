#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! Multi-agent security primitives for Clawdstrike/Hush.
//!
//! This crate implements a pragmatic, stable baseline for:
//! - Agent identities (Ed25519 public keys)
//! - Signed delegation tokens (capability grants)
//! - Signed messages (agent-to-agent integrity + replay resistance hooks)
//!
//! It intentionally uses **canonical JSON (RFC 8785 JCS)** + **Ed25519** from `hush-core`
//! to keep cross-language implementations portable (Rust/TS/Python).

mod correlation;
mod error;
mod identity_registry;
mod message;
mod revocation;
mod token;
mod types;

pub use correlation::{CorrelationContext, CrossAgentAuditEvent, CrossAgentEventType};
pub use error::{Error, Result};
pub use identity_registry::{IdentityRegistry, InMemoryIdentityRegistry};
pub use message::{MessageClaims, SignedMessage};
pub use revocation::{InMemoryRevocationStore, RevocationStore};
#[cfg(feature = "sqlite")]
pub use revocation::SqliteRevocationStore;
pub use token::{DelegationClaims, SignedDelegationToken, DELEGATION_AUDIENCE};
pub use types::{AgentCapability, AgentId, AgentIdentity, AgentRole, TrustLevel};
