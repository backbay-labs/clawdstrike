//! EAS Anchor library — batches AegisNet checkpoint hashes into
//! Ethereum Attestation Service attestations on Base L2.

pub mod batcher;
pub mod config;
pub mod eas_client;
pub mod error;
pub mod nats_sub;
