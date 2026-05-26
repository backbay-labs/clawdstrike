//! Background tasks spawned by the agent's `run_agent` orchestrator.
//!
//! Modules here host long-running tokio tasks (heartbeat loops, etc.) that
//! were extracted from `main.rs` so the orchestration code stays readable.

pub mod heartbeats;
