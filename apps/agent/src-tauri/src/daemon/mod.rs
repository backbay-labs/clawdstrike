//! Daemon management for hushd process.
//!
//! Handles spawning, monitoring, and restarting the hushd daemon.
//!
//! The submodules are deliberately small and single-purpose:
//!
//! * [`state`] — public types (`DaemonState`, `DaemonStatus`, `DaemonConfig`,
//!   `HealthResponse`).
//! * [`manager`] — [`DaemonManager`] lifecycle (start/stop/restart) and
//!   background health monitor.
//! * [`spawn`] — child-process spawn, terminate, exit tracking, and backoff.
//! * [`ready_probe`] — HTTP-based readiness/health probing.
//! * [`runtime_config`] — generates `hushd.runtime.<port>.yaml` from agent
//!   settings using [`clawdstrike_hushd_config`].
//! * [`runtime_keypair`] — materializes per-port signing/enrollment keys.
//! * [`policy_cache`] — last-known-good policy bundle for warm-start recovery.
//! * [`audit_queue`] — persistent audit-event outbox replayed when hushd is
//!   reachable.
//! * [`binary_discovery`] — locates/prepares the managed hushd binary.

mod audit_queue;
mod binary_discovery;
mod manager;
mod policy_cache;
mod ready_probe;
mod runtime_config;
mod runtime_keypair;
mod spawn;
mod state;

// Preserve the previous public surface of the single-file daemon module so
// downstream call sites in main.rs/api_server.rs/etc. are unaffected by the
// split. Some types (e.g. `AuditFlushOutcome`, `HealthResponse`) exist purely
// as part of the public API and are not currently consumed by other crate
// modules; suppress the unused-import lint for those re-exports.
#[allow(unused_imports)]
pub use audit_queue::{AuditFlushOutcome, AuditFlushProgressError, AuditQueue};
pub use binary_discovery::{find_hushd_binary, managed_hushd_path, prepare_managed_hushd_binary};
pub use manager::DaemonManager;
pub use policy_cache::PolicyCache;
#[allow(unused_imports)]
pub use state::{DaemonConfig, DaemonState, DaemonStatus, HealthResponse};
