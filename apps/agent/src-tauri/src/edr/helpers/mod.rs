//! Shared helpers used by EDR handlers and the api_server bridge.
//!
//! Each submodule holds a coherent chunk of logic that was previously inlined
//! in `api_server.rs`. Helpers stay `pub(crate)` so they remain reachable
//! through `crate::api_server::*` glob imports during the gradual relocation.

pub(crate) mod policy_snapshot;
