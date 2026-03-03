//! Custom guard plugin scaffolding.
//!
//! This module provides manifest parsing/validation, loader planning, and
//! WASM-backed guard execution for `clawdstrike.plugin.toml` plugins.

#[cfg(feature = "wasm-plugin-runtime")]
mod guard;
mod loader;
mod manifest;
#[cfg(feature = "wasm-plugin-runtime")]
mod runtime;

#[cfg(feature = "wasm-plugin-runtime")]
pub use guard::{WasmGuard, WasmGuardFactory};
pub use loader::{
    resolve_plugin_root, PluginExecutionMode, PluginInspectResult, PluginLoadPlan, PluginLoader,
    PluginLoaderOptions,
};
pub use manifest::{
    parse_plugin_manifest_toml, PluginCapabilities, PluginClawdstrikeCompatibility,
    PluginFilesystemCapabilities, PluginGuardManifestEntry, PluginManifest, PluginMetadata,
    PluginResourceLimits, PluginSandbox, PluginSecretsCapabilities, PluginTrust, PluginTrustLevel,
};
#[cfg(feature = "wasm-plugin-runtime")]
pub use runtime::{
    execute_wasm_guard_bytes, execute_wasm_guard_module, validate_wasm_guard_module,
    WasmGuardExecution, WasmGuardInputEnvelope, WasmGuardRuntimeOptions, WasmRuntimeAuditRecord,
};
