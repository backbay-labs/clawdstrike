//! Custom guard plugin scaffolding.
//!
//! This module provides manifest parsing/validation and loader planning for
//! `clawdstrike.plugin.toml` plugins. Dynamic loading/execution backends are
//! intentionally staged after this scaffold.

mod loader;
mod manifest;
#[cfg(feature = "wasm-plugin-runtime")]
mod runtime;

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
