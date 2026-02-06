//! Custom guard plugin scaffolding.
//!
//! This module provides manifest parsing/validation and loader planning for
//! `clawdstrike.plugin.toml` plugins. Dynamic loading/execution backends are
//! intentionally staged after this scaffold.

mod loader;
mod manifest;

pub use loader::{
    resolve_plugin_root, PluginExecutionMode, PluginInspectResult, PluginLoadPlan, PluginLoader,
    PluginLoaderOptions,
};
pub use manifest::{
    parse_plugin_manifest_toml, PluginCapabilities, PluginClawdstrikeCompatibility,
    PluginFilesystemCapabilities, PluginGuardManifestEntry, PluginManifest, PluginMetadata,
    PluginResourceLimits, PluginSandbox, PluginSecretsCapabilities, PluginTrust, PluginTrustLevel,
};
