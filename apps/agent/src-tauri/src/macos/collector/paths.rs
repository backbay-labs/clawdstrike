//! Default filesystem locations consumed by the macOS status helpers and
//! by the runtime-snapshot freshness checks.

use std::path::PathBuf;

pub(super) fn default_endpoint_security_runtime_snapshot_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("endpoint-security-runtime.json")
}

pub(super) fn default_network_extension_egress_policy_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("network-extension-egress-policy.json")
}

pub(super) fn default_network_extension_runtime_snapshot_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("edr")
        .join("network-extension-egress-policy.json.provider-runtime.json")
}
