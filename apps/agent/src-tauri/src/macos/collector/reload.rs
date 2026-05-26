//! Network-extension reload request: invoke the helper and validate the
//! returned acknowledgement against the requested generation and path.

use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

use tokio::time::timeout;

use super::samples::NetworkExtensionReloadToolResponse;
use super::tool::{execute_tool_with_args, ToolInvocation};
use crate::macos::host::{MacosNetworkExtensionReloadError, MacosNetworkExtensionReloadResult};

pub(super) async fn request_network_extension_reload(
    tool: Option<&ToolInvocation>,
    policy_snapshot_path: &Path,
    generation: u64,
    timeout_duration: Duration,
) -> Result<MacosNetworkExtensionReloadResult, MacosNetworkExtensionReloadError> {
    let tool = tool.ok_or(MacosNetworkExtensionReloadError::Unavailable)?;
    let args = network_extension_reload_args(policy_snapshot_path, generation);
    let stdout = match timeout(timeout_duration, execute_tool_with_args(tool, &args)).await {
        Ok(Ok(stdout)) => stdout,
        Ok(Err(error)) => {
            return Err(MacosNetworkExtensionReloadError::HelperFailed(
                error.to_string(),
            ));
        }
        Err(_) => return Err(MacosNetworkExtensionReloadError::TimedOut),
    };
    parse_network_extension_reload_response(&stdout, policy_snapshot_path, generation)
}

pub(super) fn network_extension_reload_args(
    policy_snapshot_path: &Path,
    generation: u64,
) -> [OsString; 3] {
    [
        OsString::from("request-reload"),
        policy_snapshot_path.as_os_str().to_os_string(),
        OsString::from(generation.to_string()),
    ]
}

pub(super) fn parse_network_extension_reload_response(
    stdout: &[u8],
    expected_policy_snapshot_path: &Path,
    expected_generation: u64,
) -> Result<MacosNetworkExtensionReloadResult, MacosNetworkExtensionReloadError> {
    let response = serde_json::from_slice::<NetworkExtensionReloadToolResponse>(stdout)
        .map_err(|error| MacosNetworkExtensionReloadError::InvalidResponse(error.to_string()))?;
    if response.command != "reload_policy" {
        return Err(MacosNetworkExtensionReloadError::InvalidResponse(format!(
            "unexpected command {}",
            response.command
        )));
    }
    if response.generation != expected_generation {
        return Err(MacosNetworkExtensionReloadError::InvalidResponse(format!(
            "generation mismatch: requested {expected_generation}, helper returned {}",
            response.generation
        )));
    }
    let expected_policy_snapshot_path = expected_policy_snapshot_path.display().to_string();
    if response.policy_snapshot_path != expected_policy_snapshot_path {
        return Err(MacosNetworkExtensionReloadError::InvalidResponse(format!(
            "policy snapshot path mismatch: requested {expected_policy_snapshot_path}, helper returned {}",
            response.policy_snapshot_path
        )));
    }

    Ok(MacosNetworkExtensionReloadResult {
        requested: true,
        saved: response.saved,
        request_id: response.request_id,
        policy_snapshot_path: response.policy_snapshot_path,
        generation: response.generation,
    })
}
