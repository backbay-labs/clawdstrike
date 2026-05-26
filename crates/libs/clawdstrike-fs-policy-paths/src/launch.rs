//! macOS LaunchAgents / LaunchDaemons persistence-target bounds.

use std::path::Path;

/// `~/Library/LaunchAgents/*.plist` or `/Library/Launch{Agents,Daemons}/*.plist`.
///
/// Rejects Apple-owned bundle identifiers and clawdstrike's own units so that
/// disabling persistence cannot brick the host or the agent itself.
pub(crate) fn path_is_bounded_launch_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if !normalized.ends_with(".plist")
        || !normalized.contains("/Library/LaunchAgents/")
            && !normalized.contains("/Library/LaunchDaemons/")
    {
        return false;
    }
    if let Some(file_name) = path.file_name().and_then(|value| value.to_str()) {
        let normalized_file = file_name.to_ascii_lowercase();
        if normalized_file.starts_with("com.apple.")
            || normalized_file.starts_with("com.clawdstrike.")
            || normalized_file.starts_with("io.clawdstrike.")
        {
            return false;
        }
    }
    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.starts_with("/Library/LaunchAgents/")
        || normalized.starts_with("/Library/LaunchDaemons/")
        || (normalized.starts_with("/Users/") && !normalized.contains("/../"))
}
