//! Chromium/Edge/Brave + Firefox extension manifest bounds.

use std::path::Path;

/// Browser-extension `manifest.json` files under per-browser support
/// directories.
pub(crate) fn path_is_bounded_browser_extension_manifest_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !file_name.eq_ignore_ascii_case("manifest.json") {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let allowed_root = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.starts_with("/home/")
        || normalized.starts_with("/Users/");
    if !allowed_root {
        return false;
    }

    let chromium_manifest = [
        "/Library/Application Support/Google/Chrome/",
        "/Library/Application Support/Chromium/",
        "/Library/Application Support/Microsoft Edge/",
        "/Library/Application Support/BraveSoftware/Brave-Browser/",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
        && normalized.contains("/Extensions/")
        && chromium_browser_extension_manifest_components_are_bounded(&normalized);
    let firefox_manifest = [
        "/Library/Application Support/Firefox/Profiles/",
        "/.mozilla/firefox/",
    ]
    .iter()
    .any(|marker| firefox_browser_extension_manifest_components_are_bounded(&normalized, marker));

    chromium_manifest || firefox_manifest
}

fn chromium_browser_extension_manifest_components_are_bounded(normalized: &str) -> bool {
    let Some((_, extension_suffix)) = normalized.rsplit_once("/Extensions/") else {
        return false;
    };
    let components = extension_suffix
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    components.len() == 3
        && components.last() == Some(&"manifest.json")
        && browser_extension_path_component_is_safe(components[0])
        && browser_extension_path_component_is_safe(components[1])
}

fn firefox_browser_extension_manifest_components_are_bounded(
    normalized: &str,
    profile_marker: &str,
) -> bool {
    let Some((_, profile_suffix)) = normalized.rsplit_once(profile_marker) else {
        return false;
    };
    let components = profile_suffix
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    components.len() == 4
        && components[1] == "extensions"
        && components[3].eq_ignore_ascii_case("manifest.json")
        && browser_extension_path_component_is_safe(components[0])
        && firefox_extension_path_component_is_safe(components[2])
}

fn browser_extension_path_component_is_safe(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 128
        && !component.starts_with('.')
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn firefox_extension_path_component_is_safe(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 128
        && !component.starts_with('.')
        && component.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'{' | b'}')
        })
}
