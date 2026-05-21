#![cfg_attr(test, allow(dead_code))]

use serde_json::Value;
use std::{
    env, fs,
    path::{Path, PathBuf},
};

const REQUIRED_MACOS_PACKAGING_FILES: &[&str] = &[
    "macos/system-extension/entitlements/agent-app.entitlements",
    "macos/system-extension/entitlements/combined-system-extension.entitlements",
    "macos/system-extension/plists/agent-packaging-template.plist",
    "macos/system-extension/plists/combined-system-extension-template.plist",
    "macos/system-extension/profiles/developer-id-profile-template.plist",
];

const TAURI_CONFIG_PATH: &str = "tauri.conf.json";
const SCAFFOLD_ONLY_MARKER: &str = "scaffold_only";
const REQUIRED_MACOS_MINIMUM_SYSTEM_VERSION: &str = "13.0";
const REQUIRED_MACOS_RESOURCE_GLOB: &str = "macos/system-extension/**/*";
const REQUIRED_MACOS_ENTITLEMENTS: &str =
    "macos/system-extension/entitlements/agent-app.entitlements";
const VALIDATE_MACOS_PACKAGING_ENV: &str = "CLAWDSTRIKE_VALIDATE_MACOS_PACKAGING";
const REQUIRE_CONCRETE_MACOS_PACKAGING_ENV: &str = "CLAWDSTRIKE_REQUIRE_CONCRETE_MACOS_PACKAGING";
const SYSTEM_EXTENSION_BUNDLE_PATH_ENV: &str = "CLAWDSTRIKE_SYSTEM_EXTENSION_BUNDLE_PATH";

#[cfg(not(test))]
fn main() {
    println!("cargo:rerun-if-changed={TAURI_CONFIG_PATH}");
    println!("cargo:rerun-if-env-changed={VALIDATE_MACOS_PACKAGING_ENV}");
    println!("cargo:rerun-if-env-changed={REQUIRE_CONCRETE_MACOS_PACKAGING_ENV}");
    println!("cargo:rerun-if-env-changed={SYSTEM_EXTENSION_BUNDLE_PATH_ENV}");
    for relative_path in REQUIRED_MACOS_PACKAGING_FILES {
        println!("cargo:rerun-if-changed={relative_path}");
    }

    if should_validate_macos_packaging() {
        validate_macos_packaging()
            .unwrap_or_else(|error| panic!("macOS packaging validation failed: {error}"));
    }

    tauri_build::build()
}

fn should_validate_macos_packaging() -> bool {
    env::var("TARGET")
        .map(|target| target.contains("apple-darwin"))
        .unwrap_or(false)
        || env::var_os(VALIDATE_MACOS_PACKAGING_ENV).is_some()
        || env::var_os(REQUIRE_CONCRETE_MACOS_PACKAGING_ENV).is_some()
}

fn validate_macos_packaging() -> Result<(), String> {
    let manifest_dir = manifest_dir()?;

    let mut missing_files = Vec::new();
    for relative_path in REQUIRED_MACOS_PACKAGING_FILES {
        if !manifest_dir.join(relative_path).is_file() {
            missing_files.push((*relative_path).to_string());
        }
    }
    if !missing_files.is_empty() {
        return Err(format!(
            "missing required packaging assets: {}",
            missing_files.join(", ")
        ));
    }

    let tauri_config = fs::read_to_string(manifest_dir.join(TAURI_CONFIG_PATH))
        .map_err(|error| format!("failed to read {TAURI_CONFIG_PATH}: {error}"))?;
    validate_tauri_config(&tauri_config)?;

    if env::var_os(REQUIRE_CONCRETE_MACOS_PACKAGING_ENV).is_some() {
        let files_with_placeholders = REQUIRED_MACOS_PACKAGING_FILES
            .iter()
            .filter_map(|relative_path| {
                fs::read_to_string(manifest_dir.join(relative_path))
                    .ok()
                    .filter(|contents| contains_release_placeholder(contents))
                    .map(|_| (*relative_path).to_string())
            })
            .collect::<Vec<_>>();
        if !files_with_placeholders.is_empty() {
            return Err(format!(
                "release-gated packaging placeholders remain in: {}",
                files_with_placeholders.join(", ")
            ));
        }

        let files_with_scaffold_marker = REQUIRED_MACOS_PACKAGING_FILES
            .iter()
            .filter_map(|relative_path| {
                fs::read_to_string(manifest_dir.join(relative_path))
                    .ok()
                    .filter(|contents| contents.contains(SCAFFOLD_ONLY_MARKER))
                    .map(|_| (*relative_path).to_string())
            })
            .collect::<Vec<_>>();
        if !files_with_scaffold_marker.is_empty() {
            return Err(format!(
                "release-gated packaging sources still declare scaffold_only state: {}",
                files_with_scaffold_marker.join(", ")
            ));
        }

        validate_concrete_system_extension_bundle(&manifest_dir)?;
    }

    Ok(())
}

fn validate_concrete_system_extension_bundle(manifest_dir: &Path) -> Result<(), String> {
    let bundle_path = env::var(SYSTEM_EXTENSION_BUNDLE_PATH_ENV)
        .map(|value| value.trim().to_string())
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            format!(
                "{SYSTEM_EXTENSION_BUNDLE_PATH_ENV} must point to a prebuilt signed .systemextension bundle when {REQUIRE_CONCRETE_MACOS_PACKAGING_ENV}=1"
            )
        })?;
    let bundle_path = resolve_bundle_path(manifest_dir, &bundle_path);
    if bundle_path.extension().and_then(|value| value.to_str()) != Some("systemextension") {
        return Err(format!(
            "{SYSTEM_EXTENSION_BUNDLE_PATH_ENV} must point to a .systemextension directory: {}",
            bundle_path.display()
        ));
    }
    if !bundle_path.is_dir() {
        return Err(format!(
            "{SYSTEM_EXTENSION_BUNDLE_PATH_ENV} does not reference an existing directory: {}",
            bundle_path.display()
        ));
    }

    let info_path = bundle_path.join("Contents").join("Info.plist");
    let info = fs::read_to_string(&info_path)
        .map_err(|error| format!("failed to read system extension Info.plist: {error}"))?;
    let template = fs::read_to_string(
        manifest_dir.join("macos/system-extension/plists/combined-system-extension-template.plist"),
    )
    .map_err(|error| format!("failed to read system extension plist template: {error}"))?;

    let expected_bundle_id =
        plist_string_value(&template, "CFBundleIdentifier").ok_or_else(|| {
            "system extension plist template is missing CFBundleIdentifier".to_string()
        })?;
    let expected_bundle_version = plist_string_value(&template, "CFBundleVersion")
        .ok_or_else(|| "system extension plist template is missing CFBundleVersion".to_string())?;
    let actual_bundle_id = plist_string_value(&info, "CFBundleIdentifier").ok_or_else(|| {
        "prebuilt system extension Info.plist is missing CFBundleIdentifier".to_string()
    })?;
    let actual_bundle_version = plist_string_value(&info, "CFBundleVersion").ok_or_else(|| {
        "prebuilt system extension Info.plist is missing CFBundleVersion".to_string()
    })?;
    if actual_bundle_id != expected_bundle_id {
        return Err(format!(
            "prebuilt system extension bundle id {actual_bundle_id} does not match template {expected_bundle_id}"
        ));
    }
    if actual_bundle_version != expected_bundle_version {
        return Err(format!(
            "prebuilt system extension version {actual_bundle_version} does not match template {expected_bundle_version}"
        ));
    }

    let usage =
        plist_string_value(&info, "NSSystemExtensionUsageDescription").ok_or_else(|| {
            "prebuilt system extension Info.plist is missing NSSystemExtensionUsageDescription"
                .to_string()
        })?;
    if usage.trim().is_empty() {
        return Err(
            "prebuilt system extension Info.plist has an empty NSSystemExtensionUsageDescription"
                .to_string(),
        );
    }

    let executable = plist_string_value(&info, "CFBundleExecutable").ok_or_else(|| {
        "prebuilt system extension Info.plist is missing CFBundleExecutable".to_string()
    })?;
    let executable_path = bundle_path.join("Contents").join("MacOS").join(executable);
    if !executable_path.is_file() {
        return Err(format!(
            "prebuilt system extension executable is missing: {}",
            executable_path.display()
        ));
    }

    Ok(())
}

fn resolve_bundle_path(manifest_dir: &Path, value: &str) -> PathBuf {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        path
    } else {
        manifest_dir.join(path)
    }
}

fn manifest_dir() -> Result<PathBuf, String> {
    env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map_err(|error| format!("missing CARGO_MANIFEST_DIR: {error}"))
}

fn validate_tauri_config(contents: &str) -> Result<(), String> {
    let config = serde_json::from_str::<Value>(contents)
        .map_err(|error| format!("failed to parse {TAURI_CONFIG_PATH}: {error}"))?;

    let mut missing_config = Vec::new();
    if string_at(&config, &["bundle", "macOS", "minimumSystemVersion"])
        != Some(REQUIRED_MACOS_MINIMUM_SYSTEM_VERSION)
    {
        missing_config.push(format!(
            "bundle.macOS.minimumSystemVersion = {REQUIRED_MACOS_MINIMUM_SYSTEM_VERSION}"
        ));
    }

    let has_required_resource =
        array_at(&config, &["bundle", "resources"]).is_some_and(|resources| {
            resources
                .iter()
                .any(|resource| resource.as_str() == Some(REQUIRED_MACOS_RESOURCE_GLOB))
        });
    if !has_required_resource {
        missing_config.push(format!(
            "bundle.resources contains {REQUIRED_MACOS_RESOURCE_GLOB}"
        ));
    }

    if string_at(&config, &["bundle", "macOS", "entitlements"]) != Some(REQUIRED_MACOS_ENTITLEMENTS)
    {
        missing_config.push(format!(
            "bundle.macOS.entitlements = {REQUIRED_MACOS_ENTITLEMENTS}"
        ));
    }

    if !missing_config.is_empty() {
        return Err(format!(
            "tauri.conf.json is missing required macOS packaging entries: {}",
            missing_config.join(", ")
        ));
    }

    Ok(())
}

fn contains_release_placeholder(contents: &str) -> bool {
    let bytes = contents.as_bytes();
    let mut start = 0usize;

    while start + 3 < bytes.len() {
        if bytes[start] != b'_' || bytes[start + 1] != b'_' {
            start += 1;
            continue;
        }

        let mut cursor = start + 2;
        if !matches!(bytes.get(cursor), Some(b'A'..=b'Z' | b'0'..=b'9' | b'_')) {
            start += 1;
            continue;
        }

        cursor += 1;
        while cursor < bytes.len() {
            if cursor + 1 < bytes.len() && bytes[cursor] == b'_' && bytes[cursor + 1] == b'_' {
                return true;
            }

            if !matches!(bytes[cursor], b'A'..=b'Z' | b'0'..=b'9' | b'_') {
                break;
            }

            cursor += 1;
        }

        start += 1;
    }

    false
}

fn plist_string_value(contents: &str, key: &str) -> Option<String> {
    let key_marker = format!("<key>{key}</key>");
    let after_key = contents.split_once(&key_marker)?.1;
    let after_string = after_key.split_once("<string>")?.1;
    let value = after_string.split_once("</string>")?.0.trim();
    Some(value.to_string())
}

fn string_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_str)
}

fn array_at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a [Value]> {
    path.iter()
        .try_fold(value, |current, key| current.get(*key))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
}

#[cfg(test)]
mod tests {
    use super::{contains_release_placeholder, validate_tauri_config};

    #[test]
    fn validates_tauri_config_structurally() -> Result<(), String> {
        validate_tauri_config(
            r#"{
                "bundle": {
                    "macOS": {
                        "entitlements": "macos/system-extension/entitlements/agent-app.entitlements",
                        "minimumSystemVersion": "13.0"
                    },
                    "resources": ["icons/*", "macos/system-extension/**/*"]
                }
            }"#,
        )
    }

    #[test]
    fn rejects_tauri_config_missing_required_entries() {
        let Err(error) = validate_tauri_config(r#"{"bundle":{"resources":[],"macOS":{}}}"#) else {
            panic!("expected missing macOS packaging entries");
        };
        assert!(error.contains("bundle.macOS.minimumSystemVersion = 13.0"));
        assert!(error.contains("bundle.resources contains macos/system-extension/**/*"));
        assert!(error.contains(
            "bundle.macOS.entitlements = macos/system-extension/entitlements/agent-app.entitlements"
        ));
    }

    #[test]
    fn detects_release_placeholders_with_internal_underscores() {
        assert!(contains_release_placeholder("__TEAM_ID__"));
        assert!(contains_release_placeholder(
            "<string>__EXTENSION_BUNDLE_ID__</string>"
        ));
        assert!(contains_release_placeholder("__PROFILE_123__"));
        assert!(contains_release_placeholder("___FOO__"));
        assert!(contains_release_placeholder("_____"));
    }

    #[test]
    fn ignores_non_release_placeholder_text() {
        assert!(!contains_release_placeholder("TEAM_ID"));
        assert!(!contains_release_placeholder("__team_id__"));
        assert!(!contains_release_placeholder("____"));
        assert!(!contains_release_placeholder("__TEAM_ID_"));
        assert!(!contains_release_placeholder("__TEAM-id__"));
    }
}
