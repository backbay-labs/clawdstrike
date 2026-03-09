use std::{env, fs, path::PathBuf};

const REQUIRED_MACOS_PACKAGING_FILES: &[&str] = &[
    "macos/system-extension/entitlements/agent-app.entitlements",
    "macos/system-extension/entitlements/combined-system-extension.entitlements",
    "macos/system-extension/plists/agent-packaging-template.plist",
    "macos/system-extension/plists/combined-system-extension-template.plist",
    "macos/system-extension/profiles/developer-id-profile-template.plist",
];

const TAURI_CONFIG_PATH: &str = "tauri.conf.json";
const SCAFFOLD_ONLY_MARKER: &str = "scaffold_only";
const REQUIRED_TAURI_CONFIG_SNIPPETS: &[&str] = &[
    "\"minimumSystemVersion\": \"13.0\"",
    "\"macos/system-extension/**/*\"",
    "\"entitlements\": \"macos/system-extension/entitlements/agent-app.entitlements\"",
];

fn main() {
    println!("cargo:rerun-if-changed={TAURI_CONFIG_PATH}");
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
        || env::var_os("CLAWDSTRIKE_VALIDATE_MACOS_PACKAGING").is_some()
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
    let missing_config = REQUIRED_TAURI_CONFIG_SNIPPETS
        .iter()
        .filter(|snippet| !tauri_config.contains(**snippet))
        .copied()
        .collect::<Vec<_>>();
    if !missing_config.is_empty() {
        return Err(format!(
            "tauri.conf.json is missing required macOS packaging entries: {}",
            missing_config.join(", ")
        ));
    }

    if env::var_os("CLAWDSTRIKE_REQUIRE_CONCRETE_MACOS_PACKAGING").is_some() {
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
    }

    Ok(())
}

fn manifest_dir() -> Result<PathBuf, String> {
    env::var("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .map_err(|error| format!("missing CARGO_MANIFEST_DIR: {error}"))
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
        let mut saw_placeholder_body = false;
        while cursor < bytes.len() {
            match bytes[cursor] {
                b'A'..=b'Z' | b'0'..=b'9' | b'_' => {
                    saw_placeholder_body = true;
                    cursor += 1;
                }
                _ => break,
            }
        }

        if saw_placeholder_body
            && cursor + 1 < bytes.len()
            && bytes[cursor] == b'_'
            && bytes[cursor + 1] == b'_'
        {
            return true;
        }

        start += 1;
    }

    false
}
