#![cfg_attr(test, allow(dead_code))]

use serde_json::Value;
use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

const REQUIRED_MACOS_PACKAGING_FILES: &[&str] = &[
    "macos/system-extension/entitlements/agent-app.entitlements",
    "macos/system-extension/entitlements/combined-system-extension.entitlements",
    "macos/system-extension/plists/agent-packaging-template.plist",
    "macos/system-extension/plists/combined-system-extension-template.plist",
    "macos/system-extension/profiles/developer-id-profile-template.plist",
];

const MACOS_SYSTEM_EXTENSION_DIR: &str = "macos/system-extension";
const TAURI_CONFIG_PATH: &str = "tauri.conf.json";
const SCAFFOLD_ONLY_MARKER: &str = "scaffold_only";
const REQUIRED_MACOS_MINIMUM_SYSTEM_VERSION: &str = "13.0";
const REQUIRED_MACOS_RESOURCE_GLOB: &str = "macos/system-extension/**/*";
const REQUIRED_MACOS_ENTITLEMENTS: &str =
    "macos/system-extension/entitlements/agent-app.entitlements";
const VALIDATE_MACOS_PACKAGING_ENV: &str = "CLAWDSTRIKE_VALIDATE_MACOS_PACKAGING";
const REQUIRE_CONCRETE_MACOS_PACKAGING_ENV: &str = "CLAWDSTRIKE_REQUIRE_CONCRETE_MACOS_PACKAGING";
const SYSTEM_EXTENSION_BUNDLE_PATH_ENV: &str = "CLAWDSTRIKE_SYSTEM_EXTENSION_BUNDLE_PATH";
const SYSTEM_EXTENSION_TEAM_ID_ENV: &str = "CLAWDSTRIKE_SYSTEM_EXTENSION_TEAM_ID";
const APPLE_TEAM_ID_ENV: &str = "APPLE_TEAM_ID";

#[cfg(not(test))]
fn main() {
    println!("cargo:rerun-if-changed={TAURI_CONFIG_PATH}");
    println!("cargo:rerun-if-changed={MACOS_SYSTEM_EXTENSION_DIR}");
    println!("cargo:rerun-if-env-changed={VALIDATE_MACOS_PACKAGING_ENV}");
    println!("cargo:rerun-if-env-changed={REQUIRE_CONCRETE_MACOS_PACKAGING_ENV}");
    println!("cargo:rerun-if-env-changed={SYSTEM_EXTENSION_BUNDLE_PATH_ENV}");
    println!("cargo:rerun-if-env-changed={SYSTEM_EXTENSION_TEAM_ID_ENV}");
    println!("cargo:rerun-if-env-changed={APPLE_TEAM_ID_ENV}");
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
        let mut files_with_placeholders = Vec::new();
        let mut files_with_scaffold_marker = Vec::new();

        for path in macos_packaging_source_files(&manifest_dir)? {
            let relative_path = relative_path(&manifest_dir, &path);
            let contents = fs::read_to_string(&path).map_err(|error| {
                format!("failed to read macOS packaging source {relative_path}: {error}")
            })?;
            if contains_release_placeholder(&contents) {
                files_with_placeholders.push(relative_path.clone());
            }
            if contents.contains(SCAFFOLD_ONLY_MARKER) {
                files_with_scaffold_marker.push(relative_path);
            }
        }

        if !files_with_placeholders.is_empty() {
            return Err(format!(
                "release-gated packaging placeholders remain in: {}",
                files_with_placeholders.join(", ")
            ));
        }

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

fn macos_packaging_source_files(manifest_dir: &Path) -> Result<Vec<PathBuf>, String> {
    let root = manifest_dir.join(MACOS_SYSTEM_EXTENSION_DIR);
    let mut files = Vec::new();
    collect_regular_files(&root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_regular_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| {
        format!(
            "failed to read macOS packaging source directory {}: {error}",
            dir.display()
        )
    })? {
        let entry = entry.map_err(|error| {
            format!(
                "failed to inspect macOS packaging source directory {}: {error}",
                dir.display()
            )
        })?;
        let path = entry.path();
        let file_type = entry.file_type().map_err(|error| {
            format!(
                "failed to inspect macOS packaging source {}: {error}",
                path.display()
            )
        })?;
        if file_type.is_dir() {
            if entry.file_name() == std::ffi::OsStr::new(".build") {
                continue;
            }
            collect_regular_files(&path, files)?;
        } else if file_type.is_file() {
            files.push(path);
        }
    }
    Ok(())
}

fn relative_path(manifest_dir: &Path, path: &Path) -> String {
    path.strip_prefix(manifest_dir)
        .unwrap_or(path)
        .display()
        .to_string()
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
    let info = read_plist_xml(&info_path)?;
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

    let expected_team_id = expected_system_extension_team_id().ok_or_else(|| {
        format!(
            "{SYSTEM_EXTENSION_TEAM_ID_ENV} or {APPLE_TEAM_ID_ENV} must identify the Apple team that signed the prebuilt .systemextension bundle when {REQUIRE_CONCRETE_MACOS_PACKAGING_ENV}=1"
        )
    })?;
    validate_system_extension_codesign(&bundle_path, &expected_team_id)?;

    Ok(())
}

fn validate_system_extension_codesign(
    bundle_path: &Path,
    expected_team_id: &str,
) -> Result<(), String> {
    let verify = Command::new("/usr/bin/codesign")
        .arg("--verify")
        .arg("--strict")
        .arg("--deep")
        .arg(bundle_path)
        .output()
        .map_err(|error| format!("failed to run codesign verification: {error}"))?;
    if !verify.status.success() {
        return Err(format!(
            "prebuilt system extension codesign verification failed: {}",
            String::from_utf8_lossy(&verify.stderr).trim()
        ));
    }

    let details = Command::new("/usr/bin/codesign")
        .arg("-dvv")
        .arg(bundle_path)
        .output()
        .map_err(|error| format!("failed to inspect system extension signature: {error}"))?;
    if !details.status.success() {
        return Err(format!(
            "failed to inspect system extension signature: {}",
            String::from_utf8_lossy(&details.stderr).trim()
        ));
    }
    let details_text = String::from_utf8_lossy(&details.stderr);
    if details_text.contains("Signature=adhoc") {
        return Err(
            "prebuilt system extension must be signed with a team identity, not an ad-hoc signature"
                .to_string(),
        );
    }
    let actual_team_id = codesign_team_identifier(&details_text).ok_or_else(|| {
        "prebuilt system extension signature is missing TeamIdentifier".to_string()
    })?;
    if actual_team_id != expected_team_id {
        return Err(format!(
            "prebuilt system extension TeamIdentifier {actual_team_id} does not match expected Apple team {expected_team_id}"
        ));
    }

    let entitlements = Command::new("/usr/bin/codesign")
        .arg("-d")
        .arg("--entitlements")
        .arg(":-")
        .arg(bundle_path)
        .output()
        .map_err(|error| format!("failed to inspect system extension entitlements: {error}"))?;
    let mut entitlement_text = String::from_utf8_lossy(&entitlements.stdout).to_string();
    entitlement_text.push_str(String::from_utf8_lossy(&entitlements.stderr).as_ref());
    validate_system_extension_entitlements_output(&entitlement_text)
}

fn validate_system_extension_entitlements_output(contents: &str) -> Result<(), String> {
    if !contents.contains("com.apple.developer.endpoint-security.client") {
        return Err(
            "prebuilt system extension is missing com.apple.developer.endpoint-security.client"
                .to_string(),
        );
    }
    if !contents.contains("com.apple.developer.networking.networkextension")
        || !contents.contains("content-filter-provider-systemextension")
    {
        return Err(
            "prebuilt system extension is missing content-filter-provider-systemextension NetworkExtension entitlement"
                .to_string(),
        );
    }
    Ok(())
}

fn expected_system_extension_team_id() -> Option<String> {
    env::var(SYSTEM_EXTENSION_TEAM_ID_ENV)
        .ok()
        .or_else(|| env::var(APPLE_TEAM_ID_ENV).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn codesign_team_identifier(contents: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        line.trim()
            .strip_prefix("TeamIdentifier=")
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn read_plist_xml(path: &Path) -> Result<String, String> {
    let plutil = Path::new("/usr/bin/plutil");
    if plutil.is_file() {
        let output = Command::new(plutil)
            .arg("-convert")
            .arg("xml1")
            .arg("-o")
            .arg("-")
            .arg(path)
            .output()
            .map_err(|error| format!("failed to run plutil for {}: {error}", path.display()))?;
        if !output.status.success() {
            return Err(format!(
                "failed to convert plist {} to XML: {}",
                path.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        return String::from_utf8(output.stdout).map_err(|error| {
            format!(
                "plutil returned non-UTF-8 XML for {}: {error}",
                path.display()
            )
        });
    }

    fs::read_to_string(path).map_err(|error| {
        format!(
            "failed to read plist as UTF-8 XML and /usr/bin/plutil is unavailable for {}: {error}",
            path.display()
        )
    })
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
    use super::{
        codesign_team_identifier, contains_release_placeholder,
        validate_system_extension_entitlements_output, validate_tauri_config,
    };

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

    #[test]
    fn validates_required_system_extension_entitlements() -> Result<(), String> {
        validate_system_extension_entitlements_output(
            r#"
            <dict>
              <key>com.apple.developer.endpoint-security.client</key>
              <true/>
              <key>com.apple.developer.networking.networkextension</key>
              <array>
                <string>content-filter-provider-systemextension</string>
              </array>
            </dict>
            "#,
        )
    }

    #[test]
    fn rejects_system_extension_entitlements_without_es_or_ne() {
        let Err(error) = validate_system_extension_entitlements_output(
            r#"
            <dict>
              <key>com.apple.security.app-sandbox</key>
              <true/>
            </dict>
            "#,
        ) else {
            panic!("expected entitlement validation to reject missing ES/NE entitlements");
        };
        assert!(error.contains("endpoint-security"));
    }

    #[test]
    fn extracts_codesign_team_identifier() {
        let details = r#"
Executable=/tmp/ClawdStrikeEndpointSecurity.systemextension/Contents/MacOS/ClawdStrikeEndpointSecurity
Identifier=com.backbay.clawdstrike.agent.extension
Format=bundle with Mach-O universal
CodeDirectory v=20500 size=123 flags=0x10000(runtime) hashes=1+7 location=embedded
Signature size=9001
Authority=Developer ID Application: Backbay Labs, Inc. (ABCDE12345)
TeamIdentifier=ABCDE12345
Runtime Version=14.0.0
"#;

        assert_eq!(
            codesign_team_identifier(details).as_deref(),
            Some("ABCDE12345")
        );
    }

    #[test]
    fn ignores_blank_codesign_team_identifier() {
        assert_eq!(codesign_team_identifier("TeamIdentifier=   "), None);
        assert_eq!(codesign_team_identifier("Signature=adhoc"), None);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reads_binary_plist_via_plutil() -> Result<(), String> {
        use std::process::Command;

        let dir =
            std::env::temp_dir().join(format!("clawdstrike-build-plist-{}", std::process::id()));
        std::fs::create_dir_all(&dir)
            .map_err(|error| format!("failed to create temp dir: {error}"))?;
        let xml_path = dir.join("Info.xml.plist");
        let binary_path = dir.join("Info.plist");
        std::fs::write(
            &xml_path,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.backbay.clawdstrike.agent.extension</string>
</dict>
</plist>
"#,
        )
        .map_err(|error| format!("failed to write XML plist fixture: {error}"))?;
        let convert = Command::new("/usr/bin/plutil")
            .arg("-convert")
            .arg("binary1")
            .arg("-o")
            .arg(&binary_path)
            .arg(&xml_path)
            .output()
            .map_err(|error| format!("failed to run plutil fixture conversion: {error}"))?;
        if !convert.status.success() {
            return Err(format!(
                "failed to create binary plist fixture: {}",
                String::from_utf8_lossy(&convert.stderr).trim()
            ));
        }

        let xml = super::read_plist_xml(&binary_path)?;
        assert_eq!(
            super::plist_string_value(&xml, "CFBundleIdentifier").as_deref(),
            Some("com.backbay.clawdstrike.agent.extension")
        );

        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }
}
