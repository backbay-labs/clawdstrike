#![allow(clippy::needless_pass_by_value)]
//! `hush pkg` subcommands — package management for `.cpkg` archives.

#[cfg(test)]
use clawdstrike::pkg::archive;
#[cfg(test)]
use clawdstrike::pkg::manifest::{parse_pkg_manifest_toml, PkgType};
#[cfg(test)]
use clawdstrike::pkg::merkle::LeafData;
#[cfg(test)]
use clawdstrike::pkg::store::{PackageStore, StoreMetadata};

#[cfg(test)]
use crate::registry_config::{is_file_source, RegistryConfig};
use crate::ExitCode;

pub(super) const PLUGIN_MANIFEST_FILENAME: &str = "clawdstrike.plugin.toml";
const MAX_REGISTRY_DOWNLOAD_BYTES: u64 = 100 * 1024 * 1024;

mod audit_stats;
mod auth;
mod command;
mod dispatch;
mod init;
mod install;
mod list_verify_info;
mod org;
mod pack;
mod publish;
mod scaffold;
mod search;
mod test_cmd;
mod trust;
mod trusted_publishers;
mod util;
mod yank;

use audit_stats::{cmd_pkg_audit, cmd_pkg_stats};
pub use command::{CliPkgType, OrgCommands, PkgCommands, TrustedPublisherCommands};
pub use dispatch::cmd_pkg;
use init::cmd_pkg_init;
use install::cmd_pkg_install;
#[cfg(test)]
use install::{
    create_install_rollback_backup, read_archive_identity, recompute_installed_content_fingerprint,
    requested_identity_matches_install, restore_install_from_backup,
    select_default_registry_version,
};
use list_verify_info::{cmd_pkg_info, cmd_pkg_list, cmd_pkg_verify};
use org::cmd_pkg_org;
use pack::cmd_pkg_pack;
#[cfg(test)]
use pack::validate_pack_contents;
use publish::{cmd_pkg_login, cmd_pkg_publish};
#[cfg(test)]
use scaffold::scaffold_package;
use search::cmd_pkg_search;
use test_cmd::cmd_pkg_test;
#[cfg(test)]
use trust::{
    checkpoint_signature_message, verify_transparency_proof, RegistryAttestation, RegistryProof,
};
use trusted_publishers::cmd_pkg_trusted_publishers;
#[cfg(test)]
use util::{truncate_with_ellipsis, urlencoding_simple};
use yank::cmd_pkg_yank;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn run_cmd(cmd: PkgCommands) -> (String, String, ExitCode) {
        let mut stdout_buf = Vec::new();
        let mut stderr_buf = Vec::new();
        let code = cmd_pkg(cmd, &mut stdout_buf, &mut stderr_buf);
        (
            String::from_utf8_lossy(&stdout_buf).to_string(),
            String::from_utf8_lossy(&stderr_buf).to_string(),
            code,
        )
    }

    #[test]
    fn test_scaffold_guard() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Guard, "my-test-guard").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("src").is_dir());

        let content = std::fs::read_to_string(tmp.path().join("clawdstrike-pkg.toml")).unwrap();
        assert!(content.contains("my-test-guard"));
        assert!(content.contains("guard"));
    }

    #[test]
    fn test_scaffold_guard_creates_all_template_files() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Guard, "my-guard").unwrap();

        // Guard-specific files
        assert!(tmp.path().join("src/lib.rs").exists());
        assert!(tmp.path().join("Cargo.toml").exists());
        assert!(tmp.path().join("clawdstrike.plugin.toml").exists());
        assert!(tmp.path().join("tests/basic.yaml").exists());
        assert!(tmp.path().join(".cargo/config.toml").exists());

        // Verify content of key files
        let lib_rs = std::fs::read_to_string(tmp.path().join("src/lib.rs")).unwrap();
        assert!(lib_rs.contains("clawdstrike_guard_sdk"));
        assert!(lib_rs.contains("#[clawdstrike_guard]"));
        assert!(lib_rs.contains("impl Guard for"));

        let cargo_toml = std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
        assert!(cargo_toml.contains("cdylib"));
        assert!(cargo_toml.contains("clawdstrike-guard-sdk"));

        let plugin_manifest =
            std::fs::read_to_string(tmp.path().join("clawdstrike.plugin.toml")).unwrap();
        assert!(plugin_manifest.contains("my-guard"));
        assert!(plugin_manifest
            .contains("entrypoint = \"target/wasm32-unknown-unknown/release/my_guard.wasm\""));

        let test_yaml = std::fs::read_to_string(tmp.path().join("tests/basic.yaml")).unwrap();
        assert!(test_yaml.contains("my-guard"));
        assert!(test_yaml.contains("fixtures:"));

        let cargo_config = std::fs::read_to_string(tmp.path().join(".cargo/config.toml")).unwrap();
        assert!(cargo_config.contains("wasm32-unknown-unknown"));
    }

    #[test]
    fn test_scaffold_guard_struct_name_derivation() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Guard, "@acme/my-cool-guard").unwrap();

        let lib_rs = std::fs::read_to_string(tmp.path().join("src/lib.rs")).unwrap();
        // @acme/my-cool-guard -> AcmeMyCoolGuardGuard
        assert!(lib_rs.contains("AcmeMyCoolGuardGuard"));

        let cargo_toml = std::fs::read_to_string(tmp.path().join("Cargo.toml")).unwrap();
        assert!(cargo_toml.contains("name = \"acme-my-cool-guard\""));

        let plugin_manifest =
            std::fs::read_to_string(tmp.path().join("clawdstrike.plugin.toml")).unwrap();
        assert!(plugin_manifest.contains(
            "entrypoint = \"target/wasm32-unknown-unknown/release/acme_my_cool_guard.wasm\""
        ));
    }

    #[test]
    fn test_scaffold_non_guard_skips_guard_templates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::PolicyPack, "my-policies").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(!tmp.path().join("src/lib.rs").exists());
        assert!(!tmp.path().join("clawdstrike.plugin.toml").exists());
        assert!(!tmp.path().join("tests/basic.yaml").exists());
    }

    #[test]
    fn test_scaffold_policy_pack() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::PolicyPack, "my-policies").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("policies").is_dir());
        assert!(tmp.path().join("data").is_dir());
    }

    #[test]
    fn test_scaffold_all_types() {
        for (pkg_type, expected_dir) in [
            (PkgType::Guard, Some("src")),
            (PkgType::PolicyPack, Some("policies")),
            (PkgType::Adapter, Some("src")),
            (PkgType::Engine, Some("src")),
            (PkgType::Template, Some("template")),
            (PkgType::Bundle, None),
        ] {
            let tmp = tempfile::tempdir().unwrap();
            scaffold_package(tmp.path(), &pkg_type, "test-pkg").unwrap();
            assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
            if let Some(dir) = expected_dir {
                assert!(
                    tmp.path().join(dir).is_dir(),
                    "expected {dir} for {pkg_type}"
                );
            }
        }
    }

    #[test]
    fn test_pack_missing_manifest() {
        let tmp = tempfile::tempdir().unwrap();

        let (_, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(tmp.path().to_path_buf()),
        });

        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("clawdstrike-pkg.toml"));
    }

    #[test]
    fn test_pack_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("mypkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "test-pkg"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(pkg_dir.join("src")).unwrap();
        std::fs::write(pkg_dir.join("src/lib.rs"), "// guard code").unwrap();

        let (stdout, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(pkg_dir.clone()),
        });

        assert_eq!(code, ExitCode::Ok, "stderr: {}", stderr);
        assert!(stdout.contains("Packed:"));
        assert!(stdout.contains("Hash:"));

        // Verify .cpkg file exists
        let cpkg = pkg_dir.join("test-pkg-0.1.0.cpkg");
        assert!(cpkg.exists(), "expected cpkg at {}", cpkg.display());
    }

    #[test]
    fn test_pack_excludes_existing_cpkg_files_from_archive() {
        let tmp = tempfile::tempdir().unwrap();
        let pkg_dir = tmp.path().join("mypkg");
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(
            pkg_dir.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "test-pkg"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::create_dir_all(pkg_dir.join("src")).unwrap();
        std::fs::write(pkg_dir.join("src/lib.rs"), "// guard code").unwrap();
        std::fs::write(pkg_dir.join("stale-build.cpkg"), b"stale").unwrap();

        let (_stdout, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(pkg_dir.clone()),
        });
        assert_eq!(code, ExitCode::Ok, "stderr: {stderr}");

        let cpkg = pkg_dir.join("test-pkg-0.1.0.cpkg");
        let unpacked = tmp.path().join("unpacked");
        archive::unpack(&cpkg, &unpacked).unwrap();

        assert!(!unpacked.join("stale-build.cpkg").exists());
        assert!(unpacked.join("src/lib.rs").exists());
    }

    #[test]
    fn test_list_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();
        let _ = store; // ensure store dir exists

        // We can't easily redirect the default store, so just verify
        // the list command doesn't panic with an empty store.
        // Direct testing would require a way to inject the store root.
    }

    #[test]
    fn test_install_nonexistent() {
        let (_, stderr, code) = run_cmd(PkgCommands::Install {
            source: "/tmp/nonexistent-pkg-12345.cpkg".to_string(),
            version: None,
            registry: None,
            trust_level: Some("signed".to_string()),
            allow_unverified: false,
        });

        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("not found"));
    }

    #[test]
    fn test_local_install_requires_explicit_unverified_opt_in() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("local-install");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "local-install-test"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::write(src.join("README.md"), "ok").unwrap();
        let archive_path = tmp.path().join("local-install-test-0.1.0.cpkg");
        archive::pack(&src, &archive_path).unwrap();

        let (_, stderr, code) = run_cmd(PkgCommands::Install {
            source: archive_path.to_string_lossy().to_string(),
            version: None,
            registry: None,
            trust_level: Some("signed".to_string()),
            allow_unverified: false,
        });

        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("--allow-unverified"));
        assert!(stderr.contains("registry"));
    }

    #[test]
    fn test_is_file_source() {
        // File paths
        assert!(is_file_source("/tmp/my-pkg.cpkg"));
        assert!(is_file_source("./local-pkg.cpkg"));
        assert!(is_file_source("../other.cpkg"));
        assert!(is_file_source("/absolute/path/to/pkg.cpkg"));

        // Package names (not file paths)
        assert!(!is_file_source("@acme/my-guard"));
        assert!(!is_file_source("my-guard"));
        assert!(!is_file_source("@scope/name"));
    }

    #[test]
    fn test_registry_config_defaults() {
        let cfg = RegistryConfig::from_toml_str("", "");
        assert_eq!(cfg.registry_url, "http://localhost:3100");
        assert!(cfg.auth_token.is_none());
    }

    #[test]
    fn test_registry_config_from_toml() {
        let config = r#"
[registry]
url = "https://registry.example.com"
"#;
        let creds = r#"
[registry]
auth_token = "tok_secret"
"#;
        let cfg = RegistryConfig::from_toml_str(config, creds);
        assert_eq!(cfg.registry_url, "https://registry.example.com");
        assert_eq!(cfg.auth_token.as_deref(), Some("tok_secret"));
    }

    #[test]
    fn test_urlencoding_simple() {
        assert_eq!(urlencoding_simple("hello"), "hello");
        assert_eq!(urlencoding_simple("@scope/name"), "%40scope%2Fname");
        assert_eq!(urlencoding_simple("a b"), "a%20b");
        assert_eq!(urlencoding_simple("foo+bar"), "foo%2Bbar");
    }

    #[test]
    fn test_truncate_with_ellipsis_handles_utf8_boundaries() {
        let input = "naive cafe from a roastery with emoji cafe";
        assert_eq!(truncate_with_ellipsis(input, 12), "naive cafe f...");

        let unicode_input = "naive cafe 日本語で説明する";
        assert_eq!(
            truncate_with_ellipsis(unicode_input, 12),
            "naive cafe 日..."
        );
    }

    #[test]
    fn test_publish_requires_auth() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike-pkg.toml"),
            r#"[package]
name = "test-pkg"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();

        let (_, stderr, code) = run_cmd(PkgCommands::Publish {
            path: Some(tmp.path().to_path_buf()),
            // Use a fake registry so we never actually hit a real server
            registry: Some("http://127.0.0.1:1".to_string()),
            oidc: false,
        });

        // Should fail because no auth token is configured
        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("not authenticated"));
    }

    // -----------------------------------------------------------------------
    // Enhanced scaffolding template tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_scaffold_policy_pack_creates_templates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::PolicyPack, "@acme/my-policies").unwrap();

        assert!(tmp.path().join("policies").is_dir());
        assert!(tmp.path().join("data").is_dir());
        assert!(tmp.path().join("tests").is_dir());
        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("policies/default.yaml").exists());
        assert!(tmp.path().join("tests/policy-test.yaml").exists());
        assert!(tmp.path().join("README.md").exists());

        let policy = std::fs::read_to_string(tmp.path().join("policies/default.yaml")).unwrap();
        assert!(policy.contains("version:"));
        assert!(policy.contains("guards:"));
        assert!(policy.contains("forbidden_path:"));

        let test_yaml = std::fs::read_to_string(tmp.path().join("tests/policy-test.yaml")).unwrap();
        assert!(test_yaml.contains("tests:"));
        assert!(test_yaml.contains("file_access"));

        let readme = std::fs::read_to_string(tmp.path().join("README.md")).unwrap();
        assert!(readme.contains("@acme/my-policies"));
    }

    #[test]
    fn test_scaffold_bundle_creates_templates() {
        let tmp = tempfile::tempdir().unwrap();
        scaffold_package(tmp.path(), &PkgType::Bundle, "my-bundle").unwrap();

        assert!(tmp.path().join("clawdstrike-pkg.toml").exists());
        assert!(tmp.path().join("README.md").exists());

        let manifest = std::fs::read_to_string(tmp.path().join("clawdstrike-pkg.toml")).unwrap();
        assert!(manifest.contains("[dependencies]"));
        assert!(manifest.contains("bundle"));

        let readme = std::fs::read_to_string(tmp.path().join("README.md")).unwrap();
        assert!(readme.contains("bundle"));
        assert!(readme.contains("my-bundle"));
    }

    // -----------------------------------------------------------------------
    // Pre-pack validation tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_policy_pack_missing_policies_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-pack"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("policies/ directory"));
    }

    #[test]
    fn test_validate_policy_pack_empty_policies_dir() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("policies")).unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-pack"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("at least one .yaml"));
    }

    #[test]
    fn test_validate_policy_pack_with_yaml() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("policies")).unwrap();
        std::fs::write(tmp.path().join("policies/test.yaml"), "version: \"1.2.0\"").unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-pack"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        assert!(validate_pack_contents(tmp.path(), &manifest).is_ok());
    }

    #[test]
    fn test_validate_guard_missing_src() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-guard"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("src/lib.rs"));
    }

    #[test]
    fn test_validate_bundle_empty_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-bundle"
version = "0.1.0"
pkg_type = "bundle"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let result = validate_pack_contents(tmp.path(), &manifest);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("[dependencies]"));
    }

    #[test]
    fn test_validate_bundle_with_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let manifest = parse_pkg_manifest_toml(
            r#"
[package]
name = "test-bundle"
version = "0.1.0"
pkg_type = "bundle"

[trust]
level = "trusted"
sandbox = "native"

[dependencies]
"@acme/guard" = "^0.1"
"#,
        )
        .unwrap();
        assert!(validate_pack_contents(tmp.path(), &manifest).is_ok());
    }

    #[test]
    fn test_pack_policy_pack_without_policies_fails() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike-pkg.toml"),
            r#"[package]
name = "no-policies"
version = "0.1.0"
pkg_type = "policy-pack"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let (_, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(tmp.path().to_path_buf()),
        });
        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("policies/ directory"));
    }

    #[test]
    fn test_pack_guard_without_src_fails() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("clawdstrike-pkg.toml"),
            r#"[package]
name = "no-src"
version = "0.1.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        let (_, stderr, code) = run_cmd(PkgCommands::Pack {
            path: Some(tmp.path().to_path_buf()),
        });
        assert_eq!(code, ExitCode::ConfigError);
        assert!(stderr.contains("src/lib.rs"));
    }

    #[test]
    fn install_requested_identity_mismatch_is_detected() {
        let installed = clawdstrike::pkg::store::InstalledPackage {
            name: "actual".to_string(),
            version: "1.2.3".to_string(),
            path: std::path::PathBuf::from("/tmp/actual"),
            content_hash: hush_core::sha256(b"abc"),
        };
        assert!(!requested_identity_matches_install(
            "expected", "1.2.3", &installed
        ));
        assert!(!requested_identity_matches_install(
            "actual", "9.9.9", &installed
        ));
        assert!(requested_identity_matches_install(
            "actual", "1.2.3", &installed
        ));
    }

    #[test]
    fn read_archive_identity_returns_manifest_name_and_version() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "identity-demo"
version = "1.2.3"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::write(src.join("README.md"), "ok").unwrap();
        let archive_path = tmp.path().join("identity-demo-1.2.3.cpkg");
        archive::pack(&src, &archive_path).unwrap();

        let (name, version) = read_archive_identity(&archive_path).unwrap();
        assert_eq!(name, "identity-demo");
        assert_eq!(version, "1.2.3");
    }

    #[test]
    fn select_default_registry_version_chooses_newest_non_yanked() {
        let stats = serde_json::json!({
            "versions": [
                { "version": "1.9.8", "yanked": false, "published_at": "2026-01-01T00:00:00Z" },
                { "version": "1.9.9", "yanked": false, "published_at": "2026-02-01T00:00:00Z" },
                { "version": "2.0.0", "yanked": true, "published_at": "2026-03-01T00:00:00Z" }
            ],
            "latest_version": "2.0.0"
        });
        assert_eq!(
            select_default_registry_version(&stats).as_deref(),
            Some("1.9.9")
        );
    }

    #[test]
    fn select_default_registry_version_prefers_latest_hint_when_allowed() {
        let stats = serde_json::json!({
            "versions": [
                { "version": "1.0.0", "yanked": false, "published_at": "2026-01-01T00:00:00Z" },
                { "version": "2.0.0", "yanked": false, "published_at": "2026-02-01T00:00:00Z" }
            ],
            "latest_version": "2.0.0"
        });
        assert_eq!(
            select_default_registry_version(&stats).as_deref(),
            Some("2.0.0")
        );
    }

    #[test]
    fn select_default_registry_version_returns_none_when_all_yanked() {
        let stats = serde_json::json!({
            "versions": [
                { "version": "2.0.0", "yanked": true },
                { "version": "1.9.9", "yanked": true }
            ],
            "latest_version": "2.0.0"
        });
        assert_eq!(select_default_registry_version(&stats), None);
    }

    #[test]
    fn select_default_registry_version_fails_closed_without_yank_state() {
        let stats = serde_json::json!({
            "versions": [
                { "version": "2.0.0", "published_at": "2026-03-01T00:00:00Z" },
                { "version": "1.9.9", "published_at": "2026-02-01T00:00:00Z" }
            ],
            "latest_version": "2.0.0"
        });
        assert_eq!(select_default_registry_version(&stats), None);
    }

    #[test]
    fn select_default_registry_version_falls_back_when_versions_missing() {
        let stats = serde_json::json!({
            "latest_version": "1.4.2"
        });
        assert_eq!(
            select_default_registry_version(&stats).as_deref(),
            Some("1.4.2")
        );
    }

    #[test]
    fn rollback_backup_restores_previous_install_contents() {
        let tmp = tempfile::tempdir().unwrap();
        let install_path = tmp.path().join("pkg").join("1.0.0");
        std::fs::create_dir_all(&install_path).unwrap();
        std::fs::write(install_path.join("marker.txt"), b"old").unwrap();

        let installed = clawdstrike::pkg::store::InstalledPackage {
            name: "demo".to_string(),
            version: "1.0.0".to_string(),
            path: install_path.clone(),
            content_hash: hush_core::sha256(b"old"),
        };

        let backup = create_install_rollback_backup(Some(&installed))
            .unwrap()
            .expect("backup should exist");
        assert!(backup.backup_path.exists());

        std::fs::remove_dir_all(&install_path).unwrap();
        std::fs::create_dir_all(&install_path).unwrap();
        std::fs::write(install_path.join("marker.txt"), b"new").unwrap();

        restore_install_from_backup(&backup).unwrap();

        let restored = std::fs::read(install_path.join("marker.txt")).unwrap();
        assert_eq!(restored, b"old");
        assert!(!backup.backup_path.exists());
    }

    #[test]
    fn recompute_installed_content_fingerprint_detects_tampering() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("clawdstrike-pkg.toml"),
            r#"[package]
name = "verify-demo"
version = "1.0.0"
pkg_type = "guard"

[trust]
level = "trusted"
sandbox = "native"
"#,
        )
        .unwrap();
        std::fs::write(src.join("README.md"), "hello").unwrap();
        let archive_path = tmp.path().join("verify-demo-1.0.0.cpkg");
        let archive_hash = clawdstrike::pkg::archive::pack(&src, &archive_path).unwrap();

        let store = PackageStore::with_root(tmp.path().join("store")).unwrap();
        let installed = store.install_from_file(&archive_path).unwrap();
        assert_eq!(installed.content_hash, archive_hash);

        let meta: StoreMetadata = serde_json::from_str(
            &std::fs::read_to_string(installed.path.join(".pkg-meta.json")).unwrap(),
        )
        .unwrap();
        let expected = meta.content_fingerprint.unwrap();

        let recomputed = recompute_installed_content_fingerprint(&installed.path).unwrap();
        assert_eq!(recomputed, expected);

        std::fs::write(installed.path.join("README.md"), "tampered").unwrap();
        let tampered = recompute_installed_content_fingerprint(&installed.path).unwrap();
        assert_ne!(tampered, expected);
    }

    #[test]
    fn certified_transparency_verification_rejects_tampered_proof() {
        let registry = hush_core::Keypair::from_seed(&[77u8; 32]);
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let proof = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let checkpoint_timestamp = "2026-02-28T00:00:00Z";
        let checkpoint_sig = registry
            .sign(
                checkpoint_signature_message(root.as_str(), proof.tree_size, checkpoint_timestamp)
                    .as_bytes(),
            )
            .to_hex();
        let mut tampered_hashes = proof.proof_path.clone();
        if tampered_hashes.is_empty() {
            tampered_hashes.push("00".repeat(32));
        } else {
            tampered_hashes[0] = "00".repeat(32);
        }

        let attestation = RegistryAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: None,
            registry_key: Some(registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let proof_resp = RegistryProof {
            leaf_index: proof.leaf_index,
            tree_size: proof.tree_size,
            hashes: tampered_hashes,
            root: Some(root),
            checkpoint_timestamp: Some(checkpoint_timestamp.to_string()),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(registry.public_key().to_hex()),
        };

        let err = verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof_resp,
            &registry.public_key().to_hex(),
        )
        .unwrap_err();
        assert!(err.contains("merkle inclusion proof verification failed"));
    }

    #[test]
    fn certified_transparency_verification_accepts_valid_proof() {
        let registry = hush_core::Keypair::from_seed(&[78u8; 32]);
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let checkpoint_timestamp = "2026-02-28T00:00:00Z";
        let checkpoint_sig = registry
            .sign(
                checkpoint_signature_message(
                    root.as_str(),
                    inclusion.tree_size,
                    checkpoint_timestamp,
                )
                .as_bytes(),
            )
            .to_hex();

        let attestation = RegistryAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: None,
            registry_key: Some(registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let proof_resp = RegistryProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: inclusion.proof_path,
            root: Some(root),
            checkpoint_timestamp: Some(checkpoint_timestamp.to_string()),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(registry.public_key().to_hex()),
        };

        verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof_resp,
            &registry.public_key().to_hex(),
        )
        .unwrap();
    }

    #[test]
    fn certified_transparency_verification_rejects_checkpoint_key_mismatch() {
        let trusted_registry = hush_core::Keypair::from_seed(&[79u8; 32]);
        let proof_signer = hush_core::Keypair::from_seed(&[80u8; 32]);
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let checkpoint_timestamp = "2026-02-28T00:00:00Z";
        let checkpoint_sig = proof_signer
            .sign(
                checkpoint_signature_message(
                    root.as_str(),
                    inclusion.tree_size,
                    checkpoint_timestamp,
                )
                .as_bytes(),
            )
            .to_hex();
        let attestation = RegistryAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: None,
            registry_key: Some(trusted_registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let proof_resp = RegistryProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: inclusion.proof_path,
            root: Some(root),
            checkpoint_timestamp: Some(checkpoint_timestamp.to_string()),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(proof_signer.public_key().to_hex()),
        };
        let err = verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof_resp,
            &trusted_registry.public_key().to_hex(),
        )
        .unwrap_err();
        assert!(err.contains("checkpoint key does not match"));
    }

    #[test]
    fn certified_transparency_verification_rejects_invalid_checkpoint_timestamp() {
        let registry = hush_core::Keypair::from_seed(&[81u8; 32]);
        let leaf = LeafData {
            package_name: "demo".to_string(),
            version: "1.0.0".to_string(),
            content_hash: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
        };
        let mut tree = clawdstrike::pkg::merkle::MerkleTree::new();
        let idx = tree.append_hash(leaf.leaf_hash().unwrap());
        let inclusion = tree.generate_inclusion_proof(idx).unwrap();
        let root = tree.root().unwrap();
        let bad_timestamp = "not-a-timestamp";
        let checkpoint_sig = registry
            .sign(
                checkpoint_signature_message(root.as_str(), inclusion.tree_size, bad_timestamp)
                    .as_bytes(),
            )
            .to_hex();
        let attestation = RegistryAttestation {
            checksum: "abcd".to_string(),
            publisher_key: "publisher".to_string(),
            publisher_sig: "sig".to_string(),
            registry_sig: None,
            registry_key: Some(registry.public_key().to_hex()),
            published_at: Some("2026-02-28T00:00:00Z".to_string()),
        };
        let proof_resp = RegistryProof {
            leaf_index: inclusion.leaf_index,
            tree_size: inclusion.tree_size,
            hashes: inclusion.proof_path,
            root: Some(root),
            checkpoint_timestamp: Some(bad_timestamp.to_string()),
            checkpoint_sig: Some(checkpoint_sig),
            checkpoint_key: Some(registry.public_key().to_hex()),
        };
        let err = verify_transparency_proof(
            "demo",
            "1.0.0",
            &attestation,
            &proof_resp,
            &registry.public_key().to_hex(),
        )
        .unwrap_err();
        assert!(err.contains("invalid checkpoint timestamp"));
    }
}
