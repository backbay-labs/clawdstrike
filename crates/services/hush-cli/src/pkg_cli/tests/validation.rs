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
