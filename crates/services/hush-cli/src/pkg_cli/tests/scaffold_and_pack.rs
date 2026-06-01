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
