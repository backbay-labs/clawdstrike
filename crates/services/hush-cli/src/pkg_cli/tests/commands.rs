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
