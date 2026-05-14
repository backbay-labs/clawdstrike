use hushspec::{
    BUILTIN_NAMES, LoadedSpec, ResolveError, create_composite_loader, load_builtin,
    resolve_from_path, resolve_from_path_with_builtins, resolve_with_loader,
};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn resolve_from_path_merges_extends_chain() {
    let dir = temp_dir("resolve-chain");
    fs::write(
        dir.join("base.yaml"),
        r#"
hushspec: "0.1.0"
name: base
rules:
  tool_access:
    allow: [read_file]
    default: block
"#,
    )
    .unwrap();
    fs::write(
        dir.join("child.yaml"),
        r#"
hushspec: "0.1.0"
extends: base.yaml
name: child
rules:
  egress:
    allow: [api.example.com]
    default: allow
"#,
    )
    .unwrap();

    let resolved = resolve_from_path(dir.join("child.yaml")).unwrap();
    assert!(resolved.extends.is_none());
    assert_eq!(resolved.name.as_deref(), Some("child"));
    let rules = resolved.rules.unwrap();
    let tool_access = rules.tool_access.unwrap();
    assert_eq!(tool_access.allow, vec!["read_file"]);
    assert_eq!(tool_access.default, hushspec::DefaultAction::Block);
    let egress = rules.egress.unwrap();
    assert_eq!(egress.allow, vec!["api.example.com"]);
    assert_eq!(egress.default, hushspec::DefaultAction::Allow);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn resolve_detects_cycles() {
    let dir = temp_dir("resolve-cycle");
    fs::write(
        dir.join("a.yaml"),
        r#"
hushspec: "0.1.0"
extends: b.yaml
"#,
    )
    .unwrap();
    fs::write(
        dir.join("b.yaml"),
        r#"
hushspec: "0.1.0"
extends: a.yaml
"#,
    )
    .unwrap();

    let error = resolve_from_path(dir.join("a.yaml")).unwrap_err();
    match error {
        ResolveError::Cycle { chain } => assert!(chain.contains("a.yaml")),
        other => panic!("expected cycle error, got {other:?}"),
    }

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn resolve_with_loader_uses_canonical_source_ids() {
    let child = hushspec::HushSpec::parse(
        r#"
hushspec: "0.1.0"
extends: parent
rules:
  egress:
    allow: [api.example.com]
    default: block
"#,
    )
    .unwrap();

    let resolved = resolve_with_loader(&child, Some("memory://child"), &|reference, _| {
        assert_eq!(reference, "parent");
        Ok(LoadedSpec {
            source: "memory://parent".to_string(),
            spec: hushspec::HushSpec::parse(
                r#"
hushspec: "0.1.0"
rules:
  egress:
    block: [api.example.com]
    default: allow
"#,
            )
            .unwrap(),
        })
    })
    .unwrap();

    assert!(resolved.extends.is_none());
    let egress = resolved.rules.unwrap().egress.unwrap();
    assert_eq!(egress.allow, vec!["api.example.com"]);
    assert!(egress.block.is_empty());
    assert_eq!(egress.default, hushspec::DefaultAction::Block);
}

#[test]
fn builtin_loader_resolves_all_six_rulesets() {
    for name in BUILTIN_NAMES {
        let yaml = load_builtin(name);
        assert!(yaml.is_some(), "builtin '{name}' should be available");
        let spec = hushspec::HushSpec::parse(yaml.unwrap());
        assert!(spec.is_ok(), "builtin '{name}' should parse without error");
        let spec = spec.unwrap();
        assert_eq!(spec.name.as_deref(), Some(*name));
    }
}

#[test]
fn extends_builtin_default_end_to_end() {
    let dir = temp_dir("resolve-builtin");
    fs::write(
        dir.join("child.yaml"),
        r#"
hushspec: "0.1.0"
extends: builtin:default
name: my-custom-policy
rules:
  egress:
    allow: [custom.example.com]
    default: allow
"#,
    )
    .unwrap();

    let resolved = resolve_from_path_with_builtins(dir.join("child.yaml")).unwrap();
    assert!(resolved.extends.is_none());
    assert_eq!(resolved.name.as_deref(), Some("my-custom-policy"));

    let rules = resolved.rules.as_ref().unwrap();
    // Inherited from builtin:default
    assert!(rules.forbidden_paths.is_some());
    assert!(rules.secret_patterns.is_some());
    assert!(rules.tool_access.is_some());
    // Child's own rules
    let egress = rules.egress.as_ref().unwrap();
    assert!(egress.allow.contains(&"custom.example.com".to_string()));
    assert_eq!(egress.default, hushspec::DefaultAction::Allow);

    fs::remove_dir_all(dir).unwrap();
}

#[test]
fn composite_loader_resolves_builtin_with_custom_loader() {
    let child = hushspec::HushSpec::parse(
        r#"
hushspec: "0.1.0"
extends: builtin:strict
name: custom
"#,
    )
    .unwrap();

    let loader = create_composite_loader();
    let resolved = resolve_with_loader(&child, Some("memory://child"), &loader).unwrap();
    assert!(resolved.extends.is_none());
    assert_eq!(resolved.name.as_deref(), Some("custom"));
    // Should have inherited from strict
    let rules = resolved.rules.as_ref().unwrap();
    let tool_access = rules.tool_access.as_ref().unwrap();
    assert_eq!(tool_access.default, hushspec::DefaultAction::Block);
}

fn temp_dir(prefix: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("hushspec-{prefix}-{unique}"));
    fs::create_dir_all(&dir).unwrap();
    dir
}
