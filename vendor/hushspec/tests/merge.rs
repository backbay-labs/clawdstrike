use hushspec::{HushSpec, merge};

#[test]
fn merge_replace_uses_child() {
    let base = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: base
rules:
  egress:
    allow: ["a.com"]
    default: block
"#,
    )
    .unwrap();
    let child = HushSpec::parse(
        r#"
hushspec: "0.1.0"
name: child
merge_strategy: replace
rules:
  tool_access:
    block: ["shell_exec"]
    default: allow
"#,
    )
    .unwrap();
    let merged = merge(&base, &child);
    assert_eq!(merged.name.as_deref(), Some("child"));
    assert!(merged.rules.as_ref().unwrap().egress.is_none());
    assert!(merged.rules.as_ref().unwrap().tool_access.is_some());
}

#[test]
fn merge_shallow_child_overrides_rule() {
    let base = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  egress:
    allow: ["a.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**"]
"#,
    )
    .unwrap();
    let child = HushSpec::parse(
        r#"
hushspec: "0.1.0"
merge_strategy: merge
rules:
  egress:
    allow: ["b.com"]
    default: allow
"#,
    )
    .unwrap();
    let merged = merge(&base, &child);
    let rules = merged.rules.as_ref().unwrap();
    // egress replaced by child
    assert_eq!(rules.egress.as_ref().unwrap().allow, vec!["b.com"]);
    // forbidden_paths preserved from base
    assert!(rules.forbidden_paths.is_some());
}

#[test]
fn merge_deep_child_overrides_rule() {
    let base = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  egress:
    allow: ["a.com"]
    default: block
  forbidden_paths:
    patterns: ["**/.ssh/**"]
"#,
    )
    .unwrap();
    let child = HushSpec::parse(
        r#"
hushspec: "0.1.0"
rules:
  egress:
    allow: ["b.com"]
    default: allow
"#,
    )
    .unwrap();
    let merged = merge(&base, &child);
    let rules = merged.rules.as_ref().unwrap();
    // deep_merge is default: child egress overrides base egress
    assert_eq!(rules.egress.as_ref().unwrap().allow, vec!["b.com"]);
    // forbidden_paths preserved from base
    assert!(rules.forbidden_paths.is_some());
}
