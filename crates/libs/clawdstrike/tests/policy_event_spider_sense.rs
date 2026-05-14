#![cfg(all(feature = "policy-event", not(feature = "full")))]

use clawdstrike::{hushspec_compiler, Policy};

#[test]
fn policy_event_accepts_schema_1_3_spider_sense_object() {
    let yaml = r#"
version: "1.3.0"
name: SpiderSensePolicyEvent
guards:
  spider_sense:
    enabled: true
    embedding_api_url: "https://api.openai.com/v1/embeddings"
    embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"
    embedding_model: "text-embedding-3-small"
    pattern_db_manifest_path: "/tmp/spider/manifest.json"
"#;

    let policy = Policy::from_yaml(yaml).expect("policy should parse under policy-event build");
    let spider = policy
        .guards
        .spider_sense
        .as_ref()
        .expect("spider_sense should be preserved");
    assert_eq!(
        spider
            .pointer("/pattern_db_manifest_path")
            .and_then(|value| value.as_str()),
        Some("/tmp/spider/manifest.json")
    );
}

#[test]
fn policy_event_accepts_schema_1_3_spider_sense_boolean() {
    let yaml = r#"
version: "1.3.0"
name: SpiderSensePolicyEventBool
guards:
  spider_sense: true
"#;

    let policy = Policy::from_yaml(yaml).expect("boolean spider_sense should parse");
    let spider = policy
        .guards
        .spider_sense
        .as_ref()
        .expect("spider_sense should be preserved");
    assert_eq!(spider.as_bool(), Some(true));
}

#[test]
fn policy_event_compile_hushspec_preserves_threat_intel_passthrough() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      enabled: true
      pattern_db: "builtin:s2bench-v1"
      similarity_threshold: 0.9
      top_k: 3
"#;

    let policy = hushspec_compiler::compile_hushspec(yaml)
        .expect("policy-event build should preserve threat_intel passthrough");
    let spider = policy
        .guards
        .spider_sense
        .as_ref()
        .expect("spider_sense should be preserved");
    assert_eq!(
        spider
            .pointer("/pattern_db_path")
            .and_then(|value| value.as_str()),
        Some("builtin:s2bench-v1")
    );
    assert_eq!(
        spider
            .pointer("/similarity_threshold")
            .and_then(|value| value.as_f64()),
        Some(0.9)
    );
    assert_eq!(
        spider.pointer("/top_k").and_then(|value| value.as_u64()),
        Some(3)
    );
}

#[test]
fn policy_event_decompile_hushspec_restores_threat_intel_passthrough() {
    let yaml = r#"
version: "1.3.0"
name: SpiderSenseHushSpecRoundtrip
guards:
  spider_sense:
    enabled: true
    pattern_db_path: "builtin:s2bench-v1"
    similarity_threshold: 0.9
    top_k: 3
"#;

    let policy = Policy::from_yaml(yaml).expect("policy should parse under policy-event build");
    let spec = hushspec_compiler::decompile(&policy).expect("decompile should succeed");
    let ti = spec
        .extensions
        .expect("extensions should be present")
        .detection
        .expect("detection extension should be present")
        .threat_intel
        .expect("threat_intel should be preserved");
    assert_eq!(ti.enabled, Some(true));
    assert_eq!(ti.pattern_db.as_deref(), Some("builtin:s2bench-v1"));
    assert_eq!(ti.similarity_threshold, Some(0.9));
    assert_eq!(ti.top_k, Some(3));
}

#[test]
fn policy_event_threat_intel_passthrough_preserves_unset_fields() {
    let yaml = r#"
hushspec: "0.1.0"
extensions:
  detection:
    threat_intel:
      pattern_db: "builtin:s2bench-v1"
"#;

    let policy = hushspec_compiler::compile_hushspec(yaml)
        .expect("policy-event build should preserve sparse threat_intel passthrough");
    let spider = policy
        .guards
        .spider_sense
        .as_ref()
        .expect("spider_sense should be preserved");
    assert!(spider.get("enabled").is_none());
    assert!(spider.get("similarity_threshold").is_none());
    assert!(spider.get("top_k").is_none());
    assert_eq!(
        spider
            .pointer("/pattern_db_path")
            .and_then(|value| value.as_str()),
        Some("builtin:s2bench-v1")
    );

    let spec = hushspec_compiler::decompile(
        &Policy::from_yaml(
            r#"
version: "1.3.0"
name: SpiderSenseSparseRoundtrip
guards:
  spider_sense:
    pattern_db_path: "builtin:s2bench-v1"
"#,
        )
        .expect("policy should parse under policy-event build"),
    )
    .expect("decompile should succeed");
    let ti = spec
        .extensions
        .expect("extensions should be present")
        .detection
        .expect("detection extension should be present")
        .threat_intel
        .expect("threat_intel should be preserved");
    assert_eq!(ti.enabled, None);
    assert_eq!(ti.pattern_db.as_deref(), Some("builtin:s2bench-v1"));
    assert_eq!(ti.similarity_threshold, None);
    assert_eq!(ti.top_k, None);
}
