//! Spider-Sense parsing and deep-merge presence-tracking tests.

use super::*;

#[cfg(feature = "full")]
#[test]
fn test_policy_1_3_spider_sense_fields_parse() {
    let yaml = r#"
version: "1.3.0"
name: SpiderSense13
guards:
  spider_sense:
    enabled: true
    embedding_api_url: "https://api.openai.com/v1/embeddings"
    embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.85
    ambiguity_band: 0.10
    top_k: 5
    pattern_db_manifest_path: "/tmp/spider/manifest.json"
    pattern_db_manifest_trust_store_path: "/tmp/spider/manifest-roots.json"
    llm_api_url: "https://api.openai.com/v1/chat/completions"
    llm_api_key: "${SPIDER_SENSE_LLM_KEY}"
    llm_model: "gpt-4.1-mini"
    llm_prompt_template_id: "spider_sense.deep_path.json_classifier"
    llm_prompt_template_version: "1.0.0"
    llm_timeout_ms: 1500
    llm_fail_mode: "warn"
"#;

    let policy = Policy::from_yaml(yaml).expect("1.3 spider-sense config should parse");
    let spider = policy
        .guards
        .spider_sense
        .as_ref()
        .expect("spider_sense should be present");
    assert_eq!(
        spider.pattern_db_manifest_path.as_deref(),
        Some("/tmp/spider/manifest.json")
    );
    assert_eq!(
        spider.llm_prompt_template_id.as_deref(),
        Some("spider_sense.deep_path.json_classifier")
    );
    assert_eq!(spider.llm_prompt_template_version.as_deref(), Some("1.0.0"));
}

#[cfg(all(feature = "policy-event", not(feature = "full")))]
#[test]
fn test_policy_1_3_spider_sense_fields_parse_policy_event_build() {
    let yaml = r#"
version: "1.3.0"
name: SpiderSense13PolicyEvent
guards:
  spider_sense:
    enabled: true
    embedding_api_url: "https://api.openai.com/v1/embeddings"
    embedding_api_key: "${SPIDER_SENSE_EMBEDDING_KEY}"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.85
    ambiguity_band: 0.10
    top_k: 5
    pattern_db_manifest_path: "/tmp/spider/manifest.json"
    pattern_db_manifest_trust_store_path: "/tmp/spider/manifest-roots.json"
"#;

    let policy = Policy::from_yaml(yaml).expect("1.3 spider-sense policy should parse");
    let spider = policy
        .guards
        .spider_sense
        .as_ref()
        .expect("spider_sense field should be preserved");
    assert_eq!(
        spider
            .pointer("/pattern_db_manifest_path")
            .and_then(|v| v.as_str()),
        Some("/tmp/spider/manifest.json")
    );
}

#[cfg(feature = "full")]
#[test]
fn test_spider_sense_deep_merge_allows_child_disable_override() {
    let base = GuardConfigs {
        spider_sense: Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "embedding_api_url": "https://example.invalid/v1/embeddings",
                "embedding_api_key": "base-key",
                "embedding_model": "text-embedding-3-small",
                "pattern_db_path": "builtin:s2bench-v1"
            }))
            .unwrap(),
        ),
        ..Default::default()
    };
    let child = GuardConfigs {
        spider_sense: Some(
            serde_json::from_value(serde_json::json!({
                "enabled": false
            }))
            .unwrap(),
        ),
        spider_sense_present_fields: std::iter::once("enabled".to_string()).collect(),
        ..Default::default()
    };

    let merged = base.merge_with(&child);
    let merged_spider = merged
        .spider_sense
        .expect("child disable override should preserve explicit spider_sense config");
    assert!(!merged_spider.enabled);
}

#[cfg(feature = "full")]
#[test]
fn test_spider_sense_deep_merge_preserves_base_fields_on_partial_child_override() {
    let base = GuardConfigs {
        spider_sense: Some(
            serde_json::from_value(serde_json::json!({
                "enabled": false,
                "embedding_api_url": "https://example.invalid/v1/embeddings",
                "embedding_api_key": "base-key",
                "embedding_model": "text-embedding-3-small",
                "similarity_threshold": 0.82,
                "pattern_db_path": "builtin:s2bench-v1"
            }))
            .unwrap(),
        ),
        ..Default::default()
    };
    let child = GuardConfigs {
        spider_sense: Some(
            serde_json::from_value(serde_json::json!({
                "similarity_threshold": 0.91
            }))
            .unwrap(),
        ),
        spider_sense_present_fields: std::iter::once("similarity_threshold".to_string()).collect(),
        ..Default::default()
    };

    let merged = base.merge_with(&child);
    let merged_spider = merged
        .spider_sense
        .expect("partial child override should preserve base spider_sense config");
    assert!(!merged_spider.enabled);
    assert_eq!(
        merged_spider.embedding_api_url,
        "https://example.invalid/v1/embeddings"
    );
    assert_eq!(merged_spider.embedding_api_key, "base-key");
    assert_eq!(merged_spider.embedding_model, "text-embedding-3-small");
    assert_eq!(merged_spider.pattern_db_path, "builtin:s2bench-v1");
    assert_eq!(merged_spider.similarity_threshold, 0.91);
}

#[cfg(feature = "full")]
#[test]
fn test_spider_sense_deep_merge_without_presence_treats_child_as_explicit_replacement() {
    let base = GuardConfigs {
        spider_sense: Some(
            serde_json::from_value(serde_json::json!({
                "enabled": false,
                "embedding_api_url": "https://example.invalid/v1/embeddings",
                "embedding_api_key": "base-key",
                "embedding_model": "text-embedding-3-small",
                "similarity_threshold": 0.95,
                "ambiguity_band": 0.02,
                "top_k": 9,
                "pattern_db_path": "builtin:s2bench-v1"
            }))
            .unwrap(),
        ),
        ..Default::default()
    };
    let child = GuardConfigs {
        spider_sense: Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "similarity_threshold": 0.85,
                "ambiguity_band": 0.10,
                "top_k": 5
            }))
            .unwrap(),
        ),
        ..Default::default()
    };

    let merged = base.merge_with(&child);
    let ss = merged.spider_sense.expect("merged spider_sense");
    assert!(ss.enabled);
    assert_eq!(ss.similarity_threshold, 0.85);
    assert_eq!(ss.ambiguity_band, 0.10);
    assert_eq!(ss.top_k, 5);
    assert_eq!(ss.embedding_api_key, "");
    assert_eq!(ss.pattern_db_path, "");
}

#[cfg(feature = "full")]
#[test]
fn test_spider_sense_deep_merge_without_presence_clears_stale_present_fields() {
    let base = GuardConfigs {
        spider_sense: Some(
            serde_json::from_value(serde_json::json!({
                "enabled": false,
                "embedding_api_url": "https://example.invalid/v1/embeddings",
                "embedding_api_key": "base-key",
                "embedding_model": "text-embedding-3-small",
                "similarity_threshold": 0.95,
                "pattern_db_path": "builtin:s2bench-v1"
            }))
            .unwrap(),
        ),
        spider_sense_present_fields: std::iter::once("similarity_threshold".to_string()).collect(),
        ..Default::default()
    };
    let child = GuardConfigs {
        spider_sense: Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "similarity_threshold": 0.85,
                "ambiguity_band": 0.10,
                "top_k": 5
            }))
            .unwrap(),
        ),
        // Programmatic child replacement has no explicit YAML field metadata.
        spider_sense_present_fields: Default::default(),
        ..Default::default()
    };

    let merged = base.merge_with(&child);
    assert!(
        merged.spider_sense_present_fields.is_empty(),
        "programmatic replacement should not retain stale source present_fields"
    );
}

#[cfg(feature = "full")]
#[test]
fn test_spider_sense_deep_merge_yaml_presence_preserves_parent_when_field_absent() {
    let base = Policy::from_yaml_unvalidated(
        r#"
version: "1.3.0"
name: "base"
guards:
  spider_sense:
    enabled: false
    embedding_api_url: "https://example.invalid/v1/embeddings"
    embedding_api_key: "base-key"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.82
    ambiguity_band: 0.05
    top_k: 7
    pattern_db_path: "builtin:s2bench-v1"
"#,
    )
    .unwrap();
    let child = Policy::from_yaml_unvalidated(
        r#"
version: "1.3.0"
name: "child"
guards:
  spider_sense:
    similarity_threshold: 0.91
"#,
    )
    .unwrap();

    let merged = base.merge(&child);
    let ss = merged.guards.spider_sense.expect("merged spider_sense");
    assert!(!ss.enabled, "absent child.enabled should preserve parent");
    assert_eq!(ss.similarity_threshold, 0.91);
    assert_eq!(ss.ambiguity_band, 0.05);
    assert_eq!(ss.top_k, 7);
    assert_eq!(
        ss.embedding_api_url,
        "https://example.invalid/v1/embeddings"
    );
}

#[cfg(feature = "full")]
#[test]
fn test_spider_sense_deep_merge_yaml_presence_honors_explicit_default_overrides() {
    let base = Policy::from_yaml_unvalidated(
        r#"
version: "1.3.0"
name: "base"
guards:
  spider_sense:
    enabled: false
    embedding_api_url: "https://example.invalid/v1/embeddings"
    embedding_api_key: "base-key"
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.95
    ambiguity_band: 0.02
    top_k: 9
    pattern_db_path: "builtin:s2bench-v1"
"#,
    )
    .unwrap();
    let child = Policy::from_yaml_unvalidated(
        r#"
version: "1.3.0"
name: "child"
guards:
  spider_sense:
    enabled: true
    similarity_threshold: 0.85
    ambiguity_band: 0.10
    top_k: 5
"#,
    )
    .unwrap();

    let merged = base.merge(&child);
    let ss = merged.guards.spider_sense.expect("merged spider_sense");
    assert!(ss.enabled, "explicit child.enabled should override parent");
    assert_eq!(ss.similarity_threshold, 0.85);
    assert_eq!(ss.ambiguity_band, 0.10);
    assert_eq!(ss.top_k, 5);
    assert_eq!(ss.embedding_api_key, "base-key");
    assert_eq!(ss.pattern_db_path, "builtin:s2bench-v1");
}
