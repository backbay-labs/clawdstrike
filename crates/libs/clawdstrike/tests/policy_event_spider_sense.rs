#![cfg(all(feature = "policy-event", not(feature = "full")))]

use clawdstrike::Policy;

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
