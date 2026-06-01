// Load-time verification and result-cache tests.
//
// Included into `verifier::tests` via `include!` from tests/mod.rs, so these
// bodies share that module's imports and fixtures unchanged.
    #[test]
    fn load_time_skip_when_not_enabled() {
        let policy = Policy::default();
        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time(&policy, &cache).unwrap();
        assert!(result.report.is_none());
        assert!(result.error.is_none());
        assert!(!result.cache_hit);
    }

    #[test]
    fn load_time_runs_when_enabled() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: false,
            cache: false,
        });
        policy.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time(&policy, &cache).unwrap();
        assert!(result.report.is_some());
        assert!(!result.cache_hit);
    }

    #[test]
    fn load_time_strict_blocks_on_failure() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: true,
            cache: false,
        });
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["evil.example.com".to_string()],
            block: vec!["evil.example.com".to_string()],
            default_action: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time(&policy, &cache);
        assert!(result.is_err());
    }

    #[test]
    fn load_time_strict_fails_closed_without_inheritance_context() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: true,
            cache: false,
        });
        policy.extends = Some("parent.yaml".to_string());

        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time(&policy, &cache);

        assert!(result.is_err());
        assert!(result
            .err()
            .unwrap_or_default()
            .contains("missing source location/resolver context"));
    }

    #[test]
    fn load_time_with_resolver_enforces_inheritance_soundness() {
        let parent = Policy::from_yaml(
            r#"
version: "1.1.0"
name: "parent"
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
"#,
        )
        .expect("parse parent");

        let source_policy = Policy {
            version: "1.1.0".to_string(),
            name: "child".to_string(),
            extends: Some("parent.yaml".to_string()),
            settings: clawdstrike::policy::PolicySettings {
                verification: Some(VerificationSettings {
                    enabled: true,
                    strict: true,
                    cache: false,
                }),
                ..Default::default()
            },
            guards: GuardConfigs {
                forbidden_path: Some(ForbiddenPathConfig {
                    enabled: true,
                    patterns: None,
                    exceptions: Vec::new(),
                    additional_patterns: Vec::new(),
                    remove_patterns: vec!["/etc/shadow".to_string()],
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let effective_policy = parent.merge(&source_policy);

        let cache = VerificationCache::new();
        let result = verify_policy_at_load_time_with_parent(
            &effective_policy,
            &source_policy,
            &parent,
            &cache,
        );

        let err = result.expect_err("weakened inheritance should fail strict verification");
        assert!(err.contains("inheritance"));
    }

    #[test]
    fn strict_extends_load_verifies_invalid_ancestor_transitively() {
        install_clawdstrike_policy_load_verifier();

        let dir = std::env::temp_dir().join(format!(
            "clawdstrike_logos_verifier_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let grandparent = dir.join("grandparent.yaml");
        let parent = dir.join("parent.yaml");
        let child = dir.join("child.yaml");

        std::fs::write(
            &grandparent,
            r#"
version: "1.5.0"
name: "grandparent"
settings:
  verification:
    enabled: true
    strict: true
guards:
  forbidden_path:
    enabled: true
    patterns:
      - "/etc/shadow"
"#,
        )
        .expect("write grandparent");

        std::fs::write(
            &parent,
            r#"
version: "1.5.0"
name: "parent"
extends: "grandparent.yaml"
settings:
  verification:
    enabled: true
    strict: true
guards:
  forbidden_path:
    enabled: true
    remove_patterns:
      - "/etc/shadow"
"#,
        )
        .expect("write parent");

        std::fs::write(
            &child,
            r#"
version: "1.5.0"
name: "child"
extends: "parent.yaml"
settings:
  verification:
    enabled: true
    strict: true
"#,
        )
        .expect("write child");

        let child_yaml = std::fs::read_to_string(&child).expect("read child");
        let err = Policy::from_yaml_with_extends(&child_yaml, Some(child.as_path()))
            .expect_err("invalid strict parent should fail transitively");
        assert!(err.to_string().contains("inheritance"));
    }

    #[test]
    fn load_time_caching_works() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: false,
            cache: true,
        });
        policy.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

        let cache = VerificationCache::new();
        let first = verify_policy_at_load_time(&policy, &cache).unwrap();
        let second = verify_policy_at_load_time(&policy, &cache).unwrap();

        assert!(!first.cache_hit);
        assert!(second.cache_hit);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cached_non_strict_failure_preserves_error_details() {
        let mut policy = Policy::default();
        policy.settings.verification = Some(VerificationSettings {
            enabled: true,
            strict: false,
            cache: true,
        });
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["evil.example.com".to_string()],
            block: vec!["evil.example.com".to_string()],
            default_action: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let cache = VerificationCache::new();
        let first = verify_policy_at_load_time(&policy, &cache).expect("first verification");
        let second = verify_policy_at_load_time(&policy, &cache).expect("second verification");

        assert!(!first.cache_hit);
        assert!(first.error.is_some());
        assert!(second.cache_hit);
        assert!(second.error.is_some());
    }

    #[test]
    fn cache_eviction_keeps_bounded_size() {
        let cache = VerificationCache::with_capacity_limit(2);
        let report = formula_verifier().verify(&[], None);

        cache.insert("one".to_string(), report.clone());
        cache.insert("two".to_string(), report.clone());
        cache.insert("three".to_string(), report);

        assert_eq!(cache.len(), 2);
        assert!(cache.get("one").is_none());
        assert!(cache.get("two").is_some());
        assert!(cache.get("three").is_some());
    }

    #[test]
    fn resolver_style_cache_keys_include_parent_policy_content() {
        let mut parent_with_guard = Policy::default();
        parent_with_guard.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));

        let parent_without_guard = Policy::default();

        let source_policy = Policy {
            version: "1.5.0".to_string(),
            name: "child".to_string(),
            extends: Some("parent.yaml".to_string()),
            merge_strategy: clawdstrike::policy::MergeStrategy::Replace,
            settings: clawdstrike::policy::PolicySettings {
                verification: Some(VerificationSettings {
                    enabled: true,
                    strict: false,
                    cache: true,
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let effective_policy = parent_with_guard.merge(&source_policy);
        let cache = VerificationCache::new();

        let first = verify_policy_at_load_time_with_parent(
            &effective_policy,
            &source_policy,
            &parent_with_guard,
            &cache,
        )
        .expect("first verification");
        assert!(!first.cache_hit);
        assert!(first.error.is_some());

        let second = verify_policy_at_load_time_with_parent(
            &effective_policy,
            &source_policy,
            &parent_without_guard,
            &cache,
        )
        .expect("second verification");
        assert!(!second.cache_hit);
        assert!(second.error.is_none());
        assert_eq!(cache.len(), 2);
    }

