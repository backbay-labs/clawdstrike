// Witness-synthesis internals: regex/path/domain/token sample generation.
//
// Included into `verifier::tests` via `include!` from tests/mod.rs, so these
// bodies share that module's imports and fixtures unchanged.
    #[test]
    fn shortest_common_supersequence_does_not_duplicate_shared_suffixes() {
        let left = vec!["a".to_string(), "b".to_string()];
        let right = vec!["c".to_string(), "b".to_string()];

        assert_eq!(
            shortest_common_supersequence(&left, &right),
            vec!["a".to_string(), "c".to_string(), "b".to_string()]
        );
    }

    #[test]
    fn brace_alternatives_are_fully_consumed_when_generating_tokens() {
        assert_eq!(representative_token("{alice,bob}.txt"), "alice.txt");
        assert_eq!(literal_segment("{alice,bob}.txt"), "alice.txt");
    }

    #[test]
    fn dot_prefixed_segments_stay_valid_representatives() {
        let wildcard_dot = literal_segment("*.env");
        let wildcard_qmark = literal_segment("?.config");
        assert_eq!(wildcard_dot, ".env");
        assert_eq!(wildcard_qmark, "x.config");
        assert!(Pattern::new("*.env")
            .expect("valid glob")
            .matches(&wildcard_dot));
        assert!(Pattern::new("?.config")
            .expect("valid glob")
            .matches(&wildcard_qmark));
        assert_eq!(literal_segment(".env"), ".env");
    }

    #[test]
    fn negated_char_class_probe_still_matches_pattern() {
        let probe = representative_token("[!0]");
        assert_ne!(probe, "0");
        assert!(Pattern::new("[!0]").expect("valid glob").matches(&probe));
    }

    #[test]
    fn negated_char_class_can_exclude_closing_bracket() {
        let probe = representative_token("[!]]");
        assert_ne!(probe, "]");
        assert!(Pattern::new("[!]]").expect("valid glob").matches(&probe));
    }

    #[test]
    fn negated_char_class_witness_finds_real_overlap() {
        let witness =
            path_intersection_witness("/tmp/[!0]", "/tmp/*").expect("expected overlapping witness");
        assert!(path_pattern_matches("/tmp/[!0]", &witness));
        assert!(path_pattern_matches("/tmp/*", &witness));
    }

    #[test]
    fn literal_suffix_token_keeps_escaped_meta_literals() {
        assert_eq!(literal_suffix_token(r"abc\*def"), "abc*def");
        assert_eq!(literal_suffix_token(r"abc\?def"), "abc?def");
    }

    #[test]
    fn regex_repetition_samples_respect_positive_minimum() {
        assert_eq!(regex_hir_samples_from_pattern("a{4}", 1), vec!["aaaa"]);
    }

    #[test]
    fn regex_repetition_samples_do_not_emit_empty_for_nonempty_plus_class() {
        let compiled = Regex::new(r"\s+").expect("valid regex");
        let samples = regex_hir_samples_from_pattern(r"\s+", 16);
        assert!(!samples.is_empty());
        assert!(samples.iter().all(|sample| !sample.is_empty()));
        assert!(samples.iter().all(|sample| compiled.is_match(sample)));
    }

    #[test]
    fn default_mcp_probe_returns_unused_fallback_when_probe_space_is_exhausted() {
        let mut cfg = McpToolConfig {
            enabled: true,
            allow: vec!["__clawdstrike_inheritance_probe__".to_string()],
            block: Vec::new(),
            require_confirmation: Vec::new(),
            default_action: None,
            max_args_size: None,
            additional_allow: Vec::new(),
            remove_allow: Vec::new(),
            additional_block: Vec::new(),
            remove_block: Vec::new(),
        };
        cfg.allow
            .extend((0..32).map(|idx| format!("__clawdstrike_inheritance_probe_{idx}__")));

        let probe = default_mcp_probe(&cfg, None);
        assert!(!probe.is_empty());
        assert!(!cfg.allow.contains(&probe));
        assert!(!cfg.block.contains(&probe));
        assert!(!cfg.require_confirmation.contains(&probe));
    }

