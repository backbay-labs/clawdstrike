// Core verifier tests: consistency, completeness, conflicts, attestation, metadata.
//
// Included into `verifier::tests` via `include!` from tests/mod.rs, so these
// bodies share that module's imports and fixtures unchanged.
    #[test]
    fn consistent_when_no_overlap() {
        let formulas = vec![
            Formula::prohibition(agent(), Formula::atom("access(/etc/shadow)")),
            Formula::permission(agent(), Formula::atom("egress(api.openai.com)")),
        ];
        let result = formula_verifier().check_consistency(&formulas);
        assert!(result.outcome.is_pass());
        assert_eq!(result.conflict_count, 0);
    }

    #[test]
    fn obligation_and_prohibition_conflict_detected() {
        let formulas = vec![
            Formula::obligation(agent(), Formula::atom("exec(rm -rf /)")),
            Formula::prohibition(agent(), Formula::atom("exec(rm -rf /)")),
        ];
        let result = formula_verifier()
            .with_expected_action_types(vec!["exec".to_string()])
            .verify(&formulas, None);
        assert_eq!(result.consistency.outcome, CheckOutcome::Fail);
        assert!(result
            .consistency
            .conflicts
            .iter()
            .any(|conflict| conflict.atom == "exec(rm -rf /)"));
    }

    #[test]
    fn completeness_with_custom_expected_types() {
        let formulas = vec![Formula::prohibition(
            agent(),
            Formula::atom("access(/etc/shadow)"),
        )];
        let result = formula_verifier()
            .with_expected_action_types(vec!["access".to_string()])
            .check_completeness(&formulas);
        assert!(result.outcome.is_pass());
        assert_eq!(result.covered, vec!["access".to_string()]);
    }

    #[test]
    fn inheritance_is_skipped_for_formula_only_api() {
        let formulas = vec![Formula::prohibition(
            agent(),
            Formula::atom("access(/etc/shadow)"),
        )];
        let report = formula_verifier()
            .with_expected_action_types(vec!["access".to_string()])
            .verify(&formulas, None);
        assert_eq!(report.inheritance.outcome, CheckOutcome::Skipped);
        assert_eq!(report.backend, VerificationBackend::FormulaInspection);
        assert_eq!(report.attestation_level, AttestationLevel::FormulaVerified);
    }

    #[test]
    fn dynamic_policy_completeness_only_requires_configured_guards() {
        let mut policy = Policy::default();
        policy.guards = GuardConfigs {
            forbidden_path: Some(simple_forbidden_path("/etc/shadow")),
            egress_allowlist: Some(EgressAllowlistConfig {
                enabled: true,
                allow: vec!["api.openai.com".to_string()],
                block: vec![],
                default_action: None,
                additional_allow: vec![],
                remove_allow: vec![],
                additional_block: vec![],
                remove_block: vec![],
            }),
            ..GuardConfigs::default()
        };

        let report = formula_verifier().verify_policy(&policy, agent());
        assert!(report.completeness.outcome.is_pass(), "{report:?}");
        assert_eq!(report.completeness.covered, vec!["access", "egress"]);
        assert!(report.completeness.missing.is_empty());
    }

    #[test]
    fn configured_action_types_are_derived_from_enabled_guards() {
        let mut policy = Policy::default();
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig {
            enabled: true,
            allow: vec!["api.openai.com".to_string()],
            block: vec![],
            default_action: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        assert_eq!(
            expected_action_types_for_policy_set(&policy),
            BTreeSet::from(["egress".to_string()])
        );
    }

    #[test]
    fn shell_forbidden_path_enforcement_requires_exec_coverage() {
        let mut policy = Policy::default();
        policy.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));
        policy.guards.shell_command = Some(ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec![],
            enforce_forbidden_paths: true,
        });

        assert_eq!(
            expected_action_types_for_policy_set(&policy),
            BTreeSet::from(["access".to_string(), "exec".to_string()])
        );

        let report = formula_verifier().verify_policy(&policy, agent());
        assert!(report.completeness.outcome.is_pass(), "{report:?}");
        assert!(report
            .completeness
            .covered
            .iter()
            .any(|kind| kind == "exec"));
    }

    #[test]
    fn runtime_only_guards_contribute_custom_action_coverage() {
        let mut policy = Policy::default();
        policy.guards.secret_leak = Some(SecretLeakConfig::default());
        policy.guards.prompt_injection = Some(PromptInjectionConfig::default());

        let report = formula_verifier().verify_policy(&policy, agent());
        assert!(report.formula_count > 0, "{report:?}");
        assert!(report
            .completeness
            .covered
            .iter()
            .any(|action_type| action_type == "custom"));
        assert!(report.completeness.missing.is_empty(), "{report:?}");
    }

    #[test]
    fn policy_custom_guards_downgrade_attestation_to_heuristic() {
        let mut policy = Policy::default();
        policy
            .custom_guards
            .push(clawdstrike::policy::PolicyCustomGuardSpec {
                id: "demo-guard".to_string(),
                enabled: true,
                config: serde_json::json!({}),
            });

        let report = formula_verifier().verify_policy(&policy, agent());
        assert_eq!(report.completeness.outcome, CheckOutcome::Fail);
        assert!(report
            .completeness
            .missing
            .iter()
            .any(|kind| kind == "unsupported_policy_custom_guards"));
        assert_eq!(report.attestation_level, AttestationLevel::Heuristic);
    }

    #[test]
    fn plugin_custom_guards_downgrade_attestation_to_heuristic() {
        let mut policy = Policy::default();
        policy
            .guards
            .custom
            .push(clawdstrike::policy::CustomGuardSpec {
                package: "demo-plugin".to_string(),
                registry: None,
                version: None,
                enabled: true,
                config: serde_json::json!({}),
                async_config: None,
            });

        let report = formula_verifier().verify_policy(&policy, agent());
        assert_eq!(report.completeness.outcome, CheckOutcome::Fail);
        assert!(report
            .completeness
            .missing
            .iter()
            .any(|kind| kind == "unsupported_plugin_custom_guards"));
        assert_eq!(report.attestation_level, AttestationLevel::Heuristic);
    }

    #[test]
    fn contradictory_egress_policy_detected() {
        let mut policy = Policy::default();
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

        let report = formula_verifier().verify_policy(&policy, agent());
        assert_eq!(report.consistency.outcome, CheckOutcome::Fail);
    }

    #[test]
    fn mcp_allow_and_block_same_tool_conflict() {
        let mut policy = Policy::default();
        policy.guards.mcp_tool = Some(McpToolConfig {
            enabled: true,
            allow: vec!["shell_exec".to_string()],
            block: vec!["shell_exec".to_string()],
            require_confirmation: vec![],
            default_action: None,
            max_args_size: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        });

        let report = formula_verifier().verify_policy(&policy, agent());
        assert_eq!(report.consistency.outcome, CheckOutcome::Fail);
    }

    #[test]
    fn build_policy_report_preserves_caller_timing() {
        let report = build_policy_report(
            &[Formula::prohibition(
                agent(),
                Formula::atom("access(/etc/shadow)"),
            )],
            None,
            ConsistencyResult {
                outcome: CheckOutcome::Pass,
                conflict_count: 0,
                conflicts: Vec::new(),
            },
            CompletenessResult {
                outcome: CheckOutcome::Pass,
                covered: vec!["access".to_string()],
                missing: Vec::new(),
            },
            VerificationBackend::FormulaInspection,
            37,
        );

        assert_eq!(report.verification_time_ms, 37);
    }

    #[test]
    fn receipt_metadata_uses_honest_backend_fields() {
        let formulas = vec![
            Formula::prohibition(agent(), Formula::atom("access(/etc/shadow)")),
            Formula::permission(agent(), Formula::atom("egress(api.openai.com)")),
        ];
        let report = formula_verifier()
            .with_expected_action_types(vec!["access".to_string(), "egress".to_string()])
            .verify(&formulas, None);
        let receipt = hush_core::receipt::Receipt::new(
            hush_core::hashing::Hash::zero(),
            hush_core::receipt::Verdict::pass(),
        );
        let enriched = enrich_receipt(receipt, &report);
        let metadata = enriched.metadata.expect("verification metadata");

        assert_eq!(metadata["verification"]["backend"], "formula_inspection");
        assert_eq!(metadata["verification"]["checks_passed"], true);
        assert_eq!(metadata["verification"]["consistency"], "pass");
        assert_eq!(metadata["verification"]["completeness"], "pass");
        assert_eq!(metadata["verification"]["inheritance_sound"], "skipped");
        assert_eq!(metadata["verification"]["attestation_level"], 1);
        assert_eq!(
            metadata["verification"]["attestation_level_name"],
            "formula_verified"
        );
    }

    #[test]
    fn metadata_reports_failure_honestly() {
        let formulas = vec![
            Formula::prohibition(agent(), Formula::atom("access(/etc/shadow)")),
            Formula::permission(agent(), Formula::atom("access(/etc/shadow)")),
        ];
        let report = formula_verifier()
            .with_expected_action_types(vec![])
            .verify(&formulas, None);
        let metadata = report.to_receipt_metadata();
        assert_eq!(metadata["verification"]["backend"], "formula_inspection");
        assert_eq!(metadata["verification"]["checks_passed"], false);
        assert_eq!(metadata["verification"]["consistency"], "fail");
        assert_eq!(metadata["verification"]["attestation_level"], 0);
        assert_eq!(
            metadata["verification"]["attestation_level_name"],
            "heuristic"
        );
    }

    #[test]
    fn attestation_level_roundtrip_and_ordering() {
        for level_u8 in 0..=4 {
            let level = AttestationLevel::from_u8(level_u8).unwrap();
            assert_eq!(level.as_u8(), level_u8);
        }
        assert!(AttestationLevel::from_u8(5).is_none());
        assert!(AttestationLevel::Heuristic < AttestationLevel::FormulaVerified);
        assert!(AttestationLevel::FormulaVerified < AttestationLevel::Z3Verified);
        assert!(AttestationLevel::Z3Verified < AttestationLevel::LeanProved);
        assert!(AttestationLevel::LeanProved < AttestationLevel::ImplementationVerified);
    }

    #[test]
    fn attestation_level_names_and_display_are_honest() {
        assert_eq!(AttestationLevel::Heuristic.name(), "heuristic");
        assert_eq!(AttestationLevel::FormulaVerified.name(), "formula_verified");
        assert_eq!(AttestationLevel::Z3Verified.name(), "z3_verified");
        assert_eq!(
            format!("{}", AttestationLevel::FormulaVerified),
            "Level 1 (formula_verified)"
        );
        assert_eq!(
            format!("{}", AttestationLevel::Z3Verified),
            "Level 2 (z3_verified)"
        );
    }

    #[test]
    fn action_kind_roundtrip_still_works() {
        assert_eq!(ActionKind::all().len(), 7);
        assert_eq!(ActionKind::core().len(), 4);
        for kind in ActionKind::all() {
            let prefix = format!("{kind}");
            assert_eq!(ActionKind::from_prefix(&prefix), Some(kind));
        }
        assert_eq!(ActionKind::from_prefix("unknown"), None);
    }

