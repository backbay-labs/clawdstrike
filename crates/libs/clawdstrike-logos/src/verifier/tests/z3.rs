// Z3-backed verification tests (only compiled with --features z3).
//
// Included into `verifier::tests` via `include!` from tests/mod.rs, so these
// bodies share that module's imports and fixtures unchanged.
    #[cfg(feature = "z3")]
    #[test]
    fn z3_completeness_counterexample_marks_report_failed() {
        let inspected = CompletenessResult {
            outcome: CheckOutcome::Pass,
            covered: vec!["access".to_string()],
            missing: Vec::new(),
        };
        let counterexample = logos_ffi::Counterexample::simple(
            Formula::Top,
            vec![logos_ffi::StateAssignment {
                atom: "access(__missing__)".to_string(),
                world: None,
                time: None,
                value: false,
            }],
        );

        let result = completeness_result_from_z3_counterexample(
            inspected,
            &counterexample,
            &["access".to_string()],
        );

        assert_eq!(result.outcome, CheckOutcome::Fail);
        assert_eq!(result.missing, vec!["access".to_string()]);
        assert!(result.covered.is_empty());
    }

    #[cfg(feature = "z3")]
    #[test]
    fn z3_verifier_reports_real_z3_backend() {
        let mut policy = Policy::default();
        policy.guards.forbidden_path = Some(simple_forbidden_path("/etc/shadow"));
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

        let report = PolicyVerifier::with_z3().verify_policy(&policy, agent());
        assert_eq!(report.backend, VerificationBackend::Z3);
        assert_eq!(report.attestation_level, AttestationLevel::Z3Verified);
        assert!(report.all_pass());
    }
