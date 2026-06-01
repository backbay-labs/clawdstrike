//! The [`PolicyVerifier`] and its formula/atom analysis helpers.
//!
//! Extracted from `verifier.rs`. Holds the verifier struct and its consistency,
//! completeness, and inheritance entry points, plus atom collection, formula
//! classification, expected-action-type derivation, and the optional Z3
//! counterexample helpers (all gated behind the `z3` feature).

use super::*;

/// Policy verifier that operates on compiled Logos formulas.
///
/// The verifier performs static formula inspection by default and can be
/// constructed with a Z3 backend when the `z3` feature is enabled.
pub struct PolicyVerifier {
    /// Action types that must have at least one formula for completeness.
    expected_action_types: Vec<String>,
    backend: VerificationBackend,
    #[cfg(feature = "z3")]
    z3_checker: Option<Z3Checker>,
}

impl Default for PolicyVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyVerifier {
    /// Create a verifier with the default expected action types.
    #[must_use]
    pub fn new() -> Self {
        Self {
            expected_action_types: DEFAULT_EXPECTED_ACTION_TYPES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            backend: VerificationBackend::FormulaInspection,
            #[cfg(feature = "z3")]
            z3_checker: None,
        }
    }

    #[must_use]
    pub fn with_expected_action_types(mut self, types: Vec<String>) -> Self {
        self.expected_action_types = types;
        self
    }

    #[must_use]
    pub fn backend(&self) -> VerificationBackend {
        self.backend
    }

    pub fn verify(
        &self,
        formulas: &[Formula],
        _base_formulas: Option<&[Formula]>,
    ) -> VerificationReport {
        let start = Instant::now();

        let atoms = collect_atoms(formulas);
        let atom_count = atoms.len();

        let (consistency, consistency_z3) = self.check_consistency_internal(formulas);
        let (completeness, completeness_z3) =
            self.check_completeness_for_expected(formulas, &self.expected_action_types);
        let inheritance = InheritanceResult {
            outcome: CheckOutcome::Skipped,
            weakened: Vec::new(),
        };

        let properties_checked = vec!["consistency".to_string(), "completeness".to_string()];

        let elapsed = start.elapsed();

        let backend = report_backend(consistency_z3, completeness_z3, None);
        let attestation_level =
            compute_attestation_level(backend, &consistency, &completeness, &inheritance);

        VerificationReport {
            backend,
            formula_count: formulas.len(),
            atom_count,
            consistency,
            completeness,
            inheritance,
            verification_time_ms: elapsed.as_millis() as u64,
            properties_checked,
            attestation_level,
        }
    }

    /// Create a verifier that delegates to the Z3 SMT solver when available.
    #[cfg(feature = "z3")]
    #[must_use]
    pub fn with_z3() -> Self {
        Self {
            expected_action_types: DEFAULT_EXPECTED_ACTION_TYPES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            backend: VerificationBackend::Z3,
            z3_checker: Some(Z3Checker::new()),
        }
    }

    pub fn verify_policy(&self, policy: &Policy, agent: AgentId) -> VerificationReport {
        let start = Instant::now();
        let compiler = DefaultPolicyCompiler::new(agent);
        let formulas = compiler.compile_policy(policy);
        let (consistency, consistency_z3) = self.check_consistency_internal(&formulas);
        let expected = expected_action_types_for_policy(policy);
        let (completeness, completeness_z3) =
            self.check_completeness_for_expected(&formulas, &expected);
        let backend = report_backend(consistency_z3, completeness_z3, None);

        build_policy_report(
            &formulas,
            None,
            consistency,
            completeness,
            backend,
            start.elapsed().as_millis() as u64,
        )
    }

    pub fn verify_policy_with_parent(
        &self,
        parent: &Policy,
        effective: &Policy,
        agent: AgentId,
    ) -> VerificationReport {
        let start = Instant::now();
        let compiler = DefaultPolicyCompiler::new(agent);
        let parent_formulas = compiler.compile_policy(parent);
        let effective_formulas = compiler.compile_policy(effective);
        let (consistency, consistency_z3) = self.check_consistency_internal(&effective_formulas);
        let expected = expected_action_types_for_policy(effective);
        let (completeness, completeness_z3) =
            self.check_completeness_for_expected(&effective_formulas, &expected);
        let (inheritance, inheritance_z3) =
            self.check_policy_inheritance(parent, effective, &parent_formulas, &effective_formulas);
        let backend = report_backend(consistency_z3, completeness_z3, Some(inheritance_z3));

        build_policy_report(
            &effective_formulas,
            Some(inheritance),
            consistency,
            completeness,
            backend,
            start.elapsed().as_millis() as u64,
        )
    }

    pub fn verify_policy_with_parent_and_source(
        &self,
        parent: &Policy,
        child: &Policy,
        effective: &Policy,
        agent: AgentId,
    ) -> VerificationReport {
        let start = Instant::now();
        let compiler = DefaultPolicyCompiler::new(agent);
        let parent_formulas = compiler.compile_policy(parent);
        let effective_formulas = compiler.compile_policy(effective);
        let (consistency, consistency_z3) = self.check_consistency_internal(&effective_formulas);
        let expected = expected_action_types_for_policy(effective);
        let (completeness, completeness_z3) =
            self.check_completeness_for_expected(&effective_formulas, &expected);
        let inherited = parent.merge(child);
        let inherited_formulas = compiler.compile_policy(&inherited);
        let (inheritance, inheritance_z3) = self.check_policy_inheritance(
            parent,
            &inherited,
            &parent_formulas,
            &inherited_formulas,
        );
        let backend = report_backend(consistency_z3, completeness_z3, Some(inheritance_z3));

        build_policy_report(
            &effective_formulas,
            Some(inheritance),
            consistency,
            completeness,
            backend,
            start.elapsed().as_millis() as u64,
        )
    }

    pub fn check_consistency(&self, formulas: &[Formula]) -> ConsistencyResult {
        self.check_consistency_internal(formulas).0
    }

    pub fn check_completeness(&self, formulas: &[Formula]) -> CompletenessResult {
        self.check_completeness_for_expected(formulas, &self.expected_action_types)
            .0
    }

    fn check_consistency_internal(&self, formulas: &[Formula]) -> (ConsistencyResult, bool) {
        let mut permitted: HashSet<String> = HashSet::new();
        let mut prohibited: HashSet<String> = HashSet::new();
        let mut obligated: HashSet<String> = HashSet::new();

        for formula in formulas {
            classify_formula(formula, &mut permitted, &mut prohibited, &mut obligated);
        }

        let mut conflicts: Vec<Conflict> = permitted
            .intersection(&prohibited)
            .chain(obligated.intersection(&prohibited))
            .map(|atom| Conflict { atom: atom.clone() })
            .collect();
        conflicts.sort_by(|a, b| a.atom.cmp(&b.atom));
        conflicts.dedup_by(|a, b| a.atom == b.atom);

        #[allow(unused_mut)]
        let mut inspected = ConsistencyResult {
            outcome: if conflicts.is_empty() {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail
            },
            conflict_count: conflicts.len(),
            conflicts,
        };

        #[cfg(feature = "z3")]
        if let Some(z3_checker) = self.z3_checker.as_ref() {
            let overlapping_atoms: Vec<String> = permitted
                .intersection(&prohibited)
                .chain(obligated.intersection(&prohibited))
                .cloned()
                .collect();
            let candidate_groups = consistency_candidate_groups(formulas, &overlapping_atoms);
            let groups = if candidate_groups.is_empty() {
                vec![Vec::new()]
            } else {
                candidate_groups
            };

            for group in groups {
                match z3_checker.check_consistency(&group) {
                    ProofResult::Valid(_) => {}
                    ProofResult::Invalid(counterexample) => {
                        if inspected.conflicts.is_empty() {
                            inspected.conflicts.push(Conflict {
                                atom: render_counterexample_hint(&counterexample.model_description),
                            });
                            inspected.conflict_count = inspected.conflicts.len();
                        }
                        inspected.outcome = CheckOutcome::Fail;
                        return (inspected, true);
                    }
                    ProofResult::Unknown { .. } | ProofResult::Timeout { .. } => {
                        return (inspected, false);
                    }
                }
            }

            return (inspected, true);
        }

        (inspected, false)
    }

    fn check_completeness_for_expected(
        &self,
        formulas: &[Formula],
        expected_action_types: &[String],
    ) -> (CompletenessResult, bool) {
        let atoms = collect_atoms(formulas);

        let covered_types: HashSet<String> = atoms
            .iter()
            .filter_map(|atom| atom_action_type(atom).map(String::from))
            .collect();

        let mut covered = Vec::new();
        let mut missing = Vec::new();

        for expected in expected_action_types {
            if covered_types.contains(expected.as_str()) {
                covered.push(expected.clone());
            } else {
                missing.push(expected.clone());
            }
        }

        let inspected = CompletenessResult {
            outcome: if missing.is_empty() {
                CheckOutcome::Pass
            } else {
                CheckOutcome::Fail
            },
            covered,
            missing,
        };

        #[cfg(feature = "z3")]
        if let Some(z3_checker) = self.z3_checker.as_ref() {
            let expected_atoms =
                representative_atoms_for_expected_types(&atoms, expected_action_types);
            return match z3_checker.check_completeness(formulas, &expected_atoms) {
                ProofResult::Valid(_) => (inspected, true),
                ProofResult::Invalid(counterexample) => (
                    completeness_result_from_z3_counterexample(
                        inspected,
                        &counterexample,
                        expected_action_types,
                    ),
                    true,
                ),
                ProofResult::Unknown { .. } | ProofResult::Timeout { .. } => (inspected, false),
            };
        }

        (inspected, false)
    }

    fn check_policy_inheritance(
        &self,
        parent_policy: &Policy,
        effective_policy: &Policy,
        _parent_formulas: &[Formula],
        _effective_formulas: &[Formula],
    ) -> (InheritanceResult, bool) {
        #[allow(unused_mut)]
        let mut inspected =
            inspect_policy_inheritance_against_parent(effective_policy, parent_policy);

        #[cfg(feature = "z3")]
        if let Some(z3_checker) = self.z3_checker.as_ref() {
            return match z3_checker
                .check_inheritance_soundness(_parent_formulas, _effective_formulas)
            {
                ProofResult::Valid(_) => (inspected, true),
                ProofResult::Invalid(counterexample) => {
                    if inspected.outcome == CheckOutcome::Pass {
                        inspected.outcome = CheckOutcome::Fail;
                    }
                    let hint = render_counterexample_hint(&counterexample.model_description);
                    if !inspected.weakened.iter().any(|item| item.atom == hint) {
                        inspected.weakened.push(WeakenedProhibition { atom: hint });
                    }
                    (inspected, true)
                }
                ProofResult::Unknown { .. } | ProofResult::Timeout { .. } => (inspected, false),
            };
        }

        (inspected, false)
    }
}


pub(crate) fn expected_action_types_for_policy(policy: &Policy) -> Vec<String> {
    let mut expected = BTreeSet::new();

    if let Some(cfg) = policy
        .guards
        .forbidden_path
        .as_ref()
        .filter(|cfg| cfg.enabled)
    {
        if !cfg.effective_patterns().is_empty() || !cfg.exceptions.is_empty() {
            expected.insert("access".to_string());
        }
    }

    if let Some(cfg) = policy
        .guards
        .path_allowlist
        .as_ref()
        .filter(|cfg| cfg.enabled)
    {
        if !cfg.file_access_allow.is_empty() {
            expected.insert("access".to_string());
        }
        if !cfg.file_write_allow.is_empty() {
            expected.insert("write".to_string());
        }
        if !cfg.patch_allow.is_empty() {
            expected.insert("patch".to_string());
        }
    }

    if policy
        .guards
        .egress_allowlist
        .as_ref()
        .is_some_and(|cfg| cfg.enabled)
    {
        expected.insert("egress".to_string());
    }

    if policy.guards.shell_command.as_ref().is_some_and(|cfg| {
        cfg.enabled
            && (!cfg.forbidden_patterns.is_empty()
                || shell_command_uses_forbidden_path_enforcement(policy))
    }) {
        expected.insert("exec".to_string());
    }

    if policy
        .guards
        .mcp_tool
        .as_ref()
        .is_some_and(|cfg| cfg.enabled)
    {
        expected.insert("mcp".to_string());
    }

    if policy_has_custom_runtime_guard_formulas(policy) {
        expected.insert("custom".to_string());
    }

    if policy.custom_guards.iter().any(|guard| guard.enabled) {
        expected.insert("unsupported_policy_custom_guards".to_string());
    }

    if policy.guards.custom.iter().any(|guard| guard.enabled) {
        expected.insert("unsupported_plugin_custom_guards".to_string());
    }

    expected.into_iter().collect()
}

pub(crate) fn collect_atoms(formulas: &[Formula]) -> BTreeSet<String> {
    let mut atoms = BTreeSet::new();
    for formula in formulas {
        collect_atoms_recursive(formula, &mut atoms);
    }
    atoms
}

pub(crate) fn policy_has_custom_runtime_guard_formulas(policy: &Policy) -> bool {
    policy
        .guards
        .secret_leak
        .as_ref()
        .is_some_and(|cfg| cfg.enabled)
        || policy
            .guards
            .patch_integrity
            .as_ref()
            .is_some_and(|cfg| cfg.enabled)
        || policy
            .guards
            .prompt_injection
            .as_ref()
            .is_some_and(|cfg| cfg.enabled)
        || policy
            .guards
            .jailbreak
            .as_ref()
            .is_some_and(|cfg| cfg.enabled)
        || policy
            .guards
            .computer_use
            .as_ref()
            .is_some_and(|cfg| cfg.enabled)
        || policy
            .guards
            .remote_desktop_side_channel
            .as_ref()
            .is_some_and(|cfg| cfg.enabled)
        || policy
            .guards
            .input_injection_capability
            .as_ref()
            .is_some_and(|cfg| cfg.enabled)
}

pub(crate) fn shell_command_uses_forbidden_path_enforcement(policy: &Policy) -> bool {
    let Some(shell) = policy.guards.shell_command.as_ref() else {
        return false;
    };
    if !shell.enabled || !shell.enforce_forbidden_paths {
        return false;
    }

    let forbidden_path = policy.guards.forbidden_path.clone().unwrap_or_default();
    forbidden_path.enabled && !forbidden_path.effective_patterns().is_empty()
}

pub(crate) fn collect_atoms_recursive(formula: &Formula, atoms: &mut BTreeSet<String>) {
    match formula {
        Formula::Atom(name) => {
            atoms.insert(name.clone());
        }
        Formula::Not(inner)
        | Formula::Necessity(inner)
        | Formula::Possibility(inner)
        | Formula::AlwaysFuture(inner)
        | Formula::Eventually(inner)
        | Formula::AlwaysPast(inner)
        | Formula::SometimePast(inner)
        | Formula::Perpetual(inner)
        | Formula::Sometimes(inner)
        | Formula::EpistemicPossibility(inner)
        | Formula::EpistemicNecessity(inner)
        | Formula::Obligation(_, inner)
        | Formula::Permission(_, inner)
        | Formula::Prohibition(_, inner)
        | Formula::Belief(_, inner)
        | Formula::Knowledge(_, inner) => {
            collect_atoms_recursive(inner, atoms);
        }
        Formula::ProbabilityAtLeast(inner, _) => {
            collect_atoms_recursive(inner, atoms);
        }
        Formula::And(l, r)
        | Formula::Or(l, r)
        | Formula::Implies(l, r)
        | Formula::Iff(l, r)
        | Formula::WouldCounterfactual(l, r)
        | Formula::MightCounterfactual(l, r)
        | Formula::Grounding(l, r)
        | Formula::Essence(l, r)
        | Formula::PropIdentity(l, r)
        | Formula::Causation(l, r)
        | Formula::IndicativeConditional(l, r)
        | Formula::Preference(l, r) => {
            collect_atoms_recursive(l, atoms);
            collect_atoms_recursive(r, atoms);
        }
        Formula::AgentPreference(_, l, r) => {
            collect_atoms_recursive(l, atoms);
            collect_atoms_recursive(r, atoms);
        }
        Formula::Top | Formula::Bottom => {}
    }
}

pub(crate) fn classify_formula(
    formula: &Formula,
    permitted: &mut HashSet<String>,
    prohibited: &mut HashSet<String>,
    obligated: &mut HashSet<String>,
) {
    match formula {
        Formula::Permission(_, inner) => {
            let atom = extract_atom_string(inner);
            if let Some(name) = atom {
                permitted.insert(name);
            }
        }
        Formula::Prohibition(_, inner) => {
            let atom = extract_atom_string(inner);
            if let Some(name) = atom {
                prohibited.insert(name);
            }
        }
        Formula::Obligation(_, inner) => {
            let atom = extract_atom_string(inner);
            if let Some(name) = atom {
                obligated.insert(name);
            }
        }
        _ => {}
    }
}

pub(crate) fn extract_atom_string(formula: &Formula) -> Option<String> {
    match formula {
        Formula::Atom(name) => Some(name.clone()),
        _ => None,
    }
}

pub(crate) fn atom_action_type(atom: &str) -> Option<&str> {
    atom.split('(').next()
}

#[cfg(feature = "z3")]
pub(crate) fn completeness_result_from_z3_counterexample(
    mut inspected: CompletenessResult,
    counterexample: &logos_ffi::Counterexample,
    expected_action_types: &[String],
) -> CompletenessResult {
    let mut missing: BTreeSet<String> = inspected.missing.iter().cloned().collect();

    for assignment in &counterexample.state_assignments {
        if assignment.value {
            continue;
        }
        if let Some(action_type) = atom_action_type(&assignment.atom) {
            if expected_action_types
                .iter()
                .any(|expected| expected == action_type)
            {
                missing.insert(action_type.to_string());
            }
        }
    }

    inspected.covered.retain(|kind| !missing.contains(kind));
    inspected.missing = missing.into_iter().collect();
    inspected.outcome = CheckOutcome::Fail;
    inspected
}

#[cfg(feature = "z3")]
pub(crate) fn representative_atoms_for_expected_types(
    atoms: &BTreeSet<String>,
    expected_action_types: &[String],
) -> Vec<String> {
    expected_action_types
        .iter()
        .map(|expected| {
            atoms
                .iter()
                .find(|atom| atom_action_type(atom).is_some_and(|kind| kind == expected))
                .cloned()
                .unwrap_or_else(|| format!("{expected}(__missing__)"))
        })
        .collect()
}

#[cfg(feature = "z3")]
pub(crate) fn render_counterexample_hint(description: &str) -> String {
    description.trim().to_string()
}

#[cfg(feature = "z3")]
pub(crate) fn consistency_candidate_groups(
    formulas: &[Formula],
    overlapping_atoms: &[String],
) -> Vec<Vec<Formula>> {
    let overlapping_atoms: BTreeSet<&str> = overlapping_atoms.iter().map(String::as_str).collect();
    let mut grouped = std::collections::BTreeMap::<String, Vec<Formula>>::new();

    for formula in formulas {
        if let Some(atom) = normative_formula_atom(formula) {
            if overlapping_atoms.contains(atom.as_str()) {
                grouped.entry(atom).or_default().push(formula.clone());
            }
        }
    }

    grouped.into_values().collect()
}

#[cfg(feature = "z3")]
pub(crate) fn normative_formula_atom(formula: &Formula) -> Option<String> {
    match formula {
        Formula::Permission(_, inner)
        | Formula::Prohibition(_, inner)
        | Formula::Obligation(_, inner) => extract_atom_string(inner),
        _ => None,
    }
}

