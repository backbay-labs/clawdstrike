//! Formula classification and atom-analysis helpers for the verifier.
//!
//! Extracted from `verifier_core.rs`. Holds the `pub(crate)` free functions
//! that derive expected action types from a policy, collect and classify atoms
//! from compiled Logos formulas, and (behind the `z3` feature) translate Z3
//! counterexamples into completeness/consistency hints. None of these are
//! methods on [`PolicyVerifier`]; they are shared by the verifier core, the
//! report builders, and the tests via the re-exports in `verifier.rs`.

use super::*;

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
