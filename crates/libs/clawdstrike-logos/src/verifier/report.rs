//! Verification report DTOs, attestation levels, and report builders.
//!
//! Extracted from `verifier.rs`. The report type model (backend, attestation
//! level, per-check results, and the aggregate [`VerificationReport`]) plus the
//! free report-construction helpers used by the verifier core.

use super::*;

/// Verification engine used for the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationBackend {
    FormulaInspection,
    Z3,
}

impl VerificationBackend {
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::FormulaInspection => "formula_inspection",
            Self::Z3 => "z3",
        }
    }
}

impl std::fmt::Display for VerificationBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// Verification depth tier for receipt attestation.
///
/// Each level subsumes the guarantees of all lower levels. The level in a
/// receipt represents the *minimum* of all applicable verification results.
///
/// | Level | Name | Meaning |
/// |-------|------|---------|
/// | 0 | Heuristic | Guards evaluated, no static verification |
/// | 1 | Formula-Verified | Static formula / policy inspection passed |
/// | 2 | Z3-Verified | Z3-backed checks confirmed the policy |
/// | 3 | Lean-Proved | Policy properties proved in Lean 4 reference spec |
/// | 4 | Implementation-Verified | Rust implementation verified via Aeneas |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationLevel {
    /// Level 0: Heuristic guards only (current default).
    Heuristic = 0,
    /// Level 1: Static formula and policy checks passed.
    FormulaVerified = 1,
    /// Level 2: Z3-backed checks passed.
    Z3Verified = 2,
    /// Level 3: Lean-proved policy properties.
    LeanProved = 3,
    /// Level 4: Implementation verified via Aeneas translation.
    ImplementationVerified = 4,
}

impl AttestationLevel {
    #[must_use]
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Heuristic => "heuristic",
            Self::FormulaVerified => "formula_verified",
            Self::Z3Verified => "z3_verified",
            Self::LeanProved => "lean_proved",
            Self::ImplementationVerified => "implementation_verified",
        }
    }

    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Heuristic),
            1 => Some(Self::FormulaVerified),
            2 => Some(Self::Z3Verified),
            3 => Some(Self::LeanProved),
            4 => Some(Self::ImplementationVerified),
            _ => None,
        }
    }
}

impl std::fmt::Display for AttestationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Level {} ({})", self.as_u8(), self.name())
    }
}

/// Outcome of a single verification property check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckOutcome {
    Pass,
    Fail,
    Skipped,
}

impl CheckOutcome {
    #[must_use]
    pub fn is_pass(&self) -> bool {
        *self == Self::Pass
    }
}

impl std::fmt::Display for CheckOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pass => f.write_str("pass"),
            Self::Fail => f.write_str("fail"),
            Self::Skipped => f.write_str("skipped"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Conflict {
    pub atom: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConsistencyResult {
    pub outcome: CheckOutcome,
    pub conflict_count: usize,
    pub conflicts: Vec<Conflict>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CompletenessResult {
    pub outcome: CheckOutcome,
    pub covered: Vec<String>,
    pub missing: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WeakenedProhibition {
    pub atom: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InheritanceResult {
    pub outcome: CheckOutcome,
    pub weakened: Vec<WeakenedProhibition>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VerificationReport {
    pub backend: VerificationBackend,
    pub formula_count: usize,
    pub atom_count: usize,
    pub consistency: ConsistencyResult,
    pub completeness: CompletenessResult,
    pub inheritance: InheritanceResult,
    pub verification_time_ms: u64,
    pub properties_checked: Vec<String>,
    pub attestation_level: AttestationLevel,
}

impl VerificationReport {
    #[must_use]
    pub fn all_pass(&self) -> bool {
        (self.consistency.outcome.is_pass() || self.consistency.outcome == CheckOutcome::Skipped)
            && (self.completeness.outcome.is_pass()
                || self.completeness.outcome == CheckOutcome::Skipped)
            && (self.inheritance.outcome.is_pass()
                || self.inheritance.outcome == CheckOutcome::Skipped)
    }

    /// JSON value suitable for [`hush_core::receipt::Receipt::merge_metadata`].
    #[must_use]
    pub fn to_receipt_metadata(&self) -> serde_json::Value {
        serde_json::json!({
            "verification": {
                "backend": self.backend.name(),
                "attestation_level": self.attestation_level.as_u8(),
                "attestation_level_name": self.attestation_level.name(),
                "checks_passed": self.all_pass(),
                "consistency": self.consistency.outcome.to_string(),
                "completeness": self.completeness.outcome.to_string(),
                "inheritance_sound": self.inheritance.outcome.to_string(),
                "verification_time_ms": self.verification_time_ms,
                "formula_count": self.formula_count,
                "atom_count": self.atom_count,
                "properties_checked": self.properties_checked,
            }
        })
    }
}

/// The set of action types expected for a completeness check.
///
/// By default this contains the four "core" action types that every non-trivial
/// policy should cover: `access`, `egress`, `exec`, and `mcp`.
pub static DEFAULT_EXPECTED_ACTION_TYPES: &[&str] = &["access", "egress", "exec", "mcp"];

pub(crate) fn compute_attestation_level(
    backend: VerificationBackend,
    consistency: &ConsistencyResult,
    completeness: &CompletenessResult,
    inheritance: &InheritanceResult,
) -> AttestationLevel {
    let checks_pass =
        |outcome: &CheckOutcome| matches!(outcome, CheckOutcome::Pass | CheckOutcome::Skipped);

    if checks_pass(&consistency.outcome)
        && checks_pass(&completeness.outcome)
        && checks_pass(&inheritance.outcome)
    {
        match backend {
            VerificationBackend::FormulaInspection => AttestationLevel::FormulaVerified,
            VerificationBackend::Z3 => AttestationLevel::Z3Verified,
        }
    } else {
        AttestationLevel::Heuristic
    }
}

pub(crate) fn build_policy_report(
    formulas: &[Formula],
    inheritance: Option<InheritanceResult>,
    consistency: ConsistencyResult,
    completeness: CompletenessResult,
    backend: VerificationBackend,
    verification_time_ms: u64,
) -> VerificationReport {
    let atoms = collect_atoms(formulas);
    let atom_count = atoms.len();
    let inheritance = inheritance.unwrap_or(InheritanceResult {
        outcome: CheckOutcome::Skipped,
        weakened: Vec::new(),
    });

    let mut properties_checked = vec!["consistency".to_string(), "completeness".to_string()];
    if inheritance.outcome != CheckOutcome::Skipped {
        properties_checked.push("inheritance".to_string());
    }

    let attestation_level =
        compute_attestation_level(backend, &consistency, &completeness, &inheritance);

    VerificationReport {
        backend,
        formula_count: formulas.len(),
        atom_count,
        consistency,
        completeness,
        inheritance,
        verification_time_ms,
        properties_checked,
        attestation_level,
    }
}

pub(crate) fn report_backend(
    consistency_z3: bool,
    completeness_z3: bool,
    inheritance_z3: Option<bool>,
) -> VerificationBackend {
    if consistency_z3 && completeness_z3 && inheritance_z3.unwrap_or(true) {
        VerificationBackend::Z3
    } else {
        VerificationBackend::FormulaInspection
    }
}
