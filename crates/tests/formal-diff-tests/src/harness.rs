//! Differential test harness: structured failure reporting.

use std::fmt;

#[derive(Debug)]
pub struct DiffFailure {
    pub input: String,
    pub spec_output: String,
    pub impl_output: String,
}

impl fmt::Display for DiffFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  Input:     {}", self.input)?;
        writeln!(f, "  Spec:      {}", self.spec_output)?;
        writeln!(f, "  Impl:      {}", self.impl_output)?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct DiffTestResult {
    pub test_name: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub failures: Vec<DiffFailure>,
}

impl DiffTestResult {
    #[must_use]
    pub fn new(test_name: impl Into<String>) -> Self {
        Self {
            test_name: test_name.into(),
            total: 0,
            passed: 0,
            failed: 0,
            failures: Vec::new(),
        }
    }

    pub fn record_pass(&mut self) {
        self.total += 1;
        self.passed += 1;
    }

    pub fn record_fail(&mut self, input: String, spec_output: String, impl_output: String) {
        self.total += 1;
        self.failed += 1;
        self.failures.push(DiffFailure {
            input,
            spec_output,
            impl_output,
        });
    }

    pub fn assert_all_passed(&self) {
        if self.failed > 0 {
            let mut msg = format!(
                "Differential test '{}' FAILED: {}/{} cases\n",
                self.test_name, self.failed, self.total
            );
            for (i, f) in self.failures.iter().enumerate() {
                msg.push_str(&format!("Failure #{}:\n{}\n", i + 1, f));
            }
            panic!("{}", msg);
        }
    }
}

use crate::spec::{CycleCheckSpec, SpecSeverity, SpecVerdict};
use clawdstrike::core::{CoreSeverity, CoreVerdict, CycleCheckResult};

#[must_use]
pub fn core_sev_to_spec(s: CoreSeverity) -> SpecSeverity {
    match s {
        CoreSeverity::Info => SpecSeverity::Info,
        CoreSeverity::Warning => SpecSeverity::Warning,
        CoreSeverity::Error => SpecSeverity::Error,
        CoreSeverity::Critical => SpecSeverity::Critical,
    }
}

#[must_use]
pub fn spec_sev_to_core(s: SpecSeverity) -> CoreSeverity {
    match s {
        SpecSeverity::Info => CoreSeverity::Info,
        SpecSeverity::Warning => CoreSeverity::Warning,
        SpecSeverity::Error => CoreSeverity::Error,
        SpecSeverity::Critical => CoreSeverity::Critical,
    }
}

#[must_use]
pub fn verdicts_match(spec: &SpecVerdict, core: &CoreVerdict) -> bool {
    spec.allowed == core.allowed
        && core_sev_to_spec(core.severity) == spec.severity
        && spec.sanitized == core.sanitized
}

#[must_use]
pub fn cycle_results_match(spec: &CycleCheckSpec, core: &CycleCheckResult) -> bool {
    match (spec, core) {
        (CycleCheckSpec::Ok, CycleCheckResult::Ok) => true,
        (
            CycleCheckSpec::DepthExceeded {
                depth: sd,
                limit: sl,
            },
            CycleCheckResult::DepthExceeded {
                depth: cd,
                limit: cl,
            },
        ) => sd == cd && sl == cl,
        (
            CycleCheckSpec::CycleDetected { key: sk },
            CycleCheckResult::CycleDetected { key: ck },
        ) => sk == ck,
        _ => false,
    }
}
