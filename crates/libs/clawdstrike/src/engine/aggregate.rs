//! Verdict aggregation: thin passthrough to the formally-verified
//! `crate::core::aggregate` decision logic.

use crate::guards::{GuardResult, Severity};

pub(super) fn severity_to_core(s: &Severity) -> crate::core::CoreSeverity {
    match s {
        Severity::Info => crate::core::CoreSeverity::Info,
        Severity::Warning => crate::core::CoreSeverity::Warning,
        Severity::Error => crate::core::CoreSeverity::Error,
        Severity::Critical => crate::core::CoreSeverity::Critical,
    }
}

pub(crate) fn aggregate_overall(results: &[GuardResult]) -> GuardResult {
    let tuples: Vec<(bool, crate::core::CoreSeverity, bool)> = results
        .iter()
        .map(|r| (r.allowed, severity_to_core(&r.severity), r.is_sanitized()))
        .collect();

    match crate::core::aggregate::aggregate_index(&tuples) {
        Some(idx) => results[idx].clone(),
        None => GuardResult::allow("engine"),
    }
}
