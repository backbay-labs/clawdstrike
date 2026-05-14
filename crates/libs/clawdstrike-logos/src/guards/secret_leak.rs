//! Formula translation for [`SecretLeakConfig`].

use clawdstrike::guards::{SecretLeakConfig, Severity};
use logos_ffi::{AgentId, Formula};

use super::{custom_permission, custom_prohibition, stable_token, GuardFormulas};

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
        Severity::Critical => 3,
    }
}

impl GuardFormulas for SecretLeakConfig {
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let mut formulas = vec![custom_permission(agent, "guard:secret_leak:enabled")];

        formulas.extend(
            self.effective_patterns()
                .into_iter()
                .filter(|pattern| {
                    severity_rank(&pattern.severity) >= severity_rank(&self.severity_threshold)
                })
                .flat_map(|pattern| {
                    let pattern_token = stable_token(&pattern.name);
                    [
                        custom_prohibition(
                            agent,
                            format!("secret_leak:file_write:{pattern_token}"),
                        ),
                        custom_prohibition(agent, format!("secret_leak:patch:{pattern_token}")),
                    ]
                }),
        );

        formulas
    }
}
