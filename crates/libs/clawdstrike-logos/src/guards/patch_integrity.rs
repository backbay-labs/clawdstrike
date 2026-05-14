//! Formula translation for [`PatchIntegrityConfig`].

use clawdstrike::guards::PatchIntegrityConfig;
use logos_ffi::{AgentId, Formula};

use super::{custom_permission, custom_prohibition, GuardFormulas};

fn hashed_detail(prefix: &str, value: &str) -> String {
    format!(
        "{prefix}:{}",
        hush_core::hashing::sha256(value.as_bytes()).to_hex()
    )
}

impl GuardFormulas for PatchIntegrityConfig {
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let mut formulas = vec![
            custom_permission(agent, "guard:patch_integrity:enabled"),
            custom_prohibition(
                agent,
                format!("patch_integrity:additions_exceeded:{}", self.max_additions),
            ),
            custom_prohibition(
                agent,
                format!("patch_integrity:deletions_exceeded:{}", self.max_deletions),
            ),
        ];

        if self.require_balance {
            formulas.push(custom_prohibition(
                agent,
                format!(
                    "patch_integrity:imbalance_exceeded:{:.3}",
                    self.max_imbalance_ratio
                ),
            ));
        }

        formulas.extend(self.forbidden_patterns.iter().map(|pattern| {
            custom_prohibition(
                agent,
                hashed_detail("patch_integrity:forbidden_pattern", pattern),
            )
        }));

        formulas
    }
}
