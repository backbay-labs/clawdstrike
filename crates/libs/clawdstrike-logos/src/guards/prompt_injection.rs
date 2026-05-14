//! Formula translation for [`PromptInjectionConfig`].

use clawdstrike::guards::PromptInjectionConfig;
use clawdstrike::hygiene::PromptInjectionLevel;
use logos_ffi::{AgentId, Formula};

use super::{custom_permission, custom_prohibition, GuardFormulas};

fn level_name(level: PromptInjectionLevel) -> &'static str {
    match level {
        PromptInjectionLevel::Safe => "safe",
        PromptInjectionLevel::Suspicious => "suspicious",
        PromptInjectionLevel::High => "high",
        PromptInjectionLevel::Critical => "critical",
    }
}

impl GuardFormulas for PromptInjectionConfig {
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let mut formulas = vec![custom_permission(agent, "guard:prompt_injection:enabled")];

        formulas.extend(
            [
                PromptInjectionLevel::Safe,
                PromptInjectionLevel::Suspicious,
                PromptInjectionLevel::High,
                PromptInjectionLevel::Critical,
            ]
            .into_iter()
            .filter(|level| level.at_least(self.block_at_or_above))
            .map(|level| {
                custom_prohibition(
                    agent,
                    format!("prompt_injection:level:{}", level_name(level)),
                )
            }),
        );

        formulas
    }
}
