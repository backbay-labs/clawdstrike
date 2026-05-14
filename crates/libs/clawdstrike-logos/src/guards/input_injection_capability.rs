//! Formula translation for [`InputInjectionCapabilityConfig`].

use clawdstrike::guards::InputInjectionCapabilityConfig;
use logos_ffi::{AgentId, Formula};

use super::{custom_permission, custom_prohibition, stable_token, GuardFormulas};

impl GuardFormulas for InputInjectionCapabilityConfig {
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let mut formulas = vec![custom_permission(
            agent,
            "guard:input_injection_capability:enabled",
        )];

        formulas.extend(self.allowed_input_types.iter().map(|input_type| {
            custom_permission(
                agent,
                format!("input_injection:input_type:{}", stable_token(input_type)),
            )
        }));

        if self.require_postcondition_probe {
            formulas.push(custom_prohibition(
                agent,
                "input_injection:missing_postcondition_probe",
            ));
        }

        formulas
    }
}
