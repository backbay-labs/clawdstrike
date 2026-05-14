//! Formula translation for [`ComputerUseConfig`].

use clawdstrike::guards::{ComputerUseConfig, ComputerUseMode};
use logos_ffi::{AgentId, Formula};

use super::{custom_permission, custom_prohibition, stable_token, GuardFormulas};

fn mode_name(mode: &ComputerUseMode) -> &'static str {
    match mode {
        ComputerUseMode::Observe => "observe",
        ComputerUseMode::Guardrail => "guardrail",
        ComputerUseMode::FailClosed => "fail_closed",
    }
}

impl GuardFormulas for ComputerUseConfig {
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let mut formulas = vec![
            custom_permission(agent, "guard:computer_use:enabled"),
            custom_permission(
                agent,
                format!("computer_use:mode:{}", mode_name(&self.mode)),
            ),
        ];

        formulas.extend(self.allowed_actions.iter().map(|action| {
            custom_permission(
                agent,
                format!("computer_use:action:{}", stable_token(action)),
            )
        }));

        if matches!(self.mode, ComputerUseMode::FailClosed) {
            formulas.push(custom_prohibition(agent, "computer_use:action:*"));
        }

        formulas
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent() -> AgentId {
        AgentId::new("test-agent")
    }

    #[test]
    fn fail_closed_mode_emits_custom_formulas() {
        let cfg = ComputerUseConfig {
            enabled: true,
            allowed_actions: vec!["remote.clipboard".to_string()],
            mode: ComputerUseMode::FailClosed,
        };

        let rendered: Vec<String> = cfg
            .to_formulas(&test_agent())
            .into_iter()
            .map(|formula| formula.to_string())
            .collect();

        assert!(rendered
            .iter()
            .any(|formula| formula == "P_test-agent(custom(guard:computer_use:enabled))"));
        assert!(rendered
            .iter()
            .any(|formula| formula == "F_test-agent(custom(computer_use:action:*))"));
    }
}
