//! Formula translation for [`JailbreakConfig`].

use clawdstrike::guards::JailbreakConfig;
use logos_ffi::{AgentId, Formula};

use super::{custom_permission, custom_prohibition, GuardFormulas};

impl GuardFormulas for JailbreakConfig {
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        vec![
            custom_permission(agent, "guard:jailbreak:enabled"),
            custom_prohibition(
                agent,
                format!(
                    "jailbreak:risk_score_at_or_above:{}",
                    self.detector.block_threshold
                ),
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent() -> AgentId {
        AgentId::new("test-agent")
    }

    #[test]
    fn emits_single_threshold_prohibition() {
        let cfg = JailbreakConfig::default();
        let rendered: Vec<String> = cfg
            .to_formulas(&test_agent())
            .into_iter()
            .map(|formula| formula.to_string())
            .collect();

        assert_eq!(rendered.len(), 2);
        assert!(rendered
            .iter()
            .any(|formula| formula == "P_test-agent(custom(guard:jailbreak:enabled))"));
        assert!(rendered.iter().any(|formula| {
            formula.as_str()
                == format!(
                    "F_test-agent(custom(jailbreak:risk_score_at_or_above:{}))",
                    cfg.detector.block_threshold
                )
        }));
    }
}
