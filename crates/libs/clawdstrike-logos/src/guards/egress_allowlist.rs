//! Formula translation for [`EgressAllowlistConfig`].

use clawdstrike::guards::EgressAllowlistConfig;
use hush_proxy::policy::PolicyAction;
use logos_ffi::{AgentId, Formula};

use super::GuardFormulas;
use crate::atoms::ActionAtom;

impl GuardFormulas for EgressAllowlistConfig {
    /// `P_agent(egress(d))` per allow, `F_agent(egress(d))` per block,
    /// plus a wildcard default (`egress(*)`).
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let permissions = self.effective_allow_patterns().into_iter().map(|domain| {
            let atom = ActionAtom::egress(domain);
            Formula::permission(agent.clone(), atom.to_formula())
        });

        let prohibitions = self.effective_block_patterns().into_iter().map(|domain| {
            let atom = ActionAtom::egress(domain);
            Formula::prohibition(agent.clone(), atom.to_formula())
        });

        // Default action for unmatched domains
        let default_formula = {
            let wildcard = ActionAtom::egress("*");
            match self.default_action.as_ref() {
                Some(PolicyAction::Block) => {
                    Formula::prohibition(agent.clone(), wildcard.to_formula())
                }
                _ => Formula::permission(agent.clone(), wildcard.to_formula()),
            }
        };

        permissions
            .chain(prohibitions)
            .chain(std::iter::once(default_formula))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent() -> AgentId {
        AgentId::new("test-agent")
    }

    #[test]
    fn disabled_guard_produces_no_formulas() {
        let cfg = EgressAllowlistConfig {
            enabled: false,
            allow: vec!["api.example.com".to_string()],
            block: vec![],
            default_action: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        };
        assert!(cfg.to_formulas(&test_agent()).is_empty());
    }

    #[test]
    fn allow_becomes_permission_block_becomes_prohibition() {
        let cfg = EgressAllowlistConfig {
            enabled: true,
            allow: vec!["api.openai.com".to_string()],
            block: vec!["evil.example.com".to_string()],
            default_action: Some(PolicyAction::Block),
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        // 1 permission + 1 prohibition + 1 default prohibition
        assert_eq!(formulas.len(), 3);
        assert!(matches!(&formulas[0], Formula::Permission(_, _)));
        assert!(matches!(&formulas[1], Formula::Prohibition(_, _)));
        assert!(matches!(&formulas[2], Formula::Prohibition(_, _)));

        let rendered: Vec<String> = formulas.iter().map(|f| format!("{f}")).collect();
        assert_eq!(rendered[0], "P_test-agent(egress(api.openai.com))");
        assert_eq!(rendered[1], "F_test-agent(egress(evil.example.com))");
        assert_eq!(rendered[2], "F_test-agent(egress(*))");
    }

    #[test]
    fn default_allow_produces_wildcard_permission() {
        let cfg = EgressAllowlistConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            default_action: None, // defaults to Allow
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        // Only the default wildcard permission
        assert_eq!(formulas.len(), 1);
        let rendered = format!("{}", formulas[0]);
        assert_eq!(rendered, "P_test-agent(egress(*))");
    }

    #[test]
    fn modifiers_contribute_to_formulas_when_lists_are_implicit() {
        let cfg = EgressAllowlistConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            default_action: Some(PolicyAction::Block),
            additional_allow: vec!["api.example.com".to_string()],
            remove_allow: vec![],
            additional_block: vec!["evil.example.com".to_string()],
            remove_block: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        let rendered: Vec<String> = formulas.iter().map(|f| format!("{f}")).collect();
        assert_eq!(
            rendered,
            vec![
                "P_test-agent(egress(api.example.com))".to_string(),
                "F_test-agent(egress(evil.example.com))".to_string(),
                "F_test-agent(egress(*))".to_string(),
            ]
        );
    }
}
