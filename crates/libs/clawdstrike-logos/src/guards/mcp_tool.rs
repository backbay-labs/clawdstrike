//! Formula translation for [`McpToolConfig`].

use clawdstrike::guards::{McpDefaultAction, McpToolConfig};
use logos_ffi::{AgentId, Formula};

use super::GuardFormulas;
use crate::atoms::ActionAtom;

impl GuardFormulas for McpToolConfig {
    /// `F_agent(mcp(t))` per block, `P_agent(mcp(t))` per allow,
    /// plus a wildcard default (`mcp(*)`).
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let prohibitions = self.effective_block_tools().into_iter().map(|tool| {
            let atom = ActionAtom::mcp(tool);
            Formula::prohibition(agent.clone(), atom.to_formula())
        });

        let permissions = self.effective_allow_tools().into_iter().map(|tool| {
            let atom = ActionAtom::mcp(tool);
            Formula::permission(agent.clone(), atom.to_formula())
        });

        // Default action for unmatched tools
        let default_formula = {
            let wildcard = ActionAtom::mcp("*");
            match self.default_action.as_ref() {
                Some(McpDefaultAction::Block) => {
                    Formula::prohibition(agent.clone(), wildcard.to_formula())
                }
                _ => Formula::permission(agent.clone(), wildcard.to_formula()),
            }
        };

        prohibitions
            .chain(permissions)
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
        let cfg = McpToolConfig {
            enabled: false,
            allow: vec![],
            block: vec!["shell_exec".to_string()],
            require_confirmation: vec![],
            default_action: None,
            max_args_size: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        };
        assert!(cfg.to_formulas(&test_agent()).is_empty());
    }

    #[test]
    fn block_becomes_prohibition_allow_becomes_permission() {
        let cfg = McpToolConfig {
            enabled: true,
            allow: vec!["file_read".to_string()],
            block: vec!["shell_exec".to_string()],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Allow),
            max_args_size: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        // 1 prohibition (block) + 1 permission (allow) + 1 default permission
        assert_eq!(formulas.len(), 3);
        assert!(matches!(&formulas[0], Formula::Prohibition(_, _)));
        assert!(matches!(&formulas[1], Formula::Permission(_, _)));
        assert!(matches!(&formulas[2], Formula::Permission(_, _)));

        let rendered: Vec<String> = formulas.iter().map(|f| format!("{f}")).collect();
        assert_eq!(rendered[0], "F_test-agent(mcp(shell_exec))");
        assert_eq!(rendered[1], "P_test-agent(mcp(file_read))");
        assert_eq!(rendered[2], "P_test-agent(mcp(*))");
    }

    #[test]
    fn default_block_produces_wildcard_prohibition() {
        let cfg = McpToolConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Block),
            max_args_size: None,
            additional_allow: vec![],
            remove_allow: vec![],
            additional_block: vec![],
            remove_block: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        assert_eq!(formulas.len(), 1);
        let rendered = format!("{}", formulas[0]);
        assert_eq!(rendered, "F_test-agent(mcp(*))");
    }

    #[test]
    fn modifiers_contribute_to_formulas_when_lists_are_implicit() {
        let cfg = McpToolConfig {
            enabled: true,
            allow: vec![],
            block: vec![],
            require_confirmation: vec![],
            default_action: Some(McpDefaultAction::Block),
            max_args_size: None,
            additional_allow: vec!["file_read".to_string()],
            remove_allow: vec![],
            additional_block: vec!["shell_exec".to_string()],
            remove_block: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        let rendered: Vec<String> = formulas.iter().map(|f| format!("{f}")).collect();
        assert_eq!(
            rendered,
            vec![
                "F_test-agent(mcp(shell_exec))".to_string(),
                "P_test-agent(mcp(file_read))".to_string(),
                "F_test-agent(mcp(*))".to_string(),
            ]
        );
    }
}
