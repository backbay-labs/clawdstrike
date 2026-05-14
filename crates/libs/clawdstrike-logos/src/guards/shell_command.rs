//! Formula translation for [`ShellCommandConfig`].
//!
//! The pattern string is used as the atom parameter (over-approximation since
//! Z3 cannot reason about regex matching directly).

use clawdstrike::guards::{ForbiddenPathConfig, ShellCommandConfig};
use logos_ffi::{AgentId, Formula};

use super::GuardFormulas;
use crate::atoms::ActionAtom;

pub(crate) fn shell_command_formulas(
    config: &ShellCommandConfig,
    forbidden_path: Option<&ForbiddenPathConfig>,
    agent: &AgentId,
) -> Vec<Formula> {
    if !config.enabled {
        return vec![];
    }

    let mut formulas: Vec<Formula> = config
        .forbidden_patterns
        .iter()
        .map(|pattern| {
            let atom = ActionAtom::exec(pattern);
            Formula::prohibition(agent.clone(), atom.to_formula())
        })
        .collect();

    if config.enforce_forbidden_paths {
        let forbidden_path = forbidden_path.cloned().unwrap_or_default();
        if forbidden_path.enabled {
            formulas.extend(
                forbidden_path
                    .effective_patterns()
                    .into_iter()
                    .map(|pattern| {
                        let atom = ActionAtom::exec(format!("touches_forbidden_path:{pattern}"));
                        Formula::prohibition(agent.clone(), atom.to_formula())
                    }),
            );
        }
    }

    formulas
}

impl GuardFormulas for ShellCommandConfig {
    /// `F_agent(exec(pat))` per forbidden pattern.
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        shell_command_formulas(self, None, agent)
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
        let cfg = ShellCommandConfig {
            enabled: false,
            forbidden_patterns: vec!["rm -rf /".to_string()],
            enforce_forbidden_paths: true,
        };
        assert!(cfg.to_formulas(&test_agent()).is_empty());
    }

    #[test]
    fn each_pattern_becomes_prohibition() {
        let cfg = ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec![
                r"(?i)\brm\s+(-rf?|--recursive)\s+/\s*(?:$|\*)".to_string(),
                r"(?i)\bcurl\s+[^|]*\|\s*(bash|sh|zsh)\b".to_string(),
            ],
            enforce_forbidden_paths: true,
        };
        let rendered: Vec<String> = cfg
            .to_formulas(&test_agent())
            .into_iter()
            .map(|formula| formula.to_string())
            .collect();

        assert!(rendered
            .iter()
            .all(|formula| formula.starts_with("F_test-agent(")));
        assert!(rendered.iter().any(|formula| {
            formula == r"F_test-agent(exec((?i)\brm\s+(-rf?|--recursive)\s+/\s*(?:$|\*)))"
        }));
        assert!(rendered.iter().any(|formula| {
            formula == r"F_test-agent(exec((?i)\bcurl\s+[^|]*\|\s*(bash|sh|zsh)\b))"
        }));
    }

    #[test]
    fn default_config_produces_prohibitions() {
        let cfg = ShellCommandConfig::default();
        let formulas = cfg.to_formulas(&test_agent());

        // Default config has several forbidden patterns
        assert!(!formulas.is_empty());
        for f in &formulas {
            assert!(matches!(f, Formula::Prohibition(_, _)));
        }
    }

    #[test]
    fn forbidden_path_enforcement_becomes_exec_prohibitions() {
        let cfg = ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec![],
            enforce_forbidden_paths: true,
        };
        let forbidden_path = ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["/etc/shadow".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        };

        let rendered: Vec<String> =
            shell_command_formulas(&cfg, Some(&forbidden_path), &test_agent())
                .into_iter()
                .map(|formula| formula.to_string())
                .collect();

        assert_eq!(
            rendered,
            vec!["F_test-agent(exec(touches_forbidden_path:/etc/shadow))".to_string()]
        );
    }

    #[test]
    fn forbidden_path_enforcement_uses_default_paths_when_not_overridden() {
        let cfg = ShellCommandConfig {
            enabled: true,
            forbidden_patterns: vec![],
            enforce_forbidden_paths: true,
        };

        let rendered: Vec<String> = shell_command_formulas(&cfg, None, &test_agent())
            .into_iter()
            .map(|formula| formula.to_string())
            .collect();

        assert!(rendered
            .iter()
            .any(|formula| formula.contains("exec(touches_forbidden_path:")));
    }
}
