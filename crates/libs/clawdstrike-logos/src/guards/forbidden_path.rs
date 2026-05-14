//! Formula translation for [`ForbiddenPathConfig`].

use clawdstrike::guards::ForbiddenPathConfig;
use logos_ffi::{AgentId, Formula};

use super::GuardFormulas;
use crate::atoms::ActionAtom;

impl GuardFormulas for ForbiddenPathConfig {
    /// `F_agent(access(p))` per pattern, `P_agent(access(e))` per exception.
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let effective = self.effective_patterns();

        let prohibitions = effective.iter().map(|pattern| {
            let atom = ActionAtom::access(pattern);
            Formula::prohibition(agent.clone(), atom.to_formula())
        });

        let permissions = self.exceptions.iter().map(|exception| {
            let atom = ActionAtom::access(exception);
            Formula::permission(agent.clone(), atom.to_formula())
        });

        prohibitions.chain(permissions).collect()
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
        let cfg = ForbiddenPathConfig {
            enabled: false,
            patterns: Some(vec!["/etc/shadow".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());
        assert!(formulas.is_empty());
    }

    #[test]
    fn each_pattern_becomes_prohibition() {
        let cfg = ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["/etc/shadow".to_string(), "/etc/passwd".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        assert_eq!(formulas.len(), 2);

        // Each formula should be a Prohibition wrapping the correct atom
        for formula in &formulas {
            assert!(
                matches!(formula, Formula::Prohibition(_, _)),
                "expected Prohibition, got: {formula}"
            );
        }

        // Verify the atom names in order
        let rendered: Vec<String> = formulas.iter().map(|f| format!("{f}")).collect();
        assert_eq!(rendered[0], "F_test-agent(access(/etc/shadow))");
        assert_eq!(rendered[1], "F_test-agent(access(/etc/passwd))");
    }

    #[test]
    fn additional_patterns_included() {
        let cfg = ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["/etc/shadow".to_string()]),
            exceptions: vec![],
            additional_patterns: vec!["**/secrets.yaml".to_string()],
            remove_patterns: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        assert_eq!(formulas.len(), 2);

        let rendered: Vec<String> = formulas.iter().map(|f| format!("{f}")).collect();
        assert_eq!(rendered[0], "F_test-agent(access(/etc/shadow))");
        assert_eq!(rendered[1], "F_test-agent(access(**/secrets.yaml))");
    }

    #[test]
    fn remove_patterns_excluded() {
        let cfg = ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["/etc/shadow".to_string(), "/etc/passwd".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec!["/etc/passwd".to_string()],
        };
        let formulas = cfg.to_formulas(&test_agent());

        assert_eq!(formulas.len(), 1);

        let rendered = format!("{}", formulas[0]);
        assert_eq!(rendered, "F_test-agent(access(/etc/shadow))");
    }

    #[test]
    fn exceptions_become_permissions() {
        let cfg = ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["**/.ssh/**".to_string()]),
            exceptions: vec!["/home/user/.ssh/known_hosts".to_string()],
            additional_patterns: vec![],
            remove_patterns: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        assert_eq!(formulas.len(), 2);

        // First: prohibition
        assert!(matches!(&formulas[0], Formula::Prohibition(_, _)));
        // Second: permission (exception)
        assert!(matches!(&formulas[1], Formula::Permission(_, _)));

        let rendered: Vec<String> = formulas.iter().map(|f| format!("{f}")).collect();
        assert_eq!(rendered[0], "F_test-agent(access(**/.ssh/**))");
        assert_eq!(
            rendered[1],
            "P_test-agent(access(/home/user/.ssh/known_hosts))"
        );
    }

    #[test]
    fn default_config_produces_prohibitions() {
        let cfg = ForbiddenPathConfig::default();
        let formulas = cfg.to_formulas(&test_agent());

        // Default config has many patterns, all should become prohibitions
        assert!(!formulas.is_empty());
        for formula in &formulas {
            assert!(matches!(formula, Formula::Prohibition(_, _)));
        }
    }

    #[test]
    fn atom_names_well_formed() {
        let cfg = ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["**/.env".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        assert_eq!(formulas.len(), 1);
        if let Formula::Prohibition(_, inner) = &formulas[0] {
            // The inner formula should be an Atom with the correct name
            assert!(
                matches!(inner.as_ref(), Formula::Atom(s) if s == "access(**/.env)"),
                "unexpected inner formula: {inner}"
            );
        } else {
            panic!("expected Prohibition");
        }
    }
}
