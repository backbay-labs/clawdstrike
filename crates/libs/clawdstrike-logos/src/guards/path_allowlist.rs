//! Formula translation for [`PathAllowlistConfig`].

use clawdstrike::guards::PathAllowlistConfig;
use logos_ffi::{AgentId, Formula};

use super::GuardFormulas;
use crate::atoms::ActionAtom;

impl GuardFormulas for PathAllowlistConfig {
    /// `P_agent(access(g))`, `P_agent(write(g))`, `P_agent(patch(g))` per glob.
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let access_permissions = self.file_access_allow.iter().map(|path| {
            let atom = ActionAtom::access(path);
            Formula::permission(agent.clone(), atom.to_formula())
        });

        let write_permissions = self.file_write_allow.iter().map(|path| {
            let atom = ActionAtom::write(path);
            Formula::permission(agent.clone(), atom.to_formula())
        });

        let patch_permissions = self.patch_allow.iter().map(|path| {
            let atom = ActionAtom::patch(path);
            Formula::permission(agent.clone(), atom.to_formula())
        });

        access_permissions
            .chain(write_permissions)
            .chain(patch_permissions)
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
        let cfg = PathAllowlistConfig {
            enabled: false,
            file_access_allow: vec!["/app/**".to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());
        assert!(formulas.is_empty());
    }

    #[test]
    fn file_access_allow_becomes_permission() {
        let cfg = PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec!["/app/**".to_string(), "/tmp/**".to_string()],
            file_write_allow: vec![],
            patch_allow: vec![],
        };
        let formulas = cfg.to_formulas(&test_agent());

        assert_eq!(formulas.len(), 2);
        for f in &formulas {
            assert!(matches!(f, Formula::Permission(_, _)));
        }

        let rendered: Vec<String> = formulas.iter().map(|f| format!("{f}")).collect();
        assert_eq!(rendered[0], "P_test-agent(access(/app/**))");
        assert_eq!(rendered[1], "P_test-agent(access(/tmp/**))");
    }

    #[test]
    fn write_and_patch_permissions() {
        let cfg = PathAllowlistConfig {
            enabled: true,
            file_access_allow: vec![],
            file_write_allow: vec!["/app/src/**".to_string()],
            patch_allow: vec!["/app/src/**".to_string()],
        };
        let formulas = cfg.to_formulas(&test_agent());

        assert_eq!(formulas.len(), 2);

        let rendered: Vec<String> = formulas.iter().map(|f| format!("{f}")).collect();
        assert_eq!(rendered[0], "P_test-agent(write(/app/src/**))");
        assert_eq!(rendered[1], "P_test-agent(patch(/app/src/**))");
    }
}
