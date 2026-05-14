//! Policy-to-formula compiler.

use clawdstrike::policy::{GuardConfigs, Policy};
use logos_ffi::{AgentId, Formula};

use crate::guards::{shell_command_formulas, GuardFormulas};

pub trait PolicyCompiler {
    fn compile_guards(&self, guards: &GuardConfigs) -> Vec<Formula>;

    fn compile_policy(&self, policy: &Policy) -> Vec<Formula> {
        self.compile_guards(&policy.guards)
    }
}

pub struct DefaultPolicyCompiler {
    agent: AgentId,
}

impl DefaultPolicyCompiler {
    pub fn new(agent: AgentId) -> Self {
        Self { agent }
    }

    pub fn agent(&self) -> &AgentId {
        &self.agent
    }
}

impl PolicyCompiler for DefaultPolicyCompiler {
    fn compile_guards(&self, guards: &GuardConfigs) -> Vec<Formula> {
        let mut formulas = Vec::new();

        if let Some(ref cfg) = guards.forbidden_path {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.path_allowlist {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.egress_allowlist {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.secret_leak {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.patch_integrity {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.shell_command {
            formulas.extend(shell_command_formulas(
                cfg,
                guards.forbidden_path.as_ref(),
                &self.agent,
            ));
        }

        if let Some(ref cfg) = guards.mcp_tool {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.prompt_injection {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.jailbreak {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.computer_use {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.remote_desktop_side_channel {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        if let Some(ref cfg) = guards.input_injection_capability {
            formulas.extend(cfg.to_formulas(&self.agent));
        }

        formulas
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clawdstrike::guards::{
        EgressAllowlistConfig, ForbiddenPathConfig, McpToolConfig, PathAllowlistConfig,
        PromptInjectionConfig, SecretLeakConfig, ShellCommandConfig,
    };

    fn test_agent() -> AgentId {
        AgentId::new("test-agent")
    }

    #[test]
    fn empty_guards_produce_no_formulas() {
        let compiler = DefaultPolicyCompiler::new(test_agent());
        let guards = GuardConfigs::default();
        let formulas = compiler.compile_guards(&guards);
        assert!(formulas.is_empty());
    }

    #[test]
    fn compile_guards_collects_all_guard_formulas() {
        let compiler = DefaultPolicyCompiler::new(test_agent());
        let guards = GuardConfigs {
            forbidden_path: Some(ForbiddenPathConfig {
                enabled: true,
                patterns: Some(vec!["/etc/shadow".to_string()]),
                exceptions: vec![],
                additional_patterns: vec![],
                remove_patterns: vec![],
            }),
            path_allowlist: Some(PathAllowlistConfig {
                enabled: true,
                file_access_allow: vec!["/app/**".to_string()],
                file_write_allow: vec![],
                patch_allow: vec![],
            }),
            egress_allowlist: Some(EgressAllowlistConfig {
                enabled: true,
                allow: vec!["api.openai.com".to_string()],
                block: vec![],
                default_action: None,
                additional_allow: vec![],
                remove_allow: vec![],
                additional_block: vec![],
                remove_block: vec![],
            }),
            shell_command: Some(ShellCommandConfig {
                enabled: true,
                forbidden_patterns: vec!["rm -rf /".to_string()],
                enforce_forbidden_paths: true,
            }),
            mcp_tool: Some(McpToolConfig {
                enabled: true,
                allow: vec![],
                block: vec!["shell_exec".to_string()],
                require_confirmation: vec![],
                default_action: None,
                max_args_size: None,
                additional_allow: vec![],
                remove_allow: vec![],
                additional_block: vec![],
                remove_block: vec![],
            }),
            ..GuardConfigs::default()
        };

        let formulas = compiler.compile_guards(&guards);

        // 1 forbidden_path prohibition
        // + 1 path_allowlist permission
        // + 1 egress permission + 1 egress default permission
        // + 1 shell regex prohibition + 1 shell forbidden-path prohibition
        // + 1 mcp prohibition + 1 mcp default permission
        // = 8 formulas
        assert_eq!(formulas.len(), 8);

        // Verify we have a mix of Prohibition and Permission
        let prohibition_count = formulas
            .iter()
            .filter(|f| matches!(f, Formula::Prohibition(_, _)))
            .count();
        let permission_count = formulas
            .iter()
            .filter(|f| matches!(f, Formula::Permission(_, _)))
            .count();
        assert_eq!(prohibition_count, 4);
        assert_eq!(permission_count, 4);
    }

    #[test]
    fn compile_policy_delegates_to_compile_guards() {
        let compiler = DefaultPolicyCompiler::new(test_agent());
        let mut policy = Policy::default();
        policy.guards.forbidden_path = Some(ForbiddenPathConfig {
            enabled: true,
            patterns: Some(vec!["/etc/shadow".to_string()]),
            exceptions: vec![],
            additional_patterns: vec![],
            remove_patterns: vec![],
        });

        let formulas = compiler.compile_policy(&policy);
        assert_eq!(formulas.len(), 1);
        assert!(matches!(&formulas[0], Formula::Prohibition(_, _)));
    }

    #[test]
    fn all_formulas_are_normative() {
        let compiler = DefaultPolicyCompiler::new(test_agent());
        let mut policy = Policy::default();
        policy.guards.forbidden_path = Some(ForbiddenPathConfig::default());
        policy.guards.egress_allowlist = Some(EgressAllowlistConfig::default());
        policy.guards.shell_command = Some(ShellCommandConfig::default());
        policy.guards.mcp_tool = Some(McpToolConfig::default());

        let formulas = compiler.compile_policy(&policy);
        assert!(!formulas.is_empty());

        for formula in &formulas {
            assert_eq!(
                formula.required_layer(),
                3,
                "expected Layer 3 (normative), got layer {} for: {formula}",
                formula.required_layer()
            );
        }
    }

    #[test]
    fn disabled_guards_skipped() {
        let compiler = DefaultPolicyCompiler::new(test_agent());
        let guards = GuardConfigs {
            forbidden_path: Some(ForbiddenPathConfig {
                enabled: false,
                patterns: Some(vec!["/etc/shadow".to_string()]),
                exceptions: vec![],
                additional_patterns: vec![],
                remove_patterns: vec![],
            }),
            shell_command: Some(ShellCommandConfig {
                enabled: false,
                forbidden_patterns: vec!["rm".to_string()],
                enforce_forbidden_paths: true,
            }),
            ..GuardConfigs::default()
        };

        let formulas = compiler.compile_guards(&guards);
        assert!(formulas.is_empty());
    }

    #[test]
    fn runtime_only_guards_compile_to_custom_formulas() {
        let compiler = DefaultPolicyCompiler::new(test_agent());
        let guards = GuardConfigs {
            secret_leak: Some(SecretLeakConfig::default()),
            prompt_injection: Some(PromptInjectionConfig::default()),
            ..GuardConfigs::default()
        };

        let rendered: Vec<String> = compiler
            .compile_guards(&guards)
            .into_iter()
            .map(|formula| formula.to_string())
            .collect();

        assert!(rendered.iter().any(|formula| formula.contains("custom(")));
        assert!(rendered
            .iter()
            .any(|formula| formula == "P_test-agent(custom(guard:secret_leak:enabled))"));
        assert!(rendered
            .iter()
            .any(|formula| formula == "P_test-agent(custom(guard:prompt_injection:enabled))"));
    }

    #[test]
    fn shell_forbidden_path_enforcement_emits_exec_formulas() {
        let compiler = DefaultPolicyCompiler::new(test_agent());
        let guards = GuardConfigs {
            forbidden_path: Some(ForbiddenPathConfig {
                enabled: true,
                patterns: Some(vec!["/etc/shadow".to_string()]),
                exceptions: vec![],
                additional_patterns: vec![],
                remove_patterns: vec![],
            }),
            shell_command: Some(ShellCommandConfig {
                enabled: true,
                forbidden_patterns: vec![],
                enforce_forbidden_paths: true,
            }),
            ..GuardConfigs::default()
        };

        let rendered: Vec<String> = compiler
            .compile_guards(&guards)
            .into_iter()
            .map(|formula| formula.to_string())
            .collect();

        assert_eq!(
            rendered,
            vec![
                "F_test-agent(access(/etc/shadow))".to_string(),
                "F_test-agent(exec(touches_forbidden_path:/etc/shadow))".to_string(),
            ]
        );
    }
}
