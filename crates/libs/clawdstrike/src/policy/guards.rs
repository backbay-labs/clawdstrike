//! Guard instantiation from a policy (`PolicyGuards`) and stable evaluation order.

use super::Policy;
use crate::guards::{
    ComputerUseGuard, EgressAllowlistGuard, ForbiddenPathGuard, Guard,
    InputInjectionCapabilityGuard, JailbreakGuard, McpToolGuard, PatchIntegrityGuard,
    PathAllowlistGuard, PromptInjectionGuard, RemoteDesktopSideChannelGuard, SecretLeakGuard,
    ShellCommandGuard,
};

impl Policy {
    /// Create guards from this policy
    pub(crate) fn create_guards(&self) -> PolicyGuards {
        PolicyGuards {
            forbidden_path: self
                .guards
                .forbidden_path
                .clone()
                .map(ForbiddenPathGuard::with_config)
                .unwrap_or_default(),
            path_allowlist: self
                .guards
                .path_allowlist
                .clone()
                .map(PathAllowlistGuard::with_config)
                .unwrap_or_default(),
            egress_allowlist: self
                .guards
                .egress_allowlist
                .clone()
                .map(EgressAllowlistGuard::with_config)
                .unwrap_or_default(),
            secret_leak: self
                .guards
                .secret_leak
                .clone()
                .map(SecretLeakGuard::with_config)
                .unwrap_or_default(),
            patch_integrity: self
                .guards
                .patch_integrity
                .clone()
                .map(PatchIntegrityGuard::with_config)
                .unwrap_or_default(),
            shell_command: self
                .guards
                .shell_command
                .clone()
                .map(|cfg| ShellCommandGuard::with_config(cfg, self.guards.forbidden_path.clone()))
                .unwrap_or_default(),
            mcp_tool: self
                .guards
                .mcp_tool
                .clone()
                .map(McpToolGuard::with_config)
                .unwrap_or_default(),
            prompt_injection: self
                .guards
                .prompt_injection
                .clone()
                .map(PromptInjectionGuard::with_config)
                .unwrap_or_default(),
            jailbreak: self
                .guards
                .jailbreak
                .clone()
                .map(JailbreakGuard::with_config)
                .unwrap_or_default(),
            computer_use: self
                .guards
                .computer_use
                .clone()
                .map(ComputerUseGuard::with_config)
                .unwrap_or_default(),
            remote_desktop_side_channel: self
                .guards
                .remote_desktop_side_channel
                .clone()
                .map(RemoteDesktopSideChannelGuard::with_config)
                .unwrap_or_default(),
            input_injection_capability: self
                .guards
                .input_injection_capability
                .clone()
                .map(InputInjectionCapabilityGuard::with_config)
                .unwrap_or_default(),
        }
    }
}

/// Guards instantiated from a policy
pub(crate) struct PolicyGuards {
    pub forbidden_path: ForbiddenPathGuard,
    pub path_allowlist: PathAllowlistGuard,
    pub egress_allowlist: EgressAllowlistGuard,
    pub secret_leak: SecretLeakGuard,
    pub patch_integrity: PatchIntegrityGuard,
    pub shell_command: ShellCommandGuard,
    pub mcp_tool: McpToolGuard,
    pub prompt_injection: PromptInjectionGuard,
    pub jailbreak: JailbreakGuard,
    pub computer_use: ComputerUseGuard,
    pub remote_desktop_side_channel: RemoteDesktopSideChannelGuard,
    pub input_injection_capability: InputInjectionCapabilityGuard,
}

impl PolicyGuards {
    /// Built-in guards, in a stable evaluation order.
    pub(crate) fn builtin_guards_in_order(&self) -> impl ExactSizeIterator<Item = &dyn Guard> + '_ {
        [
            &self.forbidden_path as &dyn Guard,
            &self.path_allowlist as &dyn Guard,
            &self.egress_allowlist as &dyn Guard,
            &self.secret_leak as &dyn Guard,
            &self.patch_integrity as &dyn Guard,
            &self.shell_command as &dyn Guard,
            &self.mcp_tool as &dyn Guard,
            &self.prompt_injection as &dyn Guard,
            &self.jailbreak as &dyn Guard,
            &self.computer_use as &dyn Guard,
            &self.remote_desktop_side_channel as &dyn Guard,
            &self.input_injection_capability as &dyn Guard,
        ]
        .into_iter()
    }
}
