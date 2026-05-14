//! Formula translation for [`RemoteDesktopSideChannelConfig`].

use clawdstrike::guards::RemoteDesktopSideChannelConfig;
use logos_ffi::{AgentId, Formula};

use super::{custom_permission, custom_prohibition, GuardFormulas};

impl GuardFormulas for RemoteDesktopSideChannelConfig {
    fn to_formulas(&self, agent: &AgentId) -> Vec<Formula> {
        if !self.enabled {
            return vec![];
        }

        let mut formulas = vec![custom_permission(
            agent,
            "guard:remote_desktop_side_channel:enabled",
        )];

        for (channel, enabled) in [
            ("clipboard", self.clipboard_enabled),
            ("file_transfer", self.file_transfer_enabled),
            ("session_share", self.session_share_enabled),
            ("audio", self.audio_enabled),
            ("drive_mapping", self.drive_mapping_enabled),
            ("printing", self.printing_enabled),
        ] {
            let atom = format!("remote_desktop_side_channel:channel:{channel}");
            formulas.push(if enabled {
                custom_permission(agent, atom)
            } else {
                custom_prohibition(agent, atom)
            });
        }

        if self.file_transfer_enabled {
            if let Some(limit) = self.max_transfer_size_bytes {
                formulas.push(custom_prohibition(
                    agent,
                    format!("remote_desktop_side_channel:file_transfer:size_exceeds:{limit}"),
                ));
            }
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
    fn disabled_file_transfer_omits_size_limit_formula() {
        let cfg = RemoteDesktopSideChannelConfig {
            enabled: true,
            clipboard_enabled: false,
            file_transfer_enabled: false,
            session_share_enabled: false,
            audio_enabled: false,
            drive_mapping_enabled: false,
            printing_enabled: false,
            max_transfer_size_bytes: Some(1024),
        };

        let rendered: Vec<String> = cfg
            .to_formulas(&test_agent())
            .into_iter()
            .map(|formula| formula.to_string())
            .collect();

        assert!(rendered.iter().any(|formula| formula
            == "F_test-agent(custom(remote_desktop_side_channel:channel:file_transfer))"));
        assert!(!rendered
            .iter()
            .any(|formula| formula.contains("size_exceeds")));
    }
}
