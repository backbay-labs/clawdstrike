//! Per-guard formula translation.

mod computer_use;
mod egress_allowlist;
mod forbidden_path;
mod input_injection_capability;
mod jailbreak;
mod mcp_tool;
mod patch_integrity;
mod path_allowlist;
mod prompt_injection;
mod remote_desktop_side_channel;
mod secret_leak;
mod shell_command;

use logos_ffi::Formula;
use std::fmt::Write as _;

use crate::atoms::ActionAtom;

pub(crate) use self::shell_command::shell_command_formulas;

/// Translate a guard configuration into Logos Layer 3 normative formulas.
pub trait GuardFormulas {
    fn to_formulas(&self, agent: &logos_ffi::AgentId) -> Vec<Formula>;
}

pub(super) fn custom_permission(agent: &logos_ffi::AgentId, detail: impl Into<String>) -> Formula {
    Formula::permission(agent.clone(), ActionAtom::custom(detail).to_formula())
}

pub(super) fn custom_prohibition(agent: &logos_ffi::AgentId, detail: impl Into<String>) -> Formula {
    Formula::prohibition(agent.clone(), ActionAtom::custom(detail).to_formula())
}

pub(super) fn stable_token(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return value.to_string();
    }

    if value.is_empty() {
        format!(
            "empty_{}",
            hush_core::hashing::sha256(value.as_bytes()).to_hex()
        )
    } else {
        let mut token = String::from("hex_");
        for byte in value.as_bytes() {
            let _ = write!(&mut token, "{byte:02x}");
        }
        token
    }
}

#[cfg(test)]
mod tests {
    use super::stable_token;

    #[test]
    fn stable_token_preserves_separator_distinctions() {
        assert_ne!(
            stable_token("remote.clipboard"),
            stable_token("remote_clipboard")
        );
        assert_ne!(stable_token("foo-bar"), stable_token("foo.bar"));
    }

    #[test]
    fn stable_token_avoids_escape_ambiguity() {
        assert_ne!(stable_token("_5f_"), stable_token("_"));
        assert_eq!(stable_token("keyboard"), "keyboard");
        assert_eq!(stable_token("KeyBoard"), "hex_4b6579426f617264");
    }

    #[test]
    fn stable_token_avoids_empty_hash_collision() {
        let empty = stable_token("");
        let sha256_empty = hush_core::hashing::sha256(b"").to_hex();

        assert_ne!(empty, sha256_empty);
        assert_eq!(empty, format!("empty_{sha256_empty}"));
        assert_eq!(stable_token(&sha256_empty), sha256_empty);
    }
}
