//! Secret-target detection for developer-activity classification.

use super::shell_tokens::{
    shell_command_line, shell_token_can_be_secret_target, shell_tokens_for_policy_check,
};
use crate::policy::PolicyCheckInput;

pub(super) fn secret_target_from_policy_check(input: &PolicyCheckInput) -> Option<String> {
    let mut candidates = Vec::new();
    if input.action_type.trim().eq_ignore_ascii_case("shell") {
        let command_line = shell_command_line(input);
        for token in shell_tokens_for_policy_check(input, &command_line) {
            if shell_token_can_be_secret_target(&token) {
                candidates.push(token);
            }
        }
    } else {
        candidates.push(input.target.clone());
    }
    if let Some(args) = input.args.as_ref() {
        for key in ["path", "file", "file_path", "target", "resource"] {
            if let Some(value) = args.get(key).and_then(serde_json::Value::as_str) {
                candidates.push(value.to_string());
            }
        }
    }
    candidates
        .into_iter()
        .map(|candidate| candidate.trim().to_string())
        .find(|candidate| target_looks_like_secret(candidate))
}

fn target_looks_like_secret(target: &str) -> bool {
    let lower = target.to_ascii_lowercase();
    [
        ".env",
        ".npmrc",
        ".pypirc",
        ".aws/credentials",
        ".ssh/",
        "id_rsa",
        "id_ed25519",
        "api_key",
        "apikey",
        "secret",
        "token",
        "cookie",
        "cargo/credentials",
    ]
    .iter()
    .any(|needle| lower.contains(needle))
}

pub(super) fn secret_name_from_target(target: &str) -> String {
    target
        .rsplit(['/', '\\'])
        .next()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("secret")
        .to_string()
}
