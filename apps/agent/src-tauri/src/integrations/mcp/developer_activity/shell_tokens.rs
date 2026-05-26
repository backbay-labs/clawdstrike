//! Shell tokenization helpers shared across developer-activity classifiers.

use crate::policy::PolicyCheckInput;

pub(super) fn shell_command_image(command: &str) -> String {
    command
        .split_whitespace()
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or("shell")
        .to_string()
}

pub(super) fn shell_command_line(input: &PolicyCheckInput) -> String {
    let target = input.target.trim();
    if !target.is_empty() {
        return target.to_string();
    }
    input
        .args
        .as_ref()
        .and_then(|args| {
            ["command", "cmd", "commandLine", "command_line"]
                .iter()
                .filter_map(|key| args.get(*key).and_then(serde_json::Value::as_str))
                .map(str::trim)
                .find(|value| !value.is_empty())
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "shell".to_string())
}

pub(super) fn shell_tokens_for_policy_check(
    input: &PolicyCheckInput,
    command_line: &str,
) -> Vec<String> {
    let mut tokens = shell_split_best_effort(command_line);
    if tokens.len() <= 1 {
        if let Some(arg_tokens) = input.args.as_ref().and_then(shell_arg_tokens) {
            tokens.extend(arg_tokens);
        }
    }
    tokens
}

fn shell_arg_tokens(
    args: &std::collections::HashMap<String, serde_json::Value>,
) -> Option<Vec<String>> {
    for key in ["argv", "args", "arguments"] {
        let Some(value) = args.get(key) else {
            continue;
        };
        if let Some(items) = value.as_array() {
            let tokens = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<_>>();
            if !tokens.is_empty() {
                return Some(tokens);
            }
        }
        if let Some(value) = value.as_str() {
            let tokens = shell_split_best_effort(value);
            if !tokens.is_empty() {
                return Some(tokens);
            }
        }
    }
    None
}

pub(super) fn shell_working_directory(input: &PolicyCheckInput) -> Option<String> {
    input.args.as_ref().and_then(|args| {
        ["cwd", "workingDirectory", "working_directory"]
            .iter()
            .filter_map(|key| args.get(*key).and_then(serde_json::Value::as_str))
            .map(str::trim)
            .find(|value| !value.is_empty())
            .map(ToString::to_string)
    })
}

pub(super) fn shell_split_best_effort(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(c) = chars.next() {
        if in_single {
            if c == '\'' {
                in_single = false;
            } else {
                current.push(c);
            }
            continue;
        }
        if in_double {
            match c {
                '"' => in_double = false,
                '\\' => {
                    if let Some(next) = chars.next() {
                        current.push(next);
                    }
                }
                _ => current.push(c),
            }
            continue;
        }

        match c {
            '\'' => in_single = true,
            '"' => in_double = true,
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    tokens.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

pub(super) fn normalized_shell_commands(tokens: &[String]) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for segment in shell_command_segments(tokens) {
        if let Some(command) = normalize_shell_command_segment(segment) {
            commands.push(command);
        }
    }
    commands
}

fn shell_command_segments(tokens: &[String]) -> Vec<&[String]> {
    let mut segments = Vec::new();
    let mut start = 0;
    for (index, token) in tokens.iter().enumerate() {
        if is_shell_separator(token) {
            if start < index {
                segments.push(&tokens[start..index]);
            }
            start = index + 1;
        }
    }
    if start < tokens.len() {
        segments.push(&tokens[start..]);
    }
    segments
}

fn normalize_shell_command_segment(segment: &[String]) -> Option<Vec<String>> {
    let mut index = 0;
    while index < segment.len() {
        let token = segment.get(index)?;
        let executable = executable_name(token);
        if shell_assignment(token) {
            index += 1;
            continue;
        }
        if matches!(
            executable.as_str(),
            "sudo" | "doas" | "command" | "builtin" | "nohup" | "time"
        ) {
            index += 1;
            continue;
        }
        if executable == "env" {
            index += 1;
            while index < segment.len() {
                let token = segment.get(index)?;
                if shell_assignment(token) || token.starts_with('-') {
                    index += 1;
                    continue;
                }
                break;
            }
            continue;
        }
        if matches!(executable.as_str(), "sh" | "bash" | "zsh" | "dash" | "fish") {
            if let Some(inner) = shell_c_inner_command(&segment[index + 1..]) {
                let inner_tokens = shell_split_best_effort(inner);
                return normalized_shell_commands(&inner_tokens).into_iter().next();
            }
        }
        return Some(segment[index..].to_vec());
    }
    None
}

fn shell_c_inner_command(tokens: &[String]) -> Option<&str> {
    for (index, token) in tokens.iter().enumerate() {
        if token == "-c" || (token.starts_with('-') && token.chars().skip(1).any(|c| c == 'c')) {
            return tokens.get(index + 1).map(String::as_str);
        }
    }
    None
}

fn is_shell_separator(token: &str) -> bool {
    matches!(token, "&&" | "||" | ";" | "|")
}

pub(super) fn shell_assignment(token: &str) -> bool {
    let Some((name, value)) = token.split_once('=') else {
        return false;
    };
    !name.is_empty()
        && !value.is_empty()
        && name.chars().all(|c| c == '_' || c.is_ascii_alphanumeric())
        && !name.chars().next().is_some_and(|c| c.is_ascii_digit())
}

pub(super) fn executable_name(token: &str) -> String {
    let basename = token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .trim()
        .trim_matches('"')
        .trim_matches('\'');
    basename
        .strip_suffix(".exe")
        .or_else(|| basename.strip_suffix(".cmd"))
        .or_else(|| basename.strip_suffix(".bat"))
        .unwrap_or(basename)
        .to_ascii_lowercase()
}

pub(super) fn first_non_option_arg_index(args: &[String]) -> Option<usize> {
    let mut index = 0;
    while index < args.len() {
        let arg = args.get(index)?;
        if arg == "--" {
            return (index + 1 < args.len()).then_some(index + 1);
        }
        if shell_assignment(arg) {
            index += 1;
            continue;
        }
        if arg.starts_with("--") {
            if option_takes_value(arg) && !arg.contains('=') {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            if short_option_takes_value(arg) {
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        return Some(index);
    }
    None
}

fn option_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "--prefix"
            | "--cwd"
            | "--directory"
            | "--project"
            | "--profile"
            | "--region"
            | "--subscription"
            | "--account"
            | "--configuration"
            | "--workspace"
    )
}

fn short_option_takes_value(arg: &str) -> bool {
    matches!(arg, "-C" | "-p" | "-r" | "-c" | "-m")
}

pub(super) fn shell_token_can_be_secret_target(token: &str) -> bool {
    let trimmed = token.trim_matches(['"', '\'', ',', ';']);
    trimmed.starts_with('/')
        || trimmed.starts_with("./")
        || trimmed.starts_with("../")
        || trimmed.starts_with('~')
        || trimmed.starts_with('.')
        || trimmed.contains('\\')
        || trimmed.contains("/.")
}
