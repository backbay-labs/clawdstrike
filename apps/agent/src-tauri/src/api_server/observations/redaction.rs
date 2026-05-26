use super::*;

pub(crate) fn redact_developer_activity_command_line(command_line: &str) -> String {
    let command_line = redact_developer_activity_jsonish_secret_fields(command_line);
    let parts = command_line
        .split_whitespace()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let redacted = redact_developer_activity_args(&parts).join(" ");

    if redacted != command_line.as_str() {
        redacted
    } else if developer_activity_secret_like_value(&command_line) {
        "[REDACTED]".to_string()
    } else {
        redacted
    }
}

pub(crate) fn redact_developer_activity_args(args: &[String]) -> Vec<String> {
    let mut redacted = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(redacted_arg) = redact_developer_activity_userinfo_flag_assignment(arg) {
            redacted.push(redacted_arg);
            index += 1;
            continue;
        }
        if let Some(redacted_arg) = redact_developer_activity_compact_userinfo_flag(arg) {
            redacted.push(redacted_arg);
            index += 1;
            continue;
        }
        if let Some(header) = redact_developer_activity_header_flag_assignment_value(arg) {
            redacted.push(header.redacted);
            index += 1;
            if header.consumes_next_token && index < args.len() {
                index += 1;
            }
            continue;
        }
        if let Some(header) = redact_developer_activity_authorization_header_value(arg) {
            redacted.push(header.redacted);
            index += 1;
            if header.consumes_next_token && index < args.len() {
                index += 1;
            }
            continue;
        }
        if developer_activity_authorization_header_key(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() && developer_activity_authorization_scheme_marker(&args[index]) {
                redacted.push(args[index].clone());
                index += 1;
            }
            if index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        if developer_activity_userinfo_flag_without_value(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() {
                redacted.push(redact_developer_activity_userinfo_credential(&args[index]));
                index += 1;
            }
            continue;
        }
        if developer_activity_sensitive_flag_without_value(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() && developer_activity_authorization_scheme_marker(&args[index]) {
                redacted.push(args[index].clone());
                index += 1;
            }
            if index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        if developer_activity_authorization_scheme_marker(arg) {
            redacted.push(arg.clone());
            index += 1;
            if index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        if let Some(assignment) = redact_developer_activity_sensitive_assignment(arg) {
            redacted.push(assignment.redacted);
            index += 1;
            if assignment.consumes_next_token && index < args.len() {
                redacted.push("[REDACTED]".to_string());
                index += 1;
            }
            continue;
        }
        redacted.push(redact_developer_activity_command_part(arg));
        index += 1;
    }
    redacted
}

pub(crate) struct RedactedAuthorizationHeader {
    redacted: String,
    consumes_next_token: bool,
}

pub(crate) struct RedactedSensitiveAssignment {
    redacted: String,
    consumes_next_token: bool,
}

fn developer_activity_authorization_header_key(part: &str) -> bool {
    let normalized = part.trim_end_matches(':');
    if normalized.eq_ignore_ascii_case("authorization")
        || normalized.eq_ignore_ascii_case("proxy-authorization")
        || normalized.eq_ignore_ascii_case("cookie")
        || normalized.eq_ignore_ascii_case("set-cookie")
    {
        return true;
    }
    if normalized.contains(['?', '&', '/', '\\', '=']) {
        return false;
    }
    developer_activity_sensitive_key(normalized)
        || developer_activity_sensitive_auth_header_key(normalized)
}

fn developer_activity_sensitive_auth_header_key(key: &str) -> bool {
    let normalized_key = key
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    normalized_key == "auth"
        || normalized_key.ends_with("auth")
        || normalized_key.ends_with("authentication")
        || normalized_key.ends_with("authorization")
}

fn developer_activity_userinfo_flag_key(part: &str) -> bool {
    let normalized = part
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    matches!(
        normalized.as_str(),
        "u" | "user" | "proxy-user" | "proxyuser"
    )
}

fn developer_activity_userinfo_flag_without_value(part: &str) -> bool {
    let trimmed = part.trim_end_matches(':');
    if trimmed.contains('=') || !trimmed.starts_with('-') {
        return false;
    }
    developer_activity_userinfo_flag_key(trimmed)
}

fn redact_developer_activity_userinfo_flag_assignment(part: &str) -> Option<String> {
    let (flag, credential) = part.split_once('=')?;
    if !developer_activity_userinfo_flag_key(flag) {
        return None;
    }
    Some(format!(
        "{flag}={}",
        redact_developer_activity_userinfo_credential(credential)
    ))
}

fn redact_developer_activity_compact_userinfo_flag(part: &str) -> Option<String> {
    if part.len() <= 2 || !(part.starts_with("-u") || part.starts_with("-U")) {
        return None;
    }
    let credential = &part[2..];
    if credential.starts_with('-') || !credential.contains(':') {
        return None;
    }
    Some(format!(
        "{}{}",
        &part[..2],
        redact_developer_activity_userinfo_credential(credential)
    ))
}

fn redact_developer_activity_userinfo_credential(credential: &str) -> String {
    let Some((user, password)) = credential.split_once(':') else {
        return if developer_activity_secret_like_value(credential) {
            "[REDACTED]".to_string()
        } else {
            credential.to_string()
        };
    };
    if password.is_empty() {
        credential.to_string()
    } else {
        format!("{user}:[REDACTED]")
    }
}

fn developer_activity_header_flag_key(part: &str) -> bool {
    let normalized = part
        .trim_start_matches('-')
        .to_ascii_lowercase()
        .replace('_', "-");
    matches!(
        normalized.as_str(),
        "h" | "header" | "proxy-header" | "proxyheader"
    )
}

fn redact_developer_activity_header_flag_assignment_value(
    part: &str,
) -> Option<RedactedAuthorizationHeader> {
    let (flag, header) = part.split_once('=')?;
    if !developer_activity_header_flag_key(flag) {
        return None;
    }
    let header = header.trim();
    let redacted_header =
        redact_developer_activity_authorization_header_value(header).or_else(|| {
            let header_key = header.trim_end_matches(':');
            if developer_activity_authorization_header_key(header_key) {
                Some(RedactedAuthorizationHeader {
                    redacted: format!("{header_key}: [REDACTED]"),
                    consumes_next_token: true,
                })
            } else {
                None
            }
        })?;
    Some(RedactedAuthorizationHeader {
        redacted: format!("{flag}={}", redacted_header.redacted),
        consumes_next_token: redacted_header.consumes_next_token,
    })
}

fn redact_developer_activity_authorization_header_value(
    part: &str,
) -> Option<RedactedAuthorizationHeader> {
    let (key, value) = part.split_once(':')?;
    if !developer_activity_authorization_header_key(key) {
        return None;
    }
    let trimmed_value = value.trim();
    if trimmed_value.is_empty() {
        return None;
    }
    let mut value_parts = trimmed_value.split_whitespace();
    let first = value_parts.next()?;
    if developer_activity_authorization_scheme_marker(first) {
        Some(RedactedAuthorizationHeader {
            redacted: format!("{key}: {first} [REDACTED]"),
            consumes_next_token: value_parts.next().is_none(),
        })
    } else {
        Some(RedactedAuthorizationHeader {
            redacted: format!("{key}: [REDACTED]"),
            consumes_next_token: false,
        })
    }
}

fn developer_activity_authorization_scheme_marker(part: &str) -> bool {
    let normalized = part.trim_end_matches(':');
    matches!(
        normalized.to_ascii_lowercase().as_str(),
        "apikey"
            | "api-key"
            | "aws4-hmac-sha256"
            | "basic"
            | "bearer"
            | "digest"
            | "hawk"
            | "mac"
            | "negotiate"
            | "ntlm"
            | "oauth"
            | "oauth2"
            | "sharedkey"
            | "signature"
            | "token"
    )
}

fn developer_activity_sensitive_flag_without_value(part: &str) -> bool {
    let trimmed = part.trim_end_matches(':');
    if trimmed.contains('=') || !trimmed.starts_with('-') {
        return false;
    }
    developer_activity_sensitive_key(trimmed)
}

fn redact_developer_activity_sensitive_assignment(
    part: &str,
) -> Option<RedactedSensitiveAssignment> {
    let (key, value) = part.split_once('=')?;
    if key.is_empty()
        || key.contains(['?', '&', ';', '/', '\\'])
        || !developer_activity_sensitive_key(key)
    {
        return None;
    }
    if developer_activity_authorization_scheme_marker(value) {
        Some(RedactedSensitiveAssignment {
            redacted: part.to_string(),
            consumes_next_token: true,
        })
    } else {
        Some(RedactedSensitiveAssignment {
            redacted: format!("{key}=[REDACTED]"),
            consumes_next_token: false,
        })
    }
}

fn redact_developer_activity_command_part(part: &str) -> String {
    let part = redact_developer_activity_url_userinfo(part);
    let part = redact_developer_activity_jsonish_secret_fields(&part);
    if !part.contains('=') {
        return if developer_activity_secret_like_value(&part) {
            "[REDACTED]".to_string()
        } else {
            part
        };
    }
    let mut redacted = String::with_capacity(part.len());
    let mut remaining = part.as_str();
    while let Some(equal_index) = remaining.find('=') {
        let before_equal = &remaining[..equal_index];
        let key_start = before_equal
            .rfind(['?', '&', ';', '/', '\\'])
            .map_or(0, |position| position + 1);
        let key = &before_equal[key_start..];
        if key.is_empty() || !developer_activity_sensitive_key(key) {
            redacted.push_str(&remaining[..=equal_index]);
            remaining = &remaining[equal_index + 1..];
            continue;
        }

        redacted.push_str(before_equal);
        redacted.push_str("=[REDACTED]");
        let value_start = equal_index + 1;
        let value_end = remaining[value_start..]
            .find(['&', ';'])
            .map_or(remaining.len(), |offset| value_start + offset);
        remaining = &remaining[value_end..];
    }
    redacted.push_str(remaining);
    redacted
}

fn redact_developer_activity_jsonish_secret_fields(part: &str) -> String {
    let bytes = part.as_bytes();
    let mut redacted = String::with_capacity(part.len());
    let mut cursor = 0;
    let mut index = 0;
    while index < bytes.len() {
        let quote = bytes[index];
        if quote != b'\'' && quote != b'"' {
            index += 1;
            continue;
        }
        let Some(key_end) = find_unescaped_ascii_quote(bytes, index + 1, quote) else {
            break;
        };
        let key = &part[index + 1..key_end];
        let mut colon_index = key_end + 1;
        while colon_index < bytes.len() && bytes[colon_index].is_ascii_whitespace() {
            colon_index += 1;
        }
        if colon_index >= bytes.len()
            || bytes[colon_index] != b':'
            || !developer_activity_sensitive_metadata_key(key)
        {
            index += 1;
            continue;
        }

        let mut value_start = colon_index + 1;
        while value_start < bytes.len() && bytes[value_start].is_ascii_whitespace() {
            value_start += 1;
        }
        if value_start >= bytes.len() {
            index = value_start;
            continue;
        }

        redacted.push_str(&part[cursor..value_start]);
        let value_quote = bytes[value_start];
        if value_quote == b'\'' || value_quote == b'"' {
            redacted.push(value_quote as char);
            redacted.push_str("[REDACTED]");
            let Some(value_end) = find_unescaped_ascii_quote(bytes, value_start + 1, value_quote)
            else {
                cursor = bytes.len();
                break;
            };
            redacted.push(value_quote as char);
            cursor = value_end + 1;
            index = cursor;
        } else {
            redacted.push_str("[REDACTED]");
            let value_end = bytes[value_start..]
                .iter()
                .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b',' | b'}' | b']'))
                .map_or(bytes.len(), |offset| value_start + offset);
            cursor = value_end;
            index = cursor;
        }
    }
    if cursor == 0 {
        part.to_string()
    } else {
        redacted.push_str(&part[cursor..]);
        redacted
    }
}

fn find_unescaped_ascii_quote(bytes: &[u8], start: usize, quote: u8) -> Option<usize> {
    let mut escaped = false;
    for (offset, byte) in bytes.iter().enumerate().skip(start) {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == quote {
            return Some(offset);
        }
    }
    None
}

fn redact_developer_activity_url_userinfo(part: &str) -> String {
    let Some(scheme_end) = part.find("://") else {
        return part.to_string();
    };
    let authority_start = scheme_end + 3;
    let authority_end = part[authority_start..]
        .find(['/', '?', '#'])
        .map_or(part.len(), |offset| authority_start + offset);
    let authority = &part[authority_start..authority_end];
    let Some(at_index) = authority.rfind('@') else {
        return part.to_string();
    };
    let userinfo = &authority[..at_index];
    let Some(colon_index) = userinfo.find(':') else {
        return format!(
            "{}[REDACTED]{}",
            &part[..authority_start],
            &part[authority_start + at_index..]
        );
    };
    let password = &userinfo[colon_index + 1..];
    if password.is_empty() {
        return part.to_string();
    }

    let password_start = authority_start + colon_index + 1;
    let password_end = authority_start + at_index;
    format!(
        "{}[REDACTED]{}",
        &part[..password_start],
        &part[password_end..]
    )
}

pub(crate) fn developer_activity_sensitive_key(key: &str) -> bool {
    let normalized_key = key
        .trim_start_matches('-')
        .rsplit(['?', '&', '/', '\\'])
        .next()
        .unwrap_or(key)
        .to_ascii_lowercase()
        .replace(['-', '_'], "");
    matches!(normalized_key.as_str(), "p" | "passwd")
        || normalized_key == "authorization"
        || normalized_key == "cookie"
        || normalized_key.ends_with("token")
        || normalized_key.ends_with("secret")
        || normalized_key.ends_with("password")
        || normalized_key.ends_with("credential")
        || normalized_key.ends_with("credentials")
        || normalized_key.ends_with("apikey")
        || normalized_key.ends_with("authkey")
        || normalized_key.ends_with("privatekey")
        || (normalized_key.contains("secret") && normalized_key.ends_with("key"))
}

pub(crate) fn developer_activity_secret_like_value(value: &str) -> bool {
    let value = value.trim();
    if value.contains("-----BEGIN ") && value.contains("PRIVATE KEY-----") {
        return true;
    }
    if value.starts_with("AKIA")
        && value.len() >= 20
        && value
            .chars()
            .skip(4)
            .take(16)
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit())
    {
        return true;
    }
    [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
    ]
    .iter()
    .any(|prefix| value.starts_with(prefix) && value.len() >= prefix.len() + 20)
}
