/// Canonical commandline encoding for `PolicyEvent` `command_exec` mapping.
///
/// This intentionally matches the behavior of Python's `shlex.quote` applied to each token
/// (command and args), joined with a single ASCII space.
///
/// Safe characters (not quoted): `A-Za-z0-9_@%+=:,./-`
pub(crate) fn canonical_shell_commandline(command: &str, args: &[String]) -> String {
    let mut out = canonical_shell_word(command);
    for arg in args {
        out.push(' ');
        out.push_str(&canonical_shell_word(arg));
    }
    out
}

pub(crate) fn canonical_shell_word(word: &str) -> String {
    if word.is_empty() {
        return "''".to_string();
    }

    if is_safe_shell_word(word) {
        return word.to_string();
    }

    let mut out = String::with_capacity(word.len() + 2);
    out.push('\'');

    for part in word.split('\'') {
        out.push_str(part);
        out.push_str("'\"'\"'");
    }

    out.truncate(out.len().saturating_sub("'\"'\"'".len()));
    out.push('\'');
    out
}

fn is_safe_shell_word(word: &str) -> bool {
    word.bytes().all(|b| {
        matches!(
            b,
            b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'_'
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'@'
                | b'%'
                | b'+'
                | b'='
                | b','
        )
    })
}
