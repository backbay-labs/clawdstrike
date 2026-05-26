//! Small internal helpers shared between persistence-target families.

/// Returns `true` if the trailing slice of `components` equals `suffix`.
pub(crate) fn cron_spool_components_end_with(components: &[&str], suffix: &[&str]) -> bool {
    components.len() >= suffix.len()
        && components[components.len() - suffix.len()..]
            .iter()
            .zip(suffix.iter())
            .all(|(left, right)| left == right)
}

/// Bounds the set of acceptable user-name path components (rejects empty,
/// dotfiles, privileged accounts, and anything containing non-portable bytes).
pub(crate) fn cron_spool_user_name_is_safe(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && !user.starts_with('.')
        && !matches!(user, "root" | "daemon" | "nobody")
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
