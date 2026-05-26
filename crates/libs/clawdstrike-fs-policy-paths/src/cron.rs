//! User crontab spools and `/etc/cron.d/*` system drop-in bounds.

use std::path::Path;

use crate::util::{cron_spool_components_end_with, cron_spool_user_name_is_safe};

/// `/var/spool/cron/[crontabs/]<user>` or `/usr/lib/cron/tabs/<user>`.
pub(crate) fn path_is_bounded_cron_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(user) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !cron_spool_user_name_is_safe(user) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_cron_like =
        normalized.starts_with("/var/spool/cron/") || normalized.starts_with("/usr/lib/cron/tabs/");
    if !temp_like && !system_cron_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["var", "spool", "cron", "crontabs", user])
        || cron_spool_components_end_with(&components, &["var", "spool", "cron", user])
        || cron_spool_components_end_with(&components, &["usr", "lib", "cron", "tabs", user])
}

/// `/etc/cron.d/*` drop-in files.
pub(crate) fn path_is_bounded_system_cron_dropin_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !cron_dropin_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_cron_dropin_like = normalized.starts_with("/etc/cron.d/");
    if !temp_like && !system_cron_dropin_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["etc", "cron.d", file_name])
}

fn cron_dropin_file_name_is_safe(file_name: &str) -> bool {
    let normalized = file_name.to_ascii_lowercase();
    !file_name.is_empty()
        && file_name.len() <= 128
        && !file_name.starts_with('.')
        && !matches!(
            normalized.as_str(),
            "0hourly" | "anacron" | "cron" | "cronie" | "clawdstrike"
        )
        && !normalized.starts_with("clawdstrike.")
        && !normalized.starts_with("com.clawdstrike.")
        && file_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
