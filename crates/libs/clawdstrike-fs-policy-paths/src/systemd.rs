//! systemd user + system unit and drop-in persistence-target bounds.

use std::path::Path;

use crate::util::{cron_spool_components_end_with, cron_spool_user_name_is_safe};

/// `~/.config/systemd/user/<unit>.{service,timer,socket}`.
pub(crate) fn path_is_bounded_systemd_user_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_unit_file_name_is_safe(file_name) {
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
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    systemd_user_unit_components_are_bounded(&components, file_name)
}

pub(crate) fn systemd_user_unit_components_are_bounded(
    components: &[&str],
    file_name: &str,
) -> bool {
    if components.len() < 6 {
        return false;
    }
    let base = components.len() - 6;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "systemd"
        && components[base + 4] == "user"
        && components[base + 5] == file_name
}

/// `~/.config/systemd/user/<unit>.{service,timer,socket}.d/<dropin>.conf`.
pub(crate) fn path_is_bounded_systemd_user_dropin_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_dropin_file_name_is_safe(file_name) {
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
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    systemd_user_dropin_components_are_bounded(&components, file_name)
}

pub(crate) fn systemd_user_dropin_components_are_bounded(
    components: &[&str],
    file_name: &str,
) -> bool {
    if components.len() < 7 {
        return false;
    }
    let base = components.len() - 7;
    let home_component = components[base];
    let user = components[base + 1];
    let unit_dir = components[base + 5];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "systemd"
        && components[base + 4] == "user"
        && systemd_unit_dropin_dir_name_is_safe(unit_dir)
        && components[base + 6] == file_name
}

/// `/etc/systemd/system/<unit>.{service,timer,socket}`.
pub(crate) fn path_is_bounded_systemd_system_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_system_unit_file_name_is_safe(file_name) {
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
    let system_unit_like = normalized.starts_with("/etc/systemd/system/");
    if !temp_like && !system_unit_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["etc", "systemd", "system", file_name])
}

/// `/etc/systemd/system/<unit>.{service,timer,socket}.d/<dropin>.conf`.
pub(crate) fn path_is_bounded_systemd_system_dropin_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_dropin_file_name_is_safe(file_name) {
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
    let system_unit_like = normalized.starts_with("/etc/systemd/system/");
    if !temp_like && !system_unit_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    systemd_system_dropin_components_are_bounded(&components, file_name)
}

pub(crate) fn systemd_system_dropin_components_are_bounded(
    components: &[&str],
    file_name: &str,
) -> bool {
    if components.len() < 5 {
        return false;
    }
    let base = components.len() - 5;
    let unit_dir = components[base + 3];
    components[base] == "etc"
        && components[base + 1] == "systemd"
        && components[base + 2] == "system"
        && systemd_system_unit_dropin_dir_name_is_safe(unit_dir)
        && components[base + 4] == file_name
}

fn systemd_unit_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    matches!(extension, "service" | "timer" | "socket")
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
}

fn systemd_unit_dropin_dir_name_is_safe(dir_name: &str) -> bool {
    dir_name
        .strip_suffix(".d")
        .is_some_and(systemd_unit_file_name_is_safe)
}

fn systemd_system_unit_dropin_dir_name_is_safe(dir_name: &str) -> bool {
    dir_name
        .strip_suffix(".d")
        .is_some_and(systemd_system_unit_file_name_is_safe)
}

fn systemd_dropin_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "conf"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
}

fn systemd_system_unit_file_name_is_safe(file_name: &str) -> bool {
    if !systemd_unit_file_name_is_safe(file_name) {
        return false;
    }
    let stem = file_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(file_name);
    let normalized_stem = stem.to_ascii_lowercase();
    if normalized_stem.starts_with("systemd")
        || normalized_stem.starts_with("getty")
        || normalized_stem.starts_with("serial-getty")
        || normalized_stem.starts_with("clawdstrike")
        || normalized_stem.starts_with("com.clawdstrike")
        || normalized_stem.starts_with("io.clawdstrike")
    {
        return false;
    }
    !matches!(
        normalized_stem.as_str(),
        "ssh"
            | "sshd"
            | "cron"
            | "crond"
            | "dbus"
            | "networkmanager"
            | "networking"
            | "containerd"
            | "docker"
            | "kubelet"
            | "login"
            | "sudo"
            | "polkit"
    )
}
