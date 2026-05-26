//! KDE Plasma env scripts and KDE autostart-scripts persistence-target bounds.

use std::path::Path;

use crate::util::cron_spool_user_name_is_safe;

/// `~/.config/plasma-workspace/env/*.sh`.
pub(crate) fn path_is_bounded_plasma_env_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !plasma_env_script_file_name_is_safe(file_name) {
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
    plasma_env_components_are_bounded(&components, file_name)
}

pub(crate) fn plasma_env_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 6 {
        return false;
    }
    let base = components.len() - 6;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "plasma-workspace"
        && components[base + 4] == "env"
        && components[base + 5] == file_name
}

fn plasma_env_script_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "sh"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// `~/.config/autostart-scripts/*.sh`.
pub(crate) fn path_is_bounded_kde_autostart_script_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !plasma_env_script_file_name_is_safe(file_name) {
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
    kde_autostart_script_components_are_bounded(&components, file_name)
}

pub(crate) fn kde_autostart_script_components_are_bounded(
    components: &[&str],
    file_name: &str,
) -> bool {
    if components.len() < 5 {
        return false;
    }
    let base = components.len() - 5;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "autostart-scripts"
        && components[base + 4] == file_name
}
