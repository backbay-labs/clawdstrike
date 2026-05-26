//! Shell startup, fish `conf.d`, and system `/etc/profile.d` bounds.

use std::path::Path;

use crate::util::{cron_spool_components_end_with, cron_spool_user_name_is_safe};

/// Shell startup files: `~/.bashrc`, `~/.bash_profile`, `~/.zshrc`,
/// `~/.zprofile`, `~/.profile`, and fish's `config.fish` / `conf.d/*.fish`.
pub(crate) fn path_is_bounded_shell_startup_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
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
    let user_home_like = normalized.starts_with("/Users/") || normalized.starts_with("/home/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    shell_startup_components_are_bounded(&components)
}

pub(crate) fn shell_startup_components_are_bounded(components: &[&str]) -> bool {
    let home_shell_file = if components.len() >= 3 {
        let base = components.len() - 3;
        let home_component = components[base];
        let user = components[base + 1];
        let file = components[base + 2];
        matches!(home_component, "Users" | "home")
            && cron_spool_user_name_is_safe(user)
            && matches!(
                file,
                ".bashrc" | ".bash_profile" | ".zshrc" | ".zprofile" | ".profile"
            )
    } else {
        false
    };
    let fish_config = if components.len() >= 5 {
        let base = components.len() - 5;
        let home_component = components[base];
        let user = components[base + 1];
        matches!(home_component, "Users" | "home")
            && cron_spool_user_name_is_safe(user)
            && components[base + 2] == ".config"
            && components[base + 3] == "fish"
            && components[base + 4] == "config.fish"
    } else {
        false
    };
    let fish_conf_d = if components.len() >= 6 {
        let base = components.len() - 6;
        let home_component = components[base];
        let user = components[base + 1];
        let file = components[base + 5];
        matches!(home_component, "Users" | "home")
            && cron_spool_user_name_is_safe(user)
            && components[base + 2] == ".config"
            && components[base + 3] == "fish"
            && components[base + 4] == "conf.d"
            && fish_conf_d_file_name_is_safe(file)
    } else {
        false
    };

    home_shell_file || fish_config || fish_conf_d
}

fn fish_conf_d_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "fish"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !matches!(stem.to_ascii_lowercase().as_str(), "config" | "conf")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

/// `/etc/profile.d/*.sh` system-wide shell drop-ins.
pub(crate) fn path_is_bounded_profile_d_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !profile_d_script_file_name_is_safe(file_name) {
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
    let system_profile_like = normalized.starts_with("/etc/profile.d/");
    if !temp_like && !system_profile_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["etc", "profile.d", file_name])
}

fn profile_d_script_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    let normalized_stem = stem.to_ascii_lowercase();
    extension == "sh"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !normalized_stem.starts_with("clawdstrike.")
        && !normalized_stem.starts_with("com.clawdstrike.")
        && !matches!(
            normalized_stem.as_str(),
            "bash_completion"
                | "colorgrep"
                | "colorls"
                | "lang"
                | "locale"
                | "proxy"
                | "ssh-agent"
                | "systemd"
        )
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
