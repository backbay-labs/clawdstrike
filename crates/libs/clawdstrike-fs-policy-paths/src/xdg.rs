//! XDG user + system autostart persistence-target bounds.

use std::path::Path;

use crate::util::{cron_spool_components_end_with, cron_spool_user_name_is_safe};

/// `~/.config/autostart/*.desktop` or `/etc/xdg/autostart/*.desktop`.
pub(crate) fn path_is_bounded_xdg_autostart_persistence_target(path: &Path) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !xdg_autostart_desktop_file_name_is_safe(file_name) {
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
    let system_autostart_like = normalized.starts_with("/etc/xdg/autostart/");
    if !temp_like && !user_home_like && !system_autostart_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    xdg_user_autostart_components_are_bounded(&components, file_name)
        || xdg_system_autostart_components_are_bounded(&components, file_name)
}

pub(crate) fn xdg_user_autostart_components_are_bounded(
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
        && components[base + 3] == "autostart"
        && components[base + 4] == file_name
}

pub(crate) fn xdg_system_autostart_components_are_bounded(
    components: &[&str],
    file_name: &str,
) -> bool {
    cron_spool_components_end_with(components, &["etc", "xdg", "autostart", file_name])
        && xdg_system_autostart_desktop_file_name_is_safe(file_name)
}

fn xdg_autostart_desktop_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "desktop"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn xdg_system_autostart_desktop_file_name_is_safe(file_name: &str) -> bool {
    if !xdg_autostart_desktop_file_name_is_safe(file_name) {
        return false;
    }
    let stem = file_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(file_name)
        .to_ascii_lowercase();
    if stem.starts_with("org.gnome.")
        || stem.starts_with("org.kde.")
        || stem.starts_with("org.freedesktop.")
        || stem.starts_with("gnome-keyring")
        || stem.starts_with("clawdstrike")
    {
        return false;
    }
    !matches!(
        stem.as_str(),
        "polkit" | "dbus" | "ssh-agent" | "at-spi-dbus-bus" | "xdg-user-dirs" | "nm-applet"
    )
}
