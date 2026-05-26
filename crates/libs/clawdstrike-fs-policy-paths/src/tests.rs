//! Behavioural tests ported from the agent's `api_server::tests` module when
//! the path validators were extracted into this crate. Tests cover every OS
//! persistence-target family the aggregator accepts.

use std::path::Path as FsPath;

use crate::path_is_bounded_persistence_target;

#[test]
fn bounded_shell_startup_persistence_targets_are_user_home_files_only() {
    let temp_shell =
        std::env::temp_dir().join("clawdstrike-shell-targets/home/alice/.config/fish/config.fish");
    let temp_fish_conf_d = std::env::temp_dir()
        .join("clawdstrike-shell-targets/home/alice/.config/fish/conf.d/evil-agent.fish");
    assert!(path_is_bounded_persistence_target(&temp_shell));
    assert!(path_is_bounded_persistence_target(&temp_fish_conf_d));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.bashrc"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.zprofile"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/fish/config.fish"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/fish/conf.d/evil-agent.fish"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/.zshrc"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/.config/fish/config.fish"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/.config/fish/conf.d/evil-agent.fish"
    )));

    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/root/.bashrc"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/nobody/.profile"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/bad user/.bashrc"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.ssh/rc"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.bashrc.d/evil.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/fish/conf.d/.hidden.fish"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/fish/conf.d/clawdstrike.fish"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/fish/conf.d/config.fish"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/fish/conf.d/evil agent.fish"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/fish/conf.d/evil-agent.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/profile"
    )));
}

#[test]
fn bounded_cron_persistence_targets_are_user_crontabs_or_system_dropins_only() {
    let temp_crontab =
        std::env::temp_dir().join("clawdstrike-cron-targets/var/spool/cron/crontabs/alice");
    let temp_dropin = std::env::temp_dir().join("clawdstrike-cron-targets/etc/cron.d/evil");
    assert!(path_is_bounded_persistence_target(&temp_crontab));
    assert!(path_is_bounded_persistence_target(&temp_dropin));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/var/spool/cron/alice"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/usr/lib/cron/tabs/alice"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/etc/cron.d/evil-agent"
    )));

    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/crontab"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/cron.d/.hidden"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/cron.d/clawdstrike"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/cron.hourly/evil"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/var/spool/cron/root"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/var/spool/cron/nobody"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/var/spool/cron/bad user"
    )));
}

#[test]
fn bounded_profile_d_persistence_targets_are_system_shell_dropins_only() {
    let temp_profile_dropin =
        std::env::temp_dir().join("clawdstrike-profile-targets/etc/profile.d/evil-agent.sh");
    assert!(path_is_bounded_persistence_target(&temp_profile_dropin));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/etc/profile.d/evil-agent.sh"
    )));

    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/profile"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/profile.d/.hidden.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/profile.d/clawdstrike.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/profile.d/bash_completion.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/profile.d/evil agent.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/profile.d/evil-agent.txt"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/usr/local/etc/profile.d/evil-agent.sh"
    )));
}

#[test]
fn bounded_systemd_persistence_targets_are_user_or_system_units_only() {
    let temp_unit = std::env::temp_dir()
        .join("clawdstrike-systemd-targets/home/alice/.config/systemd/user/evil.service");
    let temp_system_unit = std::env::temp_dir()
        .join("clawdstrike-systemd-targets/etc/systemd/system/evil-agent.service");
    let temp_user_dropin = std::env::temp_dir().join(
        "clawdstrike-systemd-targets/home/alice/.config/systemd/user/evil.service.d/override.conf",
    );
    let temp_system_dropin = std::env::temp_dir()
        .join("clawdstrike-systemd-targets/etc/systemd/system/evil-agent.service.d/override.conf");
    assert!(path_is_bounded_persistence_target(&temp_unit));
    assert!(path_is_bounded_persistence_target(&temp_system_unit));
    assert!(path_is_bounded_persistence_target(&temp_user_dropin));
    assert!(path_is_bounded_persistence_target(&temp_system_dropin));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/systemd/user/evil.timer"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/.config/systemd/user/evil.socket"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/etc/systemd/system/evil-agent.service"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/etc/systemd/system/evil-agent.timer.d/10-env.conf"
    )));

    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/lib/systemd/system/evil.service"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/root/.config/systemd/user/evil.service"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/systemd/system/evil.service"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/systemd/user/evil path.service"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/systemd/user/evil.conf"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/systemd/user/evil.service.d/override.txt"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/systemd/user/evil.conf.d/override.conf"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/systemd/system/ssh.service"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/systemd/system/ssh.service.d/override.conf"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/systemd/system/systemd-resolved.service"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/systemd/system/systemd-resolved.service.d/override.conf"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/systemd/system/clawdstrike.service"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/systemd/system/evil-agent.service.d/clawdstrike.conf"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/systemd/system/evil path.service"
    )));
}

#[test]
fn bounded_xdg_autostart_persistence_targets_are_desktop_entries_only() {
    let temp_user_autostart = std::env::temp_dir()
        .join("clawdstrike-xdg-targets/home/alice/.config/autostart/evil-agent.desktop");
    let temp_system_autostart =
        std::env::temp_dir().join("clawdstrike-xdg-targets/etc/xdg/autostart/evil.desktop");
    assert!(path_is_bounded_persistence_target(&temp_user_autostart));
    assert!(path_is_bounded_persistence_target(&temp_system_autostart));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/autostart/evil-agent.desktop"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/.config/autostart/evil-agent.desktop"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/etc/xdg/autostart/evil-agent.desktop"
    )));

    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/root/.config/autostart/evil-agent.desktop"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/autostart/evil-agent.txt"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/autostart/.hidden.desktop"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.local/share/applications/evil-agent.desktop"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/xdg/autostart/org.gnome.SettingsDaemon.DiskUtilityNotify.desktop"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/xdg/autostart/gnome-keyring-ssh.desktop"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/xdg/autostart/clawdstrike.desktop"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/xdg/autostart/evil agent.desktop"
    )));
}

#[test]
fn bounded_plasma_env_persistence_targets_are_user_scripts_only() {
    let temp_plasma_env = std::env::temp_dir().join(
        "clawdstrike-plasma-env-targets/home/alice/.config/plasma-workspace/env/evil-agent.sh",
    );
    assert!(path_is_bounded_persistence_target(&temp_plasma_env));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/plasma-workspace/env/evil-agent.sh"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/.config/plasma-workspace/env/evil-agent.sh"
    )));

    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/root/.config/plasma-workspace/env/evil-agent.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/plasma-workspace/env/.hidden.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/plasma-workspace/env/clawdstrike.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/plasma-workspace/env/evil agent.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/plasma-workspace/env/evil-agent.txt"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/xdg/plasma-workspace/env/evil-agent.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/plasma-workspace/shutdown/evil-agent.sh"
    )));
}

#[test]
fn bounded_kde_autostart_script_persistence_targets_are_user_scripts_only() {
    let temp_autostart_script = std::env::temp_dir().join(
        "clawdstrike-kde-autostart-script-targets/home/alice/.config/autostart-scripts/evil-agent.sh",
    );
    assert!(path_is_bounded_persistence_target(&temp_autostart_script));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/autostart-scripts/evil-agent.sh"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/.config/autostart-scripts/evil-agent.sh"
    )));

    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/root/.config/autostart-scripts/evil-agent.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/autostart-scripts/.hidden.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/autostart-scripts/clawdstrike.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/autostart-scripts/evil agent.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/autostart-scripts/evil-agent.desktop"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/etc/xdg/autostart-scripts/evil-agent.sh"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.config/autostart/evil-agent.sh"
    )));
}

#[test]
fn bounded_browser_extension_persistence_targets_are_manifest_files_only() {
    let temp_manifest = std::env::temp_dir().join(
        "clawdstrike-extension-targets/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/manifest.json",
    );
    let temp_firefox_manifest = std::env::temp_dir().join(
        "clawdstrike-extension-targets/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com/manifest.json",
    );
    assert!(path_is_bounded_persistence_target(&temp_manifest));
    assert!(path_is_bounded_persistence_target(&temp_firefox_manifest));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Microsoft Edge/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/2026.5.16/manifest.json"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default-release/extensions/{11111111-2222-4333-8444-555555555555}/manifest.json"
    )));
    assert!(path_is_bounded_persistence_target(FsPath::new(
        "/home/alice/.mozilla/firefox/dev.default/extensions/addon@example.com/manifest.json"
    )));

    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/background.js"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com/background.js"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com/nested/manifest.json"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/.hidden/manifest.json"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Firefox/Profiles/dev.default/extensions/addon@example.com.xpi"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Unknown Browser/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/manifest.json"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/../evil/manifest.json"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/Users/alice/Library/Application Support/Google/Chrome/Default/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/nested/manifest.json"
    )));
    assert!(!path_is_bounded_persistence_target(FsPath::new(
        "/Applications/Google Chrome.app/Contents/Extensions/abcdefghijklmnopabcdefghijklmnop/1.0.0/manifest.json"
    )));
}
