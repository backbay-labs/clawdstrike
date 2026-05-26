//! Pure filesystem path validators for OS persistence-target boundaries.
//!
//! These functions accept `&Path` (or string components) and return `bool`. They
//! perform no IO, hold no state, and depend on nothing outside `std`. They are
//! consumed by:
//!
//! * the agent enforcer (`apps/agent/src-tauri`) when evaluating proposed
//!   `disable_persistence` actions before they touch the filesystem;
//! * the control-plane validator (planned consumer) when scoring response-action
//!   proposals from policy receipts so the two never drift on what a "bounded
//!   persistence target" means.
//!
//! Only [`path_is_bounded_persistence_target`] is part of the public API. Every
//! helper module is `pub(crate)` because the consumers should only depend on the
//! aggregate semantics, never on individual operating-system families.
//!
//! # Coverage
//!
//! The aggregate predicate accepts paths matching any of these OS persistence
//! footholds (and rejects everything else):
//!
//! * macOS LaunchAgents / LaunchDaemons (`.plist`)
//! * systemd user + system unit files and drop-ins (`.service`, `.timer`,
//!   `.socket`, `.d/.conf`)
//! * XDG user + system autostart desktop entries (`.desktop`)
//! * KDE Plasma session env scripts and autostart scripts (`.sh`)
//! * Shell startup files (`.bashrc`, `.zshrc`, fish `config.fish` + `conf.d`)
//! * System profile.d drop-ins (`/etc/profile.d/*.sh`)
//! * User crontabs (`/var/spool/cron`, `/usr/lib/cron/tabs`) and system
//!   `/etc/cron.d/*` drop-ins
//! * Chromium/Edge/Brave/Firefox extension manifests
//!
//! Temp-rooted variants of each are accepted as well, so the predicate is safe
//! to use inside unit tests that stage the path under `std::env::temp_dir()`.

#![forbid(unsafe_code)]

use std::path::Path;

mod browser;
mod cron;
mod launch;
mod plasma;
mod shell;
mod systemd;
mod util;
mod xdg;

/// Returns `true` if `path` points at one of the bounded OS persistence
/// footholds that this crate knows how to disable.
///
/// The aggregate predicate is the union of the per-family predicates defined in
/// the (private) submodules. Callers should depend on the aggregate, not the
/// per-family details, so the supported set can grow without breaking
/// consumers.
#[must_use]
pub fn path_is_bounded_persistence_target(path: &Path) -> bool {
    launch::path_is_bounded_launch_persistence_target(path)
        || systemd::path_is_bounded_systemd_user_persistence_target(path)
        || systemd::path_is_bounded_systemd_system_persistence_target(path)
        || systemd::path_is_bounded_systemd_user_dropin_persistence_target(path)
        || systemd::path_is_bounded_systemd_system_dropin_persistence_target(path)
        || xdg::path_is_bounded_xdg_autostart_persistence_target(path)
        || plasma::path_is_bounded_plasma_env_persistence_target(path)
        || plasma::path_is_bounded_kde_autostart_script_persistence_target(path)
        || shell::path_is_bounded_shell_startup_persistence_target(path)
        || shell::path_is_bounded_profile_d_persistence_target(path)
        || cron::path_is_bounded_cron_persistence_target(path)
        || cron::path_is_bounded_system_cron_dropin_persistence_target(path)
        || browser::path_is_bounded_browser_extension_manifest_target(path)
}

#[cfg(test)]
mod tests;
