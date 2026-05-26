//! Process tree signal validation and Unix signal helpers.
//!
//! Rejects unsafe signal targets (pid 0/1, the current agent, its parent,
//! and protected system processes), verifies that durable identity bindings
//! still match the live pid, and provides Unix `kill`-based signal dispatch
//! for suspend/resume operations.

use super::*;

pub(crate) fn validate_process_signal_targets(targets: &[ProcessSignalTarget]) -> Result<()> {
    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "process tree has no signalable process nodes"
        ));
    }
    let current_pid = std::process::id();
    let parent_pid = current_parent_pid();
    for target in targets {
        if target.pid == 0 || target.pid == 1 {
            return Err(anyhow::anyhow!(
                "refusing to signal protected pid {}",
                target.pid
            ));
        }
        if target.pid == current_pid {
            return Err(anyhow::anyhow!("refusing to signal current agent process"));
        }
        if Some(target.pid) == parent_pid {
            return Err(anyhow::anyhow!("refusing to signal parent process"));
        }
        if process_label_is_protected(&target.label) {
            return Err(anyhow::anyhow!(
                "refusing to signal protected process label {}",
                target.label
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_process_signal_target_before_signal(
    target: &ProcessSignalTarget,
) -> Result<()> {
    validate_process_identity_binding(target.pid, Some(target.process_identity_key.as_str()))?;
    check_process_signalable(target.pid)
}

pub(crate) fn validate_process_effect_signal_target_before_signal(
    target: &ProcessTreeEffectSignalTarget,
) -> Result<()> {
    validate_process_identity_binding(target.pid, target.process_identity_key.as_deref())?;
    check_process_signalable(target.pid)
}

pub(crate) fn validate_process_identity_binding(
    pid: u32,
    identity_key: Option<&str>,
) -> Result<()> {
    let identity_key = identity_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing durable process identity binding"))?;
    if !identity_key.starts_with("guid:") {
        return Err(anyhow::anyhow!(
            "process identity binding is not durable: {identity_key}"
        ));
    }
    if let Some(rest) = identity_key.strip_prefix("guid:macos:") {
        let Some(identity_pid) = rest.split(':').next() else {
            return Err(anyhow::anyhow!("macOS process identity is missing pid"));
        };
        let identity_pid = identity_pid
            .parse::<u32>()
            .with_context(|| format!("parse macOS process identity pid {identity_pid}"))?;
        if identity_pid != pid {
            return Err(anyhow::anyhow!(
                "macOS process identity pid {identity_pid} does not match live target pid {pid}"
            ));
        }
    }
    Ok(())
}

fn process_label_is_protected(label: &str) -> bool {
    let normalized = label.to_ascii_lowercase();
    [
        "kernel_task",
        "launchd",
        "loginwindow",
        "windowserver",
        "systemuiserver",
        "tccd",
        "syspolicyd",
        "systemextensiond",
        "networkextensiond",
        "clawdstrike",
    ]
    .iter()
    .any(|protected| normalized.contains(protected))
}

#[cfg(unix)]
fn current_parent_pid() -> Option<u32> {
    let pid = unsafe { libc::getppid() };
    u32::try_from(pid).ok()
}

#[cfg(not(unix))]
fn current_parent_pid() -> Option<u32> {
    None
}

#[cfg(unix)]
pub(crate) fn process_suspend_signal() -> i32 {
    libc::SIGSTOP
}

#[cfg(not(unix))]
pub(crate) fn process_suspend_signal() -> i32 {
    0
}

#[cfg(unix)]
pub(crate) fn process_resume_signal() -> i32 {
    libc::SIGCONT
}

#[cfg(not(unix))]
pub(crate) fn process_resume_signal() -> i32 {
    0
}

#[cfg(unix)]
fn check_process_signalable(pid: u32) -> Result<()> {
    signal_process(pid, 0)
}

#[cfg(not(unix))]
fn check_process_signalable(_pid: u32) -> Result<()> {
    Err(anyhow::anyhow!(
        "process signalling is only supported on Unix platforms"
    ))
}

#[cfg(unix)]
pub(crate) fn signal_process(pid: u32, signal: i32) -> Result<()> {
    let pid = i32::try_from(pid).context("pid exceeds platform signal range")?;
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).with_context(|| {
            if signal == 0 {
                format!("check signal permission for pid {pid}")
            } else {
                format!("send signal {signal} to pid {pid}")
            }
        })
    }
}

#[cfg(not(unix))]
pub(crate) fn signal_process(_pid: u32, _signal: i32) -> Result<()> {
    Err(anyhow::anyhow!(
        "process signalling is only supported on Unix platforms"
    ))
}
