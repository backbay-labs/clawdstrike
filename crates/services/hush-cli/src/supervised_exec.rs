//! Supervised execution with nono sandbox + ClawdStrike guard enforcement.
//!
//! Uses nono's supervisor IPC to route file operations through guards
//! for real-time allow/deny decisions at the kernel level.
//!
//! # Process model
//!
//! 1. Pre-fork: create supervisor socket pair, prepare C strings
//! 2. Fork
//! 3. Child: close inherited fds (except child socket), apply static sandbox, exec
//! 4. Parent: run supervisor loop on dedicated OS thread, forward signals, wait
//!
//! # Platform differences
//!
//! - **Linux**: seccomp-notify intercepts openat/openat2; supervisor receives
//!   notify fd from child and runs the recv_notif loop
//! - **macOS**: extension-based flow; child sends CapabilityRequests over the
//!   supervisor socket, supervisor issues extension tokens

use std::collections::HashMap;
use std::sync::Arc;

use clawdstrike::sandbox::{SupervisorStats, TimestampedDenial};
use clawdstrike::{GuardContext, HushEngine};
use nono::{CapabilitySet, NeverGrantChecker};

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use clawdstrike::sandbox::supervisor::GuardSupervisorBackend;
#[cfg(target_os = "linux")]
use nono::sandbox::{
    classify_access_from_flags, deny_notif, inject_fd, install_seccomp_notify, notif_id_valid,
    read_notif_path, read_open_how, recv_notif, validate_openat2_size, SeccompNotif, SYS_OPENAT2,
};
#[cfg(target_os = "linux")]
use nono::{ApprovalBackend, ApprovalDecision, SupervisorSocket};

#[cfg(target_os = "linux")]
use crate::sandbox_nono;

/// Result of supervised execution.
pub struct SupervisedResult {
    pub exit_code: i32,
    pub sandbox_applied: bool,
    pub supervised_active: bool,
    pub sandbox_error: Option<String>,
    pub stats: SupervisorStats,
    pub denials: Vec<TimestampedDenial>,
}

/// Spawn a supervised child process.
///
/// The supervisor intercepts file operations and routes them through
/// ClawdStrike guards for real-time enforcement.
///
/// # Safety
///
/// After `fork()`, the child process uses only async-signal-safe
/// operations. See `sandbox_nono.rs` for the same pattern.
pub fn spawn_supervised_child(
    caps: &CapabilitySet,
    command: &[String],
    env_overrides: &HashMap<String, String>,
    engine: Arc<HushEngine>,
    context: GuardContext,
    never_grant: NeverGrantChecker,
) -> anyhow::Result<SupervisedResult> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (caps, command, env_overrides, engine, context, never_grant);
        anyhow::bail!(
            "--supervised requires Linux seccomp user notifications; refusing to fall back to static sandboxing on this platform"
        );
    }

    #[cfg(target_os = "linux")]
    {
        use nix::unistd::ForkResult;

        if command.is_empty() {
            anyhow::bail!("empty command");
        }

        // Create supervisor socket pair
        let (supervisor_sock, child_sock) = SupervisorSocket::pair()
            .map_err(|e| anyhow::anyhow!("failed to create supervisor socket: {e}"))?;

        // Pre-fork: resolve command through PATH (execve does NOT do PATH lookup)
        let resolved = sandbox_nono::resolve_command_path_pub(&command[0])?;
        let c_program =
            CString::new(resolved.as_str()).map_err(|e| anyhow::anyhow!("invalid command: {e}"))?;
        let c_args: Vec<CString> = command
            .iter()
            .map(|a| CString::new(a.as_str()).map_err(|e| anyhow::anyhow!("invalid arg: {e}")))
            .collect::<Result<_, _>>()?;

        let mut env_map: HashMap<String, String> = std::env::vars().collect();
        for (k, v) in env_overrides {
            env_map.insert(k.clone(), v.clone());
        }
        let c_env: Vec<CString> = env_map
            .iter()
            .map(|(k, v)| {
                CString::new(format!("{k}={v}")).map_err(|e| anyhow::anyhow!("invalid env: {e}"))
            })
            .collect::<Result<_, _>>()?;

        let child_sock_fd = child_sock.as_raw_fd();
        let (status_read, status_write) = sandbox_nono::create_status_pipe()?;
        let status_write_fd = status_write.as_raw_fd();

        // Pre-fork: build CStr reference slices so the child does no heap allocation.
        // After fork in a multithreaded process, malloc may deadlock on inherited locks.
        let c_args_ref: Vec<&std::ffi::CStr> = c_args.iter().map(|a| a.as_c_str()).collect();
        let c_env_ref: Vec<&std::ffi::CStr> = c_env.iter().map(|e| e.as_c_str()).collect();

        // SAFETY: fork() is safe. After fork in the child, we only use
        // async-signal-safe operations (no allocation, no panic, no `?`).
        match unsafe { nix::unistd::fork() }.map_err(|e| anyhow::anyhow!("fork failed: {e}"))? {
            ForkResult::Child => {
                // CHILD: async-signal-safe only from here.
                // No ? operator, no panic!, no allocation.

                // Close supervisor_sock fd directly instead of Drop (which may deallocate)
                // SAFETY: close is async-signal-safe
                unsafe { libc::close(supervisor_sock.as_raw_fd()) };
                unsafe { libc::close(status_read.as_raw_fd()) };

                // Close inherited fds except stdin/stdout/stderr, child socket, and
                // the bootstrap status pipe that reports setup/apply failures.
                sandbox_nono::close_inherited_fds_except(3, &[child_sock_fd, status_write_fd]);

                let notify_fd = match install_seccomp_notify() {
                    Ok(fd) => fd,
                    Err(_) => {
                        sandbox_nono::write_child_status(
                            status_write_fd,
                            sandbox_nono::supervision_setup_failed_status(),
                        );
                        const MSG: &[u8] = b"nono: supervised interception setup failed\n";
                        unsafe { libc::write(2, MSG.as_ptr().cast(), MSG.len()) };
                        unsafe { libc::_exit(126) };
                    }
                };

                if !send_fd_post_fork(child_sock_fd, notify_fd.as_raw_fd()) {
                    sandbox_nono::write_child_status(
                        status_write_fd,
                        sandbox_nono::supervision_setup_failed_status(),
                    );
                    const MSG: &[u8] = b"nono: failed to pass seccomp notify fd to supervisor\n";
                    unsafe { libc::write(2, MSG.as_ptr().cast(), MSG.len()) };
                    unsafe { libc::_exit(126) };
                }
                unsafe { libc::close(child_sock_fd) };

                // Apply static sandbox (irrevocable)
                if let Err(_e) = nono::Sandbox::apply(caps) {
                    sandbox_nono::write_child_status(
                        status_write_fd,
                        sandbox_nono::sandbox_apply_failed_status(),
                    );
                    // SAFETY: write to stderr + _exit are async-signal-safe.
                    // Using a static string to avoid heap allocation post-fork.
                    const MSG: &[u8] = b"nono: sandbox apply failed\n";
                    unsafe { libc::write(2, MSG.as_ptr().cast(), MSG.len()) };
                    unsafe { libc::_exit(126) };
                }

                let Err(_e) = nix::unistd::execve(&c_program, &c_args_ref, &c_env_ref);
                // SAFETY: write to stderr + _exit are async-signal-safe.
                const EXEC_MSG: &[u8] = b"nono: exec failed\n";
                unsafe { libc::write(2, EXEC_MSG.as_ptr().cast(), EXEC_MSG.len()) };
                unsafe { libc::_exit(127) };
            }
            ForkResult::Parent { child } => {
                drop(child_sock);
                drop(status_write);

                // Capture the Tokio runtime handle BEFORE spawning the supervisor
                // thread. std::thread::spawn threads do not inherit the Tokio
                // thread-local, so Handle::current() would panic on the new thread.
                let runtime_handle = tokio::runtime::Handle::current();
                let backend = GuardSupervisorBackend::new(engine, context, runtime_handle);
                let notify_fd = supervisor_sock.recv_fd().ok();
                let notify_fd_received = notify_fd.is_some();

                let supervisor_handle = notify_fd.map(|fd| {
                    std::thread::spawn(move || run_linux_supervisor_loop(fd, backend, never_grant))
                });

                // Install signal forwarding so SIGINT/SIGTERM reach the child
                sandbox_nono::install_signal_forwarding_pub(child);

                // Wait for child
                let status = nix::sys::wait::waitpid(child, None)
                    .map_err(|e| anyhow::anyhow!("waitpid failed: {e}"))?;
                let child_status = sandbox_nono::read_child_status(status_read)?;
                let sandbox_applied = child_status.is_none();

                let (stats, denials) = match supervisor_handle {
                    Some(handle) => handle
                        .join()
                        .map_err(|_| anyhow::anyhow!("supervisor thread panicked"))?,
                    None => (
                        SupervisorStats {
                            enabled: false,
                            backend: "clawdstrike-guard-supervisor".to_string(),
                            ..Default::default()
                        },
                        Vec::new(),
                    ),
                };
                let sandbox_error = child_status
                    .and_then(sandbox_nono::child_status_message_pub)
                    .or_else(|| {
                        if !notify_fd_received {
                            Some("supervised interception did not activate".to_string())
                        } else {
                            None
                        }
                    });

                Ok(SupervisedResult {
                    exit_code: sandbox_nono::exit_code_from_status(status),
                    sandbox_applied,
                    supervised_active: sandbox_applied && notify_fd_received,
                    sandbox_error,
                    stats,
                    denials,
                })
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn run_linux_supervisor_loop(
    notify_fd: OwnedFd,
    backend: GuardSupervisorBackend,
    never_grant: NeverGrantChecker,
) -> (SupervisorStats, Vec<TimestampedDenial>) {
    let mut stats = SupervisorStats {
        enabled: true,
        backend: backend.backend_name().to_string(),
        ..Default::default()
    };
    let mut denials = Vec::new();

    while let Ok(notif) = recv_notif(notify_fd.as_raw_fd()) {
        let request = match capability_request_from_notif(&notif) {
            Ok(request) => request,
            Err(reason) => {
                let _ = deny_notif(notify_fd.as_raw_fd(), notif.id);
                continue_denial(
                    &mut stats,
                    &mut denials,
                    "<invalid-path>",
                    "unknown",
                    reason,
                    false,
                );
                continue;
            }
        };
        stats.requests_total = stats.requests_total.saturating_add(1);

        if never_grant.is_blocked(&request.path) {
            continue_denial(
                &mut stats,
                &mut denials,
                &request.path.to_string_lossy(),
                &format!("{}", request.access),
                "Path is in never_grant list".to_string(),
                true,
            );
            let _ = deny_notif(notify_fd.as_raw_fd(), notif.id);
            continue;
        }

        match backend.request_capability(&request) {
            Ok(ApprovalDecision::Granted) => {
                match open_supervised_path(
                    &request.path,
                    notif_mode(&notif),
                    notif_flags(&notif),
                    notif_create_mode(&notif),
                ) {
                    Ok(fd) => {
                        if !is_notif_valid(notify_fd.as_raw_fd(), notif.id) {
                            continue;
                        }
                        if inject_fd(notify_fd.as_raw_fd(), notif.id, fd.as_raw_fd()).is_ok() {
                            stats.requests_granted = stats.requests_granted.saturating_add(1);
                        } else {
                            continue_denial(
                                &mut stats,
                                &mut denials,
                                &request.path.to_string_lossy(),
                                &format!("{}", request.access),
                                "failed to inject granted file descriptor".to_string(),
                                false,
                            );
                            let _ = deny_notif(notify_fd.as_raw_fd(), notif.id);
                        }
                    }
                    Err(reason) => {
                        continue_denial(
                            &mut stats,
                            &mut denials,
                            &request.path.to_string_lossy(),
                            &format!("{}", request.access),
                            reason,
                            false,
                        );
                        let _ = deny_notif(notify_fd.as_raw_fd(), notif.id);
                    }
                }
            }
            Ok(ApprovalDecision::Denied { ref reason }) => {
                continue_denial(
                    &mut stats,
                    &mut denials,
                    &request.path.to_string_lossy(),
                    &format!("{}", request.access),
                    reason.clone(),
                    false,
                );
                let _ = deny_notif(notify_fd.as_raw_fd(), notif.id);
            }
            Ok(ApprovalDecision::Timeout) => {
                continue_denial(
                    &mut stats,
                    &mut denials,
                    &request.path.to_string_lossy(),
                    &format!("{}", request.access),
                    "guard approval timed out".to_string(),
                    false,
                );
                let _ = deny_notif(notify_fd.as_raw_fd(), notif.id);
            }
            Err(e) => {
                continue_denial(
                    &mut stats,
                    &mut denials,
                    &request.path.to_string_lossy(),
                    &format!("{}", request.access),
                    format!("Guard evaluation error: {e}"),
                    false,
                );
                let _ = deny_notif(notify_fd.as_raw_fd(), notif.id);
            }
        }
    }

    (stats, denials)
}

#[cfg(target_os = "linux")]
fn continue_denial(
    stats: &mut SupervisorStats,
    denials: &mut Vec<TimestampedDenial>,
    path: &str,
    access: &str,
    reason: String,
    never_grant: bool,
) {
    stats.requests_denied = stats.requests_denied.saturating_add(1);
    if never_grant {
        stats.never_grant_blocks = stats.never_grant_blocks.saturating_add(1);
    }
    denials.push(TimestampedDenial {
        path: path.to_string(),
        access: access.to_string(),
        reason,
        timestamp: chrono::Utc::now().to_rfc3339(),
    });
}

#[cfg(target_os = "linux")]
fn capability_request_from_notif(notif: &SeccompNotif) -> Result<nono::CapabilityRequest, String> {
    let raw_path = read_notif_path(notif.pid, notif.data.args[1]).map_err(|e| e.to_string())?;
    let path = resolve_requested_path(notif.pid, notif.data.args[0] as i32, &raw_path);
    let access = notif_mode(notif);
    Ok(nono::CapabilityRequest {
        request_id: format!("notif-{}", notif.id),
        path,
        access,
        reason: Some("linux-seccomp-notify".to_string()),
        child_pid: notif.pid,
        session_id: format!("seccomp-notif-{}", notif.id),
    })
}

#[cfg(target_os = "linux")]
fn notif_mode(notif: &SeccompNotif) -> nono::AccessMode {
    classify_access_from_flags(notif_flags(notif))
}

#[cfg(target_os = "linux")]
fn notif_flags(notif: &SeccompNotif) -> i32 {
    if notif.data.nr == SYS_OPENAT2 {
        let size = notif.data.args[3] as usize;
        if !validate_openat2_size(size) {
            return libc::O_RDONLY;
        }
        match read_open_how(notif.pid, notif.data.args[2]) {
            Ok(open_how) => open_how.flags as i32,
            Err(_) => libc::O_RDONLY,
        }
    } else {
        notif.data.args[2] as i32
    }
}

#[cfg(target_os = "linux")]
fn notif_create_mode(notif: &SeccompNotif) -> libc::mode_t {
    if notif.data.nr == SYS_OPENAT2 {
        let size = notif.data.args[3] as usize;
        if !validate_openat2_size(size) {
            return 0;
        }
        match read_open_how(notif.pid, notif.data.args[2]) {
            Ok(open_how) => open_how.mode as libc::mode_t,
            Err(_) => 0,
        }
    } else {
        notif.data.args[3] as libc::mode_t
    }
}

#[cfg(target_os = "linux")]
fn resolve_requested_path(pid: u32, dirfd: i32, raw_path: &Path) -> PathBuf {
    let candidate = if raw_path.is_absolute() {
        raw_path.to_path_buf()
    } else {
        let base = if dirfd == libc::AT_FDCWD {
            std::fs::read_link(format!("/proc/{pid}/cwd")).ok()
        } else {
            std::fs::read_link(format!("/proc/{pid}/fd/{dirfd}")).ok()
        };
        base.map(|base| base.join(raw_path))
            .unwrap_or_else(|| raw_path.to_path_buf())
    };

    if let Ok(canonical) = candidate.canonicalize() {
        return canonical;
    }

    if let Some(parent) = candidate
        .parent()
        .and_then(|parent| parent.canonicalize().ok())
    {
        if let Some(name) = candidate.file_name() {
            return parent.join(name);
        }
        return parent;
    }

    candidate
}

#[cfg(target_os = "linux")]
fn open_supervised_path(
    path: &Path,
    _access: nono::AccessMode,
    flags: i32,
    mode: libc::mode_t,
) -> Result<OwnedFd, String> {
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("path contains interior null bytes: {}", path.display()))?;
    let opened = unsafe { libc::open(c_path.as_ptr(), flags, mode) };
    if opened < 0 {
        return Err(format!(
            "supervisor failed to open {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }

    Ok(unsafe { OwnedFd::from_raw_fd(opened) })
}

#[cfg(target_os = "linux")]
fn is_notif_valid(notify_fd: i32, notif_id: u64) -> bool {
    notif_id_valid(notify_fd, notif_id).unwrap_or(false)
}

#[cfg(target_os = "linux")]
fn send_fd_post_fork(socket_fd: i32, fd: i32) -> bool {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut control = [0u8; 64];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null() {
            return false;
        }
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const i32 as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<i32>(),
        );
        msg.msg_controllen = (*cmsg).cmsg_len;
        libc::sendmsg(socket_fd, &msg, 0) >= 0
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    use std::fs::{self, File};
    use std::io::Read;
    use std::os::fd::AsRawFd;

    use clawdstrike::sandbox::SupervisorStats;
    use nono::sandbox::SeccompData;

    fn openat_notif(flags: i32, mode: libc::mode_t) -> SeccompNotif {
        SeccompNotif {
            id: 7,
            pid: std::process::id(),
            flags: 0,
            data: SeccompData {
                nr: libc::SYS_openat as i32,
                args: [libc::AT_FDCWD as u64, 0, flags as u64, mode as u64, 0, 0],
                ..Default::default()
            },
        }
    }

    fn openat2_invalid_size_notif() -> SeccompNotif {
        SeccompNotif {
            id: 9,
            pid: std::process::id(),
            flags: 0,
            data: SeccompData {
                nr: SYS_OPENAT2,
                args: [libc::AT_FDCWD as u64, 0, 0, 1, 0, 0],
                ..Default::default()
            },
        }
    }

    fn recv_fd(socket_fd: i32) -> i32 {
        let mut data = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: data.as_mut_ptr().cast(),
            iov_len: data.len(),
        };
        let mut control = [0u8; 64];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len();

        let recv_len = unsafe { libc::recvmsg(socket_fd, &mut msg, 0) };
        assert!(
            recv_len >= 0,
            "recvmsg failed: {}",
            std::io::Error::last_os_error()
        );

        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        assert!(!cmsg.is_null(), "expected SCM_RIGHTS control message");
        assert_eq!(unsafe { (*cmsg).cmsg_level }, libc::SOL_SOCKET);
        assert_eq!(unsafe { (*cmsg).cmsg_type }, libc::SCM_RIGHTS);

        let mut received = -1i32;
        unsafe {
            std::ptr::copy_nonoverlapping(
                libc::CMSG_DATA(cmsg),
                (&mut received as *mut i32).cast(),
                std::mem::size_of::<i32>(),
            );
        }
        received
    }

    #[test]
    fn continue_denial_tracks_denials_and_never_grant_blocks() {
        let mut stats = SupervisorStats::default();
        let mut denials = Vec::new();

        continue_denial(
            &mut stats,
            &mut denials,
            "/tmp/blocked.txt",
            "read",
            "blocked for test".to_string(),
            true,
        );

        assert_eq!(stats.requests_denied, 1);
        assert_eq!(stats.never_grant_blocks, 1);
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].path, "/tmp/blocked.txt");
        assert_eq!(denials[0].access, "read");
        assert_eq!(denials[0].reason, "blocked for test");
    }

    #[test]
    fn notif_helpers_classify_openat_access_and_mode() {
        let notif = openat_notif(libc::O_WRONLY | libc::O_CREAT, 0o640);

        assert_eq!(notif_flags(&notif), libc::O_WRONLY | libc::O_CREAT);
        assert_eq!(notif_mode(&notif), nono::AccessMode::Write);
        assert_eq!(notif_create_mode(&notif), 0o640);
    }

    #[test]
    fn openat2_helpers_fall_back_when_open_how_size_is_invalid() {
        let notif = openat2_invalid_size_notif();

        assert_eq!(notif_flags(&notif), libc::O_RDONLY);
        assert_eq!(notif_mode(&notif), nono::AccessMode::Read);
        assert_eq!(notif_create_mode(&notif), 0);
    }

    #[test]
    fn resolve_requested_path_joins_relative_paths_against_dirfd() {
        let temp = tempfile::tempdir().expect("tempdir");
        let parent = temp.path().join("existing");
        fs::create_dir_all(&parent).expect("mkdir");
        let dir = File::open(&parent).expect("open dir");

        let resolved =
            resolve_requested_path(std::process::id(), dir.as_raw_fd(), Path::new("child.txt"));

        assert_eq!(resolved, parent.join("child.txt"));
    }

    #[test]
    fn open_supervised_path_reads_existing_file_and_creates_new_file() {
        let temp = tempfile::tempdir().expect("tempdir");
        let existing_path = temp.path().join("existing.txt");
        fs::write(&existing_path, b"hello").expect("write existing file");

        let existing_fd =
            open_supervised_path(&existing_path, nono::AccessMode::Read, libc::O_RDONLY, 0)
                .expect("open existing");
        let mut existing = File::from(existing_fd);
        let mut buf = String::new();
        existing.read_to_string(&mut buf).expect("read existing");
        assert_eq!(buf, "hello");

        let created_path = temp.path().join("created.txt");
        let _created_fd = open_supervised_path(
            &created_path,
            nono::AccessMode::ReadWrite,
            libc::O_CREAT | libc::O_RDWR,
            0o600,
        )
        .expect("create file");
        assert!(created_path.exists());
    }

    #[test]
    fn send_fd_post_fork_passes_file_descriptors_over_unix_socket() {
        let temp = tempfile::tempdir().expect("tempdir");
        let file_path = temp.path().join("fd.txt");
        fs::write(&file_path, b"fd-pass").expect("write file");
        let file = File::open(&file_path).expect("open file");

        let mut fds = [0; 2];
        let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
        assert_eq!(
            rc,
            0,
            "socketpair failed: {}",
            std::io::Error::last_os_error()
        );

        assert!(send_fd_post_fork(fds[0], file.as_raw_fd()));

        let received_fd = recv_fd(fds[1]);
        assert!(received_fd >= 0);

        let mut received = File::from(unsafe { OwnedFd::from_raw_fd(received_fd) });
        let mut buf = String::new();
        received.read_to_string(&mut buf).expect("read received");
        assert_eq!(buf, "fd-pass");

        unsafe {
            libc::close(fds[0]);
            libc::close(fds[1]);
        }
    }
}
