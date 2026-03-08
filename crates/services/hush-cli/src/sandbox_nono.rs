//! Nono-based OS-level sandbox for hush run.
//!
//! Replaces the legacy `sandbox-exec`/`bwrap` wrappers with nono's
//! cross-platform capability-based sandboxing (Landlock on Linux,
//! Seatbelt on macOS).
//!
//! Phase 1 foundation: public API is wired in by Phase 1B.

use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use nono::{CapabilitySet, Sandbox};

const CHILD_STATUS_SANDBOX_APPLY_FAILED: u8 = 1;
const CHILD_STATUS_SUPERVISION_SETUP_FAILED: u8 = 2;

/// Result of sandboxed child execution.
pub struct SandboxedChildResult {
    pub exit_code: i32,
    pub sandbox_applied: bool,
    pub sandbox_error: Option<String>,
}

/// Spawn a child process inside a nono sandbox.
///
/// # Process model
///
/// 1. Pre-fork: prepare all C strings (no allocation after fork)
/// 2. Fork
/// 3. Child: close inherited fds, apply sandbox, exec
/// 4. Parent: forward signals, wait for child
///
/// # Safety
///
/// After `fork()`, the child process uses only async-signal-safe
/// operations. No `?` operator, no `panic!`, no allocation.
/// Errors are reported via `libc::write` to stderr and terminated
/// with `libc::_exit`. See nono-cli's `exec_strategy.rs:407-418`.
pub fn spawn_sandboxed_child(
    caps: &CapabilitySet,
    command: &[String],
    env_overrides: &HashMap<String, String>,
) -> anyhow::Result<SandboxedChildResult> {
    use nix::unistd::ForkResult;

    if command.is_empty() {
        anyhow::bail!("empty command");
    }

    // Pre-fork: resolve command through PATH (execve does NOT do PATH lookup)
    let resolved = resolve_command_path(&command[0])?;
    let c_program =
        CString::new(resolved.as_str()).map_err(|e| anyhow::anyhow!("invalid command: {}", e))?;
    let c_args: Vec<CString> = command
        .iter()
        .map(|a| CString::new(a.as_str()).map_err(|e| anyhow::anyhow!("invalid arg: {}", e)))
        .collect::<Result<_, _>>()?;

    // Build child environment: inherit current env + overrides
    let mut env_map: HashMap<String, String> = std::env::vars().collect();
    for (k, v) in env_overrides {
        env_map.insert(k.clone(), v.clone());
    }
    let c_env: Vec<CString> = env_map
        .iter()
        .map(|(k, v)| {
            CString::new(format!("{}={}", k, v)).map_err(|e| anyhow::anyhow!("invalid env: {}", e))
        })
        .collect::<Result<_, _>>()?;

    // Pre-fork: build CStr reference slices so the child does no heap allocation.
    // After fork in a multithreaded process, malloc may deadlock on inherited locks.
    let c_args_ref: Vec<&std::ffi::CStr> = c_args.iter().map(|a| a.as_c_str()).collect();
    let c_env_ref: Vec<&std::ffi::CStr> = c_env.iter().map(|e| e.as_c_str()).collect();
    let (status_read, status_write) = create_status_pipe()?;
    let status_write_fd = status_write.as_raw_fd();

    // SAFETY: fork() is safe to call. After fork in the child, we only use
    // async-signal-safe operations (no allocation, no panic, no `?`).
    match unsafe { nix::unistd::fork() }.map_err(|e| anyhow::anyhow!("fork failed: {}", e))? {
        ForkResult::Child => {
            // CHILD: only async-signal-safe operations from here.
            // No ? operator, no panic!, no allocation.

            drop(status_read);

            // Close inherited fds (proxy socket, parent resources) while preserving
            // the bootstrap status pipe long enough to report sandbox setup failure.
            close_inherited_fds_except(3, &[status_write_fd]);

            // Apply sandbox (irrevocable)
            if let Err(_e) = Sandbox::apply(caps) {
                write_child_status(status_write_fd, CHILD_STATUS_SANDBOX_APPLY_FAILED);
                // SAFETY: write to stderr + _exit are async-signal-safe.
                // Using a static string to avoid heap allocation post-fork.
                const MSG: &[u8] = b"nono: sandbox apply failed\n";
                unsafe { libc::write(2, MSG.as_ptr().cast(), MSG.len()) };
                unsafe { libc::_exit(126) };
            }
            // execve returns Result<Infallible> -- on success it never returns,
            // on failure we get an Err.
            let Err(_e) = nix::unistd::execve(&c_program, &c_args_ref, &c_env_ref);
            // SAFETY: write to stderr + _exit are async-signal-safe.
            const EXEC_MSG: &[u8] = b"nono: exec failed\n";
            unsafe { libc::write(2, EXEC_MSG.as_ptr().cast(), EXEC_MSG.len()) };
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => {
            drop(status_write);

            // Install signal forwarding
            install_signal_forwarding(child);

            // Wait for child
            let status = nix::sys::wait::waitpid(child, None)
                .map_err(|e| anyhow::anyhow!("waitpid failed: {}", e))?;
            let child_status = read_child_status(status_read)?;
            Ok(SandboxedChildResult {
                exit_code: exit_code_from_status(status),
                sandbox_applied: child_status.is_none(),
                sandbox_error: child_status.and_then(child_status_message),
            })
        }
    }
}

/// Close all file descriptors >= `from_fd`.
///
/// Prevents the child from inheriting the proxy socket, supervisor
/// socket, log handles, etc.
///
/// Uses only async-signal-safe operations (libc::close, libc::getrlimit)
/// since this runs post-fork in a potentially multithreaded process.
pub(crate) fn close_inherited_fds_except(from_fd: i32, keep_fds: &[i32]) {
    // Use getrlimit directly via libc to avoid any Rust std allocation.
    let mut rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit is async-signal-safe
    let max_fd = if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) } == 0 {
        rlim.rlim_cur.min(65_536) as i32
    } else {
        1024
    };
    for fd in from_fd..max_fd {
        if keep_fds.contains(&fd) {
            continue;
        }
        // SAFETY: closing an fd is safe; EBADF for non-open fds is harmless
        unsafe { libc::close(fd) };
    }
}

pub(crate) fn create_status_pipe() -> anyhow::Result<(OwnedFd, OwnedFd)> {
    let (read_fd, write_fd) = nix::unistd::pipe()
        .map_err(|e| anyhow::anyhow!("failed to create child status pipe: {e}"))?;
    set_cloexec(read_fd.as_raw_fd())?;
    set_cloexec(write_fd.as_raw_fd())?;
    Ok((read_fd, write_fd))
}

pub(crate) fn read_child_status(fd: OwnedFd) -> anyhow::Result<Option<u8>> {
    let mut buf = [0u8; 1];
    match nix::unistd::read(&fd, &mut buf) {
        Ok(0) => Ok(None),
        Ok(_) => Ok(Some(buf[0])),
        Err(e) => Err(anyhow::anyhow!(
            "failed to read child bootstrap status: {e}"
        )),
    }
}

fn child_status_message(code: u8) -> Option<String> {
    match code {
        CHILD_STATUS_SANDBOX_APPLY_FAILED => Some("sandbox apply failed".to_string()),
        CHILD_STATUS_SUPERVISION_SETUP_FAILED => {
            Some("supervised interception setup failed".to_string())
        }
        _ => None,
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn child_status_message_pub(code: u8) -> Option<String> {
    child_status_message(code)
}

#[cfg(target_os = "linux")]
pub(crate) fn supervision_setup_failed_status() -> u8 {
    CHILD_STATUS_SUPERVISION_SETUP_FAILED
}

#[cfg(target_os = "linux")]
pub(crate) fn sandbox_apply_failed_status() -> u8 {
    CHILD_STATUS_SANDBOX_APPLY_FAILED
}

pub(crate) fn write_child_status(fd: RawFd, code: u8) {
    let buf = [code];
    // SAFETY: write is async-signal-safe, and the pipe fd remains open in the child.
    unsafe {
        libc::write(fd, buf.as_ptr().cast(), buf.len());
    }
}

fn set_cloexec(fd: RawFd) -> anyhow::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(anyhow::anyhow!(
            "failed to read fd flags for child status pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(anyhow::anyhow!(
            "failed to set CLOEXEC on child status pipe: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Resolve a command name to an absolute path via PATH lookup.
///
/// `execve` does not search PATH, so we must resolve before fork.
/// - Absolute paths are returned as-is
/// - Relative paths containing `/` (e.g. `./script.sh`, `tools/run`) are
///   canonicalized against the current directory
/// - Bare names (e.g. `ls`) are searched through PATH
fn resolve_command_path(cmd: &str) -> anyhow::Result<String> {
    let path = std::path::Path::new(cmd);
    if path.is_absolute() {
        return Ok(cmd.to_string());
    }
    // Relative path with directory component — resolve against cwd
    if cmd.contains('/') {
        let canonical = std::env::current_dir()
            .map_err(|e| anyhow::anyhow!("cannot resolve relative path {cmd}: {e}"))?
            .join(cmd);
        if canonical.exists() {
            return Ok(canonical.to_string_lossy().into_owned());
        }
        anyhow::bail!("relative command not found: {cmd} (resolved to {canonical:?})");
    }
    // Bare command name — search PATH
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            let candidate = std::path::Path::new(dir).join(cmd);
            if candidate.exists() {
                return Ok(candidate.to_string_lossy().into_owned());
            }
        }
    }
    anyhow::bail!(
        "command not found in PATH: {}. execve requires an absolute path.",
        cmd
    )
}

/// Public wrapper for PATH resolution, used by `supervised_exec`.
#[cfg(target_os = "linux")]
pub(crate) fn resolve_command_path_pub(cmd: &str) -> anyhow::Result<String> {
    resolve_command_path(cmd)
}

/// Public wrapper for signal forwarding, used by `supervised_exec`.
#[cfg(target_os = "linux")]
pub(crate) fn install_signal_forwarding_pub(child: nix::unistd::Pid) {
    install_signal_forwarding(child);
}

/// Install signal forwarding so SIGINT/SIGTERM sent to the parent
/// are forwarded to the child process.
///
/// Uses a global `AtomicI32` to communicate the child PID to the signal
/// handler. This means only ONE sandboxed child may be active at a time.
/// `hush run` enforces this — it runs a single command per invocation.
/// If concurrent sandboxed children were needed, each would require its
/// own process group and the handler would need to forward via `killpg`.
fn install_signal_forwarding(child: nix::unistd::Pid) {
    use nix::sys::signal::{self, SigHandler, Signal};

    // Global child PID for the signal handler. Only one sandboxed child
    // is active at a time (enforced by hush run's single-command model).
    static CHILD_PID: std::sync::atomic::AtomicI32 = std::sync::atomic::AtomicI32::new(0);
    CHILD_PID.store(child.as_raw(), std::sync::atomic::Ordering::SeqCst);

    extern "C" fn forward_signal(sig: libc::c_int) {
        let pid = CHILD_PID.load(std::sync::atomic::Ordering::SeqCst);
        if pid > 0 {
            // SAFETY: kill() is async-signal-safe
            unsafe { libc::kill(pid, sig) };
        }
    }

    // SAFETY: SigHandler::Handler is a valid signal handler type.
    // We install handlers for SIGINT and SIGTERM only.
    unsafe {
        let handler = SigHandler::Handler(forward_signal);
        // Ignore errors -- best effort
        let _ = signal::signal(Signal::SIGINT, handler);
        let _ = signal::signal(Signal::SIGTERM, handler);
    }
}

/// Extract exit code from wait status.
pub(crate) fn exit_code_from_status(status: nix::sys::wait::WaitStatus) -> i32 {
    use nix::sys::wait::WaitStatus;
    match status {
        WaitStatus::Exited(_, code) => code,
        WaitStatus::Signaled(_, sig, _) => 128 + sig as i32,
        _ => 1,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};

    use nono::query::{QueryContext, QueryResult};
    use nono::{AccessMode, NetworkMode};

    /// Build a capability set for testing (Phase 1 API, superseded by CapabilityBuilder).
    fn build_capability_set(
        working_dir: &Path,
        command: &[String],
        proxy_port: Option<u16>,
        extra_read_paths: &[PathBuf],
        extra_write_paths: &[PathBuf],
        blocked_commands: &[String],
    ) -> nono::Result<CapabilitySet> {
        let _ = command;
        let mut caps = CapabilitySet::new();
        caps = caps.allow_path(working_dir, AccessMode::ReadWrite)?;

        for path in system_read_paths() {
            if path.exists() {
                caps = caps.allow_path(&path, AccessMode::Read)?;
            }
        }
        for path in system_write_paths() {
            if path.exists() {
                caps = caps.allow_path(&path, AccessMode::ReadWrite)?;
            }
        }
        for path in extra_read_paths {
            if path.exists() {
                caps = caps.allow_path(path, AccessMode::Read)?;
            }
        }
        for path in extra_write_paths {
            if path.exists() {
                caps = caps.allow_path(path, AccessMode::ReadWrite)?;
            }
        }
        if let Some(port) = proxy_port {
            caps = caps.proxy_only(port);
        } else {
            caps = caps.block_network();
        }
        for cmd in blocked_commands {
            caps = caps.block_command(cmd);
        }
        Ok(caps)
    }

    fn validate_capabilities(
        caps: &CapabilitySet,
        command: &[String],
        working_dir: &Path,
    ) -> Vec<String> {
        let ctx = QueryContext::new(caps.clone());
        let mut warnings = vec![];
        if !matches!(
            ctx.query_path(working_dir, AccessMode::ReadWrite),
            QueryResult::Allowed(_)
        ) {
            warnings.push(format!(
                "Working directory {} not accessible in sandbox",
                working_dir.display()
            ));
        }
        if !command.is_empty() {
            if let Some(bin_path) = find_command_in_path(&command[0]) {
                if !matches!(
                    ctx.query_path(&bin_path, AccessMode::Read),
                    QueryResult::Allowed(_)
                ) {
                    warnings.push(format!(
                        "Command binary {} not accessible in sandbox",
                        bin_path.display()
                    ));
                }
            }
        }
        warnings
    }

    fn find_command_in_path(cmd: &str) -> Option<PathBuf> {
        let path = Path::new(cmd);
        if path.is_absolute() && path.exists() {
            return Some(path.to_path_buf());
        }
        let path_var = std::env::var("PATH").ok()?;
        for dir in path_var.split(':') {
            let candidate = Path::new(dir).join(cmd);
            if candidate.exists() {
                return Some(candidate);
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    fn system_read_paths() -> Vec<PathBuf> {
        [
            "/bin",
            "/usr",
            "/sbin",
            "/System/Library",
            "/Library",
            "/private/etc",
            "/opt/homebrew",
        ]
        .iter()
        .map(PathBuf::from)
        .collect()
    }

    #[cfg(target_os = "linux")]
    fn system_read_paths() -> Vec<PathBuf> {
        [
            "/bin", "/lib", "/lib64", "/usr", "/sbin", "/etc", "/proc", "/sys", "/run",
        ]
        .iter()
        .map(PathBuf::from)
        .collect()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn system_read_paths() -> Vec<PathBuf> {
        vec![]
    }

    #[cfg(target_os = "macos")]
    fn system_write_paths() -> Vec<PathBuf> {
        ["/tmp", "/private/tmp", "/dev"]
            .iter()
            .map(PathBuf::from)
            .collect()
    }

    #[cfg(target_os = "linux")]
    fn system_write_paths() -> Vec<PathBuf> {
        ["/tmp", "/dev", "/dev/shm"]
            .iter()
            .map(PathBuf::from)
            .collect()
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn system_write_paths() -> Vec<PathBuf> {
        vec![]
    }

    #[test]
    fn test_capability_set_allows_working_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = build_capability_set(tmp.path(), &["ls".into()], None, &[], &[], &[]).unwrap();

        let ctx = QueryContext::new(caps);
        assert!(
            matches!(
                ctx.query_path(tmp.path(), AccessMode::ReadWrite),
                QueryResult::Allowed(_)
            ),
            "working directory should be accessible"
        );
    }

    #[test]
    fn test_capability_set_blocks_ssh() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = build_capability_set(tmp.path(), &["ls".into()], None, &[], &[], &[]).unwrap();

        let ctx = QueryContext::new(caps);
        if let Some(home) = dirs::home_dir() {
            let ssh_dir = home.join(".ssh");
            assert!(
                !matches!(
                    ctx.query_path(&ssh_dir, AccessMode::Read),
                    QueryResult::Allowed(_)
                ),
                ".ssh should not be accessible"
            );
        }
    }

    #[test]
    fn test_proxy_only_network() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps =
            build_capability_set(tmp.path(), &["ls".into()], Some(8080), &[], &[], &[]).unwrap();

        assert!(
            matches!(caps.network_mode(), NetworkMode::ProxyOnly { .. }),
            "should be ProxyOnly when proxy port is set"
        );
    }

    #[test]
    fn test_blocked_network() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = build_capability_set(tmp.path(), &["ls".into()], None, &[], &[], &[]).unwrap();

        assert!(
            matches!(caps.network_mode(), NetworkMode::Blocked),
            "should be Blocked when no proxy port"
        );
    }

    #[test]
    fn test_extra_read_paths() {
        let tmp = tempfile::TempDir::new().unwrap();
        let extra = tempfile::TempDir::new().unwrap();
        let caps = build_capability_set(
            tmp.path(),
            &["ls".into()],
            None,
            &[extra.path().to_path_buf()],
            &[],
            &[],
        )
        .unwrap();

        let ctx = QueryContext::new(caps);
        assert!(
            matches!(
                ctx.query_path(extra.path(), AccessMode::Read),
                QueryResult::Allowed(_)
            ),
            "extra read path should be accessible"
        );
    }

    #[test]
    fn test_validate_capabilities_working_dir() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = build_capability_set(tmp.path(), &["ls".into()], None, &[], &[], &[]).unwrap();

        let warnings = validate_capabilities(&caps, &["ls".into()], tmp.path());
        assert!(
            !warnings.iter().any(|w| w.contains("Working directory")),
            "should not warn about working directory"
        );
    }

    #[test]
    fn test_system_read_paths_exist() {
        let paths = system_read_paths();
        assert!(!paths.is_empty(), "should have system read paths");
        assert!(
            paths.iter().any(|p| p.as_os_str() == "/usr"),
            "/usr should be in system read paths"
        );
    }

    #[test]
    fn test_system_write_paths_exist() {
        let paths = system_write_paths();
        assert!(!paths.is_empty(), "should have system write paths");
        assert!(
            paths.iter().any(|p| p.as_os_str() == "/tmp"),
            "/tmp should be in system write paths"
        );
    }

    #[test]
    fn test_find_command_in_path() {
        let result = find_command_in_path("ls");
        assert!(result.is_some(), "ls should be findable in PATH");
    }

    #[test]
    fn test_close_inherited_fds_does_not_panic() {
        close_inherited_fds_except(100, &[]);
    }

    #[test]
    fn test_resolve_command_path_absolute() {
        let result = resolve_command_path("/bin/ls");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "/bin/ls");
    }

    #[test]
    fn test_resolve_command_path_relative() {
        let result = resolve_command_path("ls");
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert!(
            std::path::Path::new(&resolved).is_absolute(),
            "resolved path should be absolute, got: {resolved}"
        );
    }

    #[test]
    fn test_resolve_command_path_not_found() {
        let result = resolve_command_path("nonexistent_command_xyz_12345");
        assert!(result.is_err());
    }

    #[test]
    fn test_blocked_commands() {
        let tmp = tempfile::TempDir::new().unwrap();
        let caps = build_capability_set(
            tmp.path(),
            &["ls".into()],
            None,
            &[],
            &[],
            &["rm".into(), "sudo".into()],
        )
        .unwrap();

        let blocked = caps.blocked_commands();
        assert!(blocked.contains(&"rm".to_string()), "rm should be blocked");
        assert!(
            blocked.contains(&"sudo".to_string()),
            "sudo should be blocked"
        );
    }
}
