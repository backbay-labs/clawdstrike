# 05 - Supervisor Enforcement (Phase 3)

Dynamic enforcement via nono's supervisor IPC, routing kernel-intercepted operations through ClawdStrike guards for real-time allow/deny decisions.

## Overview

In Phase 1-2, the sandbox is **static**: all capabilities are determined before execution. Phase 3 adds **dynamic enforcement**: the child starts with a minimal capability set, and the supervisor expands it on-demand by routing requests through ClawdStrike's `HushEngine`.

This is the most powerful integration — every filesystem operation is both guard-evaluated AND kernel-enforced, with no TOCTOU gap between policy check and enforcement.

## Platform Mechanisms

### Linux: seccomp-notify

The child installs a BPF filter that intercepts `openat`/`openat2` syscalls and routes them to the parent supervisor via a notification fd.

```
Child calls open("/project/secret.txt", O_RDONLY)
  |
  v
Kernel: seccomp-notify intercepts openat syscall
  → Child blocks (syscall suspended)
  → Notification sent to supervisor fd
  |
  v
Supervisor: recv_notif(notify_fd)
  → Read path from /proc/PID/mem
  → Validate notification still active (TOCTOU check)
  → Route through HushEngine guards
  |
  v
  If APPROVED:
    Supervisor opens file, gets fd
    inject_fd(notify_fd, notif_id, fd)  → child receives fd as return value
  If DENIED:
    deny_notif(notify_fd, notif_id)     → child receives EPERM
```

**Key nono APIs**:

| Function | File | Line | Purpose |
|----------|------|------|---------|
| `install_seccomp_notify()` | `sandbox/linux.rs` | 449-559 | Install BPF filter for openat/openat2 |
| `recv_notif()` | `sandbox/linux.rs` | 569-596 | Receive notification (blocking) |
| `read_notif_path()` | `sandbox/linux.rs` | 619-649 | Read path from child's /proc/PID/mem |
| `read_open_how()` | `sandbox/linux.rs` | 672-695 | Read openat2 struct for access mode |
| `classify_access_from_flags()` | `sandbox/linux.rs` | 389-395 | Classify O_RDONLY/O_WRONLY/O_RDWR |
| `notif_id_valid()` | `sandbox/linux.rs` | 706-730 | TOCTOU liveness check |
| `inject_fd()` | `sandbox/linux.rs` | 743-775 | Atomically inject fd + complete syscall |
| `deny_notif()` | `sandbox/linux.rs` | 785-799 | Deny with EPERM |

**BPF program** (installed by `install_seccomp_notify()`):
```
Instruction 0: Load syscall number
Instruction 1: If openat (257/56) → goto NOTIFY
Instruction 2: If openat2 (437)   → goto NOTIFY
Instruction 3: SECCOMP_RET_ALLOW (all other syscalls)
Instruction 4: SECCOMP_RET_USER_NOTIF (route to supervisor)
```

### macOS: Seatbelt Extensions

The supervisor issues HMAC-SHA256 authenticated tokens that the child consumes to expand its sandbox.

```
Child needs to access /project/file.txt
  → Sends CapabilityRequest via supervisor socket
  |
  v
Supervisor: recv_message()
  → Route through HushEngine guards
  |
  v
  If APPROVED:
    token = extension_issue_file("/project/file.txt", AccessMode::Read)
    send_message(SupervisorResponse::Decision { Granted })
    send extension token via socket
  If DENIED:
    send_message(SupervisorResponse::Decision { Denied { reason } })
  |
  v
Child: extension_consume(token)
  → Sandbox expands to include /project/file.txt
```

**Key nono APIs**:

| Function | File | Line | Purpose |
|----------|------|------|---------|
| `extension_issue_file()` | `sandbox/macos.rs` | 61-104 | Create HMAC-authenticated token |
| `extension_consume()` | `sandbox/macos.rs` | 119-136 | Consume token in sandboxed process |
| `extension_release()` | `sandbox/macos.rs` | 142-156 | Revoke dynamically-granted access |

**Token properties**:
- HMAC-SHA256 authenticated with per-boot kernel key (cannot be forged)
- Path-specific and access-class-specific
- Survives `fork()` and `exec()` — children inherit expanded access
- Revocable via `extension_release(handle)`

## Supervisor Socket IPC

**Nono API**: `supervisor/socket.rs`

The supervisor socket provides length-prefixed JSON messaging with fd-passing:

| Method | File | Line | Purpose |
|--------|------|------|---------|
| `SupervisorSocket::pair()` | `socket.rs` | 51-65 | Create connected pair before fork |
| `send_message()` | `socket.rs` | 127-132 | Send SupervisorMessage |
| `recv_message()` | `socket.rs` | 134-140 | Receive SupervisorMessage |
| `send_fd()` | `socket.rs` | 161-209 | Pass fd via SCM_RIGHTS |
| `recv_fd()` | `socket.rs` | 215-293 | Receive fd from peer |
| `peer_pid()` | `socket.rs` | 301-368 | Authenticate peer process |

**Message types** (`supervisor/types.rs`):

```rust
struct CapabilityRequest {
    request_id: String,     // Unique ID (replay protection)
    path: PathBuf,          // Requested filesystem path
    access: AccessMode,     // Read, Write, or ReadWrite
    reason: Option<String>, // Human-readable reason
    child_pid: u32,         // Requesting process PID
    session_id: String,     // Correlates requests in a session
}

enum ApprovalDecision {
    Granted,
    Denied { reason: String },
    Timeout,
}
```

## Integration with HushEngine

### GuardSupervisorBackend

Implement nono's `ApprovalBackend` trait with ClawdStrike's `HushEngine`:

```rust
use nono::supervisor::{ApprovalBackend, ApprovalDecision, CapabilityRequest};
use clawdstrike::engine::HushEngine;
use clawdstrike::guards::{GuardAction, GuardContext};

pub struct GuardSupervisorBackend {
    engine: Arc<HushEngine>,
    context: GuardContext,
    outcome: Arc<RunOutcome>,
    event_emitter: EventEmitter,
}

impl ApprovalBackend for GuardSupervisorBackend {
    fn request_capability(
        &self,
        request: &CapabilityRequest,
    ) -> nono::Result<ApprovalDecision> {
        let path = request.path.to_string_lossy();

        // Determine guard action based on access mode
        let action = match request.access {
            AccessMode::Read => GuardAction::FileAccess(&path),
            AccessMode::Write | AccessMode::ReadWrite => {
                // For writes, we don't have content — check path only
                GuardAction::FileAccess(&path)
            }
        };

        // Route through HushEngine
        let report = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(self.engine.check_action_report(&action, &self.context))
        });

        // Track outcome for receipt
        self.outcome.observe_guard_result(&report.overall);

        // Emit event
        self.event_emitter.emit(PolicyEvent::supervisor_request(
            &request,
            &report,
        ));

        if report.overall.allowed {
            Ok(ApprovalDecision::Granted)
        } else {
            Ok(ApprovalDecision::Denied {
                reason: report.overall.message.clone(),
            })
        }
    }

    fn backend_name(&self) -> &str {
        "clawdstrike-guard-supervisor"
    }
}
```

### NeverGrant Integration

Nono's `NeverGrantChecker` validates paths against a permanently-blocked list. Map ClawdStrike's most critical forbidden paths to never_grant:

```rust
/// Build the never_grant list from policy.
///
/// NOTE: NeverGrantChecker::new() takes &[String], NOT &[PathBuf].
/// It performs its own tilde expansion and canonicalization internally,
/// using the passwd database for home directory resolution (not $HOME).
/// Pass paths as strings with ~ for home-relative paths.
fn build_never_grant_list(policy: &Policy) -> Vec<String> {
    let mut paths: Vec<String> = vec![
        "~/.ssh/id_rsa".into(),
        "~/.ssh/id_ed25519".into(),
        "/etc/shadow".into(),
        "/etc/sudoers".into(),
    ];

    // From ForbiddenPathGuard with never_override flag
    if let Some(fp) = &policy.guards.forbidden_path {
        for pattern in &fp.patterns {
            for concrete_path in resolve_pattern_to_paths(pattern) {
                paths.push(concrete_path.to_string_lossy().into_owned());
            }
        }
    }

    paths
}
```

**Code ref**: `nono/crates/nono/src/supervisor/never_grant.rs:40-62`

NeverGrantChecker uses component-wise `Path::starts_with()` (not string comparison) to prevent `/etc/shadow2` matching `/etc/shadow`.

### Rate Limiting

Nono's supervisor includes a token-bucket rate limiter (10 req/sec, burst 5) to prevent fd-injection flooding. This protects against runaway agents that open thousands of files per second.

**Code ref**: `nono/crates/nono-cli/src/exec_strategy/supervisor_linux.rs:92-100` (rate_limiter parameter)

## Supervisor Loop Architecture

### Linux Implementation

```rust
// NOTE: This function is synchronous, NOT async. recv_notif() is a blocking
// ioctl that suspends the calling thread. Running this inside an async runtime
// would block the Tokio worker thread and starve other tasks. The supervisor
// loop runs on a dedicated OS thread, separate from Tokio.
//
// For guard evaluation (which uses async guards), we use block_in_place() via
// the GuardSupervisorBackend, which requires a multi-threaded Tokio runtime.
// The Tokio runtime must be started in the parent AFTER fork, with the
// supervisor loop running on its own thread via std::thread::spawn().
#[cfg(target_os = "linux")]
pub fn run_supervisor_loop(
    notify_fd: RawFd,
    child_pid: Pid,
    engine: Arc<HushEngine>,
    context: GuardContext,
    initial_caps: &CapabilitySet,
    never_grant: NeverGrantChecker,
    outcome: Arc<RunOutcome>,
    emitter: EventEmitter,
) -> Vec<DenialRecord> {
    let backend = GuardSupervisorBackend {
        engine, context, outcome, emitter,
    };

    let initial_paths: Vec<(PathBuf, bool)> = initial_caps
        .fs_capabilities()
        .iter()
        .map(|c| (c.resolved.clone(), c.is_file))
        .collect();

    let mut denials = vec![];
    let mut rate_limiter = RateLimiter::new(10, 5); // 10/sec, burst 5

    loop {
        // Blocking receive from kernel
        let notif = match linux::recv_notif(notify_fd) {
            Ok(n) => n,
            Err(_) => break, // Child exited, fd closed
        };

        // Read path from child's /proc/PID/mem
        let path = match linux::read_notif_path(notif.pid, &notif.data) {
            Ok(p) => PathBuf::from(p),
            Err(_) => {
                linux::deny_notif(notify_fd, notif.id).ok();
                continue;
            }
        };

        // Classify access mode from open flags
        let access = linux::classify_access_from_flags(notif.data.args[2] as i32);

        // 1. Check never_grant (immediate deny)
        if never_grant.is_blocked(&path) {
            denials.push(DenialRecord {
                path: path.clone(),
                access,
                reason: DenialReason::PolicyBlocked,
            });
            linux::deny_notif(notify_fd, notif.id).ok();
            continue;
        }

        // 2. Fast path: already in initial capability set
        if is_in_initial_set(&path, &initial_paths) {
            // Open the file as supervisor and inject fd
            if let Ok(fd) = open_file_for_inject(&path, access) {
                linux::inject_fd(notify_fd, notif.id, fd.as_raw_fd()).ok();
            } else {
                linux::deny_notif(notify_fd, notif.id).ok();
            }
            continue;
        }

        // 3. Rate limit check
        if !rate_limiter.try_acquire() {
            denials.push(DenialRecord {
                path: path.clone(),
                access,
                reason: DenialReason::RateLimited,
            });
            linux::deny_notif(notify_fd, notif.id).ok();
            continue;
        }

        // 4. TOCTOU check: notification still valid?
        if !linux::notif_id_valid(notify_fd, notif.id) {
            continue; // Child already moved on
        }

        // 5. Route through ClawdStrike guards
        let request = CapabilityRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            path: path.clone(),
            access,
            reason: None,
            child_pid: notif.pid,
            session_id: "todo".into(),
        };

        match backend.request_capability(&request) {
            Ok(ApprovalDecision::Granted) => {
                // Second TOCTOU check before inject
                if linux::notif_id_valid(notify_fd, notif.id) {
                    if let Ok(fd) = open_file_for_inject(&path, access) {
                        linux::inject_fd(notify_fd, notif.id, fd.as_raw_fd()).ok();
                    } else {
                        linux::deny_notif(notify_fd, notif.id).ok();
                    }
                }
            }
            Ok(ApprovalDecision::Denied { reason }) => {
                denials.push(DenialRecord {
                    path: path.clone(),
                    access,
                    reason: DenialReason::UserDenied,
                });
                linux::deny_notif(notify_fd, notif.id).ok();
            }
            _ => {
                linux::deny_notif(notify_fd, notif.id).ok();
            }
        }
    }

    denials
}
```

### macOS Implementation

macOS uses extension tokens instead of fd injection:

```rust
// NOTE: Also synchronous — recv_message() blocks on the Unix socket.
#[cfg(target_os = "macos")]
pub fn run_supervisor_loop_macos(
    socket: SupervisorSocket,
    engine: Arc<HushEngine>,
    context: GuardContext,
    never_grant: NeverGrantChecker,
    outcome: Arc<RunOutcome>,
    emitter: EventEmitter,
) -> Vec<DenialRecord> {
    let backend = GuardSupervisorBackend {
        engine, context, outcome, emitter,
    };
    let mut denials = vec![];

    loop {
        let msg = match socket.recv_message() {
            Ok(m) => m,
            Err(_) => break,
        };

        let SupervisorMessage::Request(request) = msg;

        // 1. Check never_grant
        if never_grant.is_blocked(&request.path) {
            socket.send_response(SupervisorResponse::Decision {
                request_id: request.request_id.clone(),
                decision: ApprovalDecision::Denied {
                    reason: "Path is in never_grant list".into(),
                },
            }).ok();
            continue;
        }

        // 2. Route through guards
        match backend.request_capability(&request) {
            Ok(ApprovalDecision::Granted) => {
                // Issue extension token
                match macos::extension_issue_file(&request.path, request.access) {
                    Ok(token) => {
                        socket.send_response(SupervisorResponse::Decision {
                            request_id: request.request_id.clone(),
                            decision: ApprovalDecision::Granted,
                        }).ok();
                        // Send token as a separate message
                        socket.send_extension_token(&token).ok();
                    }
                    Err(_) => {
                        socket.send_response(SupervisorResponse::Decision {
                            request_id: request.request_id.clone(),
                            decision: ApprovalDecision::Denied {
                                reason: "Failed to issue extension token".into(),
                            },
                        }).ok();
                    }
                }
            }
            Ok(decision) => {
                socket.send_response(SupervisorResponse::Decision {
                    request_id: request.request_id.clone(),
                    decision,
                }).ok();
            }
            Err(e) => {
                socket.send_response(SupervisorResponse::Decision {
                    request_id: request.request_id.clone(),
                    decision: ApprovalDecision::Denied {
                        reason: format!("Guard error: {}", e),
                    },
                }).ok();
            }
        }
    }

    denials
}
```

## Fork+Exec Integration

### Modified spawn_sandboxed_child()

```rust
pub fn spawn_supervised_child(
    caps: &CapabilitySet,
    command: &[String],
    env_vars: &[(String, String)],
    engine: Arc<HushEngine>,
    context: GuardContext,
    never_grant: NeverGrantChecker,
    outcome: Arc<RunOutcome>,
    emitter: EventEmitter,
) -> Result<(i32, Vec<DenialRecord>)> {
    // Create supervisor socket pair
    let (supervisor_sock, child_sock) = SupervisorSocket::pair()?;

    // Pre-fork allocations
    let c_program = CString::new(command[0].as_str())?;
    let c_args = /* ... */;
    let c_env = /* ... */;

    match unsafe { fork() }? {
        ForkResult::Child => {
            // CHILD: only async-signal-safe operations from here.
            // Do NOT use ? operator — it invokes Drop/unwind machinery.
            drop(supervisor_sock); // Close supervisor end

            // Close inherited fds except stdin/stdout/stderr + child_sock
            close_inherited_fds(3, &[child_sock.as_raw_fd()]);

            // Apply Landlock sandbox — no ? operator!
            if let Err(e) = Sandbox::apply(caps) {
                let msg = format!("nono: sandbox apply failed: {}\n", e);
                unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
                unsafe { libc::_exit(126) };
            }

            // Linux: install seccomp-notify, send fd to parent
            #[cfg(target_os = "linux")]
            {
                match linux::install_seccomp_notify() {
                    Ok(notify_fd) => {
                        if child_sock.send_fd(notify_fd.as_raw_fd()).is_err() {
                            unsafe { libc::_exit(126) };
                        }
                    }
                    Err(_) => unsafe { libc::_exit(126) },
                }
            }

            // macOS: enable extensions (already in CapabilitySet)

            // Exec — replaces process image
            if let Err(_) = nix::unistd::execve(&c_program, &c_args, &c_env) {
                unsafe { libc::_exit(127) };
            }
            unsafe { libc::_exit(126) }; // unreachable
        }
        ForkResult::Parent { child } => {
            drop(child_sock); // Close child end

            // Linux: receive notify_fd
            #[cfg(target_os = "linux")]
            let notify_fd = supervisor_sock.recv_fd()?;

            // Run supervisor loop (blocking until child exits)
            let denials = run_supervisor_loop(
                notify_fd,
                child,
                engine,
                context,
                caps,
                never_grant,
                outcome,
                emitter,
            );

            let status = nix::sys::wait::waitpid(child, None)?;
            Ok((exit_code_from_status(status), denials))
        }
    }
}
```

## Security Properties

### TOCTOU Protection

The supervisor loop includes two TOCTOU checks:

1. **Before guard evaluation**: `notif_id_valid()` confirms the notification is still pending
2. **After guard approval**: Second `notif_id_valid()` before fd injection

Between these checks, the child's syscall is suspended by the kernel. The child cannot proceed until the supervisor responds.

**Code ref**: `nono/crates/nono/src/sandbox/linux.rs:706-730`

### Authorization Binding

The supervisor opens the file and injects the **supervisor's fd**, not the child's requested path. This means:
- Authorization is bound to the fd, not the path
- Symlink changes between check and use don't matter
- The child receives exactly what the supervisor approved

**Code ref**: `nono/crates/nono/src/sandbox/linux.rs:743-775`

### Never-Grant Enforcement

Paths in the never_grant list are denied **before** guard evaluation. This provides a hard floor that guards cannot override:

```
~/.ssh/id_rsa     → DENIED (never_grant, before guards)
/etc/shadow       → DENIED (never_grant, before guards)
/project/file.txt → routed to guards for evaluation
```

**Code ref**: `nono/crates/nono/src/supervisor/never_grant.rs:74-87`

### Fail-Closed

Every error path in the supervisor loop results in denial:
- Path read fails → deny
- TOCTOU check fails → skip (child moved on)
- Guard errors → deny
- Rate limit exceeded → deny
- Extension token issuance fails → deny

## Performance Considerations

| Operation | Latency | Notes |
|-----------|---------|-------|
| Initial capability set (fast-path) | ~microseconds | fd already available, no guard eval |
| Guard evaluation per request | ~milliseconds | Depends on guard complexity |
| seccomp-notify round-trip | ~100-500us | Kernel context switch overhead |
| Extension token issuance (macOS) | ~microseconds | Kernel HMAC computation |
| Rate limiter check | ~nanoseconds | Token bucket comparison |

For most agent workloads (tens to hundreds of file operations per session), the overhead is negligible. For build tools opening thousands of files, the fast-path (initial capability set) handles the common case.

## Audit Trail

Every supervisor decision is logged as an `AuditEntry`:

```rust
struct AuditEntry {
    timestamp: SystemTime,
    request: CapabilityRequest,
    decision: ApprovalDecision,
    backend: String,            // "clawdstrike-guard-supervisor"
    duration_ms: u64,
}
```

These entries are included in the receipt's `metadata.sandbox.audit` field, providing a complete record of every dynamic capability expansion.
