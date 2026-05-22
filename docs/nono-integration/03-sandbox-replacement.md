# 03 - Sandbox Replacement (Phase 1)

Replace the ad-hoc `sandbox-exec`/`bwrap` wrappers in `hush run` with nono's cross-platform sandbox API.

## Current Implementation

### SandboxWrapper Enum

**File**: `crates/services/hush-cli/src/hush_run.rs:678-688`

```rust
enum SandboxWrapper {
    None,
    SandboxExec { profile_path: PathBuf },  // macOS
    Bwrap { args: Vec<String> },            // Linux
}
```

### maybe_prepare_sandbox()

**File**: `crates/services/hush-cli/src/hush_run.rs:690-743`

Generates platform-specific sandbox configuration:

- **macOS** (lines 698-718): Writes a Seatbelt profile to a temp file, returns `SandboxExec`
- **Linux** (lines 722-731): Builds bwrap bind-mount arguments, returns `Bwrap`

### generate_macos_sandbox_profile()

**File**: `crates/services/hush-cli/src/hush_run.rs:746-785`

Generates a static Seatbelt profile with hardcoded denies:

```scheme
(version 1)
(allow default)
(deny file-read* (subpath "/Users/USERNAME/.ssh"))
(deny file-read* (subpath "/Users/USERNAME/.gnupg"))
(deny file-read* (subpath "/Users/USERNAME/.aws"))
(deny file-read* (subpath "/Users/USERNAME/.config/gcloud"))
(deny file-read* (subpath "/Users/USERNAME/.config/gh"))
(deny file-read* (subpath "/Users/USERNAME/.config/git"))
(deny file-read* (subpath "/Users/USERNAME/.kube"))
```

**Problems with current approach**:
1. Not integrated with policy YAML - hardcoded paths only
2. Uses `(allow default)` - overly permissive base
3. No network enforcement
4. No signal isolation
5. No command blocking
6. Linux bwrap path is minimal (bind mounts only)
7. Not capability-based

### spawn_and_wait_child()

**File**: `crates/services/hush-cli/src/hush_run.rs:787-833`

```rust
// Current: wraps command with platform shim
let mut cmd = match sandbox {
    None => Command::new(&command[0]),
    SandboxExec { profile_path } => {
        Command::new("/usr/bin/sandbox-exec")
            .arg("-f").arg(profile_path)
            .arg(&command[0])
    }
    Bwrap { args } => {
        Command::new("bwrap")
            .args(args)
            .arg(&command[0])
    }
};
cmd.args(&command[1..]);
// ... set env vars, spawn, wait
```

## Replacement Design

### New: nono as Cargo Dependency

Add to `crates/services/hush-cli/Cargo.toml`:

```toml
[dependencies]
nono = { path = "../../../nono/crates/nono" }
# Or when published: nono = "0.11"
```

### New: sandbox_nono.rs

Replace `SandboxWrapper`, `maybe_prepare_sandbox()`, `generate_macos_sandbox_profile()`, and the sandbox branch in `spawn_and_wait_child()` with a unified module.

#### build_capability_set()

Builds a `CapabilitySet` from the current execution context:

```rust
use nono::{CapabilitySet, AccessMode, NetworkMode, Sandbox, SandboxState, QueryContext};

pub fn build_capability_set(
    working_dir: &Path,
    command: &[String],
    proxy_port: Option<u16>,
    extra_read_paths: &[PathBuf],
    extra_write_paths: &[PathBuf],
    blocked_commands: &[String],
) -> nono::Result<CapabilitySet> {
    let mut caps = CapabilitySet::new();

    // Grant working directory read-write
    caps = caps.allow_path(working_dir, AccessMode::ReadWrite)?;

    // System paths (read-only)
    // These mirror nono's system_read_* groups
    for path in system_read_paths() {
        if path.exists() {
            caps = caps.allow_path(path, AccessMode::Read)?;
        }
    }

    // System writable paths (tmp, dev)
    for path in system_write_paths() {
        if path.exists() {
            caps = caps.allow_path(path, AccessMode::ReadWrite)?;
        }
    }

    // Extra paths from policy
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

    // Network: proxy-only if proxy is active
    if let Some(port) = proxy_port {
        caps = caps.proxy_only(port);
    } else {
        caps = caps.block_network();
    }

    // Blocked commands
    for cmd in blocked_commands {
        caps = caps.block_command(cmd);
    }

    Ok(caps)
}
```

#### system_read_paths() / system_write_paths()

Platform-specific system paths, matching nono's `policy.json` groups:

```rust
#[cfg(target_os = "macos")]
fn system_read_paths() -> Vec<PathBuf> {
    // NOTE: Do NOT grant broad directories like /private/var which contains
    // sensitive data (FileVault keys, user databases, Keychain DBs).
    // Grant only specific subdirectories needed for execution.
    vec![
        "/bin", "/usr", "/sbin",
        "/System/Library", "/Library",
        "/private/etc",
        "/opt/homebrew",
    ].into_iter().map(PathBuf::from).collect()
}

#[cfg(target_os = "linux")]
fn system_read_paths() -> Vec<PathBuf> {
    vec![
        "/bin", "/lib", "/lib64", "/usr", "/sbin",
        "/etc", "/proc", "/sys", "/run",
    ].into_iter().map(PathBuf::from).collect()
}
```

#### validate_capabilities()

Pre-flight check using `QueryContext`:

```rust
pub fn validate_capabilities(
    caps: &CapabilitySet,
    command: &[String],
    working_dir: &Path,
) -> Vec<String> {
    let ctx = QueryContext::new(caps.clone());
    let mut warnings = vec![];

    // Verify working directory is accessible
    if let QueryResult::Denied(reason) = ctx.query_path(working_dir, AccessMode::ReadWrite) {
        warnings.push(format!("Working dir {} denied: {:?}", working_dir.display(), reason));
    }

    // Verify command binary is accessible
    if let Ok(bin) = which::which(&command[0]) {
        if let QueryResult::Denied(reason) = ctx.query_path(&bin, AccessMode::Read) {
            warnings.push(format!("Command {} denied: {:?}", bin.display(), reason));
        }
    }

    warnings
}
```

#### spawn_sandboxed_child()

Replace `spawn_and_wait_child()` with fork+exec:

> **SAFETY NOTE**: After `fork()`, the child process must NOT use Rust's `?` operator,
> `panic!`, or any non-async-signal-safe operations. Errors must be reported via raw
> `libc::write` to stderr and terminated with `libc::_exit`. See nono-cli's
> `exec_strategy.rs:407-418` for the reference implementation.

```rust
pub fn spawn_sandboxed_child(
    caps: &CapabilitySet,
    command: &[String],
    proxy_port: Option<u16>,
) -> Result<i32> {
    // Pre-fork: prepare all strings (no allocation after fork)
    let c_program = CString::new(command[0].as_str())?;
    let c_args: Vec<CString> = command.iter()
        .map(|a| CString::new(a.as_str()))
        .collect::<Result<_, _>>()?;

    // Build child environment: inherit current env + add proxy vars
    let mut env_map: HashMap<String, String> = std::env::vars().collect();
    if let Some(port) = proxy_port {
        let proxy_url = format!("http://127.0.0.1:{}", port);
        env_map.insert("HTTPS_PROXY".into(), proxy_url.clone());
        env_map.insert("HTTP_PROXY".into(), proxy_url.clone());
        env_map.insert("ALL_PROXY".into(), proxy_url);
    }
    let c_env: Vec<CString> = env_map.iter()
        .map(|(k, v)| CString::new(format!("{}={}", k, v)))
        .collect::<Result<_, _>>()?;

    match unsafe { nix::unistd::fork() }? {
        ForkResult::Child => {
            // CHILD: only async-signal-safe operations from here

            // Close inherited fds (proxy socket, parent resources)
            // Keep only stdin(0), stdout(1), stderr(2)
            close_inherited_fds(3);

            // Apply sandbox (irrevocable) — no ? operator!
            if let Err(e) = Sandbox::apply(caps) {
                let msg = format!("nono: sandbox apply failed: {}\n", e);
                unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
                unsafe { libc::_exit(126) };
            }

            // Exec — replaces process image
            if let Err(e) = nix::unistd::execve(&c_program, &c_args, &c_env) {
                let msg = format!("nono: exec failed: {}\n", e);
                unsafe { libc::write(2, msg.as_ptr().cast(), msg.len()) };
                unsafe { libc::_exit(127) };
            }
            unsafe { libc::_exit(126) }; // unreachable
        }
        ForkResult::Parent { child } => {
            // Forward signals to child
            // (install SIGINT/SIGTERM handler that calls kill(child, sig))

            // Wait for child (blocking — run BEFORE Tokio if applicable)
            let status = nix::sys::wait::waitpid(child, None)?;
            Ok(exit_code_from_status(status))
        }
    }
}

fn close_inherited_fds(from_fd: i32) {
    // Close all fds >= from_fd to prevent child inheriting
    // proxy socket, supervisor socket, log handles, etc.
    if let Ok(max) = rlimit::getrlimit(rlimit::Resource::NOFILE) {
        for fd in from_fd..max.0 as i32 {
            unsafe { libc::close(fd) };
        }
    }
}
```

### Changes to hush_run.rs

#### Remove

- `SandboxWrapper` enum (line 678-688)
- `maybe_prepare_sandbox()` (line 690-743)
- `generate_macos_sandbox_profile()` (line 746-785)
- Sandbox branch in `spawn_and_wait_child()` (line 787-833)

#### Modify cmd_run()

**File**: `crates/services/hush-cli/src/hush_run.rs:234-577`

Replace sandbox preparation (lines 377-383) with:

```rust
// Build capability set
let caps = sandbox_nono::build_capability_set(
    &working_dir,
    &command,
    proxy_port,
    &extra_read_paths,
    &extra_write_paths,
    &blocked_commands,
)?;

// Pre-flight validation
let warnings = sandbox_nono::validate_capabilities(&caps, &command, &working_dir);
for w in &warnings {
    eprintln!("[nono] warning: {}", w);
}

// Check platform support
if !Sandbox::is_supported() {
    eprintln!("[nono] warning: sandbox not supported on this platform");
    eprintln!("[nono] {}", Sandbox::support_info().details);
}
```

Replace child spawn (lines 385-406) with:

```rust
// Spawn sandboxed child
let child_exit_code = sandbox_nono::spawn_sandboxed_child(
    &caps,
    &command,
    &env_vars,
)?;
```

### Migration Path

1. Add `nono` dependency to hush-cli Cargo.toml
2. Create `sandbox_nono.rs` module
3. Replace `maybe_prepare_sandbox()` calls with `build_capability_set()`
4. Replace `spawn_and_wait_child()` sandbox branches with `spawn_sandboxed_child()`
5. Delete `SandboxWrapper`, `generate_macos_sandbox_profile()`
6. Update tests

### Testing

```rust
#[test]
fn test_capability_set_blocks_ssh() {
    let tmp = tempfile::TempDir::new().unwrap();  // real dir for canonicalization
    let caps = build_capability_set(
        tmp.path(),
        &["ls".into()],
        None,  // no proxy
        &[],
        &[],
        &[],
    ).unwrap();

    let ctx = QueryContext::new(caps);
    let home = dirs::home_dir().unwrap();
    let ssh_dir = home.join(".ssh");

    // .ssh should NOT be in the capability set
    assert!(matches!(
        ctx.query_path(&ssh_dir, AccessMode::Read),
        QueryResult::Denied(_)
    ));
}

#[test]
fn test_capability_set_allows_working_dir() {
    let tmp = tempfile::TempDir::new().unwrap();
    let caps = build_capability_set(
        tmp.path(),
        &["ls".into()],
        None,
        &[],
        &[],
        &[],
    ).unwrap();

    let ctx = QueryContext::new(caps);
    assert!(matches!(
        ctx.query_path(tmp.path(), AccessMode::ReadWrite),
        QueryResult::Allowed(_)
    ));
}

#[test]
fn test_proxy_only_network() {
    let tmp = tempfile::TempDir::new().unwrap();
    let caps = build_capability_set(
        tmp.path(),
        &["ls".into()],
        Some(8080),
        &[],
        &[],
        &[],
    ).unwrap();

    // network_mode() returns &NetworkMode — dereference for matches!
    assert!(matches!(
        *caps.network_mode(),
        NetworkMode::ProxyOnly { port: 8080, .. }
    ));
}
```

### Rollback Plan

If nono integration causes issues, the `--sandbox=legacy` flag can be added to fall back to the old `sandbox-exec`/`bwrap` behavior during the transition period.

## Nono API Surface Used (Phase 1)

| API | Source | Purpose |
|-----|--------|---------|
| `CapabilitySet::new()` | `capability.rs:467` | Create empty set |
| `.allow_path(path, mode)` | `capability.rs:477` | Grant directory access |
| `.allow_file(path, mode)` | `capability.rs:487` | Grant file access |
| `.block_network()` | `capability.rs:497` | Block all network |
| `.proxy_only(port)` | `capability.rs:514` | Route through proxy |
| `.block_command(cmd)` | `capability.rs:630` | Block command execution |
| `Sandbox::apply(&caps)` | `sandbox/mod.rs:77` | Apply kernel sandbox |
| `Sandbox::is_supported()` | `sandbox/mod.rs:105` | Check platform support |
| `Sandbox::support_info()` | `sandbox/mod.rs:124` | Get support details |
| `QueryContext::new(caps)` | `query.rs:58` | Create query context |
| `.query_path(path, mode)` | `query.rs:71` | Check path permission |
| `SandboxState::from_caps()` | `state.rs:34` | Serialize for receipt |
