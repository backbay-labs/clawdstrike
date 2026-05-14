//! MCP sidecar management — spawns and manages the embedded MCP server process.
//!
//! On app startup the Tauri setup handler calls [`spawn_mcp_server`] which:
//!   1. Generates a random 32-char hex auth token via `getrandom`.
//!   2. Scans ports 9877-9899 for an available one.
//!   3. Spawns the bundled MCP binary in packaged builds, or the source-tree
//!      TypeScript server (`bun run` / `npx tsx`) during local development.
//!   4. Stores connection details in [`McpState`] for the frontend to query.

use std::collections::HashSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{Manager, Runtime};
use tokio::sync::Mutex as AsyncMutex;

/// Shared state for the MCP sidecar, managed by Tauri.
#[derive(Clone)]
pub struct McpState {
    inner: Arc<Mutex<McpInner>>,
}

struct McpInner {
    port: u16,
    token: String,
    running: bool,
    last_error: Option<String>,
    child: Option<tokio::process::Child>,
    stderr_task: Option<tauri::async_runtime::JoinHandle<()>>,
    /// The resolved runtime command (e.g. "bun" or "npx").
    runtime_cmd: String,
    /// The resolved path to the MCP server entry point.
    script_path: String,
}

#[derive(Serialize, Clone)]
pub struct McpStatusResponse {
    pub url: String,
    pub token: String,
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl McpState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(McpInner {
                port: 0,
                token: String::new(),
                running: false,
                last_error: None,
                child: None,
                stderr_task: None,
                runtime_cmd: String::new(),
                script_path: String::new(),
            })),
        }
    }
}

fn clear_runtime_state(inner: &mut McpInner) {
    if let Some(stderr_task) = inner.stderr_task.take() {
        stderr_task.abort();
    }
    inner.port = 0;
    inner.token.clear();
    inner.running = false;
    inner.last_error = None;
    inner.child = None;
    inner.runtime_cmd.clear();
    inner.script_path.clear();
}

fn set_runtime_error(inner: &mut McpInner, error: impl Into<String>) {
    clear_runtime_state(inner);
    inner.last_error = Some(error.into());
}

fn persist_runtime_error(state: &McpState, error: impl Into<String>) -> String {
    let error = error.into();
    if let Ok(mut inner) = state.inner.lock() {
        set_runtime_error(&mut inner, error.clone());
    }
    error
}

fn current_status(inner: &McpInner) -> McpStatusResponse {
    McpStatusResponse {
        url: if inner.running {
            format!("http://localhost:{}/sse", inner.port)
        } else {
            String::new()
        },
        token: if inner.running {
            inner.token.clone()
        } else {
            String::new()
        },
        running: inner.running,
        error: if inner.running {
            None
        } else {
            inner.last_error.clone()
        },
    }
}

/// Generate a 36-character token (mcp_ prefix + 32 hex chars) using `getrandom`.
fn generate_token() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    // Prefix with mcp_ for recognizability
    let token = format!("mcp_{}", hex::encode(buf));
    debug_assert!(
        token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "Token contains unexpected characters"
    );
    token
}

/// Check if a port is available by attempting to bind.
/// NOTE: TOCTOU risk — port may be claimed between check and actual use.
/// Mitigated by trying multiple ports in range 9877-9899.
async fn port_available(port: u16) -> bool {
    tokio::net::TcpListener::bind(("127.0.0.1", port))
        .await
        .is_ok()
}

/// Find an available port in the range 9877..=9899.
async fn find_available_port() -> Option<u16> {
    for port in 9877..=9899 {
        if port_available(port).await {
            return Some(port);
        }
    }
    eprintln!("[mcp-sidecar] All ports 9877-9899 are occupied. Check for orphaned MCP processes or conflicting services.");
    None
}

/// Resolve the dev-mode MCP server script path.
/// SECURITY NOTE: canonicalize() follows symlinks. In dev mode, this resolves
/// relative to CARGO_MANIFEST_DIR (compile-time constant). Symlink attacks
/// require write access to the source tree, which implies full compromise.
fn resolve_dev_script_path() -> Option<String> {
    let dev_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../mcp-server/index.ts");
    if dev_path.exists() {
        return Some(
            dev_path
                .canonicalize()
                .unwrap_or_else(|_| dev_path.clone())
                .to_string_lossy()
                .to_string(),
        );
    }
    None
}

fn bundled_binary_name() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        "workbench-mcp.exe"
    }
    #[cfg(not(target_os = "windows"))]
    {
        "workbench-mcp"
    }
}

fn resolve_bundled_binary_path<R: Runtime>(app: &tauri::AppHandle<R>) -> Option<String> {
    let resource_dir = app.path().resource_dir().ok()?;
    let candidate = resource_dir.join("bin").join(bundled_binary_name());
    if candidate.exists() {
        return Some(candidate.to_string_lossy().to_string());
    }
    None
}

/// Common locations for JS runtimes on macOS/Linux that may not be on the
/// restricted PATH inherited by GUI apps launched from Finder/Dock.
#[cfg(windows)]
const EXTRA_PATHS: &[&str] = &[r"C:\Program Files\nodejs", r"C:\Program Files\Git\cmd"];
#[cfg(not(windows))]
const EXTRA_PATHS: &[&str] = &["/opt/homebrew/bin", "/usr/local/bin"];

#[cfg(windows)]
const HOME_BIN_SUBDIRS: &[&[&str]] = &[
    &["AppData", "Local", "Microsoft", "WindowsApps"],
    &["AppData", "Local", "bun", "bin"],
    &["bin"],
    &[".cargo", "bin"],
];

#[cfg(not(windows))]
const HOME_BIN_SUBDIRS: &[&[&str]] = &[
    &[".local", "bin"],
    &[".bun", "bin"],
    &[".nvm", "current", "bin"],
    &["bin"],
    &[".local", "share", "mise", "shims"],
    &[".asdf", "shims"],
    &[".proto", "shims"],
    &[".proto", "bin"],
    &[".cargo", "bin"],
    &[".nix-profile", "bin"],
    &[".pyenv", "shims"],
];

fn home_bin_path(home: &std::path::Path, subdir: &[&str]) -> PathBuf {
    subdir
        .iter()
        .fold(home.to_path_buf(), |path, segment| path.join(segment))
}

#[cfg(windows)]
fn executable_suffixes() -> Vec<String> {
    let from_env = std::env::var("PATHEXT")
        .ok()
        .map(|value| {
            value
                .split(';')
                .filter_map(|suffix| {
                    let trimmed = suffix.trim();
                    if trimmed.is_empty() {
                        return None;
                    }
                    let normalized = if trimmed.starts_with('.') {
                        trimmed.to_ascii_lowercase()
                    } else {
                        format!(".{}", trimmed.to_ascii_lowercase())
                    };
                    Some(normalized)
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if from_env.is_empty() {
        vec![
            ".com".to_string(),
            ".exe".to_string(),
            ".bat".to_string(),
            ".cmd".to_string(),
        ]
    } else {
        from_env
    }
}

fn binary_path_candidates(base: &Path) -> Vec<PathBuf> {
    #[cfg(windows)]
    let mut candidates = vec![base.to_path_buf()];
    #[cfg(not(windows))]
    let candidates = vec![base.to_path_buf()];

    #[cfg(windows)]
    {
        if base.extension().is_none() {
            for suffix in executable_suffixes() {
                candidates.push(base.with_extension(suffix.trim_start_matches('.')));
            }
        }
    }

    candidates
}

/// Resolve an absolute path for `name` by checking PATH first, then common
/// install locations. Returns `None` if the binary cannot be found anywhere.
fn resolve_binary(name: &str) -> Option<String> {
    // Try the ambient PATH first (works when launched from a terminal).
    if std::process::Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
    {
        return Some(name.to_string());
    }
    // Check the user's home-local bin (e.g. ~/.local/bin/bun, ~/.bun/bin/bun).
    // SECURITY NOTE: .exists() follows symlinks. An attacker with write access
    // to ~/.bun/bin/ etc. could point to a malicious binary. Mitigated by
    // running with user privileges (no escalation possible).
    if let Some(home) = dirs_next::home_dir() {
        for subdir in HOME_BIN_SUBDIRS {
            for candidate in binary_path_candidates(&home_bin_path(&home, subdir).join(name)) {
                if candidate.exists() {
                    return Some(candidate.to_string_lossy().to_string());
                }
            }
        }
    }
    // Check well-known system paths.
    for dir in EXTRA_PATHS {
        for candidate in binary_path_candidates(&std::path::PathBuf::from(dir).join(name)) {
            if candidate.exists() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }
    None
}

fn push_runtime_candidate(
    candidates: &mut Vec<(String, Vec<String>)>,
    seen: &mut HashSet<String>,
    command: String,
    args_prefix: Vec<String>,
) {
    let key = format!("{}|{}", command, args_prefix.join(" "));
    if seen.insert(key) {
        candidates.push((command, args_prefix));
    }
}

/// Candidate JS runtimes for the dev-side TypeScript server.
/// We prefer `npx tsx` for the desktop sidecar because it has been more stable
/// than `bun run` under the Tauri-owned GUI child process on macOS. Bun remains
/// as a fallback for machines without a Node/npm toolchain on PATH.
fn runtime_candidates() -> Vec<(String, Vec<String>)> {
    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    if let Some(npx) = resolve_binary("npx") {
        push_runtime_candidate(&mut candidates, &mut seen, npx, vec!["tsx".to_string()]);
    }
    if let Some(bun) = resolve_binary("bun") {
        push_runtime_candidate(&mut candidates, &mut seen, bun, vec!["run".to_string()]);
    }

    push_runtime_candidate(
        &mut candidates,
        &mut seen,
        "npx".to_string(),
        vec!["tsx".to_string()],
    );
    push_runtime_candidate(
        &mut candidates,
        &mut seen,
        "bun".to_string(),
        vec!["run".to_string()],
    );

    candidates
}

/// Build an enriched PATH that includes common runtime locations.
/// macOS GUI apps inherit a minimal PATH from launchd (`/usr/bin:/bin:/usr/sbin:/sbin`),
/// so runtimes installed via Homebrew, bun, or nvm won't be found without this.
fn default_path_entries() -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        vec![
            PathBuf::from(r"C:\Windows\System32"),
            PathBuf::from(r"C:\Windows"),
        ]
    }

    #[cfg(not(windows))]
    {
        vec![
            PathBuf::from("/usr/bin"),
            PathBuf::from("/bin"),
            PathBuf::from("/usr/sbin"),
            PathBuf::from("/sbin"),
        ]
    }
}

fn build_enriched_path(existing_path: Option<OsString>, home_dir: Option<PathBuf>) -> OsString {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(home) = home_dir {
        for subdir in HOME_BIN_SUBDIRS {
            dirs.push(home_bin_path(&home, subdir));
        }
    }
    dirs.extend(EXTRA_PATHS.iter().map(PathBuf::from));

    if let Some(existing) = existing_path {
        dirs.extend(std::env::split_paths(&existing));
    } else {
        dirs.extend(default_path_entries());
    }

    // Deduplicate while preserving order (first occurrence wins)
    let mut seen = std::collections::HashSet::new();
    dirs.retain(|d| seen.insert(d.clone()));

    std::env::join_paths(dirs)
        .unwrap_or_else(|_| OsString::from(std::env::var("PATH").unwrap_or_default()))
}

fn enriched_path() -> OsString {
    build_enriched_path(std::env::var_os("PATH"), dirs_next::home_dir())
}

struct LaunchConfig {
    command_path: String,
    args: Vec<String>,
    runtime_label: String,
    entry_label: String,
}

fn push_launch_config(
    configs: &mut Vec<LaunchConfig>,
    seen: &mut HashSet<String>,
    config: LaunchConfig,
) {
    let key = format!(
        "{}|{}|{}|{}",
        config.command_path,
        config.args.join(" "),
        config.runtime_label,
        config.entry_label
    );
    if seen.insert(key) {
        configs.push(config);
    }
}

fn resolve_launch_configs<R: Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<Vec<LaunchConfig>, String> {
    let mut configs = Vec::new();
    let mut seen = HashSet::new();

    if cfg!(debug_assertions) {
        if let Some(script_path) = resolve_dev_script_path() {
            for (runtime_cmd, args_prefix) in runtime_candidates() {
                let mut args = args_prefix;
                args.push(script_path.clone());
                args.push("--sse".to_string());

                push_launch_config(
                    &mut configs,
                    &mut seen,
                    LaunchConfig {
                        command_path: runtime_cmd.clone(),
                        args,
                        runtime_label: runtime_cmd,
                        entry_label: script_path.clone(),
                    },
                );
            }
        }
    }

    if let Some(binary_path) = resolve_bundled_binary_path(app) {
        push_launch_config(
            &mut configs,
            &mut seen,
            LaunchConfig {
                command_path: binary_path.clone(),
                args: vec!["--sse".to_string()],
                runtime_label: "bundled".to_string(),
                entry_label: binary_path,
            },
        );
    }

    if !cfg!(debug_assertions) && configs.is_empty() {
        if let Some(script_path) = resolve_dev_script_path() {
            for (runtime_cmd, args_prefix) in runtime_candidates() {
                let mut args = args_prefix;
                args.push(script_path.clone());
                args.push("--sse".to_string());

                push_launch_config(
                    &mut configs,
                    &mut seen,
                    LaunchConfig {
                        command_path: runtime_cmd.clone(),
                        args,
                        runtime_label: runtime_cmd,
                        entry_label: script_path.clone(),
                    },
                );
            }
        }
    }

    if configs.is_empty() {
        return Err(format!(
            "Unable to resolve bundled MCP binary or dev script. Expected resource bin/{} or ../mcp-server/index.ts",
            bundled_binary_name()
        ));
    }

    Ok(configs)
}

const SIDECAR_STARTUP_TIMEOUT_MS: u64 = 5_000;
const SIDECAR_READY_POLL_MS: u64 = 150;
const SIDECAR_HEALTHCHECK_TIMEOUT_MS: u64 = 250;
const STARTUP_STDERR_CAPTURE_LIMIT: usize = 8_192;
const SIDECAR_STARTING_MESSAGE: &str = "Embedded MCP sidecar is starting...";

async fn sidecar_healthcheck_ready(port: u16) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let connect = tokio::time::timeout(
        std::time::Duration::from_millis(SIDECAR_HEALTHCHECK_TIMEOUT_MS),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await;
    let mut stream = match connect {
        Ok(Ok(stream)) => stream,
        _ => return false,
    };

    let request =
        format!("GET /health HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).await.is_err() {
        return false;
    }

    let mut buf = [0u8; 128];
    match tokio::time::timeout(
        std::time::Duration::from_millis(SIDECAR_HEALTHCHECK_TIMEOUT_MS),
        stream.read(&mut buf),
    )
    .await
    {
        Ok(Ok(n)) if n > 0 => {
            let response = String::from_utf8_lossy(&buf[..n]);
            response.starts_with("HTTP/1.1 200") || response.starts_with("HTTP/1.0 200")
        }
        _ => false,
    }
}

async fn spawn_child_for_launch(
    launch: &LaunchConfig,
    port: u16,
    token: &str,
) -> Result<SpawnedChild, String> {
    let mut child = tokio::process::Command::new(&launch.command_path)
        .args(&launch.args)
        .env("PATH", enriched_path())
        .env("MCP_TRANSPORT", "sse")
        .env("MCP_PORT", port.to_string())
        .env("MCP_AUTH_TOKEN", token)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to spawn MCP server ({}): {e}", launch.runtime_label))?;
    let stderr_buffer = Arc::new(AsyncMutex::new(Vec::new()));
    let mut stderr_task = None;
    if let Some(stderr) = child.stderr.take() {
        let stderr_buffer_for_task = Arc::clone(&stderr_buffer);
        stderr_task = Some(tauri::async_runtime::spawn(async move {
            drain_child_stderr(stderr, stderr_buffer_for_task).await;
        }));
    }

    let startup_deadline =
        tokio::time::Instant::now() + std::time::Duration::from_millis(SIDECAR_STARTUP_TIMEOUT_MS);

    loop {
        match child.try_wait() {
            Ok(Some(exit_status)) => {
                let stderr_msg = snapshot_stderr_buffer(&stderr_buffer).await;
                let msg = format!(
                    "MCP server exited immediately (status: {exit_status}). stderr: {}",
                    if stderr_msg.is_empty() {
                        "(empty)"
                    } else {
                        stderr_msg.trim()
                    },
                );
                eprintln!("[mcp-sidecar] {msg}");
                #[cfg(unix)]
                {
                    use std::os::unix::process::ExitStatusExt;
                    if let Some(signal) = exit_status.signal() {
                        let sig_name = match signal {
                            11 => "SIGSEGV",
                            6 => "SIGABRT",
                            9 => "SIGKILL",
                            15 => "SIGTERM",
                            _ => "unknown",
                        };
                        eprintln!(
                            "[mcp-sidecar] MCP server killed by signal {signal} ({sig_name})"
                        );
                    }
                }
                if let Some(task) = stderr_task.take() {
                    task.abort();
                }
                return Err(msg);
            }
            Ok(None) => {
                if sidecar_healthcheck_ready(port).await {
                    return Ok(SpawnedChild { child, stderr_task });
                }
            }
            Err(e) => {
                let msg = format!(
                    "Failed to inspect MCP sidecar process ({}): {e}",
                    launch.runtime_label
                );
                eprintln!("[mcp-sidecar] {msg}");
                if let Some(task) = stderr_task.take() {
                    task.abort();
                }
                return Err(msg);
            }
        }

        if tokio::time::Instant::now() >= startup_deadline {
            let _ = child.start_kill();
            let stderr_msg = snapshot_stderr_buffer(&stderr_buffer).await;
            if let Some(task) = stderr_task.take() {
                task.abort();
            }
            return Err(if stderr_msg.is_empty() {
                format!(
                    "MCP server failed to become ready on /health within {}ms",
                    SIDECAR_STARTUP_TIMEOUT_MS
                )
            } else {
                format!(
                    "MCP server failed to become ready on /health within {}ms. stderr: {}",
                    SIDECAR_STARTUP_TIMEOUT_MS,
                    stderr_msg.trim()
                )
            });
        }

        tokio::time::sleep(std::time::Duration::from_millis(SIDECAR_READY_POLL_MS)).await;
    }
}

struct SpawnedChild {
    child: tokio::process::Child,
    stderr_task: Option<tauri::async_runtime::JoinHandle<()>>,
}

fn append_capped_stderr(buffer: &mut Vec<u8>, chunk: &[u8]) {
    if buffer.len() >= STARTUP_STDERR_CAPTURE_LIMIT {
        return;
    }

    let remaining = STARTUP_STDERR_CAPTURE_LIMIT - buffer.len();
    let take_len = remaining.min(chunk.len());
    buffer.extend_from_slice(&chunk[..take_len]);
}

async fn snapshot_stderr_buffer(buffer: &Arc<AsyncMutex<Vec<u8>>>) -> String {
    let bytes = buffer.lock().await;
    String::from_utf8_lossy(&bytes).to_string()
}

async fn drain_child_stderr(
    mut stderr: tokio::process::ChildStderr,
    stderr_buffer: Arc<AsyncMutex<Vec<u8>>>,
) {
    use tokio::io::AsyncReadExt;

    let mut buf = [0u8; 4096];
    loop {
        match stderr.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => {
                let mut captured = stderr_buffer.lock().await;
                append_capped_stderr(&mut captured, &buf[..n]);
            }
            Err(err) => {
                eprintln!("[mcp-sidecar] stderr drain failed: {err}");
                break;
            }
        }
    }
}

/// Spawn the MCP server process. Returns the connection info on success.
pub async fn spawn_mcp_server<R: Runtime>(
    app: &tauri::AppHandle<R>,
    state: &McpState,
) -> Result<McpStatusResponse, String> {
    // Kill any existing child process before spawning a new one
    {
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| "McpState lock poisoned".to_string())?;
        if let Some(ref mut child) = inner.child {
            let _ = child.start_kill();
        }
        clear_runtime_state(&mut inner);
        inner.last_error = Some(SIDECAR_STARTING_MESSAGE.to_string());
    }

    let token = generate_token();
    let launch_configs = match resolve_launch_configs(app) {
        Ok(configs) => configs,
        Err(error) => return Err(persist_runtime_error(state, error)),
    };
    let mut launch_errors = Vec::new();

    for launch in launch_configs {
        // Find a fresh port for each attempt — a previous failed spawn may have
        // left the port in TIME_WAIT or another process may have claimed it.
        let port = match find_available_port().await {
            Some(port) => port,
            None => {
                return Err(persist_runtime_error(
                    state,
                    "No available port in range 9877-9899",
                ));
            }
        };

        eprintln!(
            "[mcp-sidecar] spawning: {} {} (script: {}, port: {})",
            launch.runtime_label,
            launch.args.join(" "),
            launch.entry_label,
            port,
        );

        match spawn_child_for_launch(&launch, port, &token).await {
            Ok(spawned) => {
                let url = format!("http://localhost:{port}/sse");
                let response = McpStatusResponse {
                    url: url.clone(),
                    token: token.clone(),
                    running: true,
                    error: None,
                };

                {
                    let mut inner = state
                        .inner
                        .lock()
                        .map_err(|_| "McpState lock poisoned".to_string())?;
                    inner.port = port;
                    inner.token = token;
                    inner.running = true;
                    inner.last_error = None;
                    inner.child = Some(spawned.child);
                    inner.stderr_task = spawned.stderr_task;
                    inner.runtime_cmd = launch.runtime_label;
                    inner.script_path = launch.entry_label;
                }

                return Ok(response);
            }
            Err(error) => {
                launch_errors.push(format!("{} -> {}", launch.runtime_label, error));
            }
        }
    }

    let combined_error = format!(
        "Failed to start embedded MCP sidecar. Launch attempts: {}",
        launch_errors.join(" | ")
    );
    Err(persist_runtime_error(state, combined_error))
}

/// Kill the running MCP server child process if any.
pub fn kill_mcp_server(state: &McpState) {
    if let Ok(mut inner) = state.inner.lock() {
        if let Some(ref mut child) = inner.child {
            // best-effort kill
            let _ = child.start_kill();
        }
        clear_runtime_state(&mut inner);
    }
}

// Tauri commands

#[tauri::command]
pub async fn stop_mcp_server(
    state: tauri::State<'_, McpState>,
) -> Result<McpStatusResponse, String> {
    kill_mcp_server(&state);
    Ok(McpStatusResponse {
        url: String::new(),
        token: String::new(),
        running: false,
        error: None,
    })
}

#[tauri::command]
pub async fn get_mcp_status(
    state: tauri::State<'_, McpState>,
) -> Result<McpStatusResponse, String> {
    let mut inner = state
        .inner
        .lock()
        .map_err(|_| "McpState lock poisoned".to_string())?;
    // Check if the child process is still alive — it may have crashed since last check.
    if inner.running {
        if let Some(ref mut child) = inner.child {
            match child.try_wait() {
                Ok(Some(_exit_status)) => {
                    // Child exited — update state.
                    set_runtime_error(&mut inner, "Embedded MCP sidecar exited unexpectedly");
                }
                Ok(None) => { /* still running */ }
                Err(_) => {
                    set_runtime_error(&mut inner, "Failed to inspect embedded MCP sidecar status");
                }
            }
        }
    }
    Ok(current_status(&inner))
}

#[tauri::command]
pub async fn restart_mcp_server(
    app: tauri::AppHandle,
    state: tauri::State<'_, McpState>,
) -> Result<McpStatusResponse, String> {
    kill_mcp_server(&state);
    // Small delay to let the port be released
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    spawn_mcp_server(&app, &state).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_home_dir() -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\Users\tester")
        }

        #[cfg(not(windows))]
        {
            PathBuf::from("/tmp/tester")
        }
    }

    fn test_existing_path() -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(r"C:\tools\bin")
        }

        #[cfg(not(windows))]
        {
            PathBuf::from("/opt/test/bin")
        }
    }

    #[test]
    fn generate_token_has_expected_prefix_and_length() {
        let token = generate_token();
        assert!(token.starts_with("mcp_"));
        assert_eq!(token.len(), 36);
        assert!(token[4..].chars().all(|ch| ch.is_ascii_hexdigit()));
    }

    #[test]
    fn build_enriched_path_preserves_existing_entries_and_adds_runtime_dirs() {
        let enriched = build_enriched_path(
            Some(std::env::join_paths([test_existing_path()]).unwrap()),
            Some(test_home_dir()),
        );
        let entries: Vec<PathBuf> = std::env::split_paths(&enriched).collect();

        assert!(entries.contains(&home_bin_path(&test_home_dir(), HOME_BIN_SUBDIRS[0])));
        assert!(entries.contains(&home_bin_path(&test_home_dir(), HOME_BIN_SUBDIRS[1])));
        assert!(entries.contains(&test_existing_path()));
    }

    #[test]
    fn binary_path_candidates_include_platform_executable_suffixes() {
        let base = PathBuf::from("/tmp/bun");
        let candidates = binary_path_candidates(&base);

        assert!(candidates.contains(&base));

        #[cfg(windows)]
        {
            assert!(candidates
                .iter()
                .any(|candidate| candidate.ends_with("bun.exe")));
            assert!(candidates
                .iter()
                .any(|candidate| candidate.ends_with("bun.cmd")));
        }
    }

    #[test]
    fn runtime_candidates_include_bare_command_fallbacks() {
        let candidates = runtime_candidates();

        assert!(candidates
            .iter()
            .any(|(command, args)| command == "bun" && args == &vec!["run".to_string()]));
        assert!(candidates
            .iter()
            .any(|(command, args)| command == "npx" && args == &vec!["tsx".to_string()]));
    }

    #[test]
    fn clear_runtime_state_scrubs_cached_token_and_port() {
        let mut inner = McpInner {
            port: 9877,
            token: "mcp_secret".to_string(),
            running: true,
            last_error: Some("boom".to_string()),
            child: None,
            stderr_task: None,
            runtime_cmd: "bun".to_string(),
            script_path: "server.ts".to_string(),
        };

        clear_runtime_state(&mut inner);

        assert_eq!(inner.port, 0);
        assert!(inner.token.is_empty());
        assert!(!inner.running);
        assert!(inner.child.is_none());
        assert!(inner.stderr_task.is_none());
        assert!(inner.runtime_cmd.is_empty());
        assert!(inner.script_path.is_empty());
        assert!(inner.last_error.is_none());
    }

    #[test]
    fn current_status_hides_token_when_sidecar_is_stopped() {
        let inner = McpInner {
            port: 9877,
            token: "mcp_secret".to_string(),
            running: false,
            last_error: Some("sidecar stopped".to_string()),
            child: None,
            stderr_task: None,
            runtime_cmd: "bun".to_string(),
            script_path: "server.ts".to_string(),
        };

        let status = current_status(&inner);

        assert!(status.url.is_empty());
        assert!(status.token.is_empty());
        assert!(!status.running);
        assert_eq!(status.error.as_deref(), Some("sidecar stopped"));
    }

    #[test]
    fn append_capped_stderr_keeps_earliest_bytes_from_large_chunk() {
        let mut buffer = Vec::new();
        let mut chunk = vec![b'a'; STARTUP_STDERR_CAPTURE_LIMIT];
        chunk.extend_from_slice(b"trailer");

        append_capped_stderr(&mut buffer, &chunk);

        assert_eq!(buffer.len(), STARTUP_STDERR_CAPTURE_LIMIT);
        assert!(buffer.iter().all(|byte| *byte == b'a'));
    }

    #[test]
    fn append_capped_stderr_stops_appending_after_capacity() {
        let mut buffer = vec![b'a'; STARTUP_STDERR_CAPTURE_LIMIT - 4];

        append_capped_stderr(&mut buffer, b"bbbbbbbb");

        assert_eq!(buffer.len(), STARTUP_STDERR_CAPTURE_LIMIT);
        assert!(buffer[..STARTUP_STDERR_CAPTURE_LIMIT - 4]
            .iter()
            .all(|byte| *byte == b'a'));
        assert_eq!(&buffer[STARTUP_STDERR_CAPTURE_LIMIT - 4..], b"bbbb");
    }

    #[test]
    fn current_status_surfaces_starting_message_when_sidecar_is_booting() {
        let inner = McpInner {
            port: 0,
            token: String::new(),
            running: false,
            last_error: Some(SIDECAR_STARTING_MESSAGE.to_string()),
            child: None,
            stderr_task: None,
            runtime_cmd: String::new(),
            script_path: String::new(),
        };

        let status = current_status(&inner);

        assert!(!status.running);
        assert_eq!(status.error.as_deref(), Some(SIDECAR_STARTING_MESSAGE));
    }

    #[test]
    fn persist_runtime_error_replaces_starting_message() {
        let state = McpState::new();
        {
            let mut inner = match state.inner.lock() {
                Ok(inner) => inner,
                Err(_) => panic!("McpState lock poisoned"),
            };
            inner.port = 9877;
            inner.token = "mcp_secret".to_string();
            inner.running = true;
            inner.last_error = Some(SIDECAR_STARTING_MESSAGE.to_string());
            inner.runtime_cmd = "bun".to_string();
            inner.script_path = "server.ts".to_string();
        }

        let error = persist_runtime_error(&state, "No available port in range 9877-9899");

        assert_eq!(error, "No available port in range 9877-9899");

        let inner = match state.inner.lock() {
            Ok(inner) => inner,
            Err(_) => panic!("McpState lock poisoned"),
        };
        assert_eq!(
            inner.last_error.as_deref(),
            Some("No available port in range 9877-9899")
        );
        assert_eq!(inner.port, 0);
        assert!(inner.token.is_empty());
        assert!(!inner.running);
        assert!(inner.runtime_cmd.is_empty());
        assert!(inner.script_path.is_empty());
    }
}
