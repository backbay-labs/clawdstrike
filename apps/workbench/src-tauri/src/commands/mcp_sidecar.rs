//! MCP sidecar management — spawns and manages the embedded MCP server process.
//!
//! On app startup the Tauri setup handler calls [`spawn_mcp_server`] which:
//!   1. Generates a random 32-char hex auth token via `getrandom`.
//!   2. Scans ports 9877-9899 for an available one.
//!   3. Spawns the bundled MCP binary in packaged builds, or the source-tree
//!      TypeScript server (`bun run` / `npx tsx`) during local development.
//!   4. Stores connection details in [`McpState`] for the frontend to query.

use std::ffi::OsString;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{Manager, Runtime};

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
                runtime_cmd: String::new(),
                script_path: String::new(),
            })),
        }
    }
}

/// Generate a 36-character token (mcp_ prefix + 32 hex chars) using `getrandom`.
fn generate_token() -> String {
    let mut buf = [0u8; 16];
    getrandom::getrandom(&mut buf).expect("getrandom failed");
    // Prefix with mcp_ for recognizability
    let token = format!("mcp_{}", hex::encode(buf));
    debug_assert!(token.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'), "Token contains unexpected characters");
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
const EXTRA_PATHS: &[&str] = &[
    "/opt/homebrew/bin",
    "/usr/local/bin",
];

const HOME_BIN_SUBDIRS: &[&str] = &[
    ".local/bin",
    ".bun/bin",
    ".nvm/current/bin",
    "bin",
    ".local/share/mise/shims",
    ".asdf/shims",
    ".proto/shims",
    ".proto/bin",
    ".cargo/bin",
    ".nix-profile/bin",
    ".pyenv/shims",
];

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
            let candidate = home.join(subdir).join(name);
            if candidate.exists() {
                return Some(candidate.to_string_lossy().to_string());
            }
        }
    }
    // Check well-known system paths.
    for dir in EXTRA_PATHS {
        let candidate = std::path::PathBuf::from(dir).join(name);
        if candidate.exists() {
            return Some(candidate.to_string_lossy().to_string());
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
            dirs.push(home.join(subdir));
        }
    }
    dirs.extend(EXTRA_PATHS.iter().map(PathBuf::from));

    if let Some(existing) = existing_path {
        dirs.extend(std::env::split_paths(&existing));
    } else {
        dirs.extend(default_path_entries());
    }

    std::env::join_paths(dirs)
        .unwrap_or_else(|_| OsString::from(std::env::var("PATH").unwrap_or_default()))
}

fn enriched_path() -> String {
    build_enriched_path(std::env::var_os("PATH"), dirs_next::home_dir())
        .to_string_lossy()
        .to_string()
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

fn resolve_launch_configs<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<Vec<LaunchConfig>, String> {
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

async fn spawn_child_for_launch(launch: &LaunchConfig, port: u16, token: &str) -> Result<tokio::process::Child, String> {
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

    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    match child.try_wait() {
        Ok(Some(exit_status)) => {
            let stderr_msg = if let Some(stderr) = child.stderr.take() {
                use tokio::io::AsyncReadExt;
                let mut buf = vec![0u8; 8192];
                let mut reader = stderr;
                let n = reader.read(&mut buf).await.unwrap_or(0);
                buf.truncate(n);
                String::from_utf8_lossy(&buf).to_string()
            } else {
                String::new()
            };
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
                    eprintln!("[mcp-sidecar] MCP server killed by signal {signal} ({sig_name})");
                }
            }
            Err(msg)
        }
        Ok(None) => Ok(child),
        Err(e) => {
            let msg = format!("Failed to inspect MCP sidecar process ({}): {e}", launch.runtime_label);
            eprintln!("[mcp-sidecar] {msg}");
            Err(msg)
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
        let mut inner = state.inner.lock().map_err(|_| "McpState lock poisoned".to_string())?;
        if let Some(ref mut child) = inner.child {
            let _ = child.start_kill();
        }
        inner.child = None;
        inner.running = false;
        inner.last_error = None;
    }

    let token = generate_token();
    let port = find_available_port()
        .await
        .ok_or_else(|| "No available port in range 9877-9899".to_string())?;
    let launch_configs = resolve_launch_configs(app)?;
    let mut launch_errors = Vec::new();

    for launch in launch_configs {
        eprintln!(
            "[mcp-sidecar] spawning: {} {} (script: {}, port: {})",
            launch.runtime_label,
            launch.args.join(" "),
            launch.entry_label,
            port,
        );

        match spawn_child_for_launch(&launch, port, &token).await {
            Ok(child) => {
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
                    inner.child = Some(child);
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
    if let Ok(mut inner) = state.inner.lock() {
        inner.running = false;
        inner.last_error = Some(combined_error.clone());
    }
    Err(combined_error)
}

/// Kill the running MCP server child process if any.
pub fn kill_mcp_server(state: &McpState) {
    if let Ok(mut inner) = state.inner.lock() {
        if let Some(ref mut child) = inner.child {
            // best-effort kill
            let _ = child.start_kill();
        }
        inner.child = None;
        inner.running = false;
    }
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

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
                    inner.running = false;
                    inner.last_error = Some("Embedded MCP sidecar exited unexpectedly".to_string());
                    inner.child = None;
                }
                Ok(None) => { /* still running */ }
                Err(_) => {
                    inner.running = false;
                    inner.last_error =
                        Some("Failed to inspect embedded MCP sidecar status".to_string());
                    inner.child = None;
                }
            }
        }
    }
    Ok(McpStatusResponse {
        url: if inner.running {
            format!("http://localhost:{}/sse", inner.port)
        } else {
            String::new()
        },
        token: inner.token.clone(),
        running: inner.running,
        error: if inner.running {
            None
        } else {
            inner.last_error.clone()
        },
    })
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

        assert!(entries.contains(&test_home_dir().join(".local/bin")));
        assert!(entries.contains(&test_home_dir().join(".bun/bin")));
        assert!(entries.contains(&test_existing_path()));
    }

    #[test]
    fn runtime_candidates_include_bare_command_fallbacks() {
        let candidates = runtime_candidates();

        assert!(
            candidates
                .iter()
                .any(|(command, args)| command == "bun" && args == &vec!["run".to_string()])
        );
        assert!(
            candidates
                .iter()
                .any(|(command, args)| command == "npx" && args == &vec!["tsx".to_string()])
        );
    }
}
