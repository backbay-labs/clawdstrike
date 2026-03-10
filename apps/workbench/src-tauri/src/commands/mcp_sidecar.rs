//! MCP sidecar management — spawns and manages the embedded MCP server process.
//!
//! On app startup the Tauri setup handler calls [`spawn_mcp_server`] which:
//!   1. Generates a random 32-char hex auth token via `getrandom`.
//!   2. Scans ports 9877-9899 for an available one.
//!   3. Spawns the bundled MCP binary in packaged builds, or the source-tree
//!      TypeScript server (`bun run` / `npx tsx`) during local development.
//!   4. Stores connection details in [`McpState`] for the frontend to query.

use std::path::Path;
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
}

impl McpState {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(McpInner {
                port: 0,
                token: String::new(),
                running: false,
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
    format!("mcp_{}", hex::encode(buf))
}

/// Check if a TCP port is available by attempting to bind to it.
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
    None
}

/// Resolve the path to the MCP server `index.ts` relative to the Tauri
/// project root (src-tauri). In dev mode the script lives at
/// `../mcp-server/index.ts` relative to `CARGO_MANIFEST_DIR`.
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
    if let Some(home) = dirs_next::home_dir() {
        for subdir in &[".local/bin", ".bun/bin", "bin"] {
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

/// Try to find a working JS runtime. Returns `(command, args_prefix)`.
/// Tries `bun` first, then `npx tsx`.
fn find_runtime() -> (String, Vec<String>) {
    if let Some(bun) = resolve_binary("bun") {
        return (bun, vec!["run".to_string()]);
    }
    if let Some(npx) = resolve_binary("npx") {
        return (npx, vec!["tsx".to_string()]);
    }
    // Last resort — caller will get a clear spawn error.
    ("npx".to_string(), vec!["tsx".to_string()])
}

/// Build an enriched PATH that includes common runtime locations.
/// macOS GUI apps inherit a minimal PATH from launchd (`/usr/bin:/bin:/usr/sbin:/sbin`),
/// so runtimes installed via Homebrew, bun, or nvm won't be found without this.
fn enriched_path() -> String {
    let mut dirs: Vec<String> = Vec::new();
    if let Some(home) = dirs_next::home_dir() {
        let home = home.to_string_lossy().to_string();
        dirs.push(format!("{home}/.local/bin"));
        dirs.push(format!("{home}/.bun/bin"));
        dirs.push(format!("{home}/.nvm/current/bin"));
        dirs.push(format!("{home}/bin"));
    }
    for extra in EXTRA_PATHS {
        dirs.push(extra.to_string());
    }
    // Append the existing PATH so we don't lose anything.
    if let Ok(existing) = std::env::var("PATH") {
        dirs.push(existing);
    } else {
        dirs.push("/usr/bin:/bin:/usr/sbin:/sbin".to_string());
    }
    dirs.join(":")
}

struct LaunchConfig {
    command_path: String,
    args: Vec<String>,
    runtime_label: String,
    entry_label: String,
}

fn resolve_launch_config<R: Runtime>(app: &tauri::AppHandle<R>) -> Result<LaunchConfig, String> {
    if cfg!(debug_assertions) {
        if let Some(script_path) = resolve_dev_script_path() {
            let (runtime_cmd, mut args) = find_runtime();
            args.push(script_path.clone());
            args.push("--sse".to_string());

            return Ok(LaunchConfig {
                command_path: runtime_cmd.clone(),
                args,
                runtime_label: runtime_cmd,
                entry_label: script_path,
            });
        }
    }

    if let Some(binary_path) = resolve_bundled_binary_path(app) {
        return Ok(LaunchConfig {
            command_path: binary_path.clone(),
            args: vec!["--sse".to_string()],
            runtime_label: "bundled".to_string(),
            entry_label: binary_path,
        });
    }

    let script_path = resolve_dev_script_path().ok_or_else(|| {
        format!(
            "Unable to resolve bundled MCP binary or dev script. Expected resource bin/{} or ../mcp-server/index.ts",
            bundled_binary_name()
        )
    })?;
    let (runtime_cmd, mut args) = find_runtime();
    args.push(script_path.clone());
    args.push("--sse".to_string());

    Ok(LaunchConfig {
        command_path: runtime_cmd.clone(),
        args,
        runtime_label: runtime_cmd,
        entry_label: script_path,
    })
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
    }

    let token = generate_token();
    let port = find_available_port()
        .await
        .ok_or_else(|| "No available port in range 9877-9899".to_string())?;
    let launch = resolve_launch_config(app)?;

    eprintln!(
        "[mcp-sidecar] spawning: {} {} (script: {}, port: {})",
        launch.runtime_label,
        launch.args.join(" "),
        launch.entry_label,
        port,
    );

    let mut child = tokio::process::Command::new(&launch.command_path)
        .args(&launch.args)
        .env("PATH", enriched_path())
        .env("MCP_TRANSPORT", "sse")
        .env("MCP_PORT", port.to_string())
        .env("MCP_AUTH_TOKEN", &token)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to spawn MCP server ({}): {e}", launch.runtime_label))?;

    // Give the server a moment to bind.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

    // Verify the child is still alive — it may have crashed immediately.
    match child.try_wait() {
        Ok(Some(exit_status)) => {
            // Child already exited — collect stderr for diagnostics.
            let stderr_msg = if let Some(stderr) = child.stderr.take() {
                use tokio::io::AsyncReadExt;
                let mut buf = Vec::new();
                let mut reader = stderr;
                let _ = reader.read_to_end(&mut buf).await;
                String::from_utf8_lossy(&buf).to_string()
            } else {
                String::new()
            };
            let msg = format!(
                "MCP server exited immediately (status: {exit_status}). stderr: {}",
                if stderr_msg.is_empty() { "(empty)" } else { stderr_msg.trim() },
            );
            eprintln!("[mcp-sidecar] {msg}");
            return Err(msg);
        }
        Ok(None) => {
            // Still running — good.
        }
        Err(e) => {
            eprintln!("[mcp-sidecar] try_wait error: {e}");
        }
    }

    let url = format!("http://localhost:{port}/sse");
    let response = McpStatusResponse {
        url: url.clone(),
        token: token.clone(),
        running: true,
    };

    {
        let mut inner = state
            .inner
            .lock()
            .map_err(|_| "McpState lock poisoned".to_string())?;
        inner.port = port;
        inner.token = token;
        inner.running = true;
        inner.child = Some(child);
        inner.runtime_cmd = launch.runtime_label;
        inner.script_path = launch.entry_label;
    }

    Ok(response)
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
                    inner.child = None;
                }
                Ok(None) => { /* still running */ }
                Err(_) => {
                    inner.running = false;
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
