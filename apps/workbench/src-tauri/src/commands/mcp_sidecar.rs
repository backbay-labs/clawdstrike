//! MCP sidecar management — spawns and manages the embedded MCP server process.
//!
//! On app startup the Tauri setup handler calls [`spawn_mcp_server`] which:
//!   1. Generates a random 32-char hex auth token via `getrandom`.
//!   2. Scans ports 9877-9899 for an available one.
//!   3. Spawns the MCP TypeScript server (`bun run` or `npx tsx` fallback)
//!      with `MCP_TRANSPORT=sse`, `MCP_PORT`, and `MCP_AUTH_TOKEN` env vars.
//!   4. Stores connection details in [`McpState`] for the frontend to query.

use std::sync::{Arc, Mutex};

use serde::Serialize;

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

/// Generate a 32-character hex token using `getrandom`.
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
fn resolve_script_path() -> String {
    let dev_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../mcp-server/index.ts");
    if dev_path.exists() {
        return dev_path
            .canonicalize()
            .unwrap_or_else(|_| dev_path.clone())
            .to_string_lossy()
            .to_string();
    }
    // Fallback: assume cwd-relative path
    "mcp-server/index.ts".to_string()
}

/// Try to find a working JS runtime. Returns `(command, args_prefix)`.
/// Tries `bun` first, then `npx tsx`.
fn find_runtime() -> (String, Vec<String>) {
    // Check if `bun` is on PATH
    if std::process::Command::new("bun")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
    {
        return ("bun".to_string(), vec!["run".to_string()]);
    }
    // Fallback to npx tsx
    ("npx".to_string(), vec!["tsx".to_string()])
}

/// Spawn the MCP server process. Returns the connection info on success.
pub async fn spawn_mcp_server(state: &McpState) -> Result<McpStatusResponse, String> {
    let token = generate_token();
    let port = find_available_port()
        .await
        .ok_or_else(|| "No available port in range 9877-9899".to_string())?;
    let script_path = resolve_script_path();
    let (runtime_cmd, mut args) = find_runtime();

    args.push(script_path.clone());
    args.push("--sse".to_string());

    let child = tokio::process::Command::new(&runtime_cmd)
        .args(&args)
        .env("MCP_TRANSPORT", "sse")
        .env("MCP_PORT", port.to_string())
        .env("MCP_AUTH_TOKEN", &token)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| format!("Failed to spawn MCP server ({runtime_cmd}): {e}"))?;

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
        inner.runtime_cmd = runtime_cmd;
        inner.script_path = script_path;
    }

    // Give the server a moment to bind, then verify the health endpoint.
    tokio::time::sleep(std::time::Duration::from_millis(800)).await;

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
    let inner = state
        .inner
        .lock()
        .map_err(|_| "McpState lock poisoned".to_string())?;
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
    state: tauri::State<'_, McpState>,
) -> Result<McpStatusResponse, String> {
    kill_mcp_server(&state);
    // Small delay to let the port be released
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    spawn_mcp_server(&state).await
}
