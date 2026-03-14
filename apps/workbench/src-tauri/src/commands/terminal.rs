//! PTY terminal session management for SwarmBoard.
//!
//! Each session wraps a `portable-pty` pseudo-terminal, streaming output to the
//! frontend via Tauri events and maintaining a bounded ring buffer for tile
//! previews. Sessions are identified by UUIDs and stored in a thread-safe
//! [`TerminalManager`] managed by Tauri state.

use std::collections::HashMap;
use std::io::{Read as IoRead, Write as IoWrite};
use std::sync::Arc;

use chrono::Utc;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Runtime};
use tokio::sync::Mutex;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum number of lines retained in the ring buffer per session.
const RING_BUFFER_MAX_LINES: usize = 200;

/// Default number of preview lines returned by `terminal_preview`.
const DEFAULT_PREVIEW_LINES: usize = 6;

/// Default PTY size (columns x rows).
const DEFAULT_COLS: u16 = 80;
const DEFAULT_ROWS: u16 = 24;

/// Read chunk size for the stdout reader task.
const READ_CHUNK_SIZE: usize = 4096;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A live PTY session.
pub struct TerminalSession {
    pub id: String,
    pub master: Box<dyn MasterPty + Send>,
    pub child: Box<dyn Child + Send + Sync>,
    pub writer: Box<dyn IoWrite + Send>,
    pub cwd: String,
    pub branch: Option<String>,
    pub created_at: String,
    /// Handle to the background reader task so we can abort on cleanup.
    pub reader_task: Option<tauri::async_runtime::JoinHandle<()>>,
}

/// Serialisable session info returned to the frontend.
#[derive(Serialize, Clone)]
pub struct SessionInfo {
    pub id: String,
    pub cwd: String,
    pub branch: Option<String>,
    pub created_at: String,
    pub alive: bool,
    pub exit_code: Option<i32>,
    pub line_count: usize,
}

/// Central manager holding all active sessions.
pub struct TerminalManager {
    sessions: HashMap<String, TerminalSession>,
}

/// Type alias for the Tauri-managed terminal state.
pub type TerminalState = Arc<Mutex<TerminalManager>>;

impl TerminalManager {
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the current git branch in a directory (best-effort).
fn detect_git_branch(cwd: &str) -> Option<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .current_dir(cwd)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if output.status.success() {
        let branch = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if branch.is_empty() || branch == "HEAD" {
            None
        } else {
            Some(branch)
        }
    } else {
        None
    }
}

/// Environment variable names that must not be overridden by callers.
///
/// These can be used for library injection (`LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`),
/// path hijacking (`PATH`), or identity spoofing (`HOME`, `USER`). We use an
/// allowlist-style check: only env vars prefixed with `CLAWDSTRIKE_` or `SWARM_`
/// are allowed through unconditionally; everything else is checked against this
/// blocklist. The comparison is case-insensitive to cover platform differences.
const BLOCKED_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "DYLD_FRAMEWORK_PATH",
    "PATH",
    "HOME",
    "USER",
    "SHELL",
    "TERM",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
];

/// Returns `true` if `key` should be blocked from caller-supplied env overrides.
///
/// Keys prefixed with `CLAWDSTRIKE_` or `SWARM_` are always allowed (these are
/// the application's own configuration variables). All other keys are checked
/// against [`BLOCKED_ENV_VARS`] (case-insensitive).
fn is_blocked_env_var(key: &str) -> bool {
    let upper = key.to_uppercase();
    // Always allow our own namespaced variables
    if upper.starts_with("CLAWDSTRIKE_") || upper.starts_with("SWARM_") {
        return false;
    }
    BLOCKED_ENV_VARS
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(key))
}

/// Allowlist of safe shell paths. Shells not on this list are rejected to
/// prevent arbitrary binary execution through the `shell` parameter.
const ALLOWED_SHELLS: &[&str] = &[
    "/bin/bash",
    "/bin/sh",
    "/bin/zsh",
    "/usr/bin/bash",
    "/usr/bin/zsh",
    "/usr/bin/sh",
    "/usr/local/bin/bash",
    "/usr/local/bin/zsh",
    "/usr/local/bin/fish",
    "/opt/homebrew/bin/bash",
    "/opt/homebrew/bin/zsh",
    "/opt/homebrew/bin/fish",
    "cmd.exe",
    "powershell.exe",
];

/// Returns `true` if the given shell path is in the [`ALLOWED_SHELLS`] allowlist.
fn is_allowed_shell(shell: &str) -> bool {
    ALLOWED_SHELLS.contains(&shell)
}

/// Determine the default shell for the current user.
///
/// Prefers the `SHELL` environment variable. On Unix-like systems, falls back
/// through `/bin/bash` then `/bin/sh` rather than assuming zsh is installed.
fn default_shell() -> String {
    std::env::var("SHELL").unwrap_or_else(|_| {
        if cfg!(target_os = "windows") {
            "cmd.exe".to_string()
        } else if std::path::Path::new("/bin/bash").exists() {
            "/bin/bash".to_string()
        } else {
            "/bin/sh".to_string()
        }
    })
}

/// Append a chunk of output to the ring buffer, splitting on newlines and
/// enforcing the capacity limit.
///
/// Handles partial lines correctly: the first segment of a chunk is appended
/// to the last buffer entry (continuing a partial line), and subsequent
/// segments start new lines.
fn append_to_ring_buffer(buffer: &mut Vec<String>, chunk: &str) {
    let mut segments = chunk.split('\n');

    // First segment: append to the last line (partial line continuation).
    if let Some(first) = segments.next() {
        if let Some(last) = buffer.last_mut() {
            last.push_str(first);
        } else {
            buffer.push(first.to_string());
        }
    }

    // Remaining segments are new lines (each '\n' in the input starts one).
    for segment in segments {
        buffer.push(segment.to_string());
    }

    // Trim oldest lines to stay within capacity.
    if buffer.len() > RING_BUFFER_MAX_LINES {
        let excess = buffer.len() - RING_BUFFER_MAX_LINES;
        buffer.drain(..excess);
    }
}

/// Build a [`SessionInfo`] snapshot from a live session.
fn session_info(session: &mut TerminalSession) -> SessionInfo {
    let (alive, exit_code) = match session.child.try_wait() {
        Ok(Some(status)) => (false, Some(status.exit_code() as i32)),
        Ok(None) => (true, None),
        Err(_) => (false, None),
    };

    let line_count = get_ring_buffer(&session.id)
        .map(|buf| buf.len())
        .unwrap_or(0);

    SessionInfo {
        id: session.id.clone(),
        cwd: session.cwd.clone(),
        branch: session.branch.clone(),
        created_at: session.created_at.clone(),
        alive,
        exit_code,
        line_count,
    }
}

// ---------------------------------------------------------------------------
// Ring buffer shared state for the reader task
// ---------------------------------------------------------------------------

/// Shared ring buffer that the reader task writes to and the main thread reads.
/// This avoids holding the session lock during blocking I/O.
struct SharedRingBuffer {
    inner: std::sync::Mutex<Vec<String>>,
}

impl SharedRingBuffer {
    fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn append(&self, chunk: &str) {
        if let Ok(mut buf) = self.inner.lock() {
            append_to_ring_buffer(&mut buf, chunk);
        }
    }

    fn tail(&self, n: usize) -> Vec<String> {
        self.inner
            .lock()
            .map(|buf| {
                let start = buf.len().saturating_sub(n);
                buf[start..].to_vec()
            })
            .unwrap_or_default()
    }

    fn len(&self) -> usize {
        self.inner.lock().map(|buf| buf.len()).unwrap_or(0)
    }
}

// We store the shared ring buffers keyed by session ID alongside the manager
// so the reader tasks (which cannot hold the async Mutex) can write freely.
/// Global registry of shared ring buffers, keyed by session ID.
/// Uses a std::sync::Mutex so both sync reader threads and async commands can access it.
static RING_BUFFERS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, Arc<SharedRingBuffer>>>> =
    std::sync::OnceLock::new();

fn ring_buffers() -> &'static std::sync::Mutex<HashMap<String, Arc<SharedRingBuffer>>> {
    RING_BUFFERS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn get_ring_buffer(session_id: &str) -> Option<Arc<SharedRingBuffer>> {
    ring_buffers()
        .lock()
        .ok()
        .and_then(|map| map.get(session_id).cloned())
}

fn insert_ring_buffer(session_id: &str) -> Arc<SharedRingBuffer> {
    let buf = Arc::new(SharedRingBuffer::new());
    if let Ok(mut map) = ring_buffers().lock() {
        map.insert(session_id.to_string(), Arc::clone(&buf));
    }
    buf
}

fn remove_ring_buffer(session_id: &str) {
    if let Ok(mut map) = ring_buffers().lock() {
        map.remove(session_id);
    }
}

// ---------------------------------------------------------------------------
// Tauri commands
// ---------------------------------------------------------------------------

/// Create a new PTY session.
///
/// Spawns a shell process inside a pseudo-terminal and starts a background task
/// that reads stdout, populates the ring buffer, and emits `terminal:output:{id}`
/// events to the frontend.
#[tauri::command]
pub async fn terminal_create<R: Runtime>(
    app: AppHandle<R>,
    state: tauri::State<'_, TerminalState>,
    cwd: String,
    shell: Option<String>,
    env: Option<HashMap<String, String>>,
) -> Result<SessionInfo, String> {
    // Validate cwd exists
    if !std::path::Path::new(&cwd).is_dir() {
        return Err(format!("Working directory does not exist: {cwd}"));
    }

    let session_id = Uuid::new_v4().to_string();
    let shell_path = match shell {
        Some(ref s) if is_allowed_shell(s) => s.clone(),
        Some(ref s) => {
            eprintln!(
                "[terminal] Requested shell {:?} is not in the allowlist; falling back to default",
                s
            );
            default_shell()
        }
        None => default_shell(),
    };
    let branch = detect_git_branch(&cwd);
    let created_at = Utc::now().to_rfc3339();

    // Create the PTY pair
    let pty_system = native_pty_system();
    let pty_pair = pty_system
        .openpty(PtySize {
            rows: DEFAULT_ROWS,
            cols: DEFAULT_COLS,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("Failed to open PTY: {e}"))?;

    // Build the command
    let mut cmd = CommandBuilder::new(&shell_path);
    cmd.cwd(&cwd);

    // Set TERM for colour support
    cmd.env("TERM", "xterm-256color");

    // Merge caller-supplied environment variables, filtering out dangerous
    // keys that could be used for privilege escalation or library injection.
    if let Some(extra_env) = env {
        for (key, value) in extra_env {
            if is_blocked_env_var(&key) {
                continue;
            }
            cmd.env(key, value);
        }
    }

    // Spawn the child
    let child = pty_pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| format!("Failed to spawn shell ({shell_path}): {e}"))?;

    // Take a writer handle for stdin
    let writer = pty_pair
        .master
        .take_writer()
        .map_err(|e| format!("Failed to take PTY writer: {e}"))?;

    // Take a reader handle for stdout
    let mut reader = pty_pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("Failed to clone PTY reader: {e}"))?;

    // Set up the shared ring buffer
    let shared_buf = insert_ring_buffer(&session_id);

    // Spawn a background thread (not async — the PTY reader is blocking I/O)
    // that reads output, populates the ring buffer, and emits Tauri events.
    let event_session_id = session_id.clone();
    let app_handle = app.clone();
    let buf_for_task = Arc::clone(&shared_buf);
    // Clone the TerminalState Arc so the reader thread can check exit code after EOF.
    let state_for_reader: TerminalState = (*state).clone();
    let reader_task = tauri::async_runtime::spawn_blocking(move || {
        let event_name = format!("terminal:output:{}", event_session_id);
        let mut chunk_buf = vec![0u8; READ_CHUNK_SIZE];
        loop {
            match reader.read(&mut chunk_buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let text = String::from_utf8_lossy(&chunk_buf[..n]).to_string();
                    // Append to ring buffer
                    buf_for_task.append(&text);
                    // Emit to frontend
                    let _ = app_handle.emit(&event_name, &text);
                }
                Err(e) => {
                    // On macOS, EIO is expected when the child exits and the
                    // slave side of the PTY closes.
                    if e.kind() != std::io::ErrorKind::Other {
                        eprintln!("[terminal] reader error for {}: {e}", event_session_id);
                    }
                    break;
                }
            }
        }

        // PTY reader has ended — the child process has exited (or the PTY
        // was closed). Try to retrieve the exit code and emit a terminal
        // exit event so the frontend can update session status.
        //
        // Brief sleep to let the child process fully exit before we check.
        std::thread::sleep(std::time::Duration::from_millis(100));
        // Use try_lock() instead of block_on(lock().await) to avoid
        // deadlocking: we're inside spawn_blocking and must not block on
        // the async Mutex via the tokio runtime handle.
        let exit_code: Option<i32> = state_for_reader
            .try_lock()
            .ok()
            .and_then(|mut manager| {
                if let Some(session) = manager.sessions.get_mut(&event_session_id) {
                    match session.child.try_wait() {
                        Ok(Some(status)) => Some(status.exit_code() as i32),
                        _ => None,
                    }
                } else {
                    None
                }
            });

        let exit_event = format!("terminal:exit:{}", event_session_id);
        let _ = app_handle.emit(&exit_event, exit_code);
    });

    // Build the session
    let session = TerminalSession {
        id: session_id.clone(),
        master: pty_pair.master,
        child,
        writer,
        cwd: cwd.clone(),
        branch: branch.clone(),
        created_at: created_at.clone(),
        reader_task: Some(reader_task),
    };

    let info = SessionInfo {
        id: session_id.clone(),
        cwd,
        branch,
        created_at,
        alive: true,
        exit_code: None,
        line_count: 0,
    };

    // Store the session
    {
        let mut manager = state.lock().await;
        manager.sessions.insert(session_id, session);
    }

    Ok(info)
}

/// Write data to a PTY session's stdin.
#[tauri::command]
pub async fn terminal_write(
    state: tauri::State<'_, TerminalState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    let mut manager = state.lock().await;
    let session = manager
        .sessions
        .get_mut(&session_id)
        .ok_or_else(|| format!("Session not found: {session_id}"))?;

    session
        .writer
        .write_all(data.as_bytes())
        .map_err(|e| format!("Failed to write to PTY: {e}"))?;
    session
        .writer
        .flush()
        .map_err(|e| format!("Failed to flush PTY writer: {e}"))?;

    Ok(())
}

/// Resize a PTY session.
#[tauri::command]
pub async fn terminal_resize(
    state: tauri::State<'_, TerminalState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    let manager = state.lock().await;
    let session = manager
        .sessions
        .get(&session_id)
        .ok_or_else(|| format!("Session not found: {session_id}"))?;

    session
        .master
        .resize(PtySize {
            rows: rows.max(1),
            cols: cols.max(1),
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("Failed to resize PTY: {e}"))?;

    Ok(())
}

/// Kill a PTY session and clean up resources.
#[tauri::command]
pub async fn terminal_kill(
    state: tauri::State<'_, TerminalState>,
    session_id: String,
) -> Result<(), String> {
    let mut manager = state.lock().await;
    let mut session = manager
        .sessions
        .remove(&session_id)
        .ok_or_else(|| format!("Session not found: {session_id}"))?;

    // Kill the child process (best-effort)
    let _ = session.child.kill();

    // Abort the reader task
    if let Some(task) = session.reader_task.take() {
        task.abort();
    }

    // Clean up the shared ring buffer
    remove_ring_buffer(&session_id);

    Ok(())
}

/// List all active terminal sessions.
#[tauri::command]
pub async fn terminal_list(
    state: tauri::State<'_, TerminalState>,
) -> Result<Vec<SessionInfo>, String> {
    let mut manager = state.lock().await;
    let mut infos = Vec::with_capacity(manager.sessions.len());

    for session in manager.sessions.values_mut() {
        infos.push(session_info(session));
    }

    // Sort by creation time for deterministic ordering
    infos.sort_by(|a, b| a.created_at.cmp(&b.created_at));

    Ok(infos)
}

/// Return the last N lines from a session's ring buffer for tile preview.
#[tauri::command]
pub async fn terminal_preview(
    state: tauri::State<'_, TerminalState>,
    session_id: String,
    lines: Option<usize>,
) -> Result<Vec<String>, String> {
    // Verify the session exists
    {
        let manager = state.lock().await;
        if !manager.sessions.contains_key(&session_id) {
            return Err(format!("Session not found: {session_id}"));
        }
    }

    let n = lines.unwrap_or(DEFAULT_PREVIEW_LINES);

    let buf = get_ring_buffer(&session_id)
        .ok_or_else(|| format!("Ring buffer not found for session: {session_id}"))?;

    Ok(buf.tail(n))
}

/// Return the current working directory of the Tauri process.
///
/// Used by the frontend to auto-detect a sensible default for `repoRoot` when
/// none is configured (e.g. first launch).
#[tauri::command]
pub fn get_cwd() -> Result<String, String> {
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

/// Kill all sessions. Called during app shutdown.
pub async fn kill_all_sessions(state: &TerminalState) {
    let mut manager = state.lock().await;
    let session_ids: Vec<String> = manager.sessions.keys().cloned().collect();
    for id in session_ids {
        if let Some(mut session) = manager.sessions.remove(&id) {
            let _ = session.child.kill();
            if let Some(task) = session.reader_task.take() {
                task.abort();
            }
            remove_ring_buffer(&id);
        }
    }
}
