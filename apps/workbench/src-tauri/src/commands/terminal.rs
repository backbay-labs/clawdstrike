//! PTY terminal session management for SwarmBoard.
//!
//! Each session wraps a `portable-pty` pseudo-terminal, streaming output to the
//! frontend via Tauri events and maintaining a bounded ring buffer for tile
//! previews. Sessions are identified by UUIDs and stored in a thread-safe
//! [`TerminalManager`] managed by Tauri state.

use std::collections::HashMap;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::Path;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use chrono::Utc;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde::Serialize;
use tauri::{AppHandle, Emitter, Runtime};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use uuid::Uuid;

use crate::commands::capability::{authorize_sensitive_command, CommandCapabilityState};
use crate::commands::repo_roots;

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
const MAX_EXTRA_ENV_VARS: usize = 64;
const MAX_ENV_KEY_LEN: usize = 128;
const MAX_ENV_VALUE_LEN: usize = 8192;
const MAX_ACTIVE_SESSIONS: usize = 32;
const MAX_WRITE_BYTES: usize = 64 * 1024;
const MAX_PREVIEW_LINES: usize = 200;

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
    pub alive: Arc<AtomicBool>,
    pub _session_permit: OwnedSemaphorePermit,
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

/// Environment keys allowed from caller-supplied PTY spawn payloads.
const ALLOWED_EXTRA_ENV_VARS: &[&str] = &[
    "TERM",
    "LANG",
    "LC_ALL",
    "LC_COLLATE",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_MONETARY",
    "LC_NUMERIC",
    "LC_TIME",
    "NO_COLOR",
    "PAGER",
    "EDITOR",
    "VISUAL",
    "TZ",
    "TMPDIR",
    "TMP",
    "TEMP",
];

/// Returns `true` if `key` is allowed in caller-supplied env.
fn is_allowed_env_var(key: &str) -> bool {
    ALLOWED_EXTRA_ENV_VARS
        .iter()
        .any(|allowed| key.eq_ignore_ascii_case(allowed))
}

/// Allowlist of safe shell command names.
///
/// Path-like values are rejected so caller input cannot execute arbitrary binaries.
const ALLOWED_SHELLS: &[&str] = &["sh", "bash", "zsh", "fish", "cmd", "powershell", "pwsh"];

fn normalize_shell(shell: &str) -> Option<String> {
    let shell = shell.trim();
    if shell.is_empty() {
        return None;
    }

    let path = Path::new(shell);

    // Reject relative paths with directory components (e.g. `./bash`,
    // `subdir/bash`) — only bare names and absolute paths are accepted.
    if !path.is_absolute() && path.components().count() != 1 {
        eprintln!("[terminal] Rejected relative path shell value: {:?}", shell);
        return None;
    }

    // Extract the base name from the path.
    let file_name = path.file_name()?.to_string_lossy();
    let file_name = if cfg!(target_os = "windows") {
        // Case-insensitive .exe trim for Windows (e.g. CMD.EXE → CMD).
        let s = file_name.as_ref();
        if s.len() > 4 && s[s.len() - 4..].eq_ignore_ascii_case(".exe") {
            &s[..s.len() - 4]
        } else {
            s
        }
    } else {
        file_name.as_ref()
    };

    let allowed = ALLOWED_SHELLS
        .iter()
        .find(|allowed| file_name.eq_ignore_ascii_case(allowed));

    if let Some(allowed) = allowed {
        // For absolute paths (e.g. $SHELL=/bin/zsh), return the original
        // absolute path so the OS resolves the intended binary rather than
        // relying on PATH lookup. For bare names, return the canonical name.
        if path.is_absolute() {
            Some(shell.to_string())
        } else {
            Some((*allowed).to_string())
        }
    } else {
        eprintln!("[terminal] Rejected shell not in allowlist: {:?}", shell);
        None
    }
}

fn normalize_cwd(cwd: &str) -> Result<String, String> {
    if cwd.len() > 4096 {
        return Err("Working directory path is too long".to_string());
    }
    let canonical = std::fs::canonicalize(cwd)
        .map_err(|e| format!("Failed to resolve working directory {cwd}: {e}"))?;
    if !canonical.is_dir() {
        return Err(format!("Working directory is not a directory: {cwd}"));
    }
    repo_roots::ensure_path_within_approved_repo(&canonical)?;

    Ok(canonical.to_string_lossy().to_string())
}

fn validate_session_id(session_id: &str) -> Result<(), String> {
    Uuid::parse_str(session_id)
        .map(|_| ())
        .map_err(|_| format!("Invalid session id format: {session_id}"))
}

/// Determine the default shell for the current user.
///
/// Prefers the `SHELL` environment variable. On Unix-like systems, falls back
/// through `/bin/bash` then `/bin/sh` rather than assuming zsh is installed.
fn default_shell() -> String {
    std::env::var("SHELL")
        .ok()
        .and_then(|s| normalize_shell(&s))
        .unwrap_or_else(|| {
            if cfg!(target_os = "windows") {
                "cmd".to_string()
            } else if std::path::Path::new("/bin/bash").exists() {
                "bash".to_string()
            } else {
                "sh".to_string()
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
static SESSION_LIMITER: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();

fn ring_buffers() -> &'static std::sync::Mutex<HashMap<String, Arc<SharedRingBuffer>>> {
    RING_BUFFERS.get_or_init(|| std::sync::Mutex::new(HashMap::new()))
}

fn session_limiter() -> Arc<Semaphore> {
    SESSION_LIMITER
        .get_or_init(|| Arc::new(Semaphore::new(MAX_ACTIVE_SESSIONS)))
        .clone()
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
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
    cwd: String,
    shell: Option<String>,
    env: Option<HashMap<String, String>>,
) -> Result<SessionInfo, String> {
    // Validate cwd exists
    let cwd = normalize_cwd(&cwd)?;
    let shell_path = match shell.as_deref() {
        Some(requested) => normalize_shell(requested)
            .ok_or_else(|| format!("Requested shell is not allowed: {requested}"))?,
        None => default_shell(),
    };
    authorize_sensitive_command(&window, &capability_state, "terminal_create").await?;
    // Reserve capacity up front so concurrent creates cannot pass a racy
    // sessions.len()-style pre-check.
    let session_permit = session_limiter().try_acquire_owned().map_err(|_| {
        format!(
            "Too many active terminal sessions (max {})",
            MAX_ACTIVE_SESSIONS
        )
    })?;

    let session_id = Uuid::new_v4().to_string();
    let branch = detect_git_branch(&cwd);
    let created_at = Utc::now().to_rfc3339();
    let session_alive = Arc::new(AtomicBool::new(true));
    let session_alive_for_reader = Arc::clone(&session_alive);

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

    // Merge caller-supplied environment variables using explicit allowlist.
    if let Some(extra_env) = env {
        if extra_env.len() > MAX_EXTRA_ENV_VARS {
            return Err(format!(
                "Too many environment variables supplied (max {})",
                MAX_EXTRA_ENV_VARS
            ));
        }
        for (key, value) in extra_env {
            if !is_allowed_env_var(&key) {
                eprintln!("[terminal] Ignored env key from IPC payload: {}", key);
                continue;
            }
            if key.len() > MAX_ENV_KEY_LEN {
                eprintln!(
                    "[terminal] Ignored oversize env key from IPC payload: {}",
                    key
                );
                continue;
            }
            if value.len() > MAX_ENV_VALUE_LEN {
                eprintln!(
                    "[terminal] Ignored oversize env value for key {} from IPC payload",
                    key
                );
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

    // Build + store session before starting the reader task so natural-exit
    // cleanup always has a map entry to prune.
    let session = TerminalSession {
        id: session_id.clone(),
        master: pty_pair.master,
        child,
        writer,
        cwd: cwd.clone(),
        branch: branch.clone(),
        created_at: created_at.clone(),
        alive: session_alive,
        _session_permit: session_permit,
        reader_task: None,
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

    // Store the session first to avoid create/exit races.
    {
        let mut manager = state.lock().await;
        manager.sessions.insert(session_id.clone(), session);
    }

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
            if !session_alive_for_reader.load(Ordering::Acquire) {
                break;
            }
            match reader.read(&mut chunk_buf) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let text = String::from_utf8_lossy(&chunk_buf[..n]).to_string();
                    if !session_alive_for_reader.load(Ordering::Acquire) {
                        break;
                    }
                    // Append to ring buffer
                    buf_for_task.append(&text);
                    // Emit to frontend
                    if session_alive_for_reader.load(Ordering::Acquire) {
                        let _ = app_handle.emit(&event_name, &text);
                    }
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
        let natural_exit = session_alive_for_reader.load(Ordering::Acquire);
        let exit_code: Option<i32> = state_for_reader.try_lock().ok().and_then(|mut manager| {
            if let Some(session) = manager.sessions.get_mut(&event_session_id) {
                match session.child.try_wait() {
                    Ok(Some(status)) => Some(status.exit_code() as i32),
                    _ => None,
                }
            } else {
                None
            }
        });

        if natural_exit {
            let exit_event = format!("terminal:exit:{}", event_session_id);
            let _ = app_handle.emit(&exit_event, exit_code);

            // Guaranteed async cleanup for naturally exited sessions.
            // This awaits the session lock instead of bounded try_lock retries.
            let cleanup_state = state_for_reader.clone();
            let cleanup_session_id = event_session_id.clone();
            tauri::async_runtime::spawn(async move {
                let mut manager = cleanup_state.lock().await;
                manager.sessions.remove(&cleanup_session_id);
                drop(manager);
                remove_ring_buffer(&cleanup_session_id);
            });
        }
    });

    // Attach task after spawn. If the session disappeared in the tiny window
    // (e.g. immediate natural exit + cleanup), abort the task and fail create.
    let mut pending_reader_task = Some(reader_task);
    {
        let mut manager = state.lock().await;
        if let Some(session) = manager.sessions.get_mut(&session_id) {
            session.reader_task = pending_reader_task.take();
        }
    }
    if let Some(task) = pending_reader_task {
        task.abort();
        let _ = task.await;
        remove_ring_buffer(&session_id);
        return Err("Terminal session terminated during initialization".to_string());
    }

    Ok(info)
}

/// Write data to a PTY session's stdin.
#[tauri::command]
pub async fn terminal_write<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
    session_id: String,
    data: String,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    authorize_sensitive_command(&window, &capability_state, "terminal_write").await?;
    if data.len() > MAX_WRITE_BYTES {
        return Err(format!(
            "Write payload too large ({} bytes, max {})",
            data.len(),
            MAX_WRITE_BYTES
        ));
    }

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
pub async fn terminal_resize<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    authorize_sensitive_command(&window, &capability_state, "terminal_resize").await?;

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
///
/// Cleanup order is important to avoid races with the reader task:
/// 1. Signal the reader to stop (alive = false)
/// 2. Kill the child process (causes reader EOF)
/// 3. Drop the session lock so the reader's try_lock() can succeed
/// 4. Wait for the reader task to finish (ensures no more ring buffer writes)
/// 5. Remove the ring buffer
#[tauri::command]
pub async fn terminal_kill<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
    session_id: String,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    authorize_sensitive_command(&window, &capability_state, "terminal_kill").await?;

    // Extract the session and signal termination, then drop the lock before
    // waiting on the reader task (the reader may need try_lock() on the
    // manager to read exit status).
    let extracted = {
        let mut manager = state.lock().await;
        manager.sessions.remove(&session_id).map(|mut session| {
            // 1. Signal the reader to stop
            session.alive.store(false, Ordering::SeqCst);

            // 2. Kill the child process (best-effort; also causes reader EOF)
            let _ = session.child.kill();

            (session.reader_task.take(), session.id.clone())
        })
    };
    // Manager lock is dropped here.
    let Some((reader_task, sid)) = extracted else {
        // Session may have already naturally exited and been pruned asynchronously.
        remove_ring_buffer(&session_id);
        return Ok(());
    };

    // 3. Wait for the reader task to finish so no more events/ring-buffer
    //    writes can occur after this point.
    if let Some(task) = reader_task {
        task.abort();
        // Wait for the task to actually complete (abort is async).
        let _ = task.await;
    }

    // 4. Now safe to remove the ring buffer — reader is guaranteed stopped.
    remove_ring_buffer(&sid);

    Ok(())
}

/// List all active terminal sessions.
#[tauri::command]
pub async fn terminal_list<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
) -> Result<Vec<SessionInfo>, String> {
    authorize_sensitive_command(&window, &capability_state, "terminal_list").await?;

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
pub async fn terminal_preview<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
    session_id: String,
    lines: Option<usize>,
) -> Result<Vec<String>, String> {
    validate_session_id(&session_id)?;
    authorize_sensitive_command(&window, &capability_state, "terminal_preview").await?;

    // Verify the session exists
    {
        let manager = state.lock().await;
        if !manager.sessions.contains_key(&session_id) {
            return Err(format!("Session not found: {session_id}"));
        }
    }

    let n = lines.unwrap_or(DEFAULT_PREVIEW_LINES).min(MAX_PREVIEW_LINES);

    let buf = get_ring_buffer(&session_id)
        .ok_or_else(|| format!("Ring buffer not found for session: {session_id}"))?;

    Ok(buf.tail(n))
}

/// Return the current working directory of the Tauri process.
///
/// Used by the frontend to auto-detect a sensible default for `repoRoot` when
/// none is configured (e.g. first launch).
#[tauri::command]
pub async fn get_cwd<R: Runtime>(
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
) -> Result<String, String> {
    authorize_sensitive_command(&window, &capability_state, "get_cwd").await?;
    std::env::current_dir()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| e.to_string())
}

/// Kill all sessions. Called during app shutdown.
pub async fn kill_all_sessions(state: &TerminalState) {
    // Collect sessions and signal termination while holding the lock.
    let pending: Vec<(String, Option<tauri::async_runtime::JoinHandle<()>>)> = {
        let mut manager = state.lock().await;
        let session_ids: Vec<String> = manager.sessions.keys().cloned().collect();
        let mut pending = Vec::with_capacity(session_ids.len());
        for id in session_ids {
            if let Some(mut session) = manager.sessions.remove(&id) {
                session.alive.store(false, Ordering::SeqCst);
                let _ = session.child.kill();
                let task = session.reader_task.take();
                if let Some(ref t) = task {
                    t.abort();
                }
                pending.push((id, task));
            }
        }
        pending
    };
    // Manager lock is dropped here.

    // Wait for all reader tasks, then clean up ring buffers.
    for (id, task) in pending {
        if let Some(t) = task {
            let _ = t.await;
        }
        remove_ring_buffer(&id);
    }
}
