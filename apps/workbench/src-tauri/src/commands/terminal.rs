//! PTY terminal session management for SwarmBoard.
//!
//! Each session wraps a `portable-pty` pseudo-terminal, streaming output to the
//! frontend via Tauri events and maintaining a bounded ring buffer for tile
//! previews. Sessions are identified by UUIDs and stored in a thread-safe
//! [`TerminalManager`] managed by Tauri state.

use std::collections::{HashMap, HashSet};
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use chrono::Utc;
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Manager, Runtime};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout, Duration};
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
const MAX_ACTIVE_SESSIONS: usize = 64;
const MAX_WRITE_BYTES: usize = 64 * 1024;
const MAX_PREVIEW_LINES: usize = 200;
const TMUX_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_METADATA_DIRNAME: &str = "terminal-sessions";
const TMUX_SOCKET_NAME: &str = "clawdstrike";

/// Returns the `-L clawdstrike` args for socket isolation across all tmux commands.
fn tmux_socket_args() -> Vec<String> {
    vec!["-L".to_string(), TMUX_SOCKET_NAME.to_string()]
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionPersistenceMode {
    Direct,
    Tmux,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionRecoveryState {
    Fresh,
    Recoverable,
    Recovered,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct PersistedSessionMetadata {
    id: String,
    cwd: String,
    branch: Option<String>,
    created_at: String,
    shell: String,
    persistence_mode: SessionPersistenceMode,
}

/// A live PTY session.
pub struct TerminalSession {
    pub id: String,
    pub master: Box<dyn MasterPty + Send>,
    pub child: Box<dyn Child + Send + Sync>,
    pub writer: Box<dyn IoWrite + Send>,
    pub cwd: String,
    pub branch: Option<String>,
    pub created_at: String,
    pub shell: String,
    pub persistence_mode: SessionPersistenceMode,
    pub recovery_state: SessionRecoveryState,
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
    pub shell: String,
    pub persistence_mode: SessionPersistenceMode,
    pub recovery_state: SessionRecoveryState,
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

fn normalize_shell(shell: &str, allow_absolute_paths: bool) -> Option<String> {
    let shell = shell.trim();
    if shell.is_empty() {
        return None;
    }

    let path = Path::new(shell);

    if path.is_absolute() && !allow_absolute_paths {
        eprintln!(
            "[terminal] Rejected absolute shell override from caller payload: {:?}",
            shell
        );
        return None;
    }

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
        .and_then(|s| normalize_shell(&s, true))
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

fn sanitize_extra_env(
    env: Option<HashMap<String, String>>,
) -> Result<HashMap<String, String>, String> {
    let mut sanitized = HashMap::new();

    let Some(extra_env) = env else {
        return Ok(sanitized);
    };

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
        sanitized.insert(key, value);
    }

    Ok(sanitized)
}

fn apply_extra_env(cmd: &mut CommandBuilder, env: &HashMap<String, String>) {
    for (key, value) in env {
        cmd.env(key, value);
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r#"'"'"'"#))
}

fn metadata_filename(session_id: &str) -> String {
    format!("{session_id}.json")
}

fn metadata_path<R: Runtime>(app: &AppHandle<R>, session_id: &str) -> Result<PathBuf, String> {
    let app_data_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?;
    Ok(app_data_dir
        .join(SESSION_METADATA_DIRNAME)
        .join(metadata_filename(session_id)))
}

fn ensure_private_metadata_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let mut builder = DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|e| format!("Failed to create session metadata dir: {e}"))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("Failed to secure session metadata dir: {e}"))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(path)
            .map_err(|e| format!("Failed to create session metadata dir: {e}"))?;
        Ok(())
    }
}

fn write_metadata_file(path: &Path, contents: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("Failed to open session metadata file: {e}"))?;
        file.write_all(contents.as_bytes())
            .map_err(|e| format!("Failed to write session metadata file: {e}"))?;
        file.flush()
            .map_err(|e| format!("Failed to flush session metadata file: {e}"))?;
        return Ok(());
    }

    #[cfg(not(unix))]
    {
        std::fs::write(path, contents)
            .map_err(|e| format!("Failed to write session metadata file: {e}"))
    }
}

fn persist_session_metadata<R: Runtime>(
    app: &AppHandle<R>,
    metadata: &PersistedSessionMetadata,
) -> Result<(), String> {
    let metadata_path = metadata_path(app, &metadata.id)?;
    let metadata_dir = metadata_path
        .parent()
        .ok_or_else(|| "Invalid session metadata path".to_string())?;
    ensure_private_metadata_dir(metadata_dir)?;
    let serialized = serde_json::to_string_pretty(metadata)
        .map_err(|e| format!("Failed to serialize session metadata: {e}"))?;
    write_metadata_file(&metadata_path, &serialized)
}

fn read_session_metadata<R: Runtime>(
    app: &AppHandle<R>,
    session_id: &str,
) -> Result<Option<PersistedSessionMetadata>, String> {
    let metadata_path = metadata_path(app, session_id)?;
    if !metadata_path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&metadata_path)
        .map_err(|e| format!("Failed to read session metadata: {e}"))?;
    let parsed = serde_json::from_str::<PersistedSessionMetadata>(&contents)
        .map_err(|e| format!("Failed to parse session metadata: {e}"))?;
    Ok(Some(parsed))
}

fn delete_session_metadata<R: Runtime>(app: &AppHandle<R>, session_id: &str) -> Result<(), String> {
    let metadata_path = metadata_path(app, session_id)?;
    if metadata_path.exists() {
        std::fs::remove_file(&metadata_path)
            .map_err(|e| format!("Failed to remove session metadata: {e}"))?;
    }
    Ok(())
}

fn list_session_metadata<R: Runtime>(
    app: &AppHandle<R>,
) -> Result<Vec<PersistedSessionMetadata>, String> {
    let metadata_dir = app
        .path()
        .app_data_dir()
        .map_err(|e| format!("Failed to resolve app data dir: {e}"))?
        .join(SESSION_METADATA_DIRNAME);
    if !metadata_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries = Vec::new();
    let read_dir = std::fs::read_dir(&metadata_dir)
        .map_err(|e| format!("Failed to list session metadata dir: {e}"))?;

    for entry in read_dir {
        let entry = entry.map_err(|e| format!("Failed to read session metadata entry: {e}"))?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let contents = std::fs::read_to_string(&path)
            .map_err(|e| format!("Failed to read session metadata file: {e}"))?;
        let metadata = serde_json::from_str::<PersistedSessionMetadata>(&contents)
            .map_err(|e| format!("Failed to parse session metadata file: {e}"))?;
        entries.push(metadata);
    }

    entries.sort_by(|left, right| left.created_at.cmp(&right.created_at));
    Ok(entries)
}

fn tmux_session_info(
    metadata: &PersistedSessionMetadata,
    recovery_state: SessionRecoveryState,
    line_count: usize,
) -> SessionInfo {
    SessionInfo {
        id: metadata.id.clone(),
        cwd: metadata.cwd.clone(),
        branch: metadata.branch.clone(),
        created_at: metadata.created_at.clone(),
        alive: true,
        exit_code: None,
        line_count,
        shell: metadata.shell.clone(),
        persistence_mode: metadata.persistence_mode,
        recovery_state,
    }
}

fn supports_tmux_persistence() -> bool {
    cfg!(target_os = "macos") || cfg!(target_os = "linux")
}

fn bundled_tmux_path<R: Runtime>(app: &AppHandle<R>) -> Option<PathBuf> {
    let resource_dir = app.path().resource_dir().ok()?;
    let binary_name = if cfg!(target_os = "windows") {
        "tmux.exe"
    } else {
        "tmux"
    };
    let path = resource_dir.join("bin").join(binary_name);
    path.exists().then_some(path)
}

async fn resolve_tmux_binary<R: Runtime>(app: &AppHandle<R>) -> Option<String> {
    if !supports_tmux_persistence() {
        return None;
    }

    if let Some(path) = bundled_tmux_path(app) {
        return Some(path.to_string_lossy().to_string());
    }

    let probe = timeout(
        TMUX_COMMAND_TIMEOUT,
        tokio::process::Command::new("tmux").arg("-V").output(),
    )
    .await
    .ok()?
    .ok()?;

    probe.status.success().then_some("tmux".to_string())
}

/// Resolve the path to the bundled `tmux.conf` resource file.
///
/// Returns `None` in dev mode when bundled resources are not present.
fn resolve_tmux_conf<R: Runtime>(app: &AppHandle<R>) -> Option<String> {
    let resource_dir = app.path().resource_dir().ok()?;
    let conf_path = resource_dir.join("tmux.conf");
    if conf_path.exists() {
        Some(conf_path.to_string_lossy().to_string())
    } else {
        eprintln!("[terminal] tmux.conf not found at {}, using tmux defaults", conf_path.display());
        None
    }
}

fn format_tmux_command_error(args: &[String], stderr: &[u8], stdout: &[u8]) -> String {
    let stderr = String::from_utf8_lossy(stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(stdout).trim().to_string();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        "unknown tmux failure".to_string()
    };
    format!("tmux {} failed: {detail}", args.join(" "))
}

async fn run_tmux_command(
    tmux_bin: &str,
    args: &[String],
    cwd: Option<&str>,
) -> Result<String, String> {
    let mut command = tokio::process::Command::new(tmux_bin);
    command.args(args);
    if let Some(path) = cwd {
        command.current_dir(path);
    }

    let output = timeout(TMUX_COMMAND_TIMEOUT, command.output())
        .await
        .map_err(|_| format!("tmux command timed out after 5s: {}", args.join(" ")))?
        .map_err(|e| format!("Failed to launch tmux command: {e}"))?;

    if !output.status.success() {
        return Err(format_tmux_command_error(
            args,
            &output.stderr,
            &output.stdout,
        ));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn build_tmux_shell_command(
    session_id: &str,
    shell: &str,
    env: &HashMap<String, String>,
) -> String {
    let mut exports = vec![
        format!("TERM={}", shell_quote("xterm-256color")),
        format!("CLAWDSTRIKE_SESSION_ID={}", shell_quote(session_id)),
        format!("SHELL={}", shell_quote(shell)),
    ];

    for (key, value) in env {
        exports.push(format!("{key}={}", shell_quote(value)));
    }

    format!("env {} exec {}", exports.join(" "), shell_quote(shell))
}

async fn tmux_session_exists(tmux_bin: &str, session_id: &str) -> bool {
    let mut args = tmux_socket_args();
    args.extend([
        "has-session".to_string(),
        "-t".to_string(),
        session_id.to_string(),
    ]);
    run_tmux_command(tmux_bin, &args, None).await.is_ok()
}

async fn capture_tmux_scrollback(
    tmux_bin: &str,
    session_id: &str,
    line_hint: usize,
) -> Result<Vec<String>, String> {
    let start_line = line_hint.max(DEFAULT_PREVIEW_LINES).max(40) as i32 * -1;
    let mut args = tmux_socket_args();
    args.extend([
        "capture-pane".to_string(),
        "-p".to_string(),
        "-e".to_string(),
        "-S".to_string(),
        start_line.to_string(),
        "-t".to_string(),
        format!("{session_id}:0.0"),
    ]);
    let output = run_tmux_command(tmux_bin, &args, None).await?;
    let mut lines = Vec::new();
    append_to_ring_buffer(&mut lines, &output);
    Ok(lines)
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
        shell: session.shell.clone(),
        persistence_mode: session.persistence_mode,
        recovery_state: session.recovery_state,
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

struct SpawnedPty {
    master: Box<dyn MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    writer: Box<dyn IoWrite + Send>,
    reader: Box<dyn IoRead + Send>,
}

fn spawn_pty_command(cmd: CommandBuilder, description: &str) -> Result<SpawnedPty, String> {
    let pty_system = native_pty_system();
    let pty_pair = pty_system
        .openpty(PtySize {
            rows: DEFAULT_ROWS,
            cols: DEFAULT_COLS,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("Failed to open PTY: {e}"))?;

    let child = pty_pair
        .slave
        .spawn_command(cmd)
        .map_err(|e| format!("Failed to spawn {description}: {e}"))?;

    let writer = pty_pair
        .master
        .take_writer()
        .map_err(|e| format!("Failed to take PTY writer: {e}"))?;

    let reader = pty_pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("Failed to clone PTY reader: {e}"))?;

    Ok(SpawnedPty {
        master: pty_pair.master,
        child,
        writer,
        reader,
    })
}

async fn register_live_session<R: Runtime>(
    app: AppHandle<R>,
    state: TerminalState,
    session_id: String,
    cwd: String,
    branch: Option<String>,
    created_at: String,
    shell: String,
    persistence_mode: SessionPersistenceMode,
    recovery_state: SessionRecoveryState,
    session_permit: OwnedSemaphorePermit,
    spawned: SpawnedPty,
    initial_scrollback: Vec<String>,
) -> Result<SessionInfo, String> {
    let SpawnedPty {
        master,
        child,
        writer,
        mut reader,
    } = spawned;

    let session_alive = Arc::new(AtomicBool::new(true));
    let session_alive_for_reader = Arc::clone(&session_alive);
    let shared_buf = insert_ring_buffer(&session_id);

    if !initial_scrollback.is_empty() {
        shared_buf.append(&(initial_scrollback.join("\n") + "\n"));
    }

    let session = TerminalSession {
        id: session_id.clone(),
        master,
        child,
        writer,
        cwd: cwd.clone(),
        branch: branch.clone(),
        created_at: created_at.clone(),
        shell: shell.clone(),
        persistence_mode,
        recovery_state,
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
        line_count: initial_scrollback.len(),
        shell,
        persistence_mode,
        recovery_state,
    };

    {
        let mut manager = state.lock().await;
        manager.sessions.insert(session_id.clone(), session);
    }

    let event_session_id = session_id.clone();
    let app_handle = app.clone();
    let buf_for_task = Arc::clone(&shared_buf);
    let state_for_reader = state.clone();
    let reader_task = tauri::async_runtime::spawn_blocking(move || {
        let event_name = format!("terminal:output:{}", event_session_id);
        let mut chunk_buf = vec![0u8; READ_CHUNK_SIZE];
        loop {
            if !session_alive_for_reader.load(Ordering::Acquire) {
                break;
            }
            match reader.read(&mut chunk_buf) {
                Ok(0) => break,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&chunk_buf[..n]).to_string();
                    if !session_alive_for_reader.load(Ordering::Acquire) {
                        break;
                    }
                    buf_for_task.append(&text);
                    if session_alive_for_reader.load(Ordering::Acquire) {
                        let _ = app_handle.emit(&event_name, &text);
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::Other {
                        eprintln!("[terminal] reader error for {}: {e}", event_session_id);
                    }
                    break;
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(100));

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

            let cleanup_state = state_for_reader.clone();
            let cleanup_session_id = event_session_id.clone();
            let cleanup_app = app_handle.clone();
            tauri::async_runtime::spawn(async move {
                let removed_persistence_mode = {
                    let mut manager = cleanup_state.lock().await;
                    manager
                        .sessions
                        .remove(&cleanup_session_id)
                        .map(|session| session.persistence_mode)
                };
                remove_ring_buffer(&cleanup_session_id);
                if removed_persistence_mode == Some(SessionPersistenceMode::Tmux) {
                    let _ = delete_session_metadata(&cleanup_app, &cleanup_session_id);
                }
            });
        }
    });

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

async fn create_tmux_session<R: Runtime>(
    app: &AppHandle<R>,
    tmux_bin: &str,
    session_id: &str,
    cwd: &str,
    branch: Option<String>,
    created_at: &str,
    shell: &str,
    env: &HashMap<String, String>,
) -> Result<PersistedSessionMetadata, String> {
    let shell_command = build_tmux_shell_command(session_id, shell, env);
    let mut create_args = tmux_socket_args();
    // Pass -f tmux.conf if available (bundled resource).
    if let Some(conf_path) = resolve_tmux_conf(app) {
        create_args.push("-f".to_string());
        create_args.push(conf_path);
    }
    create_args.extend([
        "new-session".to_string(),
        "-d".to_string(),
        "-s".to_string(),
        session_id.to_string(),
        "-c".to_string(),
        cwd.to_string(),
        shell_command,
    ]);
    run_tmux_command(tmux_bin, &create_args, Some(cwd)).await?;

    let mut set_session_id_args = tmux_socket_args();
    set_session_id_args.extend([
        "set-environment".to_string(),
        "-t".to_string(),
        session_id.to_string(),
        "CLAWDSTRIKE_SESSION_ID".to_string(),
        session_id.to_string(),
    ]);
    run_tmux_command(tmux_bin, &set_session_id_args, None).await?;

    let mut set_shell_args = tmux_socket_args();
    set_shell_args.extend([
        "set-environment".to_string(),
        "-t".to_string(),
        session_id.to_string(),
        "SHELL".to_string(),
        shell.to_string(),
    ]);
    run_tmux_command(tmux_bin, &set_shell_args, None).await?;

    let metadata = PersistedSessionMetadata {
        id: session_id.to_string(),
        cwd: cwd.to_string(),
        branch,
        created_at: created_at.to_string(),
        shell: shell.to_string(),
        persistence_mode: SessionPersistenceMode::Tmux,
    };
    persist_session_metadata(app, &metadata)?;

    Ok(metadata)
}

async fn connect_tmux_session<R: Runtime>(
    app: AppHandle<R>,
    state: TerminalState,
    metadata: PersistedSessionMetadata,
    recovery_state: SessionRecoveryState,
) -> Result<SessionInfo, String> {
    let session_permit = session_limiter().try_acquire_owned().map_err(|_| {
        format!(
            "Too many active terminal sessions (max {})",
            MAX_ACTIVE_SESSIONS
        )
    })?;

    let tmux_bin = resolve_tmux_binary(&app)
        .await
        .ok_or_else(|| "tmux is unavailable on this platform".to_string())?;
    if !tmux_session_exists(&tmux_bin, &metadata.id).await {
        let _ = delete_session_metadata(&app, &metadata.id);
        return Err(format!("tmux session not found: {}", metadata.id));
    }

    let initial_scrollback =
        capture_tmux_scrollback(&tmux_bin, &metadata.id, MAX_PREVIEW_LINES).await?;

    let mut cmd = CommandBuilder::new(&tmux_bin);
    cmd.cwd(&metadata.cwd);
    cmd.env("TERM", "xterm-256color");
    // Socket isolation
    cmd.arg("-L");
    cmd.arg(TMUX_SOCKET_NAME);
    // Optionally pass tmux.conf for consistency (harmless on attach since server
    // already loaded it on new-session, but ensures config is loaded if the
    // server was started without it).
    if let Some(conf_path) = resolve_tmux_conf(&app) {
        cmd.arg("-f");
        cmd.arg(conf_path);
    }
    cmd.arg("attach-session");
    cmd.arg("-t");
    cmd.arg(&metadata.id);

    let spawned = spawn_pty_command(cmd, &format!("tmux attach-session {}", metadata.id))?;
    register_live_session(
        app,
        state,
        metadata.id.clone(),
        metadata.cwd.clone(),
        metadata.branch.clone(),
        metadata.created_at.clone(),
        metadata.shell.clone(),
        SessionPersistenceMode::Tmux,
        recovery_state,
        session_permit,
        spawned,
        initial_scrollback,
    )
    .await
}

async fn kill_tmux_session<R: Runtime>(app: &AppHandle<R>, session_id: &str) -> Result<(), String> {
    let Some(tmux_bin) = resolve_tmux_binary(app).await else {
        let _ = delete_session_metadata(app, session_id);
        return Ok(());
    };

    if tmux_session_exists(&tmux_bin, session_id).await {
        let mut args = tmux_socket_args();
        args.extend([
            "kill-session".to_string(),
            "-t".to_string(),
            session_id.to_string(),
        ]);
        run_tmux_command(&tmux_bin, &args, None).await?;
    }

    delete_session_metadata(app, session_id)?;
    Ok(())
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
    let cwd = normalize_cwd(&cwd)?;
    let shell_path = match shell.as_deref() {
        Some(requested) => normalize_shell(requested, false)
            .ok_or_else(|| format!("Requested shell is not allowed: {requested}"))?,
        None => default_shell(),
    };
    authorize_sensitive_command(&window, &capability_state, "terminal_create").await?;
    let sanitized_env = sanitize_extra_env(env)?;
    let session_id = Uuid::new_v4().to_string();
    let branch = detect_git_branch(&cwd);
    let created_at = Utc::now().to_rfc3339();
    let state_handle: TerminalState = (*state).clone();

    if let Some(tmux_bin) = resolve_tmux_binary(&app).await {
        let metadata = create_tmux_session(
            &app,
            &tmux_bin,
            &session_id,
            &cwd,
            branch.clone(),
            &created_at,
            &shell_path,
            &sanitized_env,
        )
        .await?;

        return match connect_tmux_session(
            app.clone(),
            state_handle,
            metadata.clone(),
            SessionRecoveryState::Fresh,
        )
        .await
        {
            Ok(info) => Ok(info),
            Err(err) => {
                let _ = kill_tmux_session(&app, &metadata.id).await;
                Err(err)
            }
        };
    }

    let session_permit = session_limiter().try_acquire_owned().map_err(|_| {
        format!(
            "Too many active terminal sessions (max {})",
            MAX_ACTIVE_SESSIONS
        )
    })?;

    let mut cmd = CommandBuilder::new(&shell_path);
    cmd.cwd(&cwd);
    cmd.env("TERM", "xterm-256color");
    apply_extra_env(&mut cmd, &sanitized_env);

    let spawned = spawn_pty_command(cmd, &format!("shell {shell_path}"))?;
    register_live_session(
        app,
        state_handle,
        session_id,
        cwd,
        branch,
        created_at,
        shell_path,
        SessionPersistenceMode::Direct,
        SessionRecoveryState::Fresh,
        session_permit,
        spawned,
        Vec::new(),
    )
    .await
}

#[tauri::command]
pub async fn terminal_discover<R: Runtime>(
    app: AppHandle<R>,
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
) -> Result<Vec<SessionInfo>, String> {
    authorize_sensitive_command(&window, &capability_state, "terminal_discover").await?;

    let Some(tmux_bin) = resolve_tmux_binary(&app).await else {
        return Ok(Vec::new());
    };

    let attached_ids = {
        let manager = state.lock().await;
        manager
            .sessions
            .values()
            .filter(|session| session.persistence_mode == SessionPersistenceMode::Tmux)
            .map(|session| session.id.clone())
            .collect::<HashSet<_>>()
    };

    let mut discovered = Vec::new();
    for metadata in list_session_metadata(&app)? {
        if metadata.persistence_mode != SessionPersistenceMode::Tmux {
            continue;
        }
        if attached_ids.contains(&metadata.id) {
            continue;
        }
        if !tmux_session_exists(&tmux_bin, &metadata.id).await {
            let _ = delete_session_metadata(&app, &metadata.id);
            continue;
        }
        discovered.push(tmux_session_info(
            &metadata,
            SessionRecoveryState::Recoverable,
            0,
        ));
    }

    // Orphan cleanup: if no metadata matched a live tmux session, check whether
    // the tmux server on our socket has orphaned sessions (e.g. from a crash)
    // and kill the server to reclaim resources.
    if discovered.is_empty() {
        let mut list_args = tmux_socket_args();
        list_args.extend([
            "list-sessions".to_string(),
            "-F".to_string(),
            "#{session_name}".to_string(),
        ]);
        if let Ok(output) = run_tmux_command(&tmux_bin, &list_args, None).await {
            let server_sessions: Vec<&str> =
                output.trim().lines().filter(|l| !l.is_empty()).collect();
            if !server_sessions.is_empty() {
                // Orphaned sessions exist with no matching metadata -- kill server
                eprintln!(
                    "[terminal] Killing orphaned tmux server with {} sessions on socket '{}'",
                    server_sessions.len(),
                    TMUX_SOCKET_NAME
                );
                let mut kill_args = tmux_socket_args();
                kill_args.push("kill-server".to_string());
                let _ = run_tmux_command(&tmux_bin, &kill_args, None).await;
            }
        }
    }

    Ok(discovered)
}

#[tauri::command]
pub async fn terminal_reconnect<R: Runtime>(
    app: AppHandle<R>,
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
    session_id: String,
) -> Result<SessionInfo, String> {
    validate_session_id(&session_id)?;
    authorize_sensitive_command(&window, &capability_state, "terminal_reconnect").await?;

    {
        let mut manager = state.lock().await;
        if let Some(session) = manager.sessions.get_mut(&session_id) {
            session.recovery_state = SessionRecoveryState::Recovered;
            return Ok(session_info(session));
        }
    }

    let metadata = read_session_metadata(&app, &session_id)?
        .ok_or_else(|| format!("Recoverable session metadata not found: {session_id}"))?;

    connect_tmux_session(
        app,
        (*state).clone(),
        metadata,
        SessionRecoveryState::Recovered,
    )
    .await
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
///
/// For tmux sessions, also issues `tmux resize-window` so the tmux pseudo-window
/// dimensions stay in sync with the PTY. The tmux resize is best-effort.
#[tauri::command]
pub async fn terminal_resize<R: Runtime>(
    app: AppHandle<R>,
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
    session_id: String,
    cols: u16,
    rows: u16,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    authorize_sensitive_command(&window, &capability_state, "terminal_resize").await?;

    // Extract what we need under the lock, then drop it before async tmux calls.
    let (persistence_mode, sid) = {
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

        (session.persistence_mode, session.id.clone())
    };

    // For tmux sessions, also resize the tmux window so dimensions stay in sync.
    if persistence_mode == SessionPersistenceMode::Tmux {
        if let Some(tmux_bin) = resolve_tmux_binary(&app).await {
            let mut args = tmux_socket_args();
            args.extend([
                "resize-window".to_string(),
                "-t".to_string(),
                sid,
                "-x".to_string(),
                cols.max(1).to_string(),
                "-y".to_string(),
                rows.max(1).to_string(),
            ]);
            if let Err(e) = run_tmux_command(&tmux_bin, &args, None).await {
                eprintln!("[terminal] tmux resize-window failed (best-effort): {e}");
            }
        }
    }

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
    app: AppHandle<R>,
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
            session.alive.store(false, Ordering::SeqCst);
            let _ = session.child.kill();

            (
                session.reader_task.take(),
                session.id.clone(),
                session.persistence_mode,
            )
        })
    };

    let Some((reader_task, sid, persistence_mode)) = extracted else {
        if read_session_metadata(&app, &session_id)?.is_some() {
            return kill_tmux_session(&app, &session_id).await;
        }
        remove_ring_buffer(&session_id);
        return Ok(());
    };

    if let Some(task) = reader_task {
        task.abort();
        let _ = task.await;
    }

    remove_ring_buffer(&sid);
    if persistence_mode == SessionPersistenceMode::Tmux {
        kill_tmux_session(&app, &sid).await?;
    }

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
    app: AppHandle<R>,
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
    session_id: String,
    lines: Option<usize>,
) -> Result<Vec<String>, String> {
    validate_session_id(&session_id)?;
    authorize_sensitive_command(&window, &capability_state, "terminal_preview").await?;

    let n = lines
        .unwrap_or(DEFAULT_PREVIEW_LINES)
        .min(MAX_PREVIEW_LINES);

    {
        let manager = state.lock().await;
        if manager.sessions.contains_key(&session_id) {
            let buf = get_ring_buffer(&session_id)
                .ok_or_else(|| format!("Ring buffer not found for session: {session_id}"))?;
            return Ok(buf.tail(n));
        }
    }

    let metadata = read_session_metadata(&app, &session_id)?
        .ok_or_else(|| format!("Session not found: {session_id}"))?;
    if metadata.persistence_mode != SessionPersistenceMode::Tmux {
        return Err(format!("Session not found: {session_id}"));
    }

    let tmux_bin = resolve_tmux_binary(&app)
        .await
        .ok_or_else(|| "tmux is unavailable on this platform".to_string())?;
    if !tmux_session_exists(&tmux_bin, &session_id).await {
        let _ = delete_session_metadata(&app, &session_id);
        return Err(format!("Session not found: {session_id}"));
    }

    let scrollback = capture_tmux_scrollback(&tmux_bin, &session_id, n).await?;
    Ok(scrollback
        .into_iter()
        .rev()
        .take(n)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect())
}

/// Detach a single tmux session without destroying it.
///
/// Kills the PTY client (`tmux attach-session` process) and removes the session
/// from the in-memory manager, but preserves the tmux server session and its
/// metadata file. The session can later be rediscovered and reconnected via
/// `terminal_discover` + `terminal_reconnect`.
///
/// Only tmux sessions can be detached; direct sessions must be killed.
#[tauri::command]
pub async fn terminal_detach<R: Runtime>(
    _app: AppHandle<R>,
    window: tauri::Window<R>,
    capability_state: tauri::State<'_, CommandCapabilityState>,
    state: tauri::State<'_, TerminalState>,
    session_id: String,
) -> Result<(), String> {
    validate_session_id(&session_id)?;
    authorize_sensitive_command(&window, &capability_state, "terminal_detach").await?;

    let extracted = {
        let mut manager = state.lock().await;
        manager.sessions.remove(&session_id).map(|mut session| {
            session.alive.store(false, Ordering::SeqCst);
            let _ = session.child.kill(); // kills tmux attach client, NOT the tmux session
            (session.reader_task.take(), session.persistence_mode)
        })
    };

    let Some((reader_task, persistence_mode)) = extracted else {
        return Err(format!("Session not found: {session_id}"));
    };

    if let Some(task) = reader_task {
        task.abort();
        let _ = task.await;
    }
    remove_ring_buffer(&session_id);

    if persistence_mode != SessionPersistenceMode::Tmux {
        return Err(
            "Only tmux sessions can be detached; direct sessions must be killed".to_string(),
        );
    }

    // Metadata is preserved -- session can be rediscovered and reconnected later
    Ok(())
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
///
/// For `Direct` sessions: kills child, aborts reader, removes ring buffer (unchanged).
/// For `Tmux` sessions: kills the PTY client (the `tmux attach-session` process)
/// to detach, aborts reader, removes ring buffer, but does NOT delete session
/// metadata files. The tmux server session persists for recovery on next launch.
pub async fn kill_all_sessions(state: &TerminalState) {
    let pending: Vec<(
        String,
        SessionPersistenceMode,
        Option<tauri::async_runtime::JoinHandle<()>>,
    )> = {
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
                pending.push((id, session.persistence_mode, task));
            }
        }
        pending
    };

    for (id, persistence_mode, task) in pending {
        if let Some(t) = task {
            let _ = t.await;
        }
        remove_ring_buffer(&id);

        match persistence_mode {
            SessionPersistenceMode::Direct => {
                // Direct sessions are fully cleaned up -- nothing more to do.
            }
            SessionPersistenceMode::Tmux => {
                // Tmux sessions: the child.kill() above killed the PTY client
                // (tmux attach-session process), which detaches from the tmux
                // server session. Metadata is preserved so the session can be
                // rediscovered on next launch.
                eprintln!(
                    "[terminal] Preserved tmux session {id} for recovery (detached on exit)"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        append_to_ring_buffer, build_tmux_shell_command, normalize_shell, shell_quote,
        tmux_socket_args, RING_BUFFER_MAX_LINES,
    };
    use std::collections::HashMap;

    #[test]
    fn normalize_shell_rejects_relative_path_components() {
        assert!(normalize_shell("./bash", false).is_none());
        assert!(normalize_shell("subdir/zsh", false).is_none());
    }

    #[test]
    fn normalize_shell_rejects_absolute_paths_from_caller_payloads() {
        #[cfg(unix)]
        let path = "/tmp/bash";
        #[cfg(windows)]
        let path = r"C:\temp\bash.exe";

        assert!(normalize_shell(path, false).is_none());
    }

    #[test]
    fn normalize_shell_allows_allowlisted_absolute_default_shells() {
        #[cfg(unix)]
        let path = "/bin/bash";
        #[cfg(windows)]
        let path = r"C:\Windows\System32\cmd.exe";

        assert_eq!(normalize_shell(path, true).as_deref(), Some(path));
    }

    #[test]
    fn test_build_tmux_shell_command_basic() {
        let env = HashMap::new();
        let cmd = build_tmux_shell_command("test-id", "/bin/zsh", &env);
        assert!(cmd.contains("CLAWDSTRIKE_SESSION_ID='test-id'"));
        assert!(cmd.contains("SHELL='/bin/zsh'"));
        assert!(cmd.contains("TERM='xterm-256color'"));
        assert!(cmd.ends_with("exec '/bin/zsh'"));
    }

    #[test]
    fn test_build_tmux_shell_command_with_extra_env() {
        let mut env = HashMap::new();
        env.insert("LANG".to_string(), "en_US.UTF-8".to_string());
        let cmd = build_tmux_shell_command("sid", "bash", &env);
        assert!(cmd.contains("LANG='en_US.UTF-8'"));
        assert!(cmd.contains("CLAWDSTRIKE_SESSION_ID='sid'"));
    }

    #[test]
    fn test_build_tmux_shell_command_quotes_special_chars() {
        let mut env = HashMap::new();
        env.insert("EDITOR".to_string(), "it's vim".to_string());
        let cmd = build_tmux_shell_command("sid", "bash", &env);
        // The value should contain the escaped single-quote sequence
        assert!(cmd.contains(r#"EDITOR='it'"'"'s vim'"#));
    }

    #[test]
    fn test_tmux_socket_args_format() {
        let args = tmux_socket_args();
        assert_eq!(args, vec!["-L".to_string(), "clawdstrike".to_string()]);
    }

    #[test]
    fn test_append_to_ring_buffer_basic() {
        let mut buf = Vec::new();
        append_to_ring_buffer(&mut buf, "line1\nline2\nline3\n");
        assert_eq!(buf, vec!["line1", "line2", "line3", ""]);
    }

    #[test]
    fn test_append_to_ring_buffer_partial_lines() {
        let mut buf = Vec::new();
        append_to_ring_buffer(&mut buf, "partial");
        assert_eq!(buf, vec!["partial"]);
        append_to_ring_buffer(&mut buf, " continuation\nnew line");
        assert_eq!(buf, vec!["partial continuation", "new line"]);
    }

    #[test]
    fn test_append_to_ring_buffer_capacity_limit() {
        let mut buf = Vec::new();
        // Fill buffer beyond capacity
        for i in 0..RING_BUFFER_MAX_LINES + 50 {
            append_to_ring_buffer(&mut buf, &format!("line{i}\n"));
        }
        assert!(buf.len() <= RING_BUFFER_MAX_LINES);
        // The last line pushed should be retained
        let last_line = format!("line{}", RING_BUFFER_MAX_LINES + 49);
        assert!(buf.iter().any(|l| l == &last_line));
    }

    #[test]
    fn test_shell_quote_handles_quotes() {
        assert_eq!(shell_quote("it's"), "'it'\"'\"'s'");
    }

    #[test]
    fn test_shell_quote_simple() {
        assert_eq!(shell_quote("hello"), "'hello'");
    }

    #[test]
    fn test_shell_quote_empty() {
        assert_eq!(shell_quote(""), "''");
    }
}
