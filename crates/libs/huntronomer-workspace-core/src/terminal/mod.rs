use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace::{WorkspaceError, WorkspaceService};

pub type Result<T> = std::result::Result<T, TerminalError>;

#[derive(Debug, Error)]
pub enum TerminalError {
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
    #[error("terminal session is not active: {0}")]
    UnknownSession(String),
    #[error("terminal task is not allowlisted: {0}")]
    TaskNotAllowlisted(String),
    #[error("terminal task rejects extra arguments: {0}")]
    TaskArgsRejected(String),
    #[error("terminal session is not writable: {0}")]
    SessionNotWritable(String),
    #[error("terminal process failed to start: {program}: {source}")]
    Spawn {
        program: String,
        source: std::io::Error,
    },
    #[error("terminal process I/O failed for {session_id}: {source}")]
    Io {
        session_id: String,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TerminalSessionKind {
    Shell,
    Task,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalSession {
    pub session_id: String,
    pub root_id: String,
    pub title: String,
    pub kind: TerminalSessionKind,
    pub cols: u16,
    pub rows: u16,
    pub cwd: String,
    pub started_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShellProfile {
    pub program: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenTerminalRequest {
    pub root_id: String,
    pub cwd: Option<String>,
    pub cols: u16,
    pub rows: u16,
    pub title: Option<String>,
    pub profile: Option<ShellProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedTerminalTask {
    pub tool: String,
    pub program: PathBuf,
    #[serde(default)]
    pub default_args: Vec<String>,
    #[serde(default)]
    pub allow_extra_args: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunTerminalTaskRequest {
    pub root_id: String,
    pub cwd: Option<String>,
    pub cols: u16,
    pub rows: u16,
    pub tool: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub title: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResizeTerminalRequest {
    pub session_id: String,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WriteTerminalRequest {
    pub session_id: String,
    pub data: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WorkspaceTerminalEventKind {
    Stdout,
    Stderr,
    Exit,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceTerminalEvent {
    pub session_id: String,
    pub kind: WorkspaceTerminalEventKind,
    pub data: Option<String>,
    pub exit_code: Option<i32>,
    pub at: String,
}

#[derive(Debug)]
struct ManagedSession {
    session: TerminalSession,
    child: Child,
    stdin: Arc<Mutex<Option<ChildStdin>>>,
}

#[derive(Debug)]
pub struct TerminalService {
    tasks: HashMap<String, AllowedTerminalTask>,
    sessions: Mutex<HashMap<String, ManagedSession>>,
    events_tx: Sender<WorkspaceTerminalEvent>,
    events_rx: Mutex<Receiver<WorkspaceTerminalEvent>>,
}

impl Default for TerminalService {
    fn default() -> Self {
        Self::new([])
    }
}

impl TerminalService {
    pub fn new(tasks: impl IntoIterator<Item = AllowedTerminalTask>) -> Self {
        let (events_tx, events_rx) = mpsc::channel();
        Self {
            tasks: tasks
                .into_iter()
                .map(|task| (task.tool.clone(), task))
                .collect(),
            sessions: Mutex::new(HashMap::new()),
            events_tx,
            events_rx: Mutex::new(events_rx),
        }
    }

    pub fn open_shell_session(
        &self,
        workspace: &WorkspaceService,
        request: OpenTerminalRequest,
    ) -> Result<TerminalSession> {
        let current_dir = resolve_cwd(workspace, &request.root_id, request.cwd.as_deref())?;
        let profile = request.profile.unwrap_or_else(default_shell_profile);
        let title = request
            .title
            .unwrap_or_else(|| profile.program.display().to_string());

        self.spawn_session(
            request.root_id,
            title,
            TerminalSessionKind::Shell,
            request.cols,
            request.rows,
            current_dir,
            &profile.program,
            &profile.args,
            &profile.env,
        )
    }

    pub fn run_task_session(
        &self,
        workspace: &WorkspaceService,
        request: RunTerminalTaskRequest,
    ) -> Result<TerminalSession> {
        let current_dir = resolve_cwd(workspace, &request.root_id, request.cwd.as_deref())?;
        let task = self
            .tasks
            .get(&request.tool)
            .ok_or_else(|| TerminalError::TaskNotAllowlisted(request.tool.clone()))?;
        if !task.allow_extra_args && !request.args.is_empty() {
            return Err(TerminalError::TaskArgsRejected(request.tool));
        }

        let mut args = task.default_args.clone();
        args.extend(request.args);
        let title = request.title.unwrap_or_else(|| task.tool.clone());

        self.spawn_session(
            request.root_id,
            title,
            TerminalSessionKind::Task,
            request.cols,
            request.rows,
            current_dir,
            &task.program,
            &args,
            &HashMap::new(),
        )
    }

    pub fn list_sessions(&self) -> Vec<TerminalSession> {
        self.collect_process_updates();
        let sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut entries: Vec<_> = sessions.values().map(|entry| entry.session.clone()).collect();
        entries.sort_by(|left, right| left.started_at.cmp(&right.started_at));
        entries
    }

    pub fn resize_session(&self, request: ResizeTerminalRequest) -> Result<TerminalSession> {
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let managed = sessions
            .get_mut(&request.session_id)
            .ok_or_else(|| TerminalError::UnknownSession(request.session_id.clone()))?;
        managed.session.cols = request.cols;
        managed.session.rows = request.rows;
        Ok(managed.session.clone())
    }

    pub fn write_input(&self, request: WriteTerminalRequest) -> Result<()> {
        let stdin = {
            let sessions = self
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            sessions
                .get(&request.session_id)
                .map(|managed| Arc::clone(&managed.stdin))
                .ok_or_else(|| TerminalError::UnknownSession(request.session_id.clone()))?
        };

        let mut handle = stdin.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let writer = handle
            .as_mut()
            .ok_or_else(|| TerminalError::SessionNotWritable(request.session_id.clone()))?;
        writer
            .write_all(request.data.as_bytes())
            .map_err(|source| TerminalError::Io {
                session_id: request.session_id.clone(),
                source,
            })?;
        writer.flush().map_err(|source| TerminalError::Io {
            session_id: request.session_id,
            source,
        })?;
        Ok(())
    }

    pub fn close_session(&self, session_id: &str) -> Result<Option<TerminalSession>> {
        let mut managed = {
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            sessions.remove(session_id)
        }
        .ok_or_else(|| TerminalError::UnknownSession(session_id.to_string()))?;

        managed
            .child
            .kill()
            .map_err(|source| TerminalError::Io {
                session_id: session_id.to_string(),
                source,
            })?;
        let status = managed
            .child
            .wait()
            .map_err(|source| TerminalError::Io {
                session_id: session_id.to_string(),
                source,
            })?;

        let _ = self.events_tx.send(WorkspaceTerminalEvent {
            session_id: session_id.to_string(),
            kind: WorkspaceTerminalEventKind::Exit,
            data: None,
            exit_code: status.code(),
            at: timestamp_now(),
        });

        Ok(Some(managed.session))
    }

    pub fn drain_events(&self) -> Vec<WorkspaceTerminalEvent> {
        self.collect_process_updates();
        let receiver = self
            .events_rx
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut events = Vec::new();
        while let Ok(event) = receiver.try_recv() {
            events.push(event);
        }
        events
    }

    fn spawn_session(
        &self,
        root_id: String,
        title: String,
        kind: TerminalSessionKind,
        cols: u16,
        rows: u16,
        current_dir: PathBuf,
        program: &PathBuf,
        args: &[String],
        env: &HashMap<String, String>,
    ) -> Result<TerminalSession> {
        let mut command = Command::new(program);
        command
            .current_dir(&current_dir)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }

        let mut child = command.spawn().map_err(|source| TerminalError::Spawn {
            program: program.display().to_string(),
            source,
        })?;

        let session = TerminalSession {
            session_id: Uuid::now_v7().to_string(),
            root_id,
            title,
            kind,
            cols,
            rows,
            cwd: current_dir.display().to_string(),
            started_at: timestamp_now(),
        };
        let stdin = Arc::new(Mutex::new(child.stdin.take()));

        if let Some(stdout) = child.stdout.take() {
            spawn_reader(
                self.events_tx.clone(),
                session.session_id.clone(),
                WorkspaceTerminalEventKind::Stdout,
                stdout,
            );
        }
        if let Some(stderr) = child.stderr.take() {
            spawn_reader(
                self.events_tx.clone(),
                session.session_id.clone(),
                WorkspaceTerminalEventKind::Stderr,
                stderr,
            );
        }

        let managed = ManagedSession {
            session: session.clone(),
            child,
            stdin,
        };
        let mut sessions = self
            .sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        sessions.insert(session.session_id.clone(), managed);

        Ok(session)
    }

    fn collect_process_updates(&self) {
        let mut completed = Vec::new();
        {
            let mut sessions = self
                .sessions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            for (session_id, managed) in sessions.iter_mut() {
                match managed.child.try_wait() {
                    Ok(Some(status)) => completed.push((session_id.clone(), status.code())),
                    Ok(None) => {}
                    Err(error) => {
                        let _ = self.events_tx.send(WorkspaceTerminalEvent {
                            session_id: session_id.clone(),
                            kind: WorkspaceTerminalEventKind::Error,
                            data: Some(error.to_string()),
                            exit_code: None,
                            at: timestamp_now(),
                        });
                        completed.push((session_id.clone(), None));
                    }
                }
            }

            for (session_id, _) in &completed {
                sessions.remove(session_id);
            }
        }

        for (session_id, exit_code) in completed {
            let _ = self.events_tx.send(WorkspaceTerminalEvent {
                session_id,
                kind: WorkspaceTerminalEventKind::Exit,
                data: None,
                exit_code,
                at: timestamp_now(),
            });
        }
    }
}

fn spawn_reader(
    events_tx: Sender<WorkspaceTerminalEvent>,
    session_id: String,
    kind: WorkspaceTerminalEventKind,
    mut reader: impl Read + Send + 'static,
) {
    std::thread::spawn(move || {
        let mut buffer = [0_u8; 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => {
                    let data = String::from_utf8_lossy(&buffer[..size]).into_owned();
                    let _ = events_tx.send(WorkspaceTerminalEvent {
                        session_id: session_id.clone(),
                        kind: kind.clone(),
                        data: Some(data),
                        exit_code: None,
                        at: timestamp_now(),
                    });
                }
                Err(error) => {
                    let _ = events_tx.send(WorkspaceTerminalEvent {
                        session_id: session_id.clone(),
                        kind: WorkspaceTerminalEventKind::Error,
                        data: Some(error.to_string()),
                        exit_code: None,
                        at: timestamp_now(),
                    });
                    break;
                }
            }
        }
    });
}

fn resolve_cwd(
    workspace: &WorkspaceService,
    root_id: &str,
    cwd: Option<&str>,
) -> Result<PathBuf> {
    match cwd {
        Some(relative_path) => Ok(workspace.resolve_existing_path(root_id, relative_path)?),
        None => Ok(PathBuf::from(workspace.root_metadata(root_id)?.canonical_path)),
    }
}

fn default_shell_profile() -> ShellProfile {
    #[cfg(target_os = "windows")]
    let program = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd.exe".to_string());
    #[cfg(not(target_os = "windows"))]
    let program = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    ShellProfile {
        program: PathBuf::from(program),
        args: Vec::new(),
        env: HashMap::new(),
    }
}

fn timestamp_now() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::{Duration, Instant};

    use crate::settings::WorkspaceSettingsStore;
    use crate::workspace::WorkspaceService;

    use super::{
        AllowedTerminalTask, OpenTerminalRequest, ResizeTerminalRequest, RunTerminalTaskRequest,
        ShellProfile, TerminalService, TerminalSessionKind, WorkspaceTerminalEventKind,
        WriteTerminalRequest,
    };

    fn unique_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "huntronomer-workspace-core-terminal-{label}-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_else(|error| {
            panic!("failed to create test directory {}: {error}", dir.display())
        });
        dir
    }

    fn write_script(path: &Path, contents: &str) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::write(path, contents)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(path)?.permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(path, permissions)?;
        }
        Ok(())
    }

    fn build_workspace(label: &str) -> Result<(WorkspaceService, String, PathBuf), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir(label);
        let settings_path = root_dir.join("workspace-settings.json");
        let workspace_dir = root_dir.join("repo");
        std::fs::create_dir_all(workspace_dir.join("src"))?;

        let mut workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;
        let root = workspace.register_root(&workspace_dir)?;
        Ok((workspace, root.id, workspace_dir))
    }

    fn wait_for_event(
        terminal: &TerminalService,
        session_id: &str,
        kind: WorkspaceTerminalEventKind,
    ) -> Option<super::WorkspaceTerminalEvent> {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(3) {
            for event in terminal.drain_events() {
                if event.session_id == session_id && event.kind == kind {
                    return Some(event);
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        None
    }

    fn wait_for_session_events(
        terminal: &TerminalService,
        session_id: &str,
        minimum_events: usize,
    ) -> Vec<super::WorkspaceTerminalEvent> {
        let started = Instant::now();
        let mut collected = Vec::new();
        while started.elapsed() < Duration::from_secs(3) {
            let mut saw_new = false;
            for event in terminal.drain_events() {
                if event.session_id == session_id {
                    collected.push(event);
                    saw_new = true;
                }
            }
            if collected.len() >= minimum_events {
                return collected;
            }
            if !saw_new {
                thread::sleep(Duration::from_millis(20));
            }
        }
        collected
    }

    #[test]
    fn shell_sessions_accept_input_and_emit_output() -> Result<(), Box<dyn std::error::Error>> {
        let (workspace, root_id, workspace_dir) = build_workspace("shell")?;
        let script = workspace_dir.join("echo-shell.sh");
        write_script(
            &script,
            "#!/bin/sh\nprintf 'ready\\n'\nwhile IFS= read -r line; do printf 'echo:%s\\n' \"$line\"; done\n",
        )?;

        let terminal = TerminalService::default();
        let session = terminal.open_shell_session(
            &workspace,
            OpenTerminalRequest {
                root_id: root_id.clone(),
                cwd: Some("src".to_string()),
                cols: 120,
                rows: 40,
                title: Some("shell".to_string()),
                profile: Some(ShellProfile {
                    program: script,
                    args: Vec::new(),
                    env: HashMap::new(),
                }),
            },
        )?;

        let ready = wait_for_event(&terminal, &session.session_id, WorkspaceTerminalEventKind::Stdout);
        assert_eq!(ready.and_then(|event| event.data).as_deref(), Some("ready\n"));

        terminal.write_input(WriteTerminalRequest {
            session_id: session.session_id.clone(),
            data: "hello\n".to_string(),
        })?;

        let echoed = wait_for_event(&terminal, &session.session_id, WorkspaceTerminalEventKind::Stdout);
        assert_eq!(echoed.and_then(|event| event.data).as_deref(), Some("echo:hello\n"));

        let resized = terminal.resize_session(ResizeTerminalRequest {
            session_id: session.session_id.clone(),
            cols: 140,
            rows: 50,
        })?;
        assert_eq!(resized.cols, 140);
        assert_eq!(resized.rows, 50);
        assert_eq!(resized.kind, TerminalSessionKind::Shell);

        let closed = terminal.close_session(&session.session_id)?;
        assert!(closed.is_some());

        Ok(())
    }

    #[test]
    fn task_sessions_enforce_allowlists_and_capture_output() -> Result<(), Box<dyn std::error::Error>> {
        let (workspace, root_id, workspace_dir) = build_workspace("task")?;
        let script = workspace_dir.join("git-status.sh");
        write_script(
            &script,
            "#!/bin/sh\nprintf 'task:%s\\n' \"$1\"\nprintf 'cwd:%s\\n' \"$PWD\"\n",
        )?;

        let terminal = TerminalService::new([AllowedTerminalTask {
            tool: "git-status".to_string(),
            program: script,
            default_args: vec!["--short".to_string()],
            allow_extra_args: false,
        }]);

        let session = terminal.run_task_session(
            &workspace,
            RunTerminalTaskRequest {
                root_id,
                cwd: Some("src".to_string()),
                cols: 100,
                rows: 24,
                tool: "git-status".to_string(),
                args: Vec::new(),
                title: Some("git status".to_string()),
            },
        )?;

        let events = wait_for_session_events(&terminal, &session.session_id, 2);
        let stdout_payload = events
            .iter()
            .find(|event| event.kind == WorkspaceTerminalEventKind::Stdout)
            .and_then(|event| event.data.as_deref());
        let exit_code = events
            .iter()
            .find(|event| event.kind == WorkspaceTerminalEventKind::Exit)
            .and_then(|event| event.exit_code);
        assert!(stdout_payload.is_some_and(|payload| payload.contains("task:--short")));
        assert_eq!(exit_code, Some(0));

        let rejected = terminal.run_task_session(
            &workspace,
            RunTerminalTaskRequest {
                root_id: session.root_id.clone(),
                cwd: None,
                cols: 80,
                rows: 24,
                tool: "git-status".to_string(),
                args: vec!["--branch".to_string()],
                title: None,
            },
        );
        assert!(rejected.is_err());

        Ok(())
    }
}
