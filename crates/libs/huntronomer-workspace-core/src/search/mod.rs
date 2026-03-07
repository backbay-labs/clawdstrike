use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use crate::workspace::{WorkspaceError, WorkspaceService};

pub type Result<T> = std::result::Result<T, SearchError>;

#[derive(Debug, Error)]
pub enum SearchError {
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
    #[error("search job is not active: {0}")]
    UnknownJob(String),
    #[error("failed to spawn search tool {tool}: {source}")]
    Spawn { tool: String, source: std::io::Error },
    #[error("search tool {tool} exited with code {exit_code:?}: {stderr}")]
    ToolFailed {
        tool: String,
        exit_code: Option<i32>,
        stderr: String,
    },
    #[error("search tool output was invalid: {0}")]
    InvalidOutput(String),
    #[error("search worker thread panicked")]
    WorkerPanicked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchJobKind {
    Path,
    Content,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchJobHandle {
    pub job_id: String,
    pub root_id: String,
    pub kind: SearchJobKind,
    pub query: String,
    pub started_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkspaceSearchEventKind {
    Match,
    Progress,
    Done,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PathSearchMatch {
    pub relative_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContentSearchMatch {
    pub relative_path: String,
    pub line_number: u64,
    pub column: u64,
    pub preview: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchSummary {
    pub matches: usize,
    pub cancelled: bool,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type", content = "data")]
pub enum SearchEventPayload {
    PathMatch(PathSearchMatch),
    ContentMatch(ContentSearchMatch),
    Progress { matches: usize },
    Summary(SearchSummary),
    Error { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceSearchEvent {
    pub job_id: String,
    pub kind: WorkspaceSearchEventKind,
    pub payload: SearchEventPayload,
}

#[derive(Debug, Clone)]
pub struct SearchTools {
    pub fd_program: Option<PathBuf>,
    pub rg_program: PathBuf,
}

impl Default for SearchTools {
    fn default() -> Self {
        Self {
            fd_program: Some(PathBuf::from("fd")),
            rg_program: PathBuf::from("rg"),
        }
    }
}

#[derive(Debug, Default)]
pub struct SearchService {
    tools: SearchTools,
    jobs: Mutex<HashMap<String, ActiveSearchJob>>,
}

impl SearchService {
    pub fn new(tools: SearchTools) -> Self {
        Self {
            tools,
            jobs: Mutex::new(HashMap::new()),
        }
    }

    pub fn start_path_search(
        &self,
        workspace: &WorkspaceService,
        root_id: &str,
        query: &str,
    ) -> Result<SearchJobHandle> {
        let root_path = root_path(workspace, root_id)?;
        let job = SearchJobHandle {
            job_id: Uuid::now_v7().to_string(),
            root_id: root_id.to_string(),
            kind: SearchJobKind::Path,
            query: query.to_string(),
            started_at: timestamp_now(),
        };
        let active_job = ActiveSearchJob::spawn_path(job.clone(), self.tools.clone(), root_path)?;
        let mut jobs = self.jobs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        jobs.insert(job.job_id.clone(), active_job);
        Ok(job)
    }

    pub fn start_content_search(
        &self,
        workspace: &WorkspaceService,
        root_id: &str,
        query: &str,
        globs: &[String],
    ) -> Result<SearchJobHandle> {
        let root_path = root_path(workspace, root_id)?;
        let job = SearchJobHandle {
            job_id: Uuid::now_v7().to_string(),
            root_id: root_id.to_string(),
            kind: SearchJobKind::Content,
            query: query.to_string(),
            started_at: timestamp_now(),
        };
        let active_job =
            ActiveSearchJob::spawn_content(job.clone(), self.tools.clone(), root_path, globs)?;
        let mut jobs = self.jobs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        jobs.insert(job.job_id.clone(), active_job);
        Ok(job)
    }

    pub fn drain_events(&self, job_id: &str) -> Result<Vec<WorkspaceSearchEvent>> {
        let mut jobs = self.jobs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let job = jobs
            .get_mut(job_id)
            .ok_or_else(|| SearchError::UnknownJob(job_id.to_string()))?;
        Ok(job.drain_events())
    }

    pub fn wait_for_job(&self, job_id: &str) -> Result<Vec<WorkspaceSearchEvent>> {
        let job = {
            let mut jobs = self.jobs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            jobs.remove(job_id)
                .ok_or_else(|| SearchError::UnknownJob(job_id.to_string()))?
        };

        job.finish()
    }

    pub fn cancel_search(&self, job_id: &str) -> Result<()> {
        let jobs = self.jobs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let job = jobs
            .get(job_id)
            .ok_or_else(|| SearchError::UnknownJob(job_id.to_string()))?;
        job.cancel()
    }
}

#[derive(Debug)]
struct ActiveSearchJob {
    receiver: std::sync::mpsc::Receiver<WorkspaceSearchEvent>,
    child: Arc<Mutex<Child>>,
    cancelled: Arc<AtomicBool>,
    join: thread::JoinHandle<std::result::Result<(), SearchError>>,
}

impl ActiveSearchJob {
    fn spawn_path(job: SearchJobHandle, tools: SearchTools, root_path: PathBuf) -> Result<Self> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let (child, tool_name, fallback_filter) = spawn_path_command(&tools, &root_path, &job.query)?;
        let child = Arc::new(Mutex::new(child));
        let cancelled = Arc::new(AtomicBool::new(false));
        let thread_child = Arc::clone(&child);
        let thread_cancelled = Arc::clone(&cancelled);
        let join = thread::spawn(move || {
            let mut matches = 0usize;
            {
                let mut child = thread_child.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let stdout = child.stdout.take().ok_or_else(|| {
                    SearchError::InvalidOutput("missing search stdout pipe".to_string())
                })?;
                let reader = BufReader::new(stdout);

                for line in reader.lines() {
                    let line = line.map_err(|error| SearchError::Spawn {
                        tool: tool_name.clone(),
                        source: error,
                    })?;
                    if let Some(filter) = &fallback_filter {
                        if !line.contains(filter) {
                            continue;
                        }
                    }
                    matches += 1;
                    let event = WorkspaceSearchEvent {
                        job_id: job.job_id.clone(),
                        kind: WorkspaceSearchEventKind::Match,
                        payload: SearchEventPayload::PathMatch(PathSearchMatch {
                            relative_path: line,
                        }),
                    };
                    let _ = sender.send(event);
                    let _ = sender.send(WorkspaceSearchEvent {
                        job_id: job.job_id.clone(),
                        kind: WorkspaceSearchEventKind::Progress,
                        payload: SearchEventPayload::Progress { matches },
                    });
                }
            }

            finish_child(&job, sender, thread_child, thread_cancelled, tool_name, matches)
        });

        Ok(Self {
            receiver,
            child,
            cancelled,
            join,
        })
    }

    fn spawn_content(
        job: SearchJobHandle,
        tools: SearchTools,
        root_path: PathBuf,
        globs: &[String],
    ) -> Result<Self> {
        let (sender, receiver) = std::sync::mpsc::channel();
        let mut command = Command::new(&tools.rg_program);
        command
            .current_dir(&root_path)
            .args(["--json", "--color", "never", "--smart-case"])
            .arg(&job.query)
            .arg(".")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for glob in globs {
            command.arg("-g").arg(glob);
        }

        let child = command.spawn().map_err(|source| SearchError::Spawn {
            tool: tools.rg_program.display().to_string(),
            source,
        })?;

        let tool_name = tools.rg_program.display().to_string();
        let child = Arc::new(Mutex::new(child));
        let cancelled = Arc::new(AtomicBool::new(false));
        let thread_child = Arc::clone(&child);
        let thread_cancelled = Arc::clone(&cancelled);
        let join = thread::spawn(move || {
            let mut matches = 0usize;
            {
                let mut child = thread_child.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let stdout = child.stdout.take().ok_or_else(|| {
                    SearchError::InvalidOutput("missing search stdout pipe".to_string())
                })?;
                let reader = BufReader::new(stdout);

                for line in reader.lines() {
                    let line = line.map_err(|error| SearchError::Spawn {
                        tool: tool_name.clone(),
                        source: error,
                    })?;
                    if let Some(search_match) = parse_rg_match(&line)? {
                        matches += 1;
                        let _ = sender.send(WorkspaceSearchEvent {
                            job_id: job.job_id.clone(),
                            kind: WorkspaceSearchEventKind::Match,
                            payload: SearchEventPayload::ContentMatch(search_match),
                        });
                        let _ = sender.send(WorkspaceSearchEvent {
                            job_id: job.job_id.clone(),
                            kind: WorkspaceSearchEventKind::Progress,
                            payload: SearchEventPayload::Progress { matches },
                        });
                    }
                }
            }

            finish_child(&job, sender, thread_child, thread_cancelled, tool_name, matches)
        });

        Ok(Self {
            receiver,
            child,
            cancelled,
            join,
        })
    }

    fn drain_events(&mut self) -> Vec<WorkspaceSearchEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.receiver.try_recv() {
            events.push(event);
        }
        events
    }

    fn finish(self) -> Result<Vec<WorkspaceSearchEvent>> {
        match self.join.join() {
            Ok(result) => result?,
            Err(_) => return Err(SearchError::WorkerPanicked),
        }

        let mut events = Vec::new();
        while let Ok(event) = self.receiver.try_recv() {
            events.push(event);
        }
        Ok(events)
    }

    fn cancel(&self) -> Result<()> {
        self.cancelled.store(true, Ordering::SeqCst);
        let mut child = self.child.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        child.kill().map_err(|source| SearchError::Spawn {
            tool: "search".to_string(),
            source,
        })
    }
}

fn finish_child(
    job: &SearchJobHandle,
    sender: std::sync::mpsc::Sender<WorkspaceSearchEvent>,
    child: Arc<Mutex<Child>>,
    cancelled: Arc<AtomicBool>,
    tool_name: String,
    matches: usize,
) -> Result<()> {
    let (status, stderr) = {
        let mut child = child.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut stderr = String::new();
        if let Some(mut stderr_reader) = child.stderr.take() {
            use std::io::Read;
            stderr_reader
                .read_to_string(&mut stderr)
                .map_err(|source| SearchError::Spawn {
                    tool: tool_name.clone(),
                    source,
                })?;
        }
        let status = child.wait().map_err(|source| SearchError::Spawn {
            tool: tool_name.clone(),
            source,
        })?;
        (status, stderr)
    };

    if status.success() || cancelled.load(Ordering::SeqCst) {
        let _ = sender.send(WorkspaceSearchEvent {
            job_id: job.job_id.clone(),
            kind: WorkspaceSearchEventKind::Done,
            payload: SearchEventPayload::Summary(SearchSummary {
                matches,
                cancelled: cancelled.load(Ordering::SeqCst),
                exit_code: status.code(),
            }),
        });
        return Ok(());
    }

    let _ = sender.send(WorkspaceSearchEvent {
        job_id: job.job_id.clone(),
        kind: WorkspaceSearchEventKind::Error,
        payload: SearchEventPayload::Error {
            message: stderr.clone(),
        },
    });
    Err(SearchError::ToolFailed {
        tool: tool_name,
        exit_code: status.code(),
        stderr,
    })
}

fn root_path(workspace: &WorkspaceService, root_id: &str) -> Result<PathBuf> {
    Ok(PathBuf::from(workspace.root_metadata(root_id)?.canonical_path))
}

fn spawn_path_command(
    tools: &SearchTools,
    root_path: &PathBuf,
    query: &str,
) -> Result<(Child, String, Option<String>)> {
    if let Some(fd_program) = &tools.fd_program {
        let mut command = Command::new(fd_program);
        command
            .current_dir(root_path)
            .args(["--color", "never", "--strip-cwd-prefix", "--full-path"])
            .arg(query)
            .arg(".")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        match command.spawn() {
            Ok(child) => {
                return Ok((child, fd_program.display().to_string(), None));
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                return Err(SearchError::Spawn {
                    tool: fd_program.display().to_string(),
                    source: error,
                });
            }
            Err(_) => {}
        }
    }

    let mut command = Command::new(&tools.rg_program);
    command
        .current_dir(root_path)
        .args(["--files"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command.spawn().map_err(|source| SearchError::Spawn {
        tool: tools.rg_program.display().to_string(),
        source,
    })?;
    Ok((
        child,
        tools.rg_program.display().to_string(),
        Some(query.to_string()),
    ))
}

fn parse_rg_match(line: &str) -> Result<Option<ContentSearchMatch>> {
    let value: Value = serde_json::from_str(line)
        .map_err(|error| SearchError::InvalidOutput(error.to_string()))?;
    if value.get("type").and_then(Value::as_str) != Some("match") {
        return Ok(None);
    }

    let data = value
        .get("data")
        .ok_or_else(|| SearchError::InvalidOutput("rg JSON event missing data".to_string()))?;
    let path = data
        .get("path")
        .and_then(|path| path.get("text"))
        .and_then(Value::as_str)
        .ok_or_else(|| SearchError::InvalidOutput("rg JSON match missing path".to_string()))?;
    let line_number = data
        .get("line_number")
        .and_then(Value::as_u64)
        .ok_or_else(|| SearchError::InvalidOutput("rg JSON match missing line number".to_string()))?;
    let preview = data
        .get("lines")
        .and_then(|lines| lines.get("text"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim_end_matches('\n')
        .to_string();
    let column = data
        .get("submatches")
        .and_then(Value::as_array)
        .and_then(|submatches| submatches.first())
        .and_then(|first| first.get("start"))
        .and_then(Value::as_u64)
        .map(|value| value + 1)
        .unwrap_or(1);

    Ok(Some(ContentSearchMatch {
        relative_path: path.to_string(),
        line_number,
        column,
        preview,
    }))
}

fn timestamp_now() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::settings::WorkspaceSettingsStore;
    use crate::workspace::WorkspaceService;

    use super::{
        SearchEventPayload, SearchService, SearchTools, WorkspaceSearchEventKind,
    };

    fn unique_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "huntronomer-workspace-core-search-{label}-{}",
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

    #[test]
    fn runs_path_search_jobs() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("path");
        let settings_path = root_dir.join("workspace-settings.json");
        let workspace_dir = root_dir.join("repo");
        std::fs::create_dir_all(&workspace_dir)?;

        let fd_script = root_dir.join("fd-stub.sh");
        write_script(
            &fd_script,
            "#!/bin/sh\nprintf 'src/main.rs\nsrc/lib.rs\nREADME.md\n'\n",
        )?;

        let mut workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;
        let root = workspace.register_root(&workspace_dir)?;
        let search = SearchService::new(SearchTools {
            fd_program: Some(fd_script),
            rg_program: PathBuf::from("rg"),
        });

        let job = search.start_path_search(&workspace, &root.id, "src")?;
        let events = search.wait_for_job(&job.job_id)?;

        assert!(events.iter().any(|event| {
            event.kind == WorkspaceSearchEventKind::Match
                && matches!(
                    &event.payload,
                    SearchEventPayload::PathMatch(found) if found.relative_path == "src/main.rs"
                )
        }));
        assert!(events.iter().any(|event| event.kind == WorkspaceSearchEventKind::Done));

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }

    #[test]
    fn runs_content_search_jobs() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("content");
        let settings_path = root_dir.join("workspace-settings.json");
        let workspace_dir = root_dir.join("repo");
        std::fs::create_dir_all(&workspace_dir)?;

        let rg_script = root_dir.join("rg-stub.sh");
        write_script(
            &rg_script,
            concat!(
                "#!/bin/sh\n",
                "cat <<'EOF'\n",
                "{\"type\":\"match\",\"data\":{\"path\":{\"text\":\"src/main.rs\"},\"lines\":{\"text\":\"fn main() {}\\n\"},\"line_number\":4,\"submatches\":[{\"start\":3}]}}\n",
                "{\"type\":\"summary\",\"data\":{\"elapsed_total\":{\"secs\":0,\"nanos\":1},\"stats\":{}}}\n",
                "EOF\n",
            ),
        )?;

        let mut workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;
        let root = workspace.register_root(&workspace_dir)?;
        let search = SearchService::new(SearchTools {
            fd_program: None,
            rg_program: rg_script,
        });

        let job = search.start_content_search(&workspace, &root.id, "main", &[])?;
        let events = search.wait_for_job(&job.job_id)?;

        assert!(events.iter().any(|event| {
            event.kind == WorkspaceSearchEventKind::Match
                && matches!(
                    &event.payload,
                    SearchEventPayload::ContentMatch(found)
                        if found.relative_path == "src/main.rs"
                            && found.line_number == 4
                            && found.column == 4
                )
        }));
        assert!(events.iter().any(|event| event.kind == WorkspaceSearchEventKind::Done));

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }
}
