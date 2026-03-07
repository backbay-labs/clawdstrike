use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::workspace::{WorkspaceError, WorkspaceService};

pub type Result<T> = std::result::Result<T, ProcError>;

#[derive(Debug, Error)]
pub enum ProcError {
    #[error(transparent)]
    Workspace(#[from] WorkspaceError),
    #[error("sidecar tool is not allowlisted: {0}")]
    ToolNotAllowlisted(String),
    #[error("sidecar process is not active: {0}")]
    UnknownProcess(String),
    #[error("sidecar process failed to start: {tool}: {source}")]
    Spawn { tool: String, source: std::io::Error },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AllowedSidecar {
    pub tool: String,
    pub program: PathBuf,
    #[serde(default)]
    pub default_args: Vec<String>,
    #[serde(default)]
    pub allow_extra_args: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpawnSidecarRequest {
    pub root_id: String,
    pub tool: String,
    pub cwd: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SidecarProcessHandle {
    pub process_id: String,
    pub root_id: String,
    pub tool: String,
    pub started_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SidecarExit {
    pub process_id: String,
    pub root_id: String,
    pub tool: String,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
    pub finished_at: String,
}

#[derive(Debug)]
struct ManagedProcess {
    handle: SidecarProcessHandle,
    child: Child,
}

#[derive(Debug, Default)]
pub struct ProcService {
    allowlist: HashMap<String, AllowedSidecar>,
    processes: Mutex<HashMap<String, ManagedProcess>>,
}

impl ProcService {
    pub fn new(allowlist: impl IntoIterator<Item = AllowedSidecar>) -> Self {
        let allowlist = allowlist
            .into_iter()
            .map(|allowed| (allowed.tool.clone(), allowed))
            .collect();
        Self {
            allowlist,
            processes: Mutex::new(HashMap::new()),
        }
    }

    pub fn spawn_sidecar(
        &self,
        workspace: &WorkspaceService,
        request: SpawnSidecarRequest,
    ) -> Result<SidecarProcessHandle> {
        let allowed = self
            .allowlist
            .get(&request.tool)
            .ok_or_else(|| ProcError::ToolNotAllowlisted(request.tool.clone()))?;
        if !allowed.allow_extra_args && !request.args.is_empty() {
            return Err(ProcError::ToolNotAllowlisted(request.tool));
        }

        let current_dir = match request.cwd.as_deref() {
            Some(relative_path) => workspace.resolve_existing_path(&request.root_id, relative_path)?,
            None => PathBuf::from(workspace.root_metadata(&request.root_id)?.canonical_path),
        };

        let mut command = Command::new(&allowed.program);
        command
            .current_dir(current_dir)
            .args(&allowed.default_args)
            .args(&request.args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let child = command.spawn().map_err(|source| ProcError::Spawn {
            tool: allowed.program.display().to_string(),
            source,
        })?;

        let handle = SidecarProcessHandle {
            process_id: Uuid::now_v7().to_string(),
            root_id: request.root_id,
            tool: allowed.tool.clone(),
            started_at: timestamp_now(),
        };
        let managed = ManagedProcess {
            handle: handle.clone(),
            child,
        };

        let mut processes = self.processes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        processes.insert(handle.process_id.clone(), managed);
        Ok(handle)
    }

    pub fn list_processes(&self) -> Vec<SidecarProcessHandle> {
        let processes = self.processes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        processes.values().map(|process| process.handle.clone()).collect()
    }

    pub fn wait(&self, process_id: &str) -> Result<SidecarExit> {
        let managed = {
            let mut processes = self.processes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            processes
                .remove(process_id)
                .ok_or_else(|| ProcError::UnknownProcess(process_id.to_string()))?
        };
        collect_exit(managed)
    }

    pub fn terminate(&self, process_id: &str) -> Result<SidecarExit> {
        let mut managed = {
            let mut processes = self.processes.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            processes
                .remove(process_id)
                .ok_or_else(|| ProcError::UnknownProcess(process_id.to_string()))?
        };
        managed.child.kill().map_err(|source| ProcError::Spawn {
            tool: managed.handle.tool.clone(),
            source,
        })?;
        collect_exit(managed)
    }
}

fn collect_exit(managed: ManagedProcess) -> Result<SidecarExit> {
    let output = managed.child.wait_with_output().map_err(|source| ProcError::Spawn {
        tool: managed.handle.tool.clone(),
        source,
    })?;
    Ok(SidecarExit {
        process_id: managed.handle.process_id,
        root_id: managed.handle.root_id,
        tool: managed.handle.tool,
        exit_code: output.status.code(),
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        finished_at: timestamp_now(),
    })
}

fn timestamp_now() -> String {
    Utc::now().to_rfc3339()
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::settings::WorkspaceSettingsStore;
    use crate::workspace::WorkspaceService;

    use super::{AllowedSidecar, ProcError, ProcService, SpawnSidecarRequest};

    fn unique_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "huntronomer-workspace-core-proc-{label}-{}",
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
    fn spawns_allowlisted_sidecars_and_collects_output() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("spawn");
        let settings_path = root_dir.join("workspace-settings.json");
        let workspace_dir = root_dir.join("repo");
        let child_dir = workspace_dir.join("src");
        std::fs::create_dir_all(&child_dir)?;

        let sidecar_script = root_dir.join("sidecar.sh");
        write_script(
            &sidecar_script,
            "#!/bin/sh\npwd\nprintf 'stderr-line\\n' >&2\nprintf 'args:%s\\n' \"$1\"\n",
        )?;

        let mut workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;
        let root = workspace.register_root(&workspace_dir)?;
        let proc = ProcService::new([AllowedSidecar {
            tool: "echoer".to_string(),
            program: sidecar_script,
            default_args: Vec::new(),
            allow_extra_args: true,
        }]);

        let handle = proc.spawn_sidecar(
            &workspace,
            SpawnSidecarRequest {
                root_id: root.id.clone(),
                tool: "echoer".to_string(),
                cwd: Some("src".to_string()),
                args: vec!["hello".to_string()],
            },
        )?;
        let exit = proc.wait(&handle.process_id)?;

        assert!(exit.success);
        assert!(exit.stdout.contains("/src"));
        assert!(exit.stdout.contains("args:hello"));
        assert!(exit.stderr.contains("stderr-line"));

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }

    #[test]
    fn rejects_unallowlisted_tools() -> Result<(), Box<dyn std::error::Error>> {
        let root_dir = unique_test_dir("reject");
        let settings_path = root_dir.join("workspace-settings.json");
        let workspace_dir = root_dir.join("repo");
        std::fs::create_dir_all(&workspace_dir)?;

        let mut workspace = WorkspaceService::new(WorkspaceSettingsStore::new(settings_path))?;
        let root = workspace.register_root(&workspace_dir)?;
        let proc = ProcService::default();

        let error = proc
            .spawn_sidecar(
                &workspace,
                SpawnSidecarRequest {
                    root_id: root.id,
                    tool: "denied".to_string(),
                    cwd: None,
                    args: Vec::new(),
                },
            )
            .expect_err("unallowlisted tool should fail");
        assert!(matches!(error, ProcError::ToolNotAllowlisted(_)));

        std::fs::remove_dir_all(root_dir)?;
        Ok(())
    }
}
