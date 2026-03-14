//! Local `clawdstrike-brokerd` lifecycle management.

use anyhow::{Context, Result};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, RwLock};

const READY_MAX_ATTEMPTS: usize = 40;
const READY_POLL_DELAY: Duration = Duration::from_millis(150);
const MONITOR_POLL_DELAY: Duration = Duration::from_secs(2);
const SIGTERM_GRACE_PERIOD: Duration = Duration::from_millis(300);
const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug)]
pub struct BrokerdConfig {
    pub enabled: bool,
    pub binary_path: PathBuf,
    pub port: u16,
    pub hushd_base_url: String,
    pub hushd_token: Option<String>,
    pub admin_token: Option<String>,
    pub secret_backend: crate::settings::BrokerdSecretBackendSettings,
    pub allow_http_loopback: bool,
    pub allow_private_upstream_hosts: bool,
    pub allow_invalid_upstream_tls: bool,
}

impl BrokerdConfig {
    pub fn health_url(&self) -> String {
        format!("http://127.0.0.1:{}/health", self.port)
    }
}

pub struct BrokerdManager {
    config: BrokerdConfig,
    child: Arc<RwLock<Option<Child>>>,
    lifecycle_lock: Arc<Mutex<()>>,
    shutdown_requested: Arc<AtomicBool>,
    monitor_started: Arc<AtomicBool>,
    monitor_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    http_client: reqwest::Client,
}

impl BrokerdManager {
    pub fn new(config: BrokerdConfig) -> Self {
        Self {
            config,
            child: Arc::new(RwLock::new(None)),
            lifecycle_lock: Arc::new(Mutex::new(())),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            monitor_started: Arc::new(AtomicBool::new(false)),
            monitor_task: Arc::new(Mutex::new(None)),
            http_client: reqwest::Client::builder()
                .timeout(HEALTH_CHECK_TIMEOUT)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub async fn start(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let _guard = self.lifecycle_lock.lock().await;
        self.shutdown_requested.store(false, Ordering::SeqCst);

        if self.is_healthy().await {
            self.ensure_monitor_loop().await;
            return Ok(());
        }

        if !self.config.binary_path.exists() {
            anyhow::bail!("brokerd binary not found at {:?}", self.config.binary_path);
        }

        self.spawn_with_fresh_trust().await?;
        self.ensure_monitor_loop().await;
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let _guard = self.lifecycle_lock.lock().await;

        self.shutdown_requested.store(true, Ordering::SeqCst);

        if let Some(task) = self.monitor_task.lock().await.take() {
            task.abort();
        }
        self.monitor_started.store(false, Ordering::SeqCst);

        terminate_child_slot(&self.child).await;
        Ok(())
    }

    pub fn health_url(&self) -> String {
        self.config.health_url()
    }

    async fn is_healthy(&self) -> bool {
        is_healthy_with_client(&self.http_client, &self.config).await
    }

    async fn spawn_with_fresh_trust(&self) -> Result<()> {
        let hushd_public_key = fetch_hushd_public_key(&self.http_client, &self.config).await?;
        let mut child = spawn_brokerd_process(&self.config, &hushd_public_key).await?;
        attach_child_logs(&mut child);
        *self.child.write().await = Some(child);
        if let Err(error) = wait_until_ready(&self.http_client, &self.config).await {
            terminate_child_slot(&self.child).await;
            return Err(error);
        }
        Ok(())
    }

    async fn ensure_monitor_loop(&self) {
        if self.monitor_started.swap(true, Ordering::SeqCst) {
            return;
        }

        let child = self.child.clone();
        let lifecycle_lock = self.lifecycle_lock.clone();
        let shutdown_requested = self.shutdown_requested.clone();
        let monitor_started = self.monitor_started.clone();
        let config = self.config.clone();
        let http_client = self.http_client.clone();
        let monitor_task = self.monitor_task.clone();
        let monitor_task_cleanup = self.monitor_task.clone();

        let task = tokio::spawn(async move {
            loop {
                if shutdown_requested.load(Ordering::SeqCst) {
                    break;
                }

                tokio::time::sleep(MONITOR_POLL_DELAY).await;

                let mut needs_restart = false;
                let child_alive = {
                    let mut guard = child.write().await;
                    if let Some(existing) = guard.as_mut() {
                        match existing.try_wait() {
                            Ok(Some(status)) => {
                                tracing::warn!(status = %status, "brokerd exited; scheduling restart");
                                *guard = None;
                                needs_restart = true;
                                false
                            }
                            Ok(None) => true,
                            Err(error) => {
                                tracing::warn!(error = %error, "failed to poll brokerd process");
                                *guard = None;
                                needs_restart = true;
                                false
                            }
                        }
                    } else {
                        false
                    }
                };

                // Health check runs outside the write lock to avoid
                // holding it during the HTTP request (up to 5s timeout).
                if !needs_restart && !is_healthy_with_client(&http_client, &config).await {
                    if child_alive {
                        tracing::warn!(
                            "brokerd alive but unhealthy; killing and scheduling restart"
                        );
                        terminate_child_slot(&child).await;
                    }
                    needs_restart = true;
                }

                if !needs_restart || shutdown_requested.load(Ordering::SeqCst) {
                    continue;
                }

                let _guard = lifecycle_lock.lock().await;
                if shutdown_requested.load(Ordering::SeqCst) {
                    break;
                }
                if is_healthy_with_client(&http_client, &config).await {
                    continue;
                }

                let public_key = match fetch_hushd_public_key(&http_client, &config).await {
                    Ok(key) => key,
                    Err(error) => {
                        tracing::error!(error = %error, "failed to refresh hushd trust for brokerd restart");
                        continue;
                    }
                };
                let mut child_process = match spawn_brokerd_process(&config, &public_key).await {
                    Ok(proc) => proc,
                    Err(error) => {
                        tracing::error!(error = %error, "failed to restart brokerd");
                        continue;
                    }
                };
                attach_child_logs(&mut child_process);
                *child.write().await = Some(child_process);
                if let Err(error) = wait_until_ready(&http_client, &config).await {
                    tracing::error!(error = %error, "brokerd restart did not become ready");
                    terminate_child_slot(&child).await;
                }
            }

            *monitor_task_cleanup.lock().await = None;
            monitor_started.store(false, Ordering::SeqCst);
        });

        *monitor_task.lock().await = Some(task);
    }
}

async fn wait_until_ready(client: &reqwest::Client, config: &BrokerdConfig) -> Result<()> {
    for _ in 0..READY_MAX_ATTEMPTS {
        if is_healthy_with_client(client, config).await {
            return Ok(());
        }
        tokio::time::sleep(READY_POLL_DELAY).await;
    }

    anyhow::bail!("brokerd did not become healthy on {}", config.health_url())
}

async fn is_healthy_with_client(client: &reqwest::Client, config: &BrokerdConfig) -> bool {
    match client.get(config.health_url()).send().await {
        Ok(response) => response.status().is_success(),
        Err(_) => false,
    }
}

async fn fetch_hushd_public_key(
    client: &reqwest::Client,
    config: &BrokerdConfig,
) -> Result<String> {
    let mut request = client.get(format!(
        "{}/api/v1/broker/public-key",
        config.hushd_base_url.trim_end_matches('/')
    ));
    if let Some(token) = &config.hushd_token {
        request = request.bearer_auth(token);
    }
    let response = request
        .send()
        .await
        .context("Failed to fetch hushd broker signing public key")?;
    if !response.status().is_success() {
        anyhow::bail!(
            "hushd broker public-key endpoint returned {}",
            response.status()
        );
    }
    let payload: serde_json::Value = response
        .json()
        .await
        .context("Failed to parse hushd broker public key response")?;
    let public_key = payload
        .get("public_key")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("hushd broker public key response was missing public_key")
        })?;
    Ok(public_key.to_string())
}

async fn spawn_brokerd_process(config: &BrokerdConfig, hushd_public_key: &str) -> Result<Child> {
    let mut cmd = Command::new(&config.binary_path);
    cmd.env(
        "CLAWDSTRIKE_BROKERD_LISTEN",
        format!("127.0.0.1:{}", config.port),
    )
    .env("CLAWDSTRIKE_BROKERD_HUSHD_URL", &config.hushd_base_url)
    .env("CLAWDSTRIKE_BROKERD_HUSHD_PUBKEYS", hushd_public_key)
    .env(
        "CLAWDSTRIKE_BROKERD_ALLOW_HTTP_LOOPBACK",
        bool_env(config.allow_http_loopback),
    )
    .env(
        "CLAWDSTRIKE_BROKERD_ALLOW_PRIVATE_UPSTREAM_HOSTS",
        bool_env(config.allow_private_upstream_hosts),
    )
    .env(
        "CLAWDSTRIKE_BROKERD_ALLOW_INVALID_TLS",
        bool_env(config.allow_invalid_upstream_tls),
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .stdin(Stdio::null());

    if let Some(token) = &config.hushd_token {
        cmd.env("CLAWDSTRIKE_BROKERD_HUSHD_TOKEN", token);
    }
    if let Some(token) = &config.admin_token {
        cmd.env("CLAWDSTRIKE_BROKERD_ADMIN_TOKEN", token);
    }

    let backend_kind = config.secret_backend.kind.trim();
    if backend_kind.eq_ignore_ascii_case("file") {
        cmd.env("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "file").env(
            "CLAWDSTRIKE_BROKERD_SECRET_FILE",
            config.secret_backend.file_path.to_string_lossy().as_ref(),
        );
    } else if backend_kind.eq_ignore_ascii_case("env") {
        cmd.env("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "env").env(
            "CLAWDSTRIKE_BROKERD_SECRET_ENV_PREFIX",
            &config.secret_backend.env_prefix,
        );
    } else if backend_kind.eq_ignore_ascii_case("http") {
        let base_url = config
            .secret_backend
            .http_base_url
            .as_ref()
            .filter(|value| !value.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("brokerd http secret backend requires http_base_url"))?;
        cmd.env("CLAWDSTRIKE_BROKERD_SECRET_BACKEND", "http")
            .env("CLAWDSTRIKE_BROKERD_SECRET_HTTP_URL", base_url)
            .env(
                "CLAWDSTRIKE_BROKERD_SECRET_HTTP_PATH_PREFIX",
                &config.secret_backend.http_path_prefix,
            );
        if let Some(token) = &config.secret_backend.http_bearer_token {
            cmd.env("CLAWDSTRIKE_BROKERD_SECRET_HTTP_TOKEN", token);
        }
    } else {
        anyhow::bail!("unsupported brokerd secret backend kind '{backend_kind}'");
    }

    cmd.spawn()
        .with_context(|| format!("Failed to spawn brokerd from {:?}", config.binary_path))
}

async fn terminate_child_slot(child_slot: &Arc<RwLock<Option<Child>>>) {
    let mut guard = child_slot.write().await;
    let mut maybe_child = guard.take();
    drop(guard);

    let Some(ref mut child) = maybe_child else {
        return;
    };

    #[cfg(unix)]
    if let Some(pid) = child.id() {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }
    tokio::time::sleep(SIGTERM_GRACE_PERIOD).await;
    let _ = child.kill().await;
    let _ = child.wait().await;
}

fn attach_child_logs(child: &mut Child) {
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::info!(target = "brokerd", "{}", line);
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                tracing::warn!(target = "brokerd", "{}", line);
            }
        });
    }
}

fn bool_env(value: bool) -> &'static str {
    if value {
        "true"
    } else {
        "false"
    }
}

fn brokerd_binary_name() -> &'static str {
    if cfg!(windows) {
        "clawdstrike-brokerd.exe"
    } else {
        "clawdstrike-brokerd"
    }
}

pub fn managed_brokerd_path() -> PathBuf {
    crate::settings::get_config_dir()
        .join("bin")
        .join(brokerd_binary_name())
}

fn bundled_brokerd_candidates() -> Vec<PathBuf> {
    let binary = brokerd_binary_name();
    let mut candidates = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(exe_dir) = exe.parent() {
            candidates.push(exe_dir.join(binary));
            if let Some(contents_dir) = exe_dir.parent() {
                candidates.push(contents_dir.join("Resources").join(binary));
                candidates.push(contents_dir.join("Resources").join("bin").join(binary));
                candidates.push(
                    contents_dir
                        .join("Resources")
                        .join("resources")
                        .join(binary),
                );
                candidates.push(
                    contents_dir
                        .join("Resources")
                        .join("resources")
                        .join("bin")
                        .join(binary),
                );
            }
        }
    }

    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let root = PathBuf::from(manifest_dir);
        candidates.push(root.join("resources").join(binary));
        candidates.push(root.join("resources").join("bin").join(binary));
        candidates.push(root.join("../../target/release").join(binary));
        candidates.push(root.join("../../target/debug").join(binary));
    }

    candidates
}

pub fn prepare_managed_brokerd_binary() -> Result<Option<PathBuf>> {
    let Some(source_path) = bundled_brokerd_candidates()
        .into_iter()
        .find(|candidate| candidate.is_file())
    else {
        return Ok(None);
    };

    let managed_path = managed_brokerd_path();
    let copy_needed = managed_brokerd_needs_copy(&source_path, &managed_path)?;

    if copy_needed {
        if let Some(parent) = managed_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create managed brokerd directory {:?}", parent)
            })?;
        }

        std::fs::copy(&source_path, &managed_path).with_context(|| {
            format!(
                "Failed to copy bundled brokerd from {:?} to {:?}",
                source_path, managed_path
            )
        })?;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&managed_path)
            .with_context(|| format!("Failed to stat managed brokerd at {:?}", managed_path))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&managed_path, perms).with_context(|| {
            format!(
                "Failed to set executable permissions on managed brokerd at {:?}",
                managed_path
            )
        })?;
    }

    #[cfg(target_os = "macos")]
    if copy_needed {
        let status = std::process::Command::new("codesign")
            .args([
                "--force",
                "--sign",
                "-",
                managed_path.to_string_lossy().as_ref(),
            ])
            .status()
            .with_context(|| format!("Failed to invoke codesign for {:?}", managed_path))?;
        if !status.success() {
            anyhow::bail!(
                "codesign failed for managed brokerd at {:?} with status {}",
                managed_path,
                status
            );
        }
    }

    Ok(Some(managed_path))
}

fn managed_brokerd_needs_copy(
    source_path: &std::path::Path,
    managed_path: &std::path::Path,
) -> Result<bool> {
    if !managed_path.is_file() {
        return Ok(true);
    }
    let source_meta = std::fs::metadata(source_path).with_context(|| {
        format!(
            "Failed to stat bundled brokerd candidate at {:?}",
            source_path
        )
    })?;
    let managed_meta = std::fs::metadata(managed_path)
        .with_context(|| format!("Failed to stat managed brokerd at {:?}", managed_path))?;
    if source_meta.len() != managed_meta.len() {
        return Ok(true);
    }

    let source_modified = source_meta
        .modified()
        .context("Failed to read bundled brokerd mtime")?;
    let managed_modified = managed_meta
        .modified()
        .context("Failed to read managed brokerd mtime")?;

    Ok(source_modified > managed_modified)
}

pub fn find_brokerd_binary() -> Option<PathBuf> {
    let binary = brokerd_binary_name();
    let mut candidates = vec![managed_brokerd_path()];
    candidates.extend(bundled_brokerd_candidates());
    candidates.extend(
        [
            which::which("clawdstrike-brokerd").ok(),
            Some(PathBuf::from("/usr/local/bin").join(binary)),
            Some(PathBuf::from("/opt/homebrew/bin").join(binary)),
            Some(PathBuf::from("/opt/clawdstrike/bin").join(binary)),
            dirs::home_dir().map(|path| path.join(".local/bin").join(binary)),
            dirs::home_dir().map(|path| path.join(".cargo/bin").join(binary)),
        ]
        .into_iter()
        .flatten(),
    );

    candidates.into_iter().find(|candidate| candidate.exists())
}
