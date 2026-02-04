#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::collections::HashSet;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use clawdstrike::policy::{LocalPolicyResolver, PolicyLocation, PolicyResolver, ResolvedPolicySource};
use clawdstrike::{Error, Result};
use hush_core::sha256;
use rand::Rng as _;
use reqwest::blocking::Client;

use crate::config::RemoteExtendsConfig;

#[derive(Clone, Debug)]
pub struct RemoteExtendsResolverConfig {
    pub allowed_hosts: HashSet<String>,
    pub cache_dir: PathBuf,
    pub max_fetch_bytes: usize,
    pub max_cache_bytes: usize,
}

impl RemoteExtendsResolverConfig {
    pub fn from_config(cfg: &RemoteExtendsConfig) -> Self {
        let cache_dir = cfg
            .cache_dir
            .clone()
            .unwrap_or_else(default_cache_dir);

        Self {
            allowed_hosts: cfg
                .allowed_hosts
                .iter()
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            cache_dir,
            max_fetch_bytes: cfg.max_fetch_bytes,
            max_cache_bytes: cfg.max_cache_bytes,
        }
    }

    pub fn remote_enabled(&self) -> bool {
        !self.allowed_hosts.is_empty()
    }
}

fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("hush")
        .join("policies")
}

#[derive(Clone, Debug)]
pub struct RemotePolicyResolver {
    cfg: RemoteExtendsResolverConfig,
    local: LocalPolicyResolver,
    client: Option<&'static Client>,
}

impl RemotePolicyResolver {
    pub fn new(cfg: RemoteExtendsResolverConfig) -> Result<Self> {
        Ok(Self {
            client: if cfg.remote_enabled() {
                Some(blocking_http_client()?)
            } else {
                None
            },
            cfg,
            local: LocalPolicyResolver::new(),
        })
    }

    fn ensure_host_allowed(&self, host: &str) -> Result<()> {
        let host = host.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Err(Error::ConfigError("Remote extends URL missing host".to_string()));
        }
        if !self.cfg.allowed_hosts.contains(&host) {
            return Err(Error::ConfigError(format!(
                "Remote extends host not allowlisted: {}",
                host
            )));
        }
        Ok(())
    }

    fn resolve_http(&self, reference: &str, base: Option<&str>) -> Result<ResolvedPolicySource> {
        let (path_or_url, expected_sha) = split_sha256_pin(reference)?;
        let url = match base {
            Some(base_url) => join_url(base_url, path_or_url)?,
            None => path_or_url.to_string(),
        };

        let host = parse_url_host(&url)?;
        self.ensure_host_allowed(&host)?;

        if !self.cfg.remote_enabled() {
            return Err(Error::ConfigError(
                "Remote extends are disabled (no allowlisted hosts)".to_string(),
            ));
        }

        let key = format!("url:{}#sha256={}", url, expected_sha);
        let cache_path = self.cache_path_for(&key, "yaml");
        if let Ok(bytes) = std::fs::read(&cache_path) {
            if sha256(&bytes).to_hex().eq_ignore_ascii_case(expected_sha) {
                let yaml = String::from_utf8(bytes)
                    .map_err(|_| Error::ConfigError("Remote policy YAML must be UTF-8".into()))?;
                return Ok(ResolvedPolicySource {
                    key,
                    yaml,
                    location: PolicyLocation::Url(url),
                });
            }

            let _ = std::fs::remove_file(&cache_path);
        }

        let bytes = self.fetch_http_bytes(&url)?;
        verify_sha256_pin(&bytes, expected_sha)?;
        self.write_cache(&cache_path, &bytes)?;

        let yaml = String::from_utf8(bytes)
            .map_err(|_| Error::ConfigError("Remote policy YAML must be UTF-8".into()))?;

        Ok(ResolvedPolicySource {
            key,
            yaml,
            location: PolicyLocation::Url(url),
        })
    }

    fn fetch_http_bytes(&self, url: &str) -> Result<Vec<u8>> {
        let Some(client) = self.client else {
            return Err(Error::ConfigError(
                "Remote extends are disabled (no allowlisted hosts)".to_string(),
            ));
        };

        let resp = client
            .get(url)
            .send()
            .map_err(|e| Error::ConfigError(format!("Failed to fetch remote policy: {}", e)))?;

        if let Some(len) = resp.content_length() {
            if len > (self.cfg.max_fetch_bytes as u64) {
                return Err(Error::ConfigError(format!(
                    "Remote policy exceeds max_fetch_bytes ({} > {})",
                    len, self.cfg.max_fetch_bytes
                )));
            }
        }

        let mut bytes = Vec::new();
        let mut limited = resp.take((self.cfg.max_fetch_bytes as u64) + 1);
        limited
            .read_to_end(&mut bytes)
            .map_err(Error::IoError)?;
        if bytes.len() > self.cfg.max_fetch_bytes {
            return Err(Error::ConfigError(format!(
                "Remote policy exceeds max_fetch_bytes ({} > {})",
                bytes.len(),
                self.cfg.max_fetch_bytes
            )));
        }
        Ok(bytes)
    }

    fn resolve_git_absolute(&self, reference: &str) -> Result<ResolvedPolicySource> {
        let (spec, expected_sha) = split_sha256_pin(reference)?;
        let spec = spec
            .strip_prefix("git+")
            .ok_or_else(|| Error::ConfigError("Invalid git extends (missing git+)".into()))?;

        let (repo, rest) = spec.rsplit_once('@').ok_or_else(|| {
            Error::ConfigError("Invalid git extends (expected ...repo@COMMIT:PATH)".into())
        })?;
        let (commit, path) = rest.split_once(':').ok_or_else(|| {
            Error::ConfigError("Invalid git extends (expected ...@COMMIT:PATH)".into())
        })?;

        if repo.is_empty() || commit.is_empty() || path.is_empty() {
            return Err(Error::ConfigError(
                "Invalid git extends (empty repo/commit/path)".into(),
            ));
        }

        if let Ok(host) = parse_url_host(repo) {
            self.ensure_host_allowed(&host)?;
        }

        if !self.cfg.remote_enabled() {
            return Err(Error::ConfigError(
                "Remote extends are disabled (no allowlisted hosts)".to_string(),
            ));
        }

        let key = format!("git:{}@{}:{}#sha256={}", repo, commit, path, expected_sha);
        let cache_path = self.cache_path_for(&key, "yaml");
        if let Ok(bytes) = std::fs::read(&cache_path) {
            if sha256(&bytes).to_hex().eq_ignore_ascii_case(expected_sha) {
                let yaml = String::from_utf8(bytes)
                    .map_err(|_| Error::ConfigError("Remote policy YAML must be UTF-8".into()))?;
                return Ok(ResolvedPolicySource {
                    key,
                    yaml,
                    location: PolicyLocation::Git {
                        repo: repo.to_string(),
                        commit: commit.to_string(),
                        path: path.to_string(),
                    },
                });
            }

            let _ = std::fs::remove_file(&cache_path);
        }

        let bytes = self.git_show_file(repo, commit, path)?;
        verify_sha256_pin(&bytes, expected_sha)?;
        self.write_cache(&cache_path, &bytes)?;

        let yaml = String::from_utf8(bytes)
            .map_err(|_| Error::ConfigError("Remote policy YAML must be UTF-8".into()))?;
        Ok(ResolvedPolicySource {
            key,
            yaml,
            location: PolicyLocation::Git {
                repo: repo.to_string(),
                commit: commit.to_string(),
                path: path.to_string(),
            },
        })
    }

    fn resolve_git_relative(
        &self,
        reference: &str,
        repo: &str,
        commit: &str,
        base_path: &str,
    ) -> Result<ResolvedPolicySource> {
        let (rel_path, expected_sha) = split_sha256_pin(reference)?;
        let joined = normalize_git_join(base_path, rel_path)?;
        let absolute = format!("git+{}@{}:{}#sha256={}", repo, commit, joined, expected_sha);
        self.resolve_git_absolute(&absolute)
    }

    fn git_show_file(&self, repo: &str, commit: &str, path: &str) -> Result<Vec<u8>> {
        let temp = TempGitDir::new()?;

        run_git(&temp.path, &["init"])?;
        run_git(&temp.path, &["remote", "add", "origin", repo])?;
        run_git(&temp.path, &["fetch", "--depth", "1", "origin", commit])?;

        let output = Command::new("git")
            .arg("-C")
            .arg(&temp.path)
            .env("GIT_TERMINAL_PROMPT", "0")
            .args(["show", &format!("FETCH_HEAD:{}", path)])
            .output()
            .map_err(Error::IoError)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::ConfigError(format!(
                "Failed to read policy from git ({}): {}",
                output.status, stderr
            )));
        }

        if output.stdout.len() > self.cfg.max_fetch_bytes {
            return Err(Error::ConfigError(format!(
                "Remote policy exceeds max_fetch_bytes ({} > {})",
                output.stdout.len(),
                self.cfg.max_fetch_bytes
            )));
        }

        Ok(output.stdout)
    }

    fn cache_path_for(&self, key: &str, ext: &str) -> PathBuf {
        let digest = sha256(key.as_bytes()).to_hex();
        self.cfg.cache_dir.join(format!("{digest}.{ext}"))
    }

    fn write_cache(&self, path: &Path, bytes: &[u8]) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(Error::IoError)?;
        }
        std::fs::write(path, bytes).map_err(Error::IoError)?;
        enforce_cache_size_limit(&self.cfg.cache_dir, self.cfg.max_cache_bytes);
        Ok(())
    }
}

impl PolicyResolver for RemotePolicyResolver {
    fn resolve(&self, reference: &str, from: &PolicyLocation) -> Result<ResolvedPolicySource> {
        if reference.starts_with("git+") {
            return self.resolve_git_absolute(reference);
        }
        if reference.starts_with("http://") || reference.starts_with("https://") {
            return self.resolve_http(reference, None);
        }

        match from {
            PolicyLocation::Url(base_url) => {
                if !reference.contains("#sha256=") {
                    return Err(Error::ConfigError(
                        "Remote extends must include an integrity pin (#sha256=...)".to_string(),
                    ));
                }
                self.resolve_http(reference, Some(base_url))
            }
            PolicyLocation::Git { repo, commit, path } => {
                if let Some((yaml, id)) = clawdstrike::RuleSet::yaml_by_name(reference) {
                    return Ok(ResolvedPolicySource {
                        key: format!("ruleset:{}", id),
                        yaml: yaml.to_string(),
                        location: PolicyLocation::Ruleset { id },
                    });
                }

                if !reference.contains("#sha256=") {
                    return Err(Error::ConfigError(
                        "Remote extends must include an integrity pin (#sha256=...)".to_string(),
                    ));
                }
                self.resolve_git_relative(reference, repo, commit, path)
            }
            _ => self.local.resolve(reference, from),
        }
    }
}

fn split_sha256_pin(reference: &str) -> Result<(&str, &str)> {
    let (path, fragment) = reference.split_once('#').ok_or_else(|| {
        Error::ConfigError("Remote extends must include an integrity pin (#sha256=...)".to_string())
    })?;
    let fragment = fragment.strip_prefix("sha256=").ok_or_else(|| {
        Error::ConfigError("Remote extends pin must be #sha256=<HEX>".to_string())
    })?;
    if fragment.len() != 64 || !fragment.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::ConfigError(
            "Remote extends sha256 pin must be 64 hex characters".to_string(),
        ));
    }
    if path.is_empty() {
        return Err(Error::ConfigError("Remote extends reference is empty".to_string()));
    }
    Ok((path, fragment))
}

fn verify_sha256_pin(bytes: &[u8], expected_hex: &str) -> Result<()> {
    let actual = sha256(bytes).to_hex();
    if !actual.eq_ignore_ascii_case(expected_hex) {
        return Err(Error::ConfigError(format!(
            "Remote extends sha256 mismatch: expected {}, got {}",
            expected_hex, actual
        )));
    }
    Ok(())
}

fn parse_url_host(url: &str) -> Result<String> {
    let (scheme, rest) = url.split_once("://").ok_or_else(|| {
        Error::ConfigError(format!("Invalid URL in remote extends: {}", url))
    })?;
    if scheme != "http" && scheme != "https" {
        return Err(Error::ConfigError(format!(
            "Unsupported URL scheme for remote extends: {}",
            scheme
        )));
    }
    let host_and_path = rest.split('/').next().unwrap_or("");
    let host_and_path = host_and_path
        .rsplit_once('@')
        .map(|(_, h)| h)
        .unwrap_or(host_and_path);
    let host = host_and_path
        .split(':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if host.is_empty() {
        return Err(Error::ConfigError(format!(
            "Invalid URL host in remote extends: {}",
            url
        )));
    }
    Ok(host)
}

fn join_url(base: &str, reference: &str) -> Result<String> {
    if reference.starts_with("http://") || reference.starts_with("https://") {
        return Ok(reference.to_string());
    }

    let (scheme, rest) = base.split_once("://").ok_or_else(|| {
        Error::ConfigError(format!("Invalid base URL for remote extends: {}", base))
    })?;
    let mut iter = rest.splitn(2, '/');
    let host = iter.next().unwrap_or("");
    let path = iter.next().unwrap_or("");

    let root = format!("{}://{}", scheme, host);
    if reference.starts_with('/') {
        return Ok(format!("{}{}", root, reference));
    }

    let dir = match path.rsplit_once('/') {
        Some((dir, _)) if !dir.is_empty() => format!("{}/{}", root, dir),
        _ => root,
    };

    Ok(format!("{}/{}", dir, reference))
}

fn normalize_git_join(base_file: &str, rel: &str) -> Result<String> {
    let base_dir = base_file.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
    let mut parts: Vec<&str> = base_dir.split('/').filter(|p| !p.is_empty()).collect();

    let rel = rel.trim_start_matches("./");
    let from_root = rel.starts_with('/');
    if from_root {
        parts.clear();
    }

    for seg in rel.trim_start_matches('/').split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(Error::ConfigError(
                        "git extends path escapes repository root".to_string(),
                    ));
                }
            }
            other => parts.push(other),
        }
    }

    Ok(parts.join("/"))
}

fn enforce_cache_size_limit(cache_dir: &Path, max_bytes: usize) {
    let mut entries: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();
    let mut total: u64 = 0;

    let Ok(rd) = std::fs::read_dir(cache_dir) else {
        return;
    };
    for e in rd.flatten() {
        let path = e.path();
        let Ok(meta) = e.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let len = meta.len();
        total = total.saturating_add(len);
        let mtime = meta.modified().unwrap_or(std::time::SystemTime::UNIX_EPOCH);
        entries.push((path, len, mtime));
    }

    if total <= (max_bytes as u64) {
        return;
    }

    entries.sort_by_key(|(_, _, mtime)| *mtime);
    for (path, len, _) in entries {
        let _ = std::fs::remove_file(&path);
        total = total.saturating_sub(len);
        if total <= (max_bytes as u64) {
            break;
        }
    }
}

fn blocking_http_client() -> Result<&'static Client> {
    static CLIENT: OnceLock<Client> = OnceLock::new();
    Ok(CLIENT.get_or_init(|| {
        let build = || {
            Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new())
        };

        // reqwest::blocking spins up its own runtime; initializing that runtime from within an
        // async Tokio context can panic. If we appear to be inside a Tokio runtime, build the
        // blocking client in a fresh OS thread.
        if tokio::runtime::Handle::try_current().is_ok() {
            std::thread::spawn(build)
                .join()
                .unwrap_or_else(|_| Client::new())
        } else {
            build()
        }
    }))
}

struct TempGitDir {
    path: PathBuf,
}

impl TempGitDir {
    fn new() -> Result<Self> {
        let mut rng = rand::rng();
        let nonce: u64 = rng.random();
        let path = std::env::temp_dir().join(format!("hushd_policy_git_{nonce:x}"));
        std::fs::create_dir_all(&path).map_err(Error::IoError)?;
        Ok(Self { path })
    }
}

impl Drop for TempGitDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn run_git(dir: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .args(args)
        .output()
        .map_err(Error::IoError)?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(Error::ConfigError(format!(
        "git {} failed ({}): {}",
        args.join(" "),
        output.status,
        stderr
    )))
}
