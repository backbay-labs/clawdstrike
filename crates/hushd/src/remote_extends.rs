#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

use std::collections::HashSet;
use std::io::Read as _;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::Command;

use clawdstrike::policy::{
    LocalPolicyResolver, PolicyLocation, PolicyResolver, ResolvedPolicySource,
};
use clawdstrike::{Error, Result};
use hush_core::sha256;
use rand::Rng as _;
use reqwest::blocking::Client;
use reqwest::header::LOCATION;
use reqwest::Url;

use crate::config::RemoteExtendsConfig;

#[derive(Clone, Debug)]
pub struct RemoteExtendsResolverConfig {
    pub allowed_hosts: HashSet<String>,
    pub cache_dir: PathBuf,
    pub https_only: bool,
    pub allow_private_ips: bool,
    pub allow_cross_host_redirects: bool,
    pub max_fetch_bytes: usize,
    pub max_cache_bytes: usize,
}

impl RemoteExtendsResolverConfig {
    pub fn from_config(cfg: &RemoteExtendsConfig) -> Self {
        let cache_dir = cfg.cache_dir.clone().unwrap_or_else(default_cache_dir);

        Self {
            allowed_hosts: cfg
                .allowed_hosts
                .iter()
                .map(|h| normalize_host(h))
                .filter(|h| !h.is_empty())
                .collect(),
            cache_dir,
            https_only: cfg.https_only,
            allow_private_ips: cfg.allow_private_ips,
            allow_cross_host_redirects: cfg.allow_cross_host_redirects,
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

fn normalize_host(host: &str) -> String {
    let host = host.trim();
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    host.to_ascii_lowercase()
}

#[derive(Clone, Debug)]
pub struct RemotePolicyResolver {
    cfg: RemoteExtendsResolverConfig,
    local: LocalPolicyResolver,
}

impl RemotePolicyResolver {
    pub fn new(cfg: RemoteExtendsResolverConfig) -> Result<Self> {
        Ok(Self {
            cfg,
            local: LocalPolicyResolver::new(),
        })
    }

    fn ensure_host_allowed(&self, host: &str) -> Result<()> {
        let host = normalize_host(host);
        if host.is_empty() {
            return Err(Error::ConfigError(
                "Remote extends URL missing host".to_string(),
            ));
        }
        if !self.cfg.allowed_hosts.contains(&host) {
            return Err(Error::ConfigError(format!(
                "Remote extends host not allowlisted: {}",
                host
            )));
        }
        Ok(())
    }

    fn validate_and_resolve_http_target(
        &self,
        url: &Url,
        initial_host: &str,
    ) -> Result<(String, Vec<SocketAddr>)> {
        if self.cfg.https_only && url.scheme() != "https" {
            return Err(Error::ConfigError(format!(
                "Remote extends require https:// URLs (got {}://)",
                url.scheme()
            )));
        }
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(Error::ConfigError(format!(
                "Unsupported URL scheme for remote extends: {}",
                url.scheme()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(Error::ConfigError(
                "Remote extends URLs must not include userinfo".to_string(),
            ));
        }

        let host = normalize_host(
            url.host_str()
                .ok_or_else(|| Error::ConfigError(format!("Invalid URL host: {}", url)))?,
        );
        self.ensure_host_allowed(&host)?;

        if !self.cfg.allow_cross_host_redirects && host != initial_host {
            return Err(Error::ConfigError(format!(
                "Remote extends redirect changed host ({} -> {}), which is not allowed",
                initial_host, host
            )));
        }

        let port = url.port_or_known_default().ok_or_else(|| {
            Error::ConfigError(format!("Remote extends URL missing port: {}", url))
        })?;

        let mut addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
            vec![SocketAddr::new(ip, port)]
        } else {
            (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|e| Error::ConfigError(format!("Failed to resolve host {}: {}", host, e)))?
                .collect()
        };

        if !self.cfg.allow_private_ips {
            addrs.retain(|addr| is_public_ip(addr.ip()));
            if addrs.is_empty() {
                return Err(Error::ConfigError(format!(
                    "Remote extends host resolved to non-public IPs (blocked): {}",
                    host
                )));
            }
        }

        Ok((host, addrs))
    }

    fn resolve_http(&self, reference: &str, base: Option<&str>) -> Result<ResolvedPolicySource> {
        if !self.cfg.remote_enabled() {
            return Err(Error::ConfigError(
                "Remote extends are disabled (no allowlisted hosts)".to_string(),
            ));
        }

        let (path_or_url, expected_sha) = split_sha256_pin(reference)?;
        let url = match base {
            Some(base_url) => join_url(base_url, path_or_url)?,
            None => path_or_url.to_string(),
        };

        let parsed = parse_remote_url(&url, self.cfg.https_only).map_err(Error::ConfigError)?;
        let host = parsed.host_str().ok_or_else(|| {
            Error::ConfigError(format!("Invalid URL host in remote extends: {}", parsed))
        })?;
        self.ensure_host_allowed(host)?;

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
        if !self.cfg.remote_enabled() {
            return Err(Error::ConfigError(
                "Remote extends are disabled (no allowlisted hosts)".to_string(),
            ));
        }

        const MAX_REDIRECTS: usize = 5;

        let mut current = parse_remote_url(url, self.cfg.https_only).map_err(Error::ConfigError)?;
        current.set_fragment(None);

        let initial_host = current
            .host_str()
            .ok_or_else(|| Error::ConfigError(format!("Invalid URL host: {}", current)))?
            .to_string();
        let initial_host = normalize_host(&initial_host);

        for _ in 0..=MAX_REDIRECTS {
            let (host, addrs) = self.validate_and_resolve_http_target(&current, &initial_host)?;
            let client =
                build_pinned_blocking_http_client(host.clone(), addrs, self.cfg.https_only)?;

            let resp = client
                .get(current.clone())
                .send()
                .map_err(|e| Error::ConfigError(format!("Failed to fetch remote policy: {}", e)))?;

            if resp.status().is_redirection() {
                let location = resp
                    .headers()
                    .get(LOCATION)
                    .and_then(|v| v.to_str().ok())
                    .ok_or_else(|| {
                        Error::ConfigError(format!(
                            "Remote policy redirect missing Location header: {}",
                            current
                        ))
                    })?;

                let mut next = current
                    .join(location)
                    .map_err(|e| Error::ConfigError(format!("Invalid redirect URL: {}", e)))?;

                // Fragments are never sent to servers; drop to keep keys consistent.
                next.set_fragment(None);

                let next = parse_remote_url(next.as_str(), self.cfg.https_only)
                    .map_err(Error::ConfigError)?;

                current = next;
                continue;
            }

            if !resp.status().is_success() {
                return Err(Error::ConfigError(format!(
                    "Failed to fetch remote policy: HTTP {}",
                    resp.status()
                )));
            }

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
            limited.read_to_end(&mut bytes).map_err(Error::IoError)?;
            if bytes.len() > self.cfg.max_fetch_bytes {
                return Err(Error::ConfigError(format!(
                    "Remote policy exceeds max_fetch_bytes ({} > {})",
                    bytes.len(),
                    self.cfg.max_fetch_bytes
                )));
            }
            return Ok(bytes);
        }

        Err(Error::ConfigError(format!(
            "Remote policy exceeded max redirects (>{})",
            MAX_REDIRECTS
        )))
    }

    fn resolve_git_absolute(&self, reference: &str) -> Result<ResolvedPolicySource> {
        if !self.cfg.remote_enabled() {
            return Err(Error::ConfigError(
                "Remote extends are disabled (no allowlisted hosts)".to_string(),
            ));
        }

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

        if let Ok(repo_url) = Url::parse(repo) {
            if matches!(repo_url.scheme(), "http" | "https") {
                let host = repo_url.host_str().ok_or_else(|| {
                    Error::ConfigError(format!("Invalid URL host in remote extends: {}", repo))
                })?;
                self.ensure_host_allowed(host)?;
            }
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
        return Err(Error::ConfigError(
            "Remote extends reference is empty".to_string(),
        ));
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

fn parse_remote_url(url: &str, https_only: bool) -> std::result::Result<Url, String> {
    let parsed =
        Url::parse(url).map_err(|e| format!("Invalid URL in remote extends: {url}: {e}"))?;

    let scheme = parsed.scheme();
    if scheme != "http" && scheme != "https" {
        return Err(format!(
            "Unsupported URL scheme for remote extends: {}",
            parsed.scheme()
        ));
    }
    if https_only && scheme != "https" {
        return Err(format!(
            "Remote extends require https:// URLs (got {}://)",
            parsed.scheme()
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("Remote extends URLs must not include userinfo".to_string());
    }
    if parsed.host_str().is_none() {
        return Err(format!("Invalid URL host in remote extends: {}", parsed));
    }

    Ok(parsed)
}

fn join_url(base: &str, reference: &str) -> Result<String> {
    if reference.starts_with("http://") || reference.starts_with("https://") {
        return Ok(reference.to_string());
    }

    let base = Url::parse(base).map_err(|e| {
        Error::ConfigError(format!(
            "Invalid base URL for remote extends: {} ({})",
            base, e
        ))
    })?;
    let joined = base.join(reference).map_err(|e| {
        Error::ConfigError(format!(
            "Invalid relative URL in remote extends: base={} reference={} ({})",
            base, reference, e
        ))
    })?;
    Ok(joined.to_string())
}

fn build_pinned_blocking_http_client(
    host: String,
    addrs: Vec<SocketAddr>,
    https_only: bool,
) -> Result<Client> {
    use reqwest::redirect::Policy;

    let build = move || {
        Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .redirect(Policy::none())
            .no_proxy()
            .https_only(https_only)
            .resolve_to_addrs(&host, &addrs)
            .build()
            .map_err(|e| Error::ConfigError(format!("Failed to build HTTP client: {}", e)))
    };

    // reqwest::blocking spins up its own runtime; initializing that runtime from within an async
    // Tokio context can panic. If we appear to be inside a Tokio runtime, build the blocking client
    // in a fresh OS thread.
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::spawn(build).join().unwrap_or_else(|_| {
            Err(Error::ConfigError(
                "Failed to build HTTP client".to_string(),
            ))
        })
    } else {
        build()
    }
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_ipv4(v4.octets()),
        IpAddr::V6(v6) => is_public_ipv6(v6.segments()),
    }
}

fn is_public_ipv4(octets: [u8; 4]) -> bool {
    let [a, b, c, d] = octets;

    // 0.0.0.0/8 (this host / "current network")
    if a == 0 {
        return false;
    }

    // 10.0.0.0/8
    if a == 10 {
        return false;
    }

    // 100.64.0.0/10 (CGNAT)
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }

    // 127.0.0.0/8 (loopback)
    if a == 127 {
        return false;
    }

    // 169.254.0.0/16 (link-local)
    if a == 169 && b == 254 {
        return false;
    }

    // 172.16.0.0/12
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }

    // 192.168.0.0/16
    if a == 192 && b == 168 {
        return false;
    }

    // Documentation / benchmarking blocks:
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 (TEST-NETs)
    if (a == 192 && b == 0 && c == 2)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
    {
        return false;
    }

    // 198.18.0.0/15 (benchmarking)
    if a == 198 && (18..=19).contains(&b) {
        return false;
    }

    // Multicast 224.0.0.0/4 and reserved 240.0.0.0/4
    if a >= 224 {
        return false;
    }

    // Broadcast (255.255.255.255)
    if a == 255 && b == 255 && c == 255 && d == 255 {
        return false;
    }

    true
}

fn is_public_ipv6(segments: [u16; 8]) -> bool {
    let [s0, s1, s2, s3, _s4, _s5, _s6, _s7] = segments;

    // ::/128 (unspecified)
    if segments == [0, 0, 0, 0, 0, 0, 0, 0] {
        return false;
    }

    // ::1/128 (loopback)
    if segments == [0, 0, 0, 0, 0, 0, 0, 1] {
        return false;
    }

    // fc00::/7 (unique local)
    if (s0 & 0xfe00) == 0xfc00 {
        return false;
    }

    // fe80::/10 (link-local unicast)
    if (s0 & 0xffc0) == 0xfe80 {
        return false;
    }

    // ff00::/8 (multicast)
    if (s0 & 0xff00) == 0xff00 {
        return false;
    }

    // 2001:db8::/32 (documentation)
    if s0 == 0x2001 && s1 == 0x0db8 {
        return false;
    }

    // 100::/64 (discard-only)
    if s0 == 0x0100 && s1 == 0 && s2 == 0 && s3 == 0 {
        return false;
    }

    // Otherwise treat as public (global unicast). This is intentionally conservative: we block
    // the most common private/special ranges to reduce SSRF/DNS rebinding risk.
    true
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    fn spawn_server_on<F>(
        bind_addr: &str,
        handler: F,
    ) -> (
        u16,
        Arc<AtomicUsize>,
        Arc<AtomicBool>,
        thread::JoinHandle<()>,
    )
    where
        F: Fn(&mut std::net::TcpStream) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind(bind_addr).expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        listener.set_nonblocking(true).expect("set_nonblocking");

        let calls = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let calls_thread = calls.clone();
        let stop_thread = stop.clone();
        let handler = Arc::new(handler);

        let handle = thread::spawn(move || {
            while !stop_thread.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        calls_thread.fetch_add(1, Ordering::Relaxed);
                        handler(&mut stream);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });

        (port, calls, stop, handle)
    }

    fn spawn_server<F>(
        handler: F,
    ) -> (
        u16,
        Arc<AtomicUsize>,
        Arc<AtomicBool>,
        thread::JoinHandle<()>,
    )
    where
        F: Fn(&mut std::net::TcpStream) + Send + Sync + 'static,
    {
        spawn_server_on("127.0.0.1:0", handler)
    }

    #[test]
    fn redirect_to_disallowed_host_is_rejected() {
        let (b_port, b_calls, b_stop, b_handle) = spawn_server(|stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let body = b"ok\n";
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(body);
        });

        let redirect_target = format!("http://localhost:{}/policy.yaml", b_port);
        let (a_port, _a_calls, a_stop, a_handle) = spawn_server(move |stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                redirect_target
            );
            let _ = stream.write_all(resp.as_bytes());
        });

        let cache_dir = std::env::temp_dir().join(format!(
            "hushd-remote-extends-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");

        let cfg = RemoteExtendsResolverConfig {
            allowed_hosts: ["127.0.0.1".to_string()].into_iter().collect(),
            cache_dir: cache_dir.clone(),
            https_only: false,
            allow_private_ips: true,
            allow_cross_host_redirects: true,
            max_fetch_bytes: 1024 * 1024,
            max_cache_bytes: 1024 * 1024,
        };
        let resolver = RemotePolicyResolver::new(cfg).expect("create resolver");

        let reference = format!(
            "http://127.0.0.1:{}/policy.yaml#sha256={}",
            a_port,
            "0".repeat(64)
        );
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("redirect to disallowed host should fail");
        assert!(
            err.to_string().contains("allowlisted"),
            "expected allowlist failure, got: {err}"
        );

        thread::sleep(Duration::from_millis(100));
        assert_eq!(b_calls.load(Ordering::Relaxed), 0);

        a_stop.store(true, Ordering::Relaxed);
        b_stop.store(true, Ordering::Relaxed);
        let _ = a_handle.join();
        let _ = b_handle.join();

        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn https_only_rejects_http_urls() {
        let cache_dir = std::env::temp_dir().join(format!(
            "hushd-remote-extends-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");

        let cfg = RemoteExtendsResolverConfig {
            allowed_hosts: ["127.0.0.1".to_string()].into_iter().collect(),
            cache_dir: cache_dir.clone(),
            https_only: true,
            allow_private_ips: true,
            allow_cross_host_redirects: false,
            max_fetch_bytes: 1024 * 1024,
            max_cache_bytes: 1024 * 1024,
        };
        let resolver = RemotePolicyResolver::new(cfg).expect("create resolver");

        let reference = format!("http://127.0.0.1:1/policy.yaml#sha256={}", "0".repeat(64));
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("http should be rejected when https_only=true");
        assert!(
            err.to_string().contains("require https://"),
            "expected https-only rejection, got: {err}"
        );

        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn private_ip_resolution_is_blocked_by_default() {
        let cache_dir = std::env::temp_dir().join(format!(
            "hushd-remote-extends-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");

        let cfg = RemoteExtendsResolverConfig {
            allowed_hosts: ["127.0.0.1".to_string()].into_iter().collect(),
            cache_dir: cache_dir.clone(),
            https_only: false,
            allow_private_ips: false,
            allow_cross_host_redirects: false,
            max_fetch_bytes: 1024 * 1024,
            max_cache_bytes: 1024 * 1024,
        };
        let resolver = RemotePolicyResolver::new(cfg).expect("create resolver");

        let reference = format!("http://127.0.0.1:1/policy.yaml#sha256={}", "0".repeat(64));
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("private IPs should be rejected by default");
        assert!(
            err.to_string().contains("non-public IPs"),
            "expected private-IP rejection, got: {err}"
        );

        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn allow_private_ips_allows_fetching_localhost() {
        let (port, _calls, stop, handle) = spawn_server(|stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let body = b"ok\n";
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(body);
        });

        let cache_dir = std::env::temp_dir().join(format!(
            "hushd-remote-extends-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");

        let cfg = RemoteExtendsResolverConfig {
            allowed_hosts: ["127.0.0.1".to_string()].into_iter().collect(),
            cache_dir: cache_dir.clone(),
            https_only: false,
            allow_private_ips: true,
            allow_cross_host_redirects: false,
            max_fetch_bytes: 1024 * 1024,
            max_cache_bytes: 1024 * 1024,
        };
        let resolver = RemotePolicyResolver::new(cfg).expect("create resolver");

        let expected_sha = sha256(b"ok\n").to_hex();
        let reference = format!(
            "http://127.0.0.1:{}/policy.yaml#sha256={}",
            port, expected_sha
        );
        let resolved = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect("fetch should succeed when private IPs are allowed");
        assert_eq!(resolved.yaml, "ok\n");

        stop.store(true, Ordering::Relaxed);
        let _ = handle.join();
        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn cross_host_redirects_are_blocked_by_default() {
        let (b_port, b_calls, b_stop, b_handle) = spawn_server_on("[::1]:0", |stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let body = b"ok\n";
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(body);
        });

        let redirect_target = format!("http://[::1]:{}/policy.yaml", b_port);
        let (a_port, _a_calls, a_stop, a_handle) = spawn_server(move |stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                redirect_target
            );
            let _ = stream.write_all(resp.as_bytes());
        });

        let cache_dir = std::env::temp_dir().join(format!(
            "hushd-remote-extends-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");

        let cfg = RemoteExtendsResolverConfig {
            allowed_hosts: ["127.0.0.1".to_string(), "::1".to_string()]
                .into_iter()
                .collect(),
            cache_dir: cache_dir.clone(),
            https_only: false,
            allow_private_ips: true,
            allow_cross_host_redirects: false,
            max_fetch_bytes: 1024 * 1024,
            max_cache_bytes: 1024 * 1024,
        };
        let resolver = RemotePolicyResolver::new(cfg).expect("create resolver");

        let reference = format!(
            "http://127.0.0.1:{}/policy.yaml#sha256={}",
            a_port,
            "0".repeat(64)
        );
        let err = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect_err("cross-host redirect should be rejected by default");
        assert!(
            err.to_string().contains("redirect changed host"),
            "expected cross-host redirect rejection, got: {err}"
        );

        thread::sleep(Duration::from_millis(100));
        assert_eq!(
            b_calls.load(Ordering::Relaxed),
            0,
            "redirect target should not be contacted"
        );

        a_stop.store(true, Ordering::Relaxed);
        b_stop.store(true, Ordering::Relaxed);
        let _ = a_handle.join();
        let _ = b_handle.join();

        let _ = std::fs::remove_dir_all(&cache_dir);
    }

    #[test]
    fn allow_cross_host_redirects_allows_redirect_to_allowlisted_host() {
        let (b_port, _b_calls, b_stop, b_handle) = spawn_server_on("[::1]:0", |stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let body = b"ok\n";
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(body);
        });

        let redirect_target = format!("http://[::1]:{}/policy.yaml", b_port);
        let (a_port, _a_calls, a_stop, a_handle) = spawn_server(move |stream| {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf);

            let resp = format!(
                "HTTP/1.1 302 Found\r\nLocation: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                redirect_target
            );
            let _ = stream.write_all(resp.as_bytes());
        });

        let cache_dir = std::env::temp_dir().join(format!(
            "hushd-remote-extends-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&cache_dir).expect("create cache dir");

        let cfg = RemoteExtendsResolverConfig {
            allowed_hosts: ["127.0.0.1".to_string(), "::1".to_string()]
                .into_iter()
                .collect(),
            cache_dir: cache_dir.clone(),
            https_only: false,
            allow_private_ips: true,
            allow_cross_host_redirects: true,
            max_fetch_bytes: 1024 * 1024,
            max_cache_bytes: 1024 * 1024,
        };
        let resolver = RemotePolicyResolver::new(cfg).expect("create resolver");

        let expected_sha = sha256(b"ok\n").to_hex();
        let reference = format!(
            "http://127.0.0.1:{}/policy.yaml#sha256={}",
            a_port, expected_sha
        );
        let resolved = resolver
            .resolve(&reference, &PolicyLocation::None)
            .expect("cross-host redirect should succeed when enabled and allowlisted");
        assert_eq!(resolved.yaml, "ok\n");

        a_stop.store(true, Ordering::Relaxed);
        b_stop.store(true, Ordering::Relaxed);
        let _ = a_handle.join();
        let _ = b_handle.join();

        let _ = std::fs::remove_dir_all(&cache_dir);
    }
}
