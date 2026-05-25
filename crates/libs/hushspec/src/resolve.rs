use crate::{HushSpec, merge};
use std::fs;
use std::path::{Path, PathBuf};

/// A loaded HushSpec document plus its canonical source identifier.
#[derive(Clone, Debug)]
pub struct LoadedSpec {
    pub source: String,
    pub spec: HushSpec,
}

/// Errors raised while resolving `extends`.
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("failed to read HushSpec document at {path}: {message}")]
    Read { path: String, message: String },
    #[error("failed to parse HushSpec document at {path}: {message}")]
    Parse { path: String, message: String },
    #[error("circular extends detected: {chain}")]
    Cycle { chain: String },
    #[error("{message}")]
    Http { message: String },
    #[error("could not resolve reference '{reference}': {message}")]
    NotFound { reference: String, message: String },
}

/// Embedded built-in ruleset YAML strings.
pub fn load_builtin(name: &str) -> Option<&'static str> {
    match name {
        "default" | "builtin:default" => Some(include_str!("../rulesets/default.yaml")),
        "strict" | "builtin:strict" => Some(include_str!("../rulesets/strict.yaml")),
        "permissive" | "builtin:permissive" => Some(include_str!("../rulesets/permissive.yaml")),
        "ai-agent" | "builtin:ai-agent" => Some(include_str!("../rulesets/ai-agent.yaml")),
        "cicd" | "builtin:cicd" => Some(include_str!("../rulesets/cicd.yaml")),
        "remote-desktop" | "builtin:remote-desktop" => {
            Some(include_str!("../rulesets/remote-desktop.yaml"))
        }
        _ => None,
    }
}

pub const BUILTIN_NAMES: &[&str] = &[
    "default",
    "strict",
    "permissive",
    "ai-agent",
    "cicd",
    "remote-desktop",
];

fn try_load_builtin(reference: &str) -> Option<Result<LoadedSpec, ResolveError>> {
    let yaml = load_builtin(reference)?;
    let source = if reference.starts_with("builtin:") {
        reference.to_string()
    } else {
        format!("builtin:{reference}")
    };
    Some(
        HushSpec::parse(yaml)
            .map(|spec| LoadedSpec { source, spec })
            .map_err(|error| ResolveError::Parse {
                path: reference.to_string(),
                message: error.to_string(),
            }),
    )
}

#[cfg(feature = "http")]
pub mod http {
    use super::*;
    use std::io::Read as _;
    use std::net::IpAddr;

    #[derive(Clone, Debug)]
    pub struct HttpLoaderConfig {
        pub timeout_ms: u64,
        pub max_size: usize,
        pub verify_tls: bool,
        pub auth_header: Option<String>,
        pub cache_dir: Option<PathBuf>,
    }

    impl Default for HttpLoaderConfig {
        fn default() -> Self {
            Self {
                timeout_ms: 10_000,
                max_size: 1_048_576, // 1 MB
                verify_tls: true,
                auth_header: None,
                cache_dir: None,
            }
        }
    }

    fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback()          // 127.0.0.0/8
                    || v4.is_private()     // 10/8, 172.16/12, 192.168/16
                    || v4.is_link_local()  // 169.254/16
                    || v4.is_unspecified() // 0.0.0.0
            }
            IpAddr::V6(v6) => {
                v6.is_loopback()          // ::1
                    || v6.is_unspecified() // ::
                    || v6.is_unique_local() // fc00::/7
                    || v6.is_unicast_link_local() // fe80::/10
                    // IPv4-mapped addresses
                    || v6.to_ipv4_mapped().is_some_and(|v4| {
                        v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
                    })
            }
        }
    }

    /// SSRF protection: require HTTPS and reject private IPs.
    fn validate_url(url_str: &str) -> Result<url::Url, ResolveError> {
        let parsed = url::Url::parse(url_str).map_err(|e| ResolveError::Http {
            message: format!("invalid URL '{url_str}': {e}"),
        })?;

        if parsed.scheme() != "https" {
            return Err(ResolveError::Http {
                message: format!("only HTTPS URLs are allowed, got '{}'", parsed.scheme()),
            });
        }

        let host = parsed.host_str().ok_or_else(|| ResolveError::Http {
            message: format!("URL '{url_str}' has no host"),
        })?;

        let addrs: Vec<std::net::SocketAddr> =
            std::net::ToSocketAddrs::to_socket_addrs(&(host, 443))
                .map_err(|e| ResolveError::Http {
                    message: format!("failed to resolve host '{host}': {e}"),
                })?
                .collect();

        if addrs.is_empty() {
            return Err(ResolveError::Http {
                message: format!("host '{host}' did not resolve to any addresses"),
            });
        }

        for addr in &addrs {
            if is_private_ip(&addr.ip()) {
                return Err(ResolveError::Http {
                    message: format!(
                        "SSRF protection: host '{host}' resolves to private IP {}",
                        addr.ip()
                    ),
                });
            }
        }

        Ok(parsed)
    }

    #[derive(serde::Serialize, serde::Deserialize)]
    struct CacheEntry {
        etag: String,
        url: String,
    }

    fn cache_key(url: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        url.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    fn read_cache(cache_dir: &Path, url: &str) -> Option<(String, String)> {
        let key = cache_key(url);
        let meta_path = cache_dir.join(format!("{key}.meta.json"));
        let body_path = cache_dir.join(format!("{key}.yaml"));

        let meta_content = fs::read_to_string(&meta_path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&meta_content).ok()?;
        if entry.url != url {
            return None;
        }
        let body = fs::read_to_string(&body_path).ok()?;
        Some((entry.etag, body))
    }

    fn write_cache(
        cache_dir: &Path,
        url: &str,
        etag: &str,
        body: &str,
    ) -> Result<(), std::io::Error> {
        fs::create_dir_all(cache_dir)?;
        let key = cache_key(url);
        let entry = CacheEntry {
            etag: etag.to_string(),
            url: url.to_string(),
        };
        fs::write(
            cache_dir.join(format!("{key}.meta.json")),
            serde_json::to_string(&entry).unwrap(),
        )?;
        fs::write(cache_dir.join(format!("{key}.yaml")), body)?;
        Ok(())
    }

    /// Fetch a HushSpec document over HTTPS.
    ///
    /// Enforces HTTPS-only, SSRF protection, timeout, and max body size.
    /// Supports ETag-based caching when `config.cache_dir` is set.
    pub fn load_from_https(
        url_str: &str,
        config: &HttpLoaderConfig,
    ) -> Result<LoadedSpec, ResolveError> {
        let _validated_url = validate_url(url_str)?;

        let timeout = std::time::Duration::from_millis(config.timeout_ms);
        let client = reqwest::blocking::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(!config.verify_tls)
            .build()
            .map_err(|e| ResolveError::Http {
                message: format!("failed to build HTTP client: {e}"),
            })?;

        let mut request = client.get(url_str);

        if let Some(ref auth) = config.auth_header {
            request = request.header("Authorization", auth);
        }

        let cached = config
            .cache_dir
            .as_ref()
            .and_then(|dir| read_cache(dir, url_str));

        if let Some((ref etag, _)) = cached {
            request = request.header("If-None-Match", etag.as_str());
        }

        let response = request.send().map_err(|e| ResolveError::Http {
            message: format!("HTTP request to '{url_str}' failed: {e}"),
        })?;

        let status = response.status();

        if status == reqwest::StatusCode::NOT_MODIFIED
            && let Some((_, ref body)) = cached
        {
            let spec = HushSpec::parse(body).map_err(|e| ResolveError::Parse {
                path: url_str.to_string(),
                message: e.to_string(),
            })?;
            return Ok(LoadedSpec {
                source: url_str.to_string(),
                spec,
            });
        }

        if !status.is_success() {
            return Err(ResolveError::Http {
                message: format!("HTTP request to '{url_str}' returned status {status}"),
            });
        }

        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let mut body = Vec::new();
        let mut reader = response.take(config.max_size as u64 + 1);
        reader
            .read_to_end(&mut body)
            .map_err(|e| ResolveError::Http {
                message: format!("failed to read response from '{url_str}': {e}"),
            })?;

        if body.len() > config.max_size {
            return Err(ResolveError::Http {
                message: format!(
                    "response from '{url_str}' exceeds maximum size of {} bytes",
                    config.max_size
                ),
            });
        }

        let body_str = String::from_utf8(body).map_err(|e| ResolveError::Http {
            message: format!("response from '{url_str}' is not valid UTF-8: {e}"),
        })?;

        if let (Some(etag_val), Some(cache_dir)) = (&etag, &config.cache_dir) {
            let _ = write_cache(cache_dir, url_str, etag_val, &body_str);
        }

        let spec = HushSpec::parse(&body_str).map_err(|e| ResolveError::Parse {
            path: url_str.to_string(),
            message: e.to_string(),
        })?;

        Ok(LoadedSpec {
            source: url_str.to_string(),
            spec,
        })
    }

    /// Create a composite loader that chains: builtin -> file -> HTTPS.
    ///
    /// Reference dispatch:
    /// - `builtin:*` or bare names matching a builtin -> builtin loader
    /// - `https://` -> HTTP loader
    /// - everything else -> filesystem loader
    pub fn create_default_loader(
        config: HttpLoaderConfig,
    ) -> impl Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError> {
        move |reference: &str, from: Option<&str>| -> Result<LoadedSpec, ResolveError> {
            // 1. Explicit builtin prefix
            if reference.starts_with("builtin:") {
                return match try_load_builtin(reference) {
                    Some(result) => result,
                    None => Err(ResolveError::NotFound {
                        reference: reference.to_string(),
                        message: "unknown builtin ruleset".to_string(),
                    }),
                };
            }

            if reference.starts_with("https://") {
                return load_from_https(reference, &config);
            }

            if reference.starts_with("http://") {
                return Err(ResolveError::Http {
                    message: "only HTTPS URLs are allowed, got 'http'".to_string(),
                });
            }

            if !reference.contains('/')
                && !reference.contains('\\')
                && !reference.contains('.')
                && let Some(result) = try_load_builtin(reference)
            {
                return result;
            }

            load_from_filesystem(reference, from)
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn rejects_http_urls() {
            let result = validate_url("http://example.com/policy.yaml");
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("only HTTPS URLs are allowed"));
        }

        #[test]
        fn rejects_private_ips_localhost() {
            let result = validate_url("https://127.0.0.1/policy.yaml");
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("SSRF protection") || msg.contains("private IP"));
        }

        #[test]
        fn rejects_private_ips_10_network() {
            let result = validate_url("https://10.0.0.1/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_private_ips_172_network() {
            let result = validate_url("https://172.16.0.1/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_private_ips_192_168_network() {
            let result = validate_url("https://192.168.1.1/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv6_loopback() {
            let result = validate_url("https://[::1]/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv6_unique_local() {
            let result = validate_url("https://[fc00::1]/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn rejects_ipv6_link_local() {
            let result = validate_url("https://[fe80::1]/policy.yaml");
            assert!(result.is_err());
        }

        #[test]
        fn accepts_valid_https_url() {
            // This test requires network access so we just validate the URL
            // parsing without actually connecting.
            let parsed = url::Url::parse("https://example.com/policy.yaml");
            assert!(parsed.is_ok());
            let url = parsed.unwrap();
            assert_eq!(url.scheme(), "https");
        }

        #[test]
        fn http_loader_rejects_plain_http() {
            let config = HttpLoaderConfig::default();
            let loader = create_default_loader(config);
            let result = loader("http://example.com/policy.yaml", None);
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(msg.contains("only HTTPS URLs are allowed"));
        }

        #[test]
        fn is_private_ip_checks() {
            use std::net::{Ipv4Addr, Ipv6Addr};

            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::LOCALHOST)));
            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::LOCALHOST)));
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0xfc00, 0, 0, 0, 0, 0, 0, 1
            ))));
            assert!(is_private_ip(&IpAddr::V6(Ipv6Addr::new(
                0xfe80, 0, 0, 0, 0, 0, 0, 1
            ))));
            assert!(is_private_ip(&IpAddr::V4(Ipv4Addr::UNSPECIFIED)));

            assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
            assert!(!is_private_ip(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        }

        #[test]
        fn etag_cache_round_trip() {
            let dir = std::env::temp_dir().join(format!(
                "hushspec-cache-test-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));

            let url = "https://example.com/test-policy.yaml";
            let etag = "\"abc123\"";
            let body = "hushspec: \"0.1.0\"\nname: cached\n";

            write_cache(&dir, url, etag, body).unwrap();

            let (cached_etag, cached_body) = read_cache(&dir, url).unwrap();
            assert_eq!(cached_etag, etag);
            assert_eq!(cached_body, body);

            assert!(read_cache(&dir, "https://other.com/policy.yaml").is_none());

            fs::remove_dir_all(&dir).unwrap();
        }
    }
}

/// Create a composite loader that chains: builtin -> file.
///
/// Reference dispatch:
/// - `builtin:*` or bare names matching a builtin -> builtin loader
/// - everything else -> filesystem loader
///
/// When the `http` feature is enabled, use
/// [`http::create_default_loader`] instead for HTTPS support.
pub fn create_composite_loader() -> impl Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>
{
    move |reference: &str, from: Option<&str>| -> Result<LoadedSpec, ResolveError> {
        if reference.starts_with("builtin:") {
            return match try_load_builtin(reference) {
                Some(result) => result,
                None => Err(ResolveError::NotFound {
                    reference: reference.to_string(),
                    message: "unknown builtin ruleset".to_string(),
                }),
            };
        }

        if reference.starts_with("https://") || reference.starts_with("http://") {
            return Err(ResolveError::Http {
                message: "HTTP-based policy loading requires the 'http' feature".to_string(),
            });
        }

        if !reference.contains('/')
            && !reference.contains('\\')
            && !reference.contains('.')
            && let Some(result) = try_load_builtin(reference)
        {
            return result;
        }

        load_from_filesystem(reference, from)
    }
}

/// Resolve a parsed spec using a caller-provided loader.
pub fn resolve_with_loader<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
{
    let mut stack = Vec::new();
    if let Some(source) = source {
        stack.push(source.to_string());
    }
    resolve_inner(spec, source, loader, &mut stack)
}

pub fn resolve_from_path(path: impl AsRef<Path>) -> Result<HushSpec, ResolveError> {
    let path = canonical_path(path.as_ref())?;
    let spec = load_spec_from_file(&path)?;
    resolve_with_loader(&spec, Some(&path.to_string_lossy()), &load_from_filesystem)
}

/// Resolve a HushSpec document using the composite loader (builtin + file).
///
/// This supports `extends: builtin:default` in addition to filesystem paths.
pub fn resolve_from_path_with_builtins(path: impl AsRef<Path>) -> Result<HushSpec, ResolveError> {
    let path = canonical_path(path.as_ref())?;
    let spec = load_spec_from_file(&path)?;
    let loader = create_composite_loader();
    resolve_with_loader(&spec, Some(&path.to_string_lossy()), &loader)
}

fn resolve_inner<F>(
    spec: &HushSpec,
    source: Option<&str>,
    loader: &F,
    stack: &mut Vec<String>,
) -> Result<HushSpec, ResolveError>
where
    F: Fn(&str, Option<&str>) -> Result<LoadedSpec, ResolveError>,
{
    let Some(reference) = spec.extends.as_deref() else {
        return Ok(spec.clone());
    };

    let loaded = loader(reference, source)?;
    if let Some(index) = stack.iter().position(|entry| entry == &loaded.source) {
        let mut cycle = stack[index..].to_vec();
        cycle.push(loaded.source);
        return Err(ResolveError::Cycle {
            chain: cycle.join(" -> "),
        });
    }

    stack.push(loaded.source.clone());
    let resolved_parent = resolve_inner(&loaded.spec, Some(&loaded.source), loader, stack)?;
    stack.pop();
    Ok(merge(&resolved_parent, spec))
}

fn load_from_filesystem(reference: &str, from: Option<&str>) -> Result<LoadedSpec, ResolveError> {
    let path = resolve_reference_path(reference, from);
    let canonical = canonical_path(&path)?;
    let spec = load_spec_from_file(&canonical)?;
    Ok(LoadedSpec {
        source: canonical.to_string_lossy().into_owned(),
        spec,
    })
}

fn resolve_reference_path(reference: &str, from: Option<&str>) -> PathBuf {
    let candidate = PathBuf::from(reference);
    if candidate.is_absolute() {
        return candidate;
    }

    match from
        .map(PathBuf::from)
        .and_then(|path| path.parent().map(Path::to_path_buf))
    {
        Some(parent) => parent.join(candidate),
        None => candidate,
    }
}

fn canonical_path(path: &Path) -> Result<PathBuf, ResolveError> {
    fs::canonicalize(path).map_err(|error| ResolveError::Read {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

fn load_spec_from_file(path: &Path) -> Result<HushSpec, ResolveError> {
    let content = fs::read_to_string(path).map_err(|error| ResolveError::Read {
        path: path.display().to_string(),
        message: error.to_string(),
    })?;
    HushSpec::parse(&content).map_err(|error| ResolveError::Parse {
        path: path.display().to_string(),
        message: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_loader_resolves_all_rulesets() {
        for name in BUILTIN_NAMES {
            let yaml = load_builtin(name);
            assert!(yaml.is_some(), "builtin '{name}' should exist");
            let spec = HushSpec::parse(yaml.unwrap());
            assert!(spec.is_ok(), "builtin '{name}' should parse: {spec:?}");
        }
    }

    #[test]
    fn builtin_loader_with_prefix() {
        for name in BUILTIN_NAMES {
            let prefixed = format!("builtin:{name}");
            let yaml = load_builtin(&prefixed);
            assert!(yaml.is_some(), "builtin '{prefixed}' should exist");
        }
    }

    #[test]
    fn builtin_loader_returns_none_for_unknown() {
        assert!(load_builtin("nonexistent").is_none());
        assert!(load_builtin("builtin:nonexistent").is_none());
    }

    #[test]
    fn try_load_builtin_returns_loaded_spec() {
        let result = try_load_builtin("builtin:default");
        assert!(result.is_some());
        let loaded = result.unwrap().unwrap();
        assert_eq!(loaded.source, "builtin:default");
        assert_eq!(loaded.spec.name.as_deref(), Some("default"));
    }

    #[test]
    fn try_load_builtin_bare_name() {
        let result = try_load_builtin("strict");
        assert!(result.is_some());
        let loaded = result.unwrap().unwrap();
        assert_eq!(loaded.source, "builtin:strict");
        assert_eq!(loaded.spec.name.as_deref(), Some("strict"));
    }

    #[test]
    fn composite_loader_resolves_builtins() {
        let loader = create_composite_loader();
        let loaded = loader("builtin:default", None).unwrap();
        assert_eq!(loaded.source, "builtin:default");
        assert_eq!(loaded.spec.name.as_deref(), Some("default"));
    }

    #[test]
    fn composite_loader_resolves_bare_builtin_names() {
        let loader = create_composite_loader();
        // "default" has no dots, slashes, or backslashes, so should be
        // tried as a builtin first.
        let loaded = loader("default", None).unwrap();
        assert_eq!(loaded.source, "builtin:default");
    }

    #[test]
    fn extends_builtin_default_end_to_end() {
        let child = HushSpec::parse(
            r#"
hushspec: "0.1.0"
extends: builtin:default
name: my-policy
rules:
  egress:
    allow: [custom.example.com]
    default: allow
"#,
        )
        .unwrap();

        let loader = create_composite_loader();
        let resolved = resolve_with_loader(&child, Some("memory://child"), &loader).unwrap();

        assert!(resolved.extends.is_none());
        assert_eq!(resolved.name.as_deref(), Some("my-policy"));
        let rules = resolved.rules.as_ref().unwrap();
        assert!(rules.forbidden_paths.is_some());
        let egress = rules.egress.as_ref().unwrap();
        assert!(egress.allow.contains(&"custom.example.com".to_string()));
    }

    #[test]
    fn composite_loader_rejects_http_without_feature() {
        let loader = create_composite_loader();
        let result = loader("https://example.com/policy.yaml", None);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("http") || msg.contains("HTTP"));
    }
}
