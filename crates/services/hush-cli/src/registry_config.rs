//! Registry configuration: URL, auth tokens, and publisher key paths.
//!
//! Configuration is layered:
//!   1. Defaults (`http://localhost:3100`)
//!   2. `~/.clawdstrike/config.toml` `[registry]` section
//!   3. `~/.clawdstrike/credentials.toml` (auth token)
//!   4. Environment variables (`CLAWDSTRIKE_REGISTRY_URL`, `CLAWDSTRIKE_AUTH_TOKEN`)
//!   5. CLI flag `--registry <url>` (highest priority)

use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const DEFAULT_REGISTRY_URL: &str = "http://localhost:3100";

/// Registry configuration resolved from config files, env vars, and CLI flags.
#[derive(Clone, Debug)]
pub struct RegistryConfig {
    pub registry_url: String,
    pub auth_token: Option<String>,
    pub publisher_key_path: Option<PathBuf>,
    /// Optional pinned Ed25519 public key hex for registry signature trust.
    pub registry_public_key: Option<String>,
}

/// Deserialization shape for `~/.clawdstrike/config.toml`.
#[derive(Deserialize, Default)]
struct ConfigFile {
    #[serde(default)]
    registry: RegistrySection,
}

#[derive(Deserialize, Default)]
struct RegistrySection {
    url: Option<String>,
    publisher_key: Option<PathBuf>,
    public_key: Option<String>,
}

/// Deserialization shape for `~/.clawdstrike/credentials.toml`.
#[derive(Serialize, Deserialize, Default)]
struct CredentialsFile {
    #[serde(default)]
    registry: CredentialsSection,
}

#[derive(Serialize, Deserialize, Default)]
struct CredentialsSection {
    auth_token: Option<String>,
}

impl RegistryConfig {
    /// Load configuration from disk and environment.
    ///
    /// `cli_registry` is the optional `--registry` flag value, which overrides everything.
    pub fn load(cli_registry: Option<&str>) -> Self {
        let clawdstrike_dir = clawdstrike_home();

        // -- Layer 1: defaults --
        let mut url = DEFAULT_REGISTRY_URL.to_string();
        let mut auth_token: Option<String> = None;
        let mut publisher_key_path: Option<PathBuf> = None;
        let mut registry_public_key: Option<String> = None;

        // -- Layer 2: config.toml --
        if let Some(ref dir) = clawdstrike_dir {
            let config_path = dir.join("config.toml");
            if let Ok(contents) = std::fs::read_to_string(&config_path) {
                if let Ok(cfg) = toml::from_str::<ConfigFile>(&contents) {
                    if let Some(u) = cfg.registry.url {
                        url = u;
                    }
                    if let Some(k) = cfg.registry.publisher_key {
                        publisher_key_path = Some(k);
                    }
                    if let Some(k) = cfg.registry.public_key {
                        registry_public_key = Some(k);
                    }
                }
            }
        }

        // -- Layer 3: credentials.toml --
        if let Some(ref dir) = clawdstrike_dir {
            let creds_path = dir.join("credentials.toml");
            if let Ok(contents) = std::fs::read_to_string(&creds_path) {
                if let Ok(creds) = toml::from_str::<CredentialsFile>(&contents) {
                    auth_token = creds.registry.auth_token;
                }
            }
        }

        // Default publisher key path if not overridden
        if publisher_key_path.is_none() {
            if let Some(ref dir) = clawdstrike_dir {
                let default_key = dir.join("keys").join("publisher.key");
                if default_key.exists() {
                    publisher_key_path = Some(default_key);
                }
            }
        }

        // -- Layer 4: env vars --
        if let Ok(env_url) = std::env::var("CLAWDSTRIKE_REGISTRY_URL") {
            if !env_url.is_empty() {
                url = env_url;
            }
        }
        if let Ok(env_token) = std::env::var("CLAWDSTRIKE_AUTH_TOKEN") {
            if !env_token.is_empty() {
                auth_token = Some(env_token);
            }
        }
        if let Ok(env_registry_key) = std::env::var("CLAWDSTRIKE_REGISTRY_PUBLIC_KEY") {
            if !env_registry_key.is_empty() {
                registry_public_key = Some(env_registry_key);
            }
        }

        // -- Layer 5: CLI flag --
        if let Some(cli_url) = cli_registry {
            url = cli_url.to_string();
        }

        Self {
            registry_url: url,
            auth_token,
            publisher_key_path,
            registry_public_key,
        }
    }

    /// Load from a TOML string (for testing).
    #[cfg(test)]
    pub fn from_toml_str(config_toml: &str, creds_toml: &str) -> Self {
        let mut url = DEFAULT_REGISTRY_URL.to_string();
        let mut auth_token: Option<String> = None;
        let mut publisher_key_path: Option<PathBuf> = None;
        let mut registry_public_key: Option<String> = None;

        if let Ok(cfg) = toml::from_str::<ConfigFile>(config_toml) {
            if let Some(u) = cfg.registry.url {
                url = u;
            }
            if let Some(k) = cfg.registry.publisher_key {
                publisher_key_path = Some(k);
            }
            if let Some(k) = cfg.registry.public_key {
                registry_public_key = Some(k);
            }
        }

        if let Ok(creds) = toml::from_str::<CredentialsFile>(creds_toml) {
            auth_token = creds.registry.auth_token;
        }

        Self {
            registry_url: url,
            auth_token,
            publisher_key_path,
            registry_public_key,
        }
    }
}

/// Return `~/.clawdstrike/` if determinable.
pub fn clawdstrike_home() -> Option<PathBuf> {
    dirs::home_dir().map(|h| h.join(".clawdstrike"))
}

/// Write an auth token to `~/.clawdstrike/credentials.toml`.
///
/// Currently unused — will be called when the `/api/v1/auth/register` endpoint
/// is added in a future phase.
#[allow(dead_code)]
pub fn save_credentials(token: &str) -> std::io::Result<()> {
    let dir = clawdstrike_home().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "cannot determine home directory",
        )
    })?;
    std::fs::create_dir_all(&dir)?;

    let creds = CredentialsFile {
        registry: CredentialsSection {
            auth_token: Some(token.to_string()),
        },
    };
    let toml_str = toml::to_string_pretty(&creds)
        .map_err(|e| std::io::Error::other(format!("failed to serialize credentials: {e}")))?;
    std::fs::write(dir.join("credentials.toml"), toml_str)
}

/// Read a publisher keypair from the configured key path (or the default path),
/// generating a new one if it does not exist. Returns the loaded [`hush_core::Keypair`].
pub fn load_or_generate_publisher_keypair(
    config: &RegistryConfig,
    stderr: &mut dyn Write,
) -> Result<hush_core::Keypair, String> {
    let dir = clawdstrike_home().ok_or("cannot determine home directory")?;

    // Use override path from config if set, otherwise default location
    let (priv_path, pub_path) = if let Some(ref key_path) = config.publisher_key_path {
        let pub_path = key_path.with_extension("pub");
        (key_path.clone(), pub_path)
    } else {
        let keys_dir = dir.join("keys");
        (
            keys_dir.join("publisher.key"),
            keys_dir.join("publisher.pub"),
        )
    };

    if priv_path.exists() {
        let hex_seed = std::fs::read_to_string(&priv_path)
            .map_err(|e| format!("cannot read {}: {e}", priv_path.display()))?;
        let keypair = hush_core::Keypair::from_hex(hex_seed.trim())
            .map_err(|e| format!("invalid publisher key: {e}"))?;
        return Ok(keypair);
    }

    // Generate new keypair
    let _ = writeln!(stderr, "Generating new publisher keypair...");
    if let Some(parent) = priv_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }

    let keypair = hush_core::Keypair::generate();
    std::fs::write(&priv_path, keypair.to_hex())
        .map_err(|e| format!("cannot write {}: {e}", priv_path.display()))?;
    std::fs::write(&pub_path, keypair.public_key().to_hex())
        .map_err(|e| format!("cannot write {}: {e}", pub_path.display()))?;

    // Best-effort: restrict permissions on private key (Unix only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&priv_path, std::fs::Permissions::from_mode(0o600));
    }

    Ok(keypair)
}

/// Heuristic: is the given string a local file path (vs. a registry package name)?
pub fn is_file_source(source: &str) -> bool {
    source.ends_with(".cpkg")
        || source.starts_with('/')
        || source.starts_with("./")
        || source.starts_with("../")
        || (source.contains('/') && !source.starts_with('@'))
        || Path::new(source)
            .extension()
            .is_some_and(|ext| ext == "cpkg")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_defaults() {
        let cfg = RegistryConfig::from_toml_str("", "");
        assert_eq!(cfg.registry_url, DEFAULT_REGISTRY_URL);
        assert!(cfg.auth_token.is_none());
        assert!(cfg.publisher_key_path.is_none());
        assert!(cfg.registry_public_key.is_none());
    }

    #[test]
    fn test_load_config_toml() {
        let config = r#"
[registry]
url = "https://registry.example.com"
publisher_key = "/tmp/my.key"
public_key = "abababababababababababababababababababababababababababababababab"
"#;
        let cfg = RegistryConfig::from_toml_str(config, "");
        assert_eq!(cfg.registry_url, "https://registry.example.com");
        assert_eq!(cfg.publisher_key_path, Some(PathBuf::from("/tmp/my.key")));
        assert_eq!(
            cfg.registry_public_key.as_deref(),
            Some("abababababababababababababababababababababababababababababababab")
        );
    }

    #[test]
    fn test_load_credentials_toml() {
        let creds = r#"
[registry]
auth_token = "tok_abc123"
"#;
        let cfg = RegistryConfig::from_toml_str("", creds);
        assert_eq!(cfg.auth_token.as_deref(), Some("tok_abc123"));
    }

    #[test]
    fn test_cli_registry_overrides() {
        let cfg = RegistryConfig::load(Some("https://override.example.com"));
        assert_eq!(cfg.registry_url, "https://override.example.com");
    }

    #[test]
    fn test_save_and_read_credentials() {
        let tmp = tempfile::tempdir().unwrap();
        let fake_home = tmp.path().to_path_buf();
        let creds_dir = fake_home.join(".clawdstrike");
        std::fs::create_dir_all(&creds_dir).unwrap();

        let creds_path = creds_dir.join("credentials.toml");
        let creds = super::CredentialsFile {
            registry: super::CredentialsSection {
                auth_token: Some("my-token".to_string()),
            },
        };
        let toml_str = toml::to_string_pretty(&creds).unwrap();
        std::fs::write(&creds_path, &toml_str).unwrap();

        let read_back = std::fs::read_to_string(&creds_path).unwrap();
        let parsed: super::CredentialsFile = toml::from_str(&read_back).unwrap();
        assert_eq!(parsed.registry.auth_token.as_deref(), Some("my-token"));
    }

    #[test]
    fn test_source_detection_file_vs_name() {
        // File paths: end with .cpkg or contain path separators
        assert!(is_file_source("/tmp/my-pkg.cpkg"));
        assert!(is_file_source("./local-pkg.cpkg"));
        assert!(is_file_source("packages/foo.cpkg"));

        // Package names: no extension, no path separators
        assert!(!is_file_source("@acme/my-guard"));
        assert!(!is_file_source("my-guard"));
        assert!(!is_file_source("@scope/name"));
    }

    /// Helper used by tests and by install command to distinguish file paths from package names.
    fn is_file_source(source: &str) -> bool {
        super::is_file_source(source)
    }
}
