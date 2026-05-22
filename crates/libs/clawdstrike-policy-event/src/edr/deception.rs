use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::event::{EndpointEvent, EndpointObservation};
use super::{
    create_new_honey_file, ensure_safe_relative_path, honey_artifact, hostname_from_url_like,
    normalize_hostname, normalize_path_string, stable_id,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoneyArtifactKind {
    SshPrivateKey,
    ApiTokenFile,
    CloudCredentials,
    PackageRegistryToken,
    BrowserCookieJar,
    InternalHostname,
}

impl HoneyArtifactKind {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SshPrivateKey => "ssh_private_key",
            Self::ApiTokenFile => "api_token_file",
            Self::CloudCredentials => "cloud_credentials",
            Self::PackageRegistryToken => "package_registry_token",
            Self::BrowserCookieJar => "browser_cookie_jar",
            Self::InternalHostname => "internal_hostname",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HoneyArtifact {
    pub artifact_id: String,
    pub kind: HoneyArtifactKind,
    pub relative_path: PathBuf,
    pub marker: String,
    pub contents: String,
    pub permissions_octal: u32,
    pub tags: Vec<String>,
}

impl HoneyArtifact {
    #[must_use]
    pub fn absolute_path(&self, root: &Path) -> PathBuf {
        root.join(&self.relative_path)
    }

    #[must_use]
    pub fn matches_path(&self, path: &str) -> bool {
        let observed = normalize_path_string(path);
        let relative = normalize_path_string(&self.relative_path.display().to_string());
        observed == relative || observed.ends_with(&format!("/{relative}"))
    }

    #[must_use]
    pub fn internal_hostname(&self) -> Option<&str> {
        if self.kind != HoneyArtifactKind::InternalHostname {
            return None;
        }
        self.contents
            .lines()
            .flat_map(str::split_whitespace)
            .find(|token| token.contains('.') && !token.starts_with('#'))
    }

    #[must_use]
    pub fn matches_network_destination(&self, host: &str, url: Option<&str>) -> bool {
        let Some(honey_host) = self.internal_hostname() else {
            return false;
        };
        let honey_host = normalize_hostname(honey_host);
        if honey_host.is_empty() {
            return false;
        }

        normalize_hostname(host) == honey_host
            || url
                .and_then(hostname_from_url_like)
                .map(|url_host| url_host == honey_host)
                .unwrap_or(false)
    }

    #[must_use]
    pub fn browser_cookie_indicators(&self) -> Vec<String> {
        if self.kind != HoneyArtifactKind::BrowserCookieJar {
            return Vec::new();
        }

        let mut indicators = vec![self.marker.clone()];
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(&self.contents) {
            if let Some(cookies) = value.get("cookies").and_then(serde_json::Value::as_array) {
                for cookie in cookies {
                    let domain = cookie
                        .get("domain")
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.trim().is_empty());
                    let name = cookie
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.trim().is_empty());
                    let value = cookie
                        .get("value")
                        .and_then(serde_json::Value::as_str)
                        .filter(|value| !value.trim().is_empty());

                    if let Some(value) = value {
                        indicators.push(value.to_string());
                    }
                    if let Some(domain) = domain {
                        indicators.push(domain.to_string());
                    }
                    if let (Some(domain), Some(name)) = (domain, name) {
                        indicators.push(format!("{domain}/{name}"));
                    }
                    if let (Some(name), Some(value)) = (name, value) {
                        indicators.push(format!("{name}={value}"));
                    }
                }
            }
        }

        indicators.sort();
        indicators.dedup();
        indicators
    }

    #[must_use]
    pub fn matches_browser_cookie_access(&self, name: Option<&str>) -> bool {
        let Some(name) = name else {
            return false;
        };
        let observed = name.to_ascii_lowercase();
        self.browser_cookie_indicators()
            .into_iter()
            .map(|indicator| indicator.to_ascii_lowercase())
            .filter(|indicator| !indicator.is_empty())
            .any(|indicator| observed.contains(&indicator))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeceptionPlan {
    pub root: PathBuf,
    pub endpoint_id: String,
    pub artifacts: Vec<HoneyArtifact>,
}

impl DeceptionPlan {
    #[must_use]
    pub fn standard(root: impl Into<PathBuf>, endpoint_id: impl Into<String>) -> Self {
        let root = root.into();
        let endpoint_id = endpoint_id.into();
        let artifact_specs = [
            (HoneyArtifactKind::SshPrivateKey, ".ssh/id_prod_ed25519"),
            (
                HoneyArtifactKind::ApiTokenFile,
                ".config/clawdstrike/tokens/prod-api-token.txt",
            ),
            (HoneyArtifactKind::CloudCredentials, ".aws/credentials"),
            (HoneyArtifactKind::PackageRegistryToken, ".npmrc"),
            (
                HoneyArtifactKind::BrowserCookieJar,
                "Library/Application Support/ClawdStrike/Honey/Cookies.json",
            ),
            (
                HoneyArtifactKind::InternalHostname,
                ".config/clawdstrike/internal-hosts.txt",
            ),
        ];

        let artifacts = artifact_specs
            .into_iter()
            .map(|(kind, relative_path)| honey_artifact(&endpoint_id, kind, relative_path))
            .collect();

        Self {
            root,
            endpoint_id,
            artifacts,
        }
    }

    pub fn materialize(&self) -> Result<DeceptionMaterializationReport> {
        let mut created = Vec::new();
        let mut skipped = Vec::new();

        for artifact in &self.artifacts {
            ensure_safe_relative_path(&artifact.relative_path)?;
            let path = artifact.absolute_path(&self.root);
            let Some(parent) = path.parent() else {
                return Err(anyhow!(
                    "honey artifact path has no parent: {}",
                    path.display()
                ));
            };
            fs::create_dir_all(parent)
                .with_context(|| format!("create honey artifact directory {}", parent.display()))?;

            match create_new_honey_file(&path, artifact) {
                Ok(()) => created.push(path.display().to_string()),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    if existing_honey_file_matches(&path, artifact)? {
                        skipped.push(path.display().to_string());
                    } else {
                        return Err(anyhow!(
                            "refusing to materialize honey artifact over pre-existing non-honey path: {}",
                            path.display()
                        ));
                    }
                }
                Err(err) => {
                    return Err(err)
                        .with_context(|| format!("create honey artifact {}", path.display()));
                }
            }
        }

        Ok(DeceptionMaterializationReport { created, skipped })
    }
}

fn existing_honey_file_matches(path: &Path, artifact: &HoneyArtifact) -> Result<bool> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect existing honey artifact {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Ok(false);
    }

    let contents = fs::read(path)
        .with_context(|| format!("read existing honey artifact {}", path.display()))?;
    if contents != artifact.contents.as_bytes() {
        return Ok(false);
    }

    honey_file_permissions_match(&metadata, artifact.permissions_octal)
}

#[cfg(unix)]
fn honey_file_permissions_match(metadata: &fs::Metadata, permissions_octal: u32) -> Result<bool> {
    use std::os::unix::fs::PermissionsExt;

    Ok(metadata.permissions().mode() & 0o777 == permissions_octal & 0o777)
}

#[cfg(not(unix))]
fn honey_file_permissions_match(_metadata: &fs::Metadata, _permissions_octal: u32) -> Result<bool> {
    Ok(true)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeceptionMaterializationReport {
    pub created: Vec<String>,
    pub skipped: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeceptionCleanupReport {
    pub dry_run: bool,
    pub removed: Vec<String>,
    pub would_remove: Vec<String>,
    pub missing: Vec<String>,
    pub refused: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeceptionRotationReport {
    pub dry_run: bool,
    pub cleanup: DeceptionCleanupReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub materialization: Option<DeceptionMaterializationReport>,
    pub deregistered_artifact_count: usize,
    pub registered_artifact_count: usize,
    pub remaining_registered_artifact_count: usize,
}
