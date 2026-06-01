//! Honey artifact construction and safe materialization helpers.
//!
//! These build deterministic deception artifacts (and match observations
//! against them) without ever writing outside a relative, sanitized path.

#![allow(dead_code)]

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, Result};
use serde::Serialize;

use super::{
    ev, stable_id, CredentialKind, DetectionEvidence, EndpointEvent, EndpointObservation,
    HoneyArtifact, HoneyArtifactKind,
};

fn observed_path(observation: &EndpointObservation) -> Option<&str> {
    match &observation.event {
        EndpointEvent::FileAccess { path, .. }
        | EndpointEvent::DylibLoad { path, .. }
        | EndpointEvent::LaunchPersistence { path, .. }
        | EndpointEvent::BrowserExtensionInstall { path, .. }
        | EndpointEvent::BrowserDownload { path, .. } => Some(path),
        EndpointEvent::CredentialAccess { path, .. } => path.as_deref(),
        _ => None,
    }
}

pub(crate) fn honey_artifact_match_evidence(
    artifact: &HoneyArtifact,
    observation: &EndpointObservation,
) -> Option<Vec<DetectionEvidence>> {
    let mut evidence = vec![
        ev("artifactId", &artifact.artifact_id),
        ev("artifactKind", artifact.kind.as_str()),
        ev("artifactPath", artifact.relative_path.display().to_string()),
    ];

    if let Some(accessed_path) = observed_path(observation) {
        if artifact.matches_path(accessed_path) {
            evidence.push(ev("matchType", "path"));
            evidence.push(ev("observedPath", accessed_path));
            return Some(evidence);
        }
    }

    if let EndpointEvent::NetworkFlow { host, url, .. } = &observation.event {
        if artifact.matches_network_destination(host, url.as_deref()) {
            evidence.push(ev("matchType", "network_destination"));
            evidence.push(ev("observedHost", host));
            if let Some(url) = url {
                evidence.push(ev("observedUrl", url));
            }
            if let Some(honey_host) = artifact.internal_hostname() {
                evidence.push(ev("honeyHost", honey_host));
            }
            return Some(evidence);
        }
    }

    if let EndpointEvent::DnsLookup { query, answers, .. } = &observation.event {
        if artifact.matches_network_destination(query, None)
            || answers
                .iter()
                .any(|answer| artifact.matches_network_destination(answer, None))
        {
            evidence.push(ev("matchType", "dns_query"));
            evidence.push(ev("observedQuery", query));
            if !answers.is_empty() {
                evidence.push(ev("observedAnswers", answers.join(",")));
            }
            if let Some(honey_host) = artifact.internal_hostname() {
                evidence.push(ev("honeyHost", honey_host));
            }
            return Some(evidence);
        }
    }

    if let EndpointEvent::CredentialAccess { kind, name, .. } = &observation.event {
        if *kind == CredentialKind::BrowserCookie
            && artifact.matches_browser_cookie_access(name.as_deref())
        {
            evidence.push(ev("matchType", "browser_cookie"));
            if let Some(name) = name {
                evidence.push(ev("credentialName", name));
            }
            return Some(evidence);
        }
    }

    if observation_contains_marker(observation, &artifact.marker) {
        evidence.push(ev("matchType", "marker"));
        return Some(evidence);
    }

    None
}

fn observation_contains_marker(observation: &EndpointObservation, marker: &str) -> bool {
    if marker.is_empty() {
        return false;
    }
    match &observation.event {
        EndpointEvent::FileAccess {
            content_preview: Some(content),
            ..
        } if content.contains(marker) => true,
        _ => {
            serialized_contains_marker(&observation.event, marker)
                || serialized_contains_marker(&observation.metadata, marker)
        }
    }
}

fn serialized_contains_marker<T: Serialize>(value: &T, marker: &str) -> bool {
    serde_json::to_string(value)
        .map(|value| value.contains(marker))
        .unwrap_or(false)
}

pub(crate) fn honey_artifact(
    endpoint_id: &str,
    kind: HoneyArtifactKind,
    relative_path: &str,
) -> HoneyArtifact {
    let artifact_id = stable_id("honey", [endpoint_id, kind.as_str(), relative_path]);
    let marker = format!("clawdstrike-honey-{artifact_id}");
    let contents = honey_contents(&kind, endpoint_id, &marker);
    HoneyArtifact {
        artifact_id,
        kind,
        relative_path: PathBuf::from(relative_path),
        marker,
        contents,
        permissions_octal: 0o600,
        tags: vec!["deception".to_string(), "endpoint".to_string()],
    }
}

fn honey_contents(kind: &HoneyArtifactKind, endpoint_id: &str, marker: &str) -> String {
    match kind {
        HoneyArtifactKind::SshPrivateKey => format!(
            "# honey ssh key for endpoint {endpoint_id}\n# marker: {marker}\n-----BEGIN OPENSSH PRIVATE KEY-----\n{marker}\n-----END OPENSSH PRIVATE KEY-----\n"
        ),
        HoneyArtifactKind::ApiTokenFile => {
            format!("CLAWDSTRIKE_PROD_API_TOKEN=cs_live_{marker}\n")
        }
        HoneyArtifactKind::CloudCredentials => format!(
            "[prod]\naws_access_key_id = AKIA{marker}\naws_secret_access_key = {marker}\naws_session_token = {marker}\n"
        ),
        HoneyArtifactKind::PackageRegistryToken => {
            format!("//registry.npmjs.org/:_authToken=npm_{marker}\n")
        }
        HoneyArtifactKind::BrowserCookieJar => format!(
            "{{\"cookies\":[{{\"domain\":\"intranet.invalid\",\"name\":\"session\",\"value\":\"{marker}\"}}]}}\n"
        ),
        HoneyArtifactKind::InternalHostname => {
            format!("prod-admin-{endpoint_id}.corp.invalid # {marker}\n")
        }
    }
}

pub(crate) fn ensure_safe_relative_path(path: &Path) -> Result<()> {
    if path.is_absolute() {
        return Err(anyhow!(
            "honey artifact path must be relative: {}",
            path.display()
        ));
    }
    for component in path.components() {
        if matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        ) {
            return Err(anyhow!(
                "honey artifact path contains unsafe component: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn create_new_honey_file(path: &Path, artifact: &HoneyArtifact) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(artifact.contents.as_bytes())?;
    set_file_permissions(path, artifact.permissions_octal)
}

#[cfg(unix)]
fn set_file_permissions(path: &Path, permissions_octal: u32) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(permissions_octal))
}

#[cfg(not(unix))]
fn set_file_permissions(_path: &Path, _permissions_octal: u32) -> std::io::Result<()> {
    Ok(())
}
