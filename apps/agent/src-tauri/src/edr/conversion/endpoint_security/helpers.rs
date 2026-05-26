//! Small helpers for EndpointSecurity conversion: command-line formatting,
//! file-operation parsing, credential-kind classification, decision
//! normalization, and bad-request shaping.

use crate::api_server::{non_empty, trimmed_owned};
use crate::edr::dto::EdrEndpointSecurityEvent;
use axum::http::StatusCode;
use clawdstrike_policy_event::edr::{CredentialKind, FileOperation};

pub(crate) fn endpoint_security_command_line(image: &str, args: &[String]) -> String {
    if args.is_empty() {
        image.to_string()
    } else {
        format!("{image} {}", args.join(" "))
    }
}

pub(crate) fn endpoint_security_file_operation(value: Option<&str>) -> Option<FileOperation> {
    match value
        .and_then(|value| non_empty(Some(value)))
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("read" | "open" | "auth_open") => Some(FileOperation::Read),
        Some("write") => Some(FileOperation::Write),
        Some("create") => Some(FileOperation::Create),
        Some("delete" | "unlink") => Some(FileOperation::Delete),
        Some("rename" | "move") => Some(FileOperation::Rename),
        Some("execute" | "exec") => Some(FileOperation::Execute),
        Some("chmod") => Some(FileOperation::Chmod),
        _ => None,
    }
}

pub(crate) fn endpoint_security_credential_kind_for_path(path: &str) -> Option<CredentialKind> {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    let basename = path.rsplit('/').next().unwrap_or(path.as_str());

    if path.contains("/.ssh/") || matches!(basename, "id_rsa" | "id_ed25519" | "id_ecdsa") {
        return Some(CredentialKind::SshKey);
    }

    if path.contains("/.aws/")
        || path.contains("/.config/gcloud/")
        || path.contains("/.azure/")
        || path.contains("/.kube/config")
        || path.contains("/.pulumi/credentials.json")
        || path.contains("/.config/pulumi/credentials.json")
        || path.contains("/.terraform.d/credentials.tfrc.json")
        || path.contains("/.terraformrc")
    {
        return Some(CredentialKind::CloudCredential);
    }

    if path.contains("/.npmrc")
        || path.contains("/.pypirc")
        || path.contains("/.netrc")
        || path.contains("/.docker/config.json")
        || path.contains("/.cargo/credentials")
        || path.contains("/.config/pypoetry/auth.toml")
        || path.contains("/library/application support/pypoetry/auth.toml")
        || path.contains("/.config/pip/pip.conf")
        || path.contains("/.pip/pip.conf")
        || path.contains("/pip/pip.ini")
        || path.contains("/.yarnrc.yml")
        || path.contains("/.pnpmrc")
        || path.contains("/.m2/settings.xml")
        || path.contains("/.gradle/gradle.properties")
        || path.contains("/.nuget/nuget/nuget.config")
    {
        return Some(CredentialKind::PackageRegistryToken);
    }

    if path.contains("/.config/gh/hosts.yml")
        || path.contains("/.config/gh/config.yml")
        || path.contains("/.config/glab-cli/hosts.yml")
        || path.contains("/.config/glab-cli/config.yml")
        || path.contains("/.config/hub")
        || path.contains("/.config/git-credential/")
    {
        return Some(CredentialKind::ApiToken);
    }

    if path.contains("/.gnupg/private-keys-v1.d/")
        || path.contains("/.gnupg/secring.gpg")
        || path.contains("/.config/sops/age/keys.txt")
        || path.contains("/.age/key.txt")
    {
        return Some(CredentialKind::SigningKey);
    }

    if basename == "cookies"
        || basename == "login data"
        || basename == "local state"
        || path.contains("/keychains/")
    {
        return Some(CredentialKind::BrowserCookie);
    }

    None
}

pub(crate) fn normalized_endpoint_security_decision(value: Option<&str>) -> Option<&'static str> {
    match value
        .and_then(|value| non_empty(Some(value)))
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("allow" | "allowed" | "permit" | "permitted") => Some("allowed"),
        Some("deny" | "denied" | "block" | "blocked") => Some("blocked"),
        _ => None,
    }
}

pub(crate) fn required_endpoint_security_event_string(
    event: &EdrEndpointSecurityEvent,
    field: &str,
    value: Option<&str>,
) -> Result<String, (StatusCode, String)> {
    trimmed_owned(value).ok_or_else(|| {
        bad_endpoint_security_event_request(
            event,
            &format!(
                "{field} is required for EndpointSecurity {} events",
                event.kind.as_str()
            ),
        )
    })
}

pub(crate) fn bad_endpoint_security_event_request(
    event: &EdrEndpointSecurityEvent,
    message: &str,
) -> (StatusCode, String) {
    let event_id = event
        .event_id
        .as_deref()
        .and_then(|value| non_empty(Some(value)))
        .unwrap_or("unknown");
    (
        StatusCode::BAD_REQUEST,
        format!("invalid EndpointSecurity event {event_id}: {message}"),
    )
}
