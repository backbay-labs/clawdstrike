//! Miscellaneous helpers used across api_server route handlers.

use super::*;
use axum::http::header::COOKIE;
use axum::http::{uri::Authority, HeaderMap, Uri};
use hush_core::sha256;
use serde_json::Value;
use std::collections::BTreeSet;

pub(crate) fn local_stable_id<'a>(
    prefix: &str,
    parts: impl IntoIterator<Item = &'a str>,
) -> String {
    let mut material = String::from(prefix);
    for part in parts {
        material.push('\0');
        material.push_str(part);
    }
    let hash = sha256(material.as_bytes()).to_hex_prefixed();
    let fragment = hash
        .trim_start_matches("0x")
        .chars()
        .take(32)
        .collect::<String>();
    format!("{prefix}-{fragment}")
}

pub(crate) fn node_attribute_string(
    attributes: &std::collections::BTreeMap<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    attributes
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

pub(crate) fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

pub(crate) fn query_value(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn is_local_host_header(headers: &HeaderMap) -> bool {
    let Some(host) = headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
    else {
        return false;
    };

    let host_only = host
        .parse::<Authority>()
        .map(|authority| authority.host().to_ascii_lowercase())
        .unwrap_or_else(|_| host.to_ascii_lowercase());
    let host_only = host_only
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_string();

    host_only == "localhost" || host_only == "127.0.0.1" || host_only == "::1"
}

pub(crate) fn has_query_param(uri: &Uri, param_name: &str) -> bool {
    let Some(query) = uri.query() else {
        return false;
    };

    query.split('&').any(|pair| {
        if pair.is_empty() {
            return false;
        }
        let (name, _) = pair.split_once('=').unwrap_or((pair, ""));
        name == param_name
    })
}

pub(crate) fn query_param(uri: &Uri, param_name: &str) -> Option<String> {
    let query = uri.query()?;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if name == param_name {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return None;
            }
            return Some(trimmed.to_string());
        }
    }
    None
}

pub(crate) fn sanitize_ui_next_path(candidate: Option<&str>) -> String {
    let raw = candidate.unwrap_or("/ui").trim();
    if raw.is_empty() {
        return "/ui".to_string();
    }
    if raw.contains('\n') || raw.contains('\r') {
        return "/ui".to_string();
    }
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return "/ui".to_string();
    }
    if !raw.starts_with("/ui") {
        return "/ui".to_string();
    }
    raw.to_string()
}

pub(crate) fn normalize_bootstrap_code(raw: &str) -> Option<String> {
    let normalized: String = raw
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if normalized.len() != 8 {
        return None;
    }
    Some(normalized)
}

pub(crate) fn generate_ui_bootstrap_code() -> (String, String) {
    let random = uuid::Uuid::new_v4()
        .simple()
        .to_string()
        .to_ascii_uppercase();
    let normalized = random.chars().take(8).collect::<String>();
    let display = format!("{}-{}", &normalized[..4], &normalized[4..]);
    (normalized, display)
}

pub(crate) fn is_valid_bootstrap_session_id(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate.len() <= 64
        && candidate
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

pub(crate) fn auth_token_from_cookie(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers.get(COOKIE)?.to_str().ok()?;
    for cookie in cookie_header.split(';') {
        let Some((name, value)) = cookie.trim().split_once('=') else {
            continue;
        };
        if name.trim() == AGENT_AUTH_COOKIE_NAME {
            let token = value.trim();
            if !token.is_empty() {
                return Some(token.to_string());
            }
        }
    }
    None
}

pub(crate) fn truncate_delivery_error(message: &str) -> String {
    const MAX_LEN: usize = 240;
    if message.chars().count() <= MAX_LEN {
        return message.to_string();
    }
    let mut out = message
        .chars()
        .take(MAX_LEN.saturating_sub(3))
        .collect::<String>();
    out.push_str("...");
    out
}

pub(crate) fn trim_tail_lines(content: &str, lines: usize) -> String {
    if lines == 0 {
        return String::new();
    }
    let mut collected = content.lines().rev().take(lines).collect::<Vec<_>>();
    collected.reverse();
    collected.join("\n")
}

pub(crate) fn redact_settings_json(raw: &mut Value) {
    let Some(obj) = raw.as_object_mut() else {
        return;
    };

    for key in [
        "api_key",
        "token",
        "nkey_seed",
        "enrollment_token",
        "secret",
    ] {
        if let Some(value) = obj.get_mut(key) {
            *value = Value::String("[REDACTED]".to_string());
        }
    }

    if let Some(integrations) = obj.get_mut("integrations").and_then(Value::as_object_mut) {
        if let Some(siem) = integrations.get_mut("siem").and_then(Value::as_object_mut) {
            if let Some(value) = siem.get_mut("api_key") {
                *value = Value::String("[REDACTED]".to_string());
            }
        }
        if let Some(webhooks) = integrations
            .get_mut("webhooks")
            .and_then(Value::as_object_mut)
        {
            if let Some(value) = webhooks.get_mut("secret") {
                *value = Value::String("[REDACTED]".to_string());
            }
        }
    }

    if let Some(control_api) = obj.get_mut("control_api").and_then(Value::as_object_mut) {
        if let Some(value) = control_api.get_mut("api_key") {
            *value = Value::String("[REDACTED]".to_string());
        }
    }

    if let Some(nats) = obj.get_mut("nats").and_then(Value::as_object_mut) {
        for key in ["token", "nkey_seed", "creds_file"] {
            if let Some(value) = nats.get_mut(key) {
                *value = Value::String("[REDACTED]".to_string());
            }
        }
    }
}

pub(crate) fn rule_id_fragment(value: &str) -> String {
    let mut fragment = value
        .chars()
        .take(64)
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '_'
            }
        })
        .collect::<String>();
    while fragment.contains("__") {
        fragment = fragment.replace("__", "_");
    }
    let fragment = fragment.trim_matches('_').to_string();
    if fragment.is_empty() {
        "root".to_string()
    } else {
        fragment
    }
}

pub(crate) fn detection_stage_names(stage_plan: &[EdrDetectionCandidateStage]) -> String {
    stage_plan
        .iter()
        .map(|candidate| candidate.stage.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

pub(crate) fn agent_secret_touch_publish_keys(
    credential_node_id: &str,
    graph: &clawdstrike_policy_event::edr::CausalGraph,
    observation_ids: Option<&BTreeSet<&str>>,
) -> BTreeSet<String> {
    use clawdstrike_policy_event::edr::{CausalEdgeKind, CausalNodeKind};
    let Some(credential_node) = graph.nodes.get(credential_node_id) else {
        return BTreeSet::new();
    };
    if credential_node.kind != CausalNodeKind::Credential {
        return BTreeSet::new();
    }
    graph
        .edges
        .iter()
        .filter(|edge| {
            edge.kind == CausalEdgeKind::AccessedCredential
                && edge.to == credential_node_id
                && observation_ids
                    .map(|ids| ids.contains(edge.observation_id.as_str()))
                    .unwrap_or(true)
        })
        .map(|edge| format!("{}|{}", credential_node_id, edge.observation_id))
        .collect()
}

pub(crate) fn is_credential_access_observation(
    observation: &clawdstrike_policy_event::edr::EndpointObservation,
) -> bool {
    use clawdstrike_policy_event::edr::EndpointEvent;
    matches!(&observation.event, EndpointEvent::CredentialAccess { .. })
}

pub(crate) fn credential_node_matches_observation_credential(
    node: &clawdstrike_policy_event::edr::CausalNode,
    observation: &clawdstrike_policy_event::edr::EndpointObservation,
) -> bool {
    use clawdstrike_policy_event::edr::EndpointEvent;
    let EndpointEvent::CredentialAccess { kind, path, name } = &observation.event else {
        return false;
    };
    let node_kind = node_attribute_string(&node.attributes, "credentialKind")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if node_kind != kind.as_str() {
        return false;
    }
    if let Some(path) = path.as_deref() {
        return node_attribute_string(&node.attributes, "path").as_deref() == Some(path)
            || node.label == path;
    }
    if let Some(name) = name.as_deref() {
        return node_attribute_string(&node.attributes, "name").as_deref() == Some(name)
            || node.label == name;
    }
    true
}

pub(crate) fn first_graph_attribute(
    graph: &clawdstrike_policy_event::edr::CausalGraph,
    key: &str,
) -> Option<String> {
    graph
        .nodes
        .values()
        .find_map(|node| node_attribute_string(&node.attributes, key))
}

pub(crate) fn graph_context_has_attribute(
    context: &clawdstrike_policy_event::edr::CausalGraph,
    key: &str,
    expected: &str,
) -> bool {
    context
        .nodes
        .values()
        .any(|node| node_attribute_string(&node.attributes, key).as_deref() == Some(expected))
        || context
            .edges
            .iter()
            .any(|edge| node_attribute_string(&edge.attributes, key).as_deref() == Some(expected))
}

pub(crate) fn graph_agent_context(
    context: &clawdstrike_policy_event::edr::CausalGraph,
) -> (Vec<String>, Vec<String>) {
    use clawdstrike_policy_event::edr::CausalNodeKind;
    let mut node_ids = BTreeSet::new();
    let mut labels = BTreeSet::new();
    for node in context.nodes.values() {
        if node.kind == CausalNodeKind::Tool {
            node_ids.insert(node.node_id.clone());
            labels.insert(node.label.clone());
            continue;
        }
        if node.kind == CausalNodeKind::Process {
            if let Some(agent_id) = node_attribute_string(&node.attributes, "agentId") {
                node_ids.insert(node.node_id.clone());
                labels.insert(agent_id);
            }
        }
    }
    (node_ids.into_iter().collect(), labels.into_iter().collect())
}

pub(crate) fn causal_node_kind_name(
    kind: &clawdstrike_policy_event::edr::CausalNodeKind,
) -> &'static str {
    use clawdstrike_policy_event::edr::CausalNodeKind;
    match kind {
        CausalNodeKind::Host => "host",
        CausalNodeKind::User => "user",
        CausalNodeKind::Session => "session",
        CausalNodeKind::Agent => "agent",
        CausalNodeKind::Workload => "workload",
        CausalNodeKind::Approval => "approval",
        CausalNodeKind::Process => "process",
        CausalNodeKind::File => "file",
        CausalNodeKind::Network => "network",
        CausalNodeKind::DnsName => "dns_name",
        CausalNodeKind::PackageScript => "package_script",
        CausalNodeKind::Credential => "credential",
        CausalNodeKind::BrowserDownload => "browser_download",
        CausalNodeKind::BrowserExtension => "browser_extension",
        CausalNodeKind::PolicyDecision => "policy_decision",
        CausalNodeKind::Tool => "tool",
        CausalNodeKind::DeceptionArtifact => "deception_artifact",
        CausalNodeKind::Other => "other",
    }
}
