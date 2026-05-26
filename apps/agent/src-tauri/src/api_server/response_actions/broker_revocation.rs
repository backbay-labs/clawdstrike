//! Broker capability and local integration secret revocation.
//!
//! Maps causal-graph credential nodes to durable revocation targets
//! (`RevokeGrantTarget`), then drives revocation through brokerd's HTTP
//! capability API for broker capabilities or by clearing the configured
//! settings field for local integration secrets.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RevokeGrantTarget {
    LocalApiAuthToken,
    BrokerCapability { capability_id: String },
    LocalIntegrationSecret { secret: LocalIntegrationSecretKind },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct BrokerCapabilityRevokeReport {
    pub(crate) capability_id: String,
    pub(crate) revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) provider_revocation: Option<BrokerProviderTokenRevocationReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct BrokerProviderTokenRevocationReport {
    pub(crate) provider: String,
    pub(crate) secret_ref_id: String,
    pub(crate) attempted: bool,
    pub(crate) supported: bool,
    pub(crate) revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) provider_token_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) response_body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalIntegrationSecretKind {
    #[serde(rename = "siem.api_key")]
    SiemApiKey,
    #[serde(rename = "webhooks.secret")]
    WebhooksSecret,
}

impl LocalIntegrationSecretKind {
    pub(crate) fn target_suffix(self) -> &'static str {
        match self {
            Self::SiemApiKey => "siem.api_key",
            Self::WebhooksSecret => "webhooks.secret",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalIntegrationSecretRevokeReport {
    pub(crate) secret: LocalIntegrationSecretKind,
    pub(crate) previous_secret_hash: String,
    pub(crate) integration_disabled: bool,
    pub(crate) revoked: bool,
}

pub(crate) fn revoke_grant_target(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<RevokeGrantTarget> {
    let root = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    if let Some(root_target) = revoke_grant_target_from_credential_node(root) {
        return Ok(root_target);
    }

    let mut targets = Vec::new();
    for node in graph.nodes.values() {
        let Some(target) = revoke_grant_target_from_credential_node(node) else {
            continue;
        };
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    if targets.len() == 1 {
        return Ok(targets.remove(0));
    }
    if targets.len() > 1 {
        return Err(anyhow::anyhow!(
            "ambiguous live revoke_grant target: graph contains multiple revocable credential targets; select the specific credential root node"
        ));
    }

    Err(anyhow::anyhow!(
        "live revoke_grant currently supports graph targets containing a local agent API token credential, local broker capability credential, or local integration secret credential"
    ))
}

fn revoke_grant_target_from_credential_node(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Option<RevokeGrantTarget> {
    if credential_node_is_local_api_grant(node) {
        return Some(RevokeGrantTarget::LocalApiAuthToken);
    }
    if let Some(capability_id) = broker_capability_id_from_credential_node(node) {
        return Some(RevokeGrantTarget::BrokerCapability { capability_id });
    }
    local_integration_secret_from_credential_node(node)
        .map(|secret| RevokeGrantTarget::LocalIntegrationSecret { secret })
}

fn credential_node_is_local_api_grant(node: &clawdstrike_policy_event::edr::CausalNode) -> bool {
    if node.kind != CausalNodeKind::Credential {
        return false;
    }
    let mut values = vec![node.label.as_str()];
    for key in ["path", "name", "credentialKind"] {
        if let Some(value) = node.attributes.get(key).and_then(Value::as_str) {
            values.push(value);
        }
    }
    values.iter().any(|value| {
        let normalized = value.to_ascii_lowercase();
        normalized.contains("agent-local-token")
            || normalized.contains("clawdstrike_agent_auth")
            || normalized.contains("clawdstrike-local-api-token")
            || normalized.contains("local_api_auth_token")
    })
}

fn broker_capability_id_from_credential_node(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Option<String> {
    if node.kind != CausalNodeKind::Credential {
        return None;
    }

    for key in ["capabilityId", "capability_id", "brokerCapabilityId"] {
        if let Some(value) = node.attributes.get(key).and_then(Value::as_str) {
            if let Some(capability_id) = normalize_broker_capability_id(value) {
                return Some(capability_id);
            }
        }
    }

    let values = credential_node_string_values(node);
    for value in &values {
        if let Some(capability_id) = extract_prefixed_broker_capability_id(value) {
            return Some(capability_id);
        }
    }

    let credential_kind = node
        .attributes
        .get("credentialKind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    let is_broker_capability = matches!(
        credential_kind.as_str(),
        "broker_capability" | "clawdstrike_broker_capability" | "brokerd_capability"
    );
    if !is_broker_capability {
        return None;
    }

    values
        .iter()
        .filter(|value| !broker_capability_value_is_kind_sentinel(value))
        .find_map(|value| normalize_broker_capability_id(value))
}

fn credential_node_string_values(node: &clawdstrike_policy_event::edr::CausalNode) -> Vec<String> {
    let mut values = vec![node.label.clone()];
    for key in ["path", "name"] {
        if let Some(value) = node.attributes.get(key).and_then(Value::as_str) {
            values.push(value.to_string());
        }
    }
    values
}

fn local_integration_secret_from_credential_node(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Option<LocalIntegrationSecretKind> {
    if node.kind != CausalNodeKind::Credential {
        return None;
    }

    if let Some(secret) = local_integration_secret_kind_from_structured_attributes(&node.attributes)
    {
        return Some(secret);
    }

    let values = credential_node_string_values(node);
    values
        .iter()
        .find_map(|value| local_integration_secret_kind_from_value(value))
}

fn local_integration_secret_kind_from_structured_attributes(
    attributes: &BTreeMap<String, Value>,
) -> Option<LocalIntegrationSecretKind> {
    const STRUCTURED_SECRET_KEYS: &[&str] = &[
        "credentialKind",
        "credential_kind",
        "integrationSecret",
        "integration_secret",
        "integrationSecretKind",
        "integration_secret_kind",
        "localIntegrationSecret",
        "local_integration_secret",
        "settingKey",
        "setting_key",
        "settingsKey",
        "settings_key",
        "configKey",
        "config_key",
        "secretRef",
        "secret_ref",
        "secretRefId",
        "secret_ref_id",
    ];

    STRUCTURED_SECRET_KEYS
        .iter()
        .filter_map(|key| attributes.get(*key))
        .find_map(local_integration_secret_kind_from_attribute_value)
}

fn local_integration_secret_kind_from_attribute_value(
    value: &Value,
) -> Option<LocalIntegrationSecretKind> {
    match value {
        Value::String(value) => local_integration_secret_kind_from_value(value),
        Value::Array(items) => items
            .iter()
            .find_map(local_integration_secret_kind_from_attribute_value),
        Value::Object(object) => [
            "kind",
            "secretKind",
            "secret_kind",
            "settingKey",
            "setting_key",
            "settingsKey",
            "settings_key",
            "configKey",
            "config_key",
            "ref",
            "id",
            "name",
            "path",
        ]
        .iter()
        .filter_map(|key| object.get(*key))
        .find_map(local_integration_secret_kind_from_attribute_value),
        _ => None,
    }
}

fn local_integration_secret_kind_from_value(value: &str) -> Option<LocalIntegrationSecretKind> {
    let normalized = normalize_secret_identifier(value);
    if matches!(
        normalized.as_str(),
        "siem_api_key"
            | "integrations_siem_api_key"
            | "integration_siem_api_key"
            | "clawdstrike_integrations_siem_api_key"
    ) || normalized.contains("clawdstrike_integrations_siem_api_key")
        || normalized.contains("agent_integrations_siem_api_key")
        || normalized.contains("integration_siem_api_key")
        || normalized.contains("integrations_siem_api_key")
        || normalized.contains("local_siem_api_key")
        || normalized.contains("clawdstrike_siem_api_key")
        || normalized.contains("datadog_api_key")
        || normalized.contains("splunk_token")
        || normalized.contains("elastic_api_key")
    {
        return Some(LocalIntegrationSecretKind::SiemApiKey);
    }
    if matches!(
        normalized.as_str(),
        "webhook_secret"
            | "webhooks_secret"
            | "integrations_webhook_secret"
            | "integrations_webhooks_secret"
            | "clawdstrike_integrations_webhooks_secret"
    ) || normalized.contains("clawdstrike_integrations_webhooks_secret")
        || normalized.contains("agent_integrations_webhooks_secret")
        || normalized.contains("integration_webhook_secret")
        || normalized.contains("integrations_webhook_secret")
        || normalized.contains("integrations_webhooks_secret")
        || normalized.contains("local_webhook_secret")
        || normalized.contains("clawdstrike_webhook_secret")
        || normalized.contains("webhook_signing_secret")
        || normalized.contains("webhook_secret")
    {
        return Some(LocalIntegrationSecretKind::WebhooksSecret);
    }
    None
}

fn normalize_secret_identifier(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut last_was_separator = false;
    for byte in value.bytes() {
        let next = if byte.is_ascii_alphanumeric() {
            last_was_separator = false;
            Some(byte.to_ascii_lowercase() as char)
        } else if !last_was_separator {
            last_was_separator = true;
            Some('_')
        } else {
            None
        };
        if let Some(next) = next {
            normalized.push(next);
        }
    }
    normalized.trim_matches('_').to_string()
}

fn extract_prefixed_broker_capability_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let normalized = trimmed.to_ascii_lowercase();
    for prefix in [
        "credential:broker-capability:",
        "credential:broker_capability:",
        "broker-capability:",
        "broker_capability:",
        "broker capability:",
        "capability:",
    ] {
        if normalized.starts_with(prefix) {
            return normalize_broker_capability_id(&trimmed[prefix.len()..]);
        }
    }
    None
}

fn normalize_broker_capability_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if !broker_capability_id_is_safe_for_path(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

fn broker_capability_value_is_kind_sentinel(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    matches!(
        normalized.as_str(),
        "broker_capability" | "clawdstrike_broker_capability" | "brokerd_capability"
    )
}

fn broker_capability_id_is_safe_for_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) async fn revoke_broker_capability_grant(
    state: &AgentApiState,
    capability_id: &str,
) -> Result<BrokerCapabilityRevokeReport, (StatusCode, String)> {
    if !broker_capability_id_is_safe_for_path(capability_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("unsafe broker capability id for revoke_grant: {capability_id}"),
        ));
    }

    let (enabled, port, admin_token) = {
        let settings = state.settings.read().await;
        (
            settings.brokerd.enabled,
            settings.brokerd.port,
            settings.brokerd.admin_token.clone(),
        )
    };
    if !enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            "brokerd is disabled; cannot revoke broker capability grant".to_string(),
        ));
    }

    let url = format!("http://127.0.0.1:{port}/v1/capabilities/{capability_id}/revoke");
    let mut request = state.http_client.post(url);
    if let Some(token) = admin_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {token}"));
    }

    let response = request.send().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("brokerd capability revoke request failed: {err}"),
        )
    })?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| String::new());
        let detail = if body.trim().is_empty() {
            format!("brokerd capability revoke returned HTTP {status}")
        } else {
            format!(
                "brokerd capability revoke returned HTTP {status}: {}",
                sanitize_brokerd_error_body(&body)
            )
        };
        return Err((status, detail));
    }

    let body = response.text().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("brokerd capability revoke response body could not be read: {err}"),
        )
    })?;
    serde_json::from_str::<BrokerCapabilityRevokeReport>(&body).map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("brokerd capability revoke response was invalid: {err}"),
        )
    })
}

pub(crate) async fn revoke_local_integration_secret_grant(
    state: &AgentApiState,
    secret: LocalIntegrationSecretKind,
) -> Result<LocalIntegrationSecretRevokeReport, (StatusCode, String)> {
    let mut settings = state.settings.write().await;
    let mut next_integrations = settings.integrations.clone();
    let (previous_secret, integration_disabled) = match secret {
        LocalIntegrationSecretKind::SiemApiKey => {
            let previous_secret = next_integrations.siem.api_key.trim().to_string();
            let integration_disabled = next_integrations.siem.enabled;
            next_integrations.siem.api_key.clear();
            next_integrations.siem.enabled = false;
            (previous_secret, integration_disabled)
        }
        LocalIntegrationSecretKind::WebhooksSecret => {
            let previous_secret = next_integrations.webhooks.secret.trim().to_string();
            let integration_disabled = next_integrations.webhooks.enabled;
            next_integrations.webhooks.secret.clear();
            next_integrations.webhooks.enabled = false;
            (previous_secret, integration_disabled)
        }
    };

    if previous_secret.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "local integration secret {} is not configured; cannot revoke grant",
                secret.target_suffix()
            ),
        ));
    }

    let previous_secret_hash = sha256(previous_secret.as_bytes()).to_hex_prefixed();
    let mut next_settings = settings.clone();
    next_settings.integrations = next_integrations.clone();
    next_settings
        .save()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    settings.integrations = next_integrations;

    Ok(LocalIntegrationSecretRevokeReport {
        secret,
        previous_secret_hash,
        integration_disabled,
        revoked: true,
    })
}
