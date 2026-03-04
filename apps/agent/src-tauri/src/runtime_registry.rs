//! Runtime-agent registration and identity normalization.
//!
//! Maintains a local persistent catalog of runtime agents (Claude Code/OpenClaw/MCP/etc)
//! so policy events can reference stable runtime IDs.

use crate::settings::{RuntimeAgentRegistration, Settings};

#[derive(Debug, Clone)]
pub struct RuntimeRegistrationResult {
    pub endpoint_agent_id: String,
    pub runtime_agent_id: String,
    pub runtime_agent_kind: String,
    pub external_runtime_id: Option<String>,
    pub first_seen_at: String,
    pub last_seen_at: String,
}

#[derive(Debug, Clone)]
pub struct RuntimeRegistrationInput {
    pub endpoint_agent_id: String,
    pub runtime_agent_kind: String,
    pub external_runtime_id: Option<String>,
    pub display_name: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

fn normalize_non_empty(input: Option<&str>) -> Option<String> {
    input
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn normalize_kind(raw: &str) -> String {
    let normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();

    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized
    }
}

fn short_kind(kind: &str) -> String {
    let mut out = kind
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .take(8)
        .collect::<String>();
    if out.is_empty() {
        out = "runtime".to_string();
    }
    out
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn build_runtime_id(endpoint_agent_id: &str, kind: &str, external_runtime_id: Option<&str>) -> String {
    if let Some(external) = external_runtime_id {
        let material = format!("{endpoint_agent_id}:{kind}:{external}");
        let digest = hush_core::sha256(material.as_bytes()).to_hex();
        return format!("rt-{}-{}", short_kind(kind), &digest[..12]);
    }

    let random = uuid::Uuid::new_v4().simple().to_string();
    format!("rt-{}-{}", short_kind(kind), &random[..12])
}

pub fn resolve_effective_endpoint_agent_id(settings: &mut Settings, requested: Option<&str>) -> String {
    if let Some(endpoint_id) = normalize_non_empty(requested) {
        return endpoint_id;
    }

    if let Some(agent_id) = settings.nats.agent_id.as_deref().map(str::trim) {
        if !agent_id.is_empty() {
            return agent_id.to_string();
        }
    }

    if let Some(agent_uuid) = settings.enrollment.agent_uuid.as_deref().map(str::trim) {
        if !agent_uuid.is_empty() {
            return agent_uuid.to_string();
        }
    }

    if let Some(local_agent_id) = settings.local_agent_id.as_deref().map(str::trim) {
        if !local_agent_id.is_empty() {
            return local_agent_id.to_string();
        }
    }

    let generated = format!("endpoint-{}", uuid::Uuid::new_v4());
    settings.local_agent_id = Some(generated.clone());
    if let Err(err) = settings.save() {
        tracing::warn!(
            error = %err,
            "Failed to persist generated local endpoint_agent_id"
        );
    }
    generated
}

pub fn register_runtime_agent(
    settings: &mut Settings,
    input: RuntimeRegistrationInput,
) -> RuntimeRegistrationResult {
    let endpoint_agent_id = input.endpoint_agent_id.trim().to_string();
    let runtime_agent_kind = normalize_kind(&input.runtime_agent_kind);
    let external_runtime_id = normalize_non_empty(input.external_runtime_id.as_deref());
    let display_name = normalize_non_empty(input.display_name.as_deref());
    let now = now_rfc3339();

    // First pass: treat a provided external_runtime_id as an idempotent registration key.
    if let Some(external) = external_runtime_id.as_deref() {
        if let Some(existing) = settings.runtime_registry.runtimes.iter_mut().find(|entry| {
            entry.endpoint_agent_id == endpoint_agent_id
                && entry.runtime_agent_kind == runtime_agent_kind
                && entry.external_runtime_id.as_deref() == Some(external)
        }) {
            existing.last_seen_at = now.clone();
            existing.policy_event_count = existing.policy_event_count.saturating_add(1);
            if let Some(name) = display_name {
                existing.display_name = Some(name);
            }
            if let Some(metadata) = input.metadata {
                existing.metadata = Some(metadata);
            }

            return RuntimeRegistrationResult {
                endpoint_agent_id: existing.endpoint_agent_id.clone(),
                runtime_agent_id: existing.runtime_agent_id.clone(),
                runtime_agent_kind: existing.runtime_agent_kind.clone(),
                external_runtime_id: existing.external_runtime_id.clone(),
                first_seen_at: existing.first_seen_at.clone(),
                last_seen_at: existing.last_seen_at.clone(),
            };
        }
    }

    // Second pass: if the caller already knows our stable runtime id, refresh it in-place.
    if let Some(stable_id) = external_runtime_id.as_deref() {
        if let Some(existing) = settings.runtime_registry.runtimes.iter_mut().find(|entry| {
            entry.endpoint_agent_id == endpoint_agent_id && entry.runtime_agent_id == stable_id
        }) {
            existing.last_seen_at = now.clone();
            existing.policy_event_count = existing.policy_event_count.saturating_add(1);
            if let Some(metadata) = input.metadata {
                existing.metadata = Some(metadata);
            }
            return RuntimeRegistrationResult {
                endpoint_agent_id: existing.endpoint_agent_id.clone(),
                runtime_agent_id: existing.runtime_agent_id.clone(),
                runtime_agent_kind: existing.runtime_agent_kind.clone(),
                external_runtime_id: existing.external_runtime_id.clone(),
                first_seen_at: existing.first_seen_at.clone(),
                last_seen_at: existing.last_seen_at.clone(),
            };
        }
    }

    let runtime_agent_id = {
        let mut candidate = build_runtime_id(
            &endpoint_agent_id,
            &runtime_agent_kind,
            external_runtime_id.as_deref(),
        );
        while settings
            .runtime_registry
            .runtimes
            .iter()
            .any(|entry| entry.runtime_agent_id == candidate)
        {
            candidate = build_runtime_id(&endpoint_agent_id, &runtime_agent_kind, None);
        }
        candidate
    };

    let record = RuntimeAgentRegistration {
        runtime_agent_id: runtime_agent_id.clone(),
        runtime_agent_kind: runtime_agent_kind.clone(),
        endpoint_agent_id: endpoint_agent_id.clone(),
        external_runtime_id: external_runtime_id.clone(),
        display_name,
        metadata: input.metadata,
        first_seen_at: now.clone(),
        last_seen_at: now.clone(),
        policy_event_count: 1,
    };

    settings.runtime_registry.runtimes.push(record);

    RuntimeRegistrationResult {
        endpoint_agent_id,
        runtime_agent_id,
        runtime_agent_kind,
        external_runtime_id,
        first_seen_at: now.clone(),
        last_seen_at: now,
    }
}

pub fn resolve_runtime_for_policy_event(
    settings: &mut Settings,
    endpoint_agent_id: &str,
    runtime_agent_id: Option<&str>,
    runtime_agent_kind: Option<&str>,
) -> Result<Option<RuntimeRegistrationResult>, String> {
    let runtime_agent_id = normalize_non_empty(runtime_agent_id);
    let runtime_agent_kind = normalize_non_empty(runtime_agent_kind);

    match (runtime_agent_id, runtime_agent_kind) {
        (None, None) => Ok(None),
        (Some(_), None) | (None, Some(_)) => Err(
            "runtime_agent_id and runtime_agent_kind must be provided together".to_string(),
        ),
        (Some(external_runtime_id), Some(kind)) => {
            let registration = register_runtime_agent(
                settings,
                RuntimeRegistrationInput {
                    endpoint_agent_id: endpoint_agent_id.to_string(),
                    runtime_agent_kind: kind,
                    external_runtime_id: Some(external_runtime_id),
                    display_name: None,
                    metadata: None,
                },
            );
            Ok(Some(registration))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_endpoint_agent_id_uses_explicit_request() {
        let mut settings = Settings::default();
        let endpoint = resolve_effective_endpoint_agent_id(&mut settings, Some("desktop-123"));
        assert_eq!(endpoint, "desktop-123");
    }

    #[test]
    fn runtime_registration_is_idempotent_for_same_external_key() {
        let mut settings = Settings::default();
        let first = register_runtime_agent(
            &mut settings,
            RuntimeRegistrationInput {
                endpoint_agent_id: "desktop-a".to_string(),
                runtime_agent_kind: "claude_code".to_string(),
                external_runtime_id: Some("conversation-1".to_string()),
                display_name: Some("Claude".to_string()),
                metadata: None,
            },
        );
        let second = register_runtime_agent(
            &mut settings,
            RuntimeRegistrationInput {
                endpoint_agent_id: "desktop-a".to_string(),
                runtime_agent_kind: "claude_code".to_string(),
                external_runtime_id: Some("conversation-1".to_string()),
                display_name: None,
                metadata: None,
            },
        );

        assert_eq!(first.runtime_agent_id, second.runtime_agent_id);
        assert_eq!(settings.runtime_registry.runtimes.len(), 1);
    }

    #[test]
    fn runtime_policy_resolution_requires_complete_runtime_identity_pair() {
        let mut settings = Settings::default();
        let result = resolve_runtime_for_policy_event(
            &mut settings,
            "desktop-a",
            Some("runtime-1"),
            None,
        );
        assert!(result.is_err());
    }
}
