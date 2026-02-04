use std::collections::HashMap;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::audit::AuditEvent;

#[derive(Clone, Debug, thiserror::Error)]
pub enum SecurityEventValidationError {
    #[error("missing {field}")]
    MissingField { field: &'static str },
    #[error("invalid field {field}: {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityEvent {
    /// Schema version for forward/backward compatibility.
    pub schema_version: String,

    // Identity
    pub event_id: Uuid,
    pub event_type: SecurityEventType,
    pub event_category: EventCategory,

    // Timing
    pub timestamp: DateTime<Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingested_at: Option<DateTime<Utc>>,

    // Source
    pub agent: AgentInfo,

    // Session context
    pub session: SessionInfo,

    // Event data
    pub outcome: Outcome,
    pub action: String,

    // Security-specific
    #[serde(default)]
    pub threat: ThreatInfo,

    // Decision details
    pub decision: DecisionInfo,

    // Resource affected
    pub resource: ResourceInfo,

    // Extensibility
    #[serde(default)]
    pub metadata: serde_json::Value,
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

impl SecurityEvent {
    pub fn validate(&self) -> Result<(), SecurityEventValidationError> {
        if self.schema_version.trim().is_empty() {
            return Err(SecurityEventValidationError::MissingField {
                field: "schema_version",
            });
        }
        if self.action.trim().is_empty() {
            return Err(SecurityEventValidationError::MissingField { field: "action" });
        }
        if self.agent.id.trim().is_empty() {
            return Err(SecurityEventValidationError::MissingField { field: "agent.id" });
        }
        if self.session.id.trim().is_empty() {
            return Err(SecurityEventValidationError::MissingField {
                field: "session.id",
            });
        }
        if self.resource.name.trim().is_empty() {
            return Err(SecurityEventValidationError::MissingField {
                field: "resource.name",
            });
        }
        Ok(())
    }

    pub fn timestamp_rfc3339_nanos(&self) -> String {
        self.timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true)
    }

    pub fn from_audit_event(audit: &AuditEvent, ctx: &SecurityEventContext) -> Self {
        let event_id = audit.id.parse::<Uuid>().unwrap_or_else(|_| Uuid::now_v7());

        let (resource, threat) = resource_and_threat_from_audit(audit);

        let (event_type, category) = event_type_and_category_from_audit(audit, &resource);

        let allowed = audit.decision == "allowed";
        let decision = DecisionInfo {
            allowed,
            guard: audit.guard.clone().unwrap_or_else(|| "engine".to_string()),
            severity: map_severity_str(audit.severity.as_deref()).unwrap_or(SecuritySeverity::Info),
            reason: audit
                .message
                .clone()
                .unwrap_or_else(|| audit.event_type.clone()),
            policy_hash: ctx.policy_hash.clone(),
            ruleset: ctx.ruleset.clone(),
        };

        let agent_id = audit
            .agent_id
            .clone()
            .unwrap_or_else(|| ctx.default_agent_id.clone());

        let session_id = audit
            .session_id
            .clone()
            .unwrap_or_else(|| ctx.default_session_id.clone());

        let outcome = if allowed {
            Outcome::Success
        } else {
            Outcome::Failure
        };

        Self {
            schema_version: ctx.schema_version.clone(),
            event_id,
            event_type,
            event_category: category,
            timestamp: audit.timestamp,
            ingested_at: None,
            agent: AgentInfo {
                id: agent_id.clone(),
                name: ctx.agent_name.clone().unwrap_or(agent_id),
                version: ctx.agent_version.clone(),
                agent_type: "clawdstrike".to_string(),
            },
            session: SessionInfo {
                id: session_id,
                user_id: None,
                tenant_id: ctx.tenant_id.clone(),
                environment: ctx.environment.clone(),
            },
            outcome,
            action: audit.action_type.clone(),
            threat,
            decision,
            resource,
            metadata: audit
                .metadata
                .clone()
                .unwrap_or_else(|| serde_json::json!({})),
            labels: ctx.labels.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SecurityEventContext {
    pub schema_version: String,
    pub environment: Option<String>,
    pub tenant_id: Option<String>,
    pub agent_name: Option<String>,
    pub agent_version: String,
    pub policy_hash: Option<String>,
    pub ruleset: Option<String>,
    pub default_session_id: String,
    pub default_agent_id: String,
    pub labels: HashMap<String, String>,
}

impl SecurityEventContext {
    pub fn hushd(session_id: String) -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            environment: None,
            tenant_id: None,
            agent_name: Some("hushd".to_string()),
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
            policy_hash: None,
            ruleset: None,
            default_session_id: session_id,
            default_agent_id: "hushd".to_string(),
            labels: HashMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub agent_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionInfo {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityEventType {
    PolicyViolation,
    PolicyAllow,
    GuardBlock,
    GuardWarn,
    SecretDetected,
    EgressBlocked,
    ForbiddenPath,
    PatchRejected,
    SessionStart,
    SessionEnd,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventCategory {
    Authentication,
    Authorization,
    File,
    Network,
    Process,
    Tool,
    Configuration,
    Session,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SecuritySeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ThreatInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indicator: Option<ThreatIndicator>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactic: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technique: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatIndicator {
    #[serde(rename = "type")]
    pub indicator_type: ThreatIndicatorType,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatIndicatorType {
    Domain,
    FilePath,
    Pattern,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DecisionInfo {
    pub allowed: bool,
    pub guard: String,
    pub severity: SecuritySeverity,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ruleset: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResourceInfo {
    #[serde(rename = "type")]
    pub resource_type: ResourceType,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceType {
    File,
    Network,
    Process,
    Tool,
    Configuration,
}

fn map_severity_str(s: Option<&str>) -> Option<SecuritySeverity> {
    let s = s?.trim();
    if s.eq_ignore_ascii_case("critical") {
        return Some(SecuritySeverity::Critical);
    }
    if s.eq_ignore_ascii_case("error") {
        return Some(SecuritySeverity::High);
    }
    if s.eq_ignore_ascii_case("warning") {
        return Some(SecuritySeverity::Medium);
    }
    if s.eq_ignore_ascii_case("info") {
        return Some(SecuritySeverity::Info);
    }
    None
}

fn event_type_and_category_from_audit(
    audit: &AuditEvent,
    resource: &ResourceInfo,
) -> (SecurityEventType, EventCategory) {
    match audit.event_type.as_str() {
        "session_start" => return (SecurityEventType::SessionStart, EventCategory::Session),
        "session_end" => return (SecurityEventType::SessionEnd, EventCategory::Session),
        _ => {}
    }

    let allowed = audit.decision == "allowed";

    let event_type = if allowed {
        // Warning results are still allowed, but represent a guard warn signal.
        if matches!(
            audit.severity.as_deref(),
            Some("Warning") | Some("warning") | Some("WARN") | Some("warn")
        ) {
            SecurityEventType::GuardWarn
        } else {
            SecurityEventType::PolicyAllow
        }
    } else {
        // Specialize blocked events when we can infer the guard/action.
        if audit.guard.as_deref() == Some("secret_leak") {
            SecurityEventType::SecretDetected
        } else if audit.action_type == "egress" {
            SecurityEventType::EgressBlocked
        } else if audit.guard.as_deref() == Some("forbidden_path") {
            SecurityEventType::ForbiddenPath
        } else if audit.action_type == "patch" || audit.guard.as_deref() == Some("patch_integrity")
        {
            SecurityEventType::PatchRejected
        } else {
            SecurityEventType::GuardBlock
        }
    };

    let category = match resource.resource_type {
        ResourceType::File => EventCategory::File,
        ResourceType::Network => EventCategory::Network,
        ResourceType::Process => EventCategory::Process,
        ResourceType::Tool => EventCategory::Tool,
        ResourceType::Configuration => EventCategory::Configuration,
    };

    (event_type, category)
}

fn resource_and_threat_from_audit(audit: &AuditEvent) -> (ResourceInfo, ThreatInfo) {
    let target = audit.target.clone().unwrap_or_default();

    match audit.action_type.as_str() {
        "egress" => {
            let (host, port) = parse_egress_target_like_api(&target);
            (
                ResourceInfo {
                    resource_type: ResourceType::Network,
                    name: host.clone(),
                    path: None,
                    host: Some(host.clone()),
                    port: Some(port),
                },
                ThreatInfo {
                    indicator: Some(ThreatIndicator {
                        indicator_type: ThreatIndicatorType::Domain,
                        value: host,
                    }),
                    tactic: None,
                    technique: None,
                },
            )
        }
        "file_access" | "file_write" => (
            ResourceInfo {
                resource_type: ResourceType::File,
                name: target.clone(),
                path: Some(target.clone()),
                host: None,
                port: None,
            },
            ThreatInfo {
                indicator: Some(ThreatIndicator {
                    indicator_type: ThreatIndicatorType::FilePath,
                    value: target,
                }),
                tactic: None,
                technique: None,
            },
        ),
        "patch" => (
            ResourceInfo {
                resource_type: ResourceType::File,
                name: target.clone(),
                path: Some(target.clone()),
                host: None,
                port: None,
            },
            ThreatInfo::default(),
        ),
        "shell" => (
            ResourceInfo {
                resource_type: ResourceType::Process,
                name: target,
                path: None,
                host: None,
                port: None,
            },
            ThreatInfo::default(),
        ),
        "mcp_tool" => (
            ResourceInfo {
                resource_type: ResourceType::Tool,
                name: target,
                path: None,
                host: None,
                port: None,
            },
            ThreatInfo::default(),
        ),
        _ => (
            ResourceInfo {
                resource_type: ResourceType::Configuration,
                name: audit.action_type.clone(),
                path: audit.target.clone(),
                host: None,
                port: None,
            },
            ThreatInfo::default(),
        ),
    }
}

fn parse_egress_target_like_api(target: &str) -> (String, u16) {
    let target = target.trim();
    if target.is_empty() {
        return ("".to_string(), 443);
    }

    if let Some(rest) = target.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let host = &rest[..end];
            let after = &rest[end + 1..];
            let port = if after.is_empty() {
                443
            } else if let Some(port_str) = after.strip_prefix(':') {
                port_str.parse::<u16>().unwrap_or(443)
            } else {
                443
            };
            return (host.to_string(), port);
        }
    }

    if let Some((host, port_str)) = target.rsplit_once(':') {
        if !host.is_empty() && !port_str.is_empty() && port_str.chars().all(|c| c.is_ascii_digit())
        {
            return (host.to_string(), port_str.parse::<u16>().unwrap_or(443));
        }
    }

    (target.to_string(), 443)
}
