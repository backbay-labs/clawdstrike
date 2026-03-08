//! Origin context types for origin-aware policy enforcement.
//!
//! These types represent where an action originates from (e.g., a Slack channel,
//! a GitHub issue, an email thread) and carry provenance metadata used by the
//! policy engine to select and scope security rules.
//!
//! All types are WASM-compatible — no `std::time::Instant`, `std::fs`, or `tokio`.

use std::fmt;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// OriginProvider
// ---------------------------------------------------------------------------

/// The messaging/collaboration provider an action originates from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginProvider {
    Slack,
    Teams,
    GitHub,
    Jira,
    Email,
    Discord,
    Webhook,
    /// An arbitrary provider not covered by the built-in variants.
    Custom(String),
}

impl fmt::Display for OriginProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Slack => "slack",
            Self::Teams => "teams",
            Self::GitHub => "github",
            Self::Jira => "jira",
            Self::Email => "email",
            Self::Discord => "discord",
            Self::Webhook => "webhook",
            Self::Custom(s) => s.as_str(),
        };
        write!(f, "{label}")
    }
}

impl Serialize for OriginProvider {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for OriginProvider {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "slack" => Self::Slack,
            "teams" => Self::Teams,
            "github" => Self::GitHub,
            "jira" => Self::Jira,
            "email" => Self::Email,
            "discord" => Self::Discord,
            "webhook" => Self::Webhook,
            _ => Self::Custom(s),
        })
    }
}

// ---------------------------------------------------------------------------
// SpaceType
// ---------------------------------------------------------------------------

/// The kind of space/container the action originated in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpaceType {
    Channel,
    Group,
    Dm,
    Thread,
    Issue,
    Ticket,
    PullRequest,
    EmailThread,
    /// An arbitrary space type not covered by the built-in variants.
    Custom(String),
}

impl fmt::Display for SpaceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Channel => "channel",
            Self::Group => "group",
            Self::Dm => "dm",
            Self::Thread => "thread",
            Self::Issue => "issue",
            Self::Ticket => "ticket",
            Self::PullRequest => "pull_request",
            Self::EmailThread => "email_thread",
            Self::Custom(s) => s.as_str(),
        };
        write!(f, "{label}")
    }
}

impl Serialize for SpaceType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for SpaceType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "channel" => Self::Channel,
            "group" => Self::Group,
            "dm" => Self::Dm,
            "thread" => Self::Thread,
            "issue" => Self::Issue,
            "ticket" => Self::Ticket,
            "pull_request" => Self::PullRequest,
            "email_thread" => Self::EmailThread,
            _ => Self::Custom(s),
        })
    }
}

// ---------------------------------------------------------------------------
// Visibility
// ---------------------------------------------------------------------------

/// Visibility level of the originating space.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Private,
    Internal,
    Public,
    ExternalShared,
    #[default]
    Unknown,
}

impl fmt::Display for Visibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Private => "private",
            Self::Internal => "internal",
            Self::Public => "public",
            Self::ExternalShared => "external_shared",
            Self::Unknown => "unknown",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// ProvenanceConfidence
// ---------------------------------------------------------------------------

/// How confident the system is in the origin provenance chain.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceConfidence {
    Strong,
    Medium,
    Weak,
    #[default]
    Unknown,
}

impl fmt::Display for ProvenanceConfidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Strong => "strong",
            Self::Medium => "medium",
            Self::Weak => "weak",
            Self::Unknown => "unknown",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// ActorType
// ---------------------------------------------------------------------------

/// The type of actor that initiated the action.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    Human,
    Bot,
    Service,
    Unknown,
}

impl fmt::Display for ActorType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Human => "human",
            Self::Bot => "bot",
            Self::Service => "service",
            Self::Unknown => "unknown",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// OriginContext
// ---------------------------------------------------------------------------

/// The core type representing where an action originates from.
///
/// This is attached to guard evaluation requests so that the policy engine can
/// select origin-specific rules (e.g., stricter controls for public channels,
/// relaxed rules for internal CI bots).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginContext {
    /// The messaging/collaboration provider.
    pub provider: OriginProvider,

    /// Tenant/workspace identifier (e.g., Slack workspace ID).
    #[serde(skip_serializing_if = "Option::is_none", alias = "tenantId")]
    pub tenant_id: Option<String>,

    /// Space/channel/room identifier.
    #[serde(skip_serializing_if = "Option::is_none", alias = "spaceId")]
    pub space_id: Option<String>,

    /// Kind of space (channel, DM, issue, etc.).
    #[serde(skip_serializing_if = "Option::is_none", alias = "spaceType")]
    pub space_type: Option<SpaceType>,

    /// Thread/conversation identifier within the space.
    #[serde(skip_serializing_if = "Option::is_none", alias = "threadId")]
    pub thread_id: Option<String>,

    /// Identifier of the actor who initiated the action.
    #[serde(skip_serializing_if = "Option::is_none", alias = "actorId")]
    pub actor_id: Option<String>,

    /// Type of actor (human, bot, service).
    #[serde(skip_serializing_if = "Option::is_none", alias = "actorType")]
    pub actor_type: Option<ActorType>,

    /// Provider-specific actor role used by origin profile matching.
    #[serde(skip_serializing_if = "Option::is_none", alias = "actorRole")]
    pub actor_role: Option<String>,

    /// Visibility level of the originating space.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<Visibility>,

    /// Whether external (non-org) participants are present.
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "externalParticipants"
    )]
    pub external_participants: Option<bool>,

    /// Free-form tags for policy matching (e.g., `["pci", "hipaa"]`).
    #[serde(default)]
    pub tags: Vec<String>,

    /// Data sensitivity classification label.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,

    /// Confidence in the provenance chain.
    #[serde(
        skip_serializing_if = "Option::is_none",
        alias = "provenanceConfidence"
    )]
    pub provenance_confidence: Option<ProvenanceConfidence>,

    /// Arbitrary provider-specific metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl Default for OriginContext {
    fn default() -> Self {
        Self {
            provider: OriginProvider::Custom("unknown".into()),
            tenant_id: None,
            space_id: None,
            space_type: None,
            thread_id: None,
            actor_id: None,
            actor_type: None,
            actor_role: None,
            visibility: None,
            external_participants: None,
            tags: Vec::new(),
            sensitivity: None,
            provenance_confidence: None,
            metadata: None,
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip_full() {
        let ctx = OriginContext {
            provider: OriginProvider::Slack,
            tenant_id: Some("T12345".into()),
            space_id: Some("C99999".into()),
            space_type: Some(SpaceType::Channel),
            thread_id: Some("thread-1".into()),
            actor_id: Some("U001".into()),
            actor_type: Some(ActorType::Human),
            actor_role: Some("incident_commander".into()),
            visibility: Some(Visibility::Internal),
            external_participants: Some(false),
            tags: vec!["hipaa".into(), "prod".into()],
            sensitivity: Some("high".into()),
            provenance_confidence: Some(ProvenanceConfidence::Strong),
            metadata: Some(serde_json::json!({"team": "platform"})),
        };

        let json = serde_json::to_string(&ctx).unwrap();
        let deserialized: OriginContext = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.provider, OriginProvider::Slack);
        assert_eq!(deserialized.tenant_id.as_deref(), Some("T12345"));
        assert_eq!(deserialized.space_id.as_deref(), Some("C99999"));
        assert_eq!(deserialized.space_type, Some(SpaceType::Channel));
        assert_eq!(deserialized.thread_id.as_deref(), Some("thread-1"));
        assert_eq!(deserialized.actor_id.as_deref(), Some("U001"));
        assert_eq!(deserialized.actor_type, Some(ActorType::Human));
        assert_eq!(
            deserialized.actor_role.as_deref(),
            Some("incident_commander")
        );
        assert_eq!(deserialized.visibility, Some(Visibility::Internal));
        assert_eq!(deserialized.external_participants, Some(false));
        assert_eq!(deserialized.tags, vec!["hipaa", "prod"]);
        assert_eq!(deserialized.sensitivity.as_deref(), Some("high"));
        assert_eq!(
            deserialized.provenance_confidence,
            Some(ProvenanceConfidence::Strong)
        );
        assert!(deserialized.metadata.is_some());
    }

    #[test]
    fn serde_roundtrip_minimal() {
        let json = r#"{"provider":"github"}"#;
        let ctx: OriginContext = serde_json::from_str(json).unwrap();

        assert_eq!(ctx.provider, OriginProvider::GitHub);
        assert_eq!(ctx.tenant_id, None);
        assert_eq!(ctx.space_id, None);
        assert_eq!(ctx.space_type, None);
        assert_eq!(ctx.thread_id, None);
        assert_eq!(ctx.actor_id, None);
        assert_eq!(ctx.actor_type, None);
        assert_eq!(ctx.actor_role, None);
        assert_eq!(ctx.visibility, None);
        assert_eq!(ctx.external_participants, None);
        assert!(ctx.tags.is_empty());
        assert_eq!(ctx.sensitivity, None);
        assert_eq!(ctx.provenance_confidence, None);
        assert_eq!(ctx.metadata, None);

        // Re-serialize and roundtrip again
        let json2 = serde_json::to_string(&ctx).unwrap();
        let ctx2: OriginContext = serde_json::from_str(&json2).unwrap();
        assert_eq!(ctx2.provider, OriginProvider::GitHub);
    }

    #[test]
    fn deserialize_rejects_unknown_fields() {
        let json = r#"{"provider":"slack","unknown_field":"boom"}"#;
        let result = serde_json::from_str::<OriginContext>(json);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("unknown field"),
            "expected 'unknown field' in error, got: {err_msg}"
        );
    }

    #[test]
    fn default_values() {
        let ctx = OriginContext::default();
        assert_eq!(ctx.provider, OriginProvider::Custom("unknown".into()));
        assert!(ctx.tags.is_empty());
        assert_eq!(ctx.tenant_id, None);

        assert_eq!(Visibility::default(), Visibility::Unknown);
        assert_eq!(
            ProvenanceConfidence::default(),
            ProvenanceConfidence::Unknown
        );
    }

    #[test]
    fn display_implementations() {
        assert_eq!(OriginProvider::Slack.to_string(), "slack");
        assert_eq!(OriginProvider::Teams.to_string(), "teams");
        assert_eq!(OriginProvider::GitHub.to_string(), "github");
        assert_eq!(OriginProvider::Jira.to_string(), "jira");
        assert_eq!(OriginProvider::Email.to_string(), "email");
        assert_eq!(OriginProvider::Discord.to_string(), "discord");
        assert_eq!(OriginProvider::Webhook.to_string(), "webhook");
        assert_eq!(
            OriginProvider::Custom("my_provider".into()).to_string(),
            "my_provider"
        );

        assert_eq!(SpaceType::Channel.to_string(), "channel");
        assert_eq!(SpaceType::Group.to_string(), "group");
        assert_eq!(SpaceType::Dm.to_string(), "dm");
        assert_eq!(SpaceType::Thread.to_string(), "thread");
        assert_eq!(SpaceType::Issue.to_string(), "issue");
        assert_eq!(SpaceType::Ticket.to_string(), "ticket");
        assert_eq!(SpaceType::PullRequest.to_string(), "pull_request");
        assert_eq!(SpaceType::EmailThread.to_string(), "email_thread");
        assert_eq!(
            SpaceType::Custom("wiki_page".into()).to_string(),
            "wiki_page"
        );

        assert_eq!(Visibility::Private.to_string(), "private");
        assert_eq!(Visibility::Internal.to_string(), "internal");
        assert_eq!(Visibility::Public.to_string(), "public");
        assert_eq!(Visibility::ExternalShared.to_string(), "external_shared");
        assert_eq!(Visibility::Unknown.to_string(), "unknown");

        assert_eq!(ProvenanceConfidence::Strong.to_string(), "strong");
        assert_eq!(ProvenanceConfidence::Medium.to_string(), "medium");
        assert_eq!(ProvenanceConfidence::Weak.to_string(), "weak");
        assert_eq!(ProvenanceConfidence::Unknown.to_string(), "unknown");

        assert_eq!(ActorType::Human.to_string(), "human");
        assert_eq!(ActorType::Bot.to_string(), "bot");
        assert_eq!(ActorType::Service.to_string(), "service");
        assert_eq!(ActorType::Unknown.to_string(), "unknown");
    }

    #[test]
    fn deserialize_snake_case_enums() {
        let json = r#"{
            "provider": "slack",
            "space_type": "pull_request",
            "visibility": "external_shared",
            "actor_type": "service",
            "actor_role": "approver",
            "provenance_confidence": "medium"
        }"#;
        let ctx: OriginContext = serde_json::from_str(json).unwrap();

        assert_eq!(ctx.provider, OriginProvider::Slack);
        assert_eq!(ctx.space_type, Some(SpaceType::PullRequest));
        assert_eq!(ctx.visibility, Some(Visibility::ExternalShared));
        assert_eq!(ctx.actor_type, Some(ActorType::Service));
        assert_eq!(ctx.actor_role.as_deref(), Some("approver"));
        assert_eq!(
            ctx.provenance_confidence,
            Some(ProvenanceConfidence::Medium)
        );
    }

    #[test]
    fn deserialize_accepts_camel_case_fields() {
        let json = r#"{
            "provider": "slack",
            "tenantId": "T123",
            "spaceId": "C999",
            "spaceType": "channel",
            "threadId": "thread-1",
            "actorId": "U001",
            "actorType": "human",
            "actorRole": "incident_commander",
            "externalParticipants": true,
            "provenanceConfidence": "strong"
        }"#;
        let ctx: OriginContext = serde_json::from_str(json).unwrap();

        assert_eq!(ctx.tenant_id.as_deref(), Some("T123"));
        assert_eq!(ctx.space_id.as_deref(), Some("C999"));
        assert_eq!(ctx.space_type, Some(SpaceType::Channel));
        assert_eq!(ctx.thread_id.as_deref(), Some("thread-1"));
        assert_eq!(ctx.actor_id.as_deref(), Some("U001"));
        assert_eq!(ctx.actor_type, Some(ActorType::Human));
        assert_eq!(ctx.actor_role.as_deref(), Some("incident_commander"));
        assert_eq!(ctx.external_participants, Some(true));
        assert_eq!(
            ctx.provenance_confidence,
            Some(ProvenanceConfidence::Strong)
        );
    }

    #[test]
    fn custom_variants_serde() {
        // OriginProvider::Custom
        let provider = OriginProvider::Custom("my_internal_tool".into());
        let json = serde_json::to_value(&provider).unwrap();
        assert_eq!(json, serde_json::json!("my_internal_tool"));
        let back: OriginProvider = serde_json::from_value(json).unwrap();
        assert_eq!(back, OriginProvider::Custom("my_internal_tool".into()));

        // SpaceType::Custom
        let space = SpaceType::Custom("wiki_page".into());
        let json = serde_json::to_value(&space).unwrap();
        assert_eq!(json, serde_json::json!("wiki_page"));
        let back: SpaceType = serde_json::from_value(json).unwrap();
        assert_eq!(back, SpaceType::Custom("wiki_page".into()));

        // Roundtrip through OriginContext
        let ctx = OriginContext {
            provider: OriginProvider::Custom("matrix".into()),
            space_type: Some(SpaceType::Custom("room".into())),
            ..OriginContext::default()
        };
        let json = serde_json::to_string(&ctx).unwrap();
        let back: OriginContext = serde_json::from_str(&json).unwrap();
        assert_eq!(back.provider, OriginProvider::Custom("matrix".into()));
        assert_eq!(back.space_type, Some(SpaceType::Custom("room".into())));
    }
}
