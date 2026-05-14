//! Canonical PolicyEvent types and mapping logic.
//!
//! Extracted from `hushd::policy_event` (the canonical version) with richer
//! `to_guard_context()` from `hush-cli`.

use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use clawdstrike::guards::GuardAction;
use clawdstrike::{
    GuardContext, IdentityPrincipal, OrganizationContext, OriginContext, RequestContext,
    SessionContext,
};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// PolicyEventType
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum PolicyEventType {
    FileRead,
    FileWrite,
    NetworkEgress,
    CommandExec,
    PatchApply,
    ToolCall,
    SecretAccess,
    Custom,
    // CUA (Computer Use Agent) event types
    RemoteSessionConnect,
    RemoteSessionDisconnect,
    RemoteSessionReconnect,
    InputInject,
    ClipboardTransfer,
    FileTransfer,
    RemoteAudio,
    RemoteDriveMapping,
    RemotePrinting,
    SessionShare,
    Other(String),
}

impl PolicyEventType {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::NetworkEgress => "network_egress",
            Self::CommandExec => "command_exec",
            Self::PatchApply => "patch_apply",
            Self::ToolCall => "tool_call",
            Self::SecretAccess => "secret_access",
            Self::Custom => "custom",
            Self::RemoteSessionConnect => "remote.session.connect",
            Self::RemoteSessionDisconnect => "remote.session.disconnect",
            Self::RemoteSessionReconnect => "remote.session.reconnect",
            Self::InputInject => "input.inject",
            Self::ClipboardTransfer => "remote.clipboard",
            Self::FileTransfer => "remote.file_transfer",
            Self::RemoteAudio => "remote.audio",
            Self::RemoteDriveMapping => "remote.drive_mapping",
            Self::RemotePrinting => "remote.printing",
            Self::SessionShare => "remote.session_share",
            Self::Other(s) => s.as_str(),
        }
    }
}

impl std::fmt::Debug for PolicyEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PolicyEventType")
            .field(&self.as_str())
            .finish()
    }
}

impl std::fmt::Display for PolicyEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PartialEq for PolicyEventType {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for PolicyEventType {}

// Clone is derived — all variants are either unit or contain a Clone type (String).

impl<'de> Deserialize<'de> for PolicyEventType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Ok(match raw.as_str() {
            "file_read" => Self::FileRead,
            "file_write" => Self::FileWrite,
            "network_egress" => Self::NetworkEgress,
            "command_exec" => Self::CommandExec,
            "patch_apply" => Self::PatchApply,
            "tool_call" => Self::ToolCall,
            "secret_access" => Self::SecretAccess,
            "custom" => Self::Custom,
            "remote.session.connect" => Self::RemoteSessionConnect,
            "remote.session.disconnect" => Self::RemoteSessionDisconnect,
            "remote.session.reconnect" => Self::RemoteSessionReconnect,
            "input.inject" => Self::InputInject,
            "remote.clipboard" => Self::ClipboardTransfer,
            "remote.file_transfer" => Self::FileTransfer,
            "remote.audio" => Self::RemoteAudio,
            "remote.drive_mapping" => Self::RemoteDriveMapping,
            "remote.printing" => Self::RemotePrinting,
            "remote.session_share" => Self::SessionShare,
            other => Self::Other(other.to_string()),
        })
    }
}

impl Serialize for PolicyEventType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// PolicyEvent
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEvent {
    #[serde(alias = "event_id")]
    pub event_id: String,
    #[serde(alias = "event_type")]
    pub event_type: PolicyEventType,
    pub timestamp: DateTime<Utc>,
    #[serde(default, alias = "session_id", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub data: PolicyEventData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
    #[serde(default, skip_serializing)]
    pub context: Option<serde_json::Value>,
}

impl PolicyEvent {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.event_id.trim().is_empty() {
            anyhow::bail!("eventId must be a non-empty string");
        }

        match (&self.event_type, &self.data) {
            (PolicyEventType::FileRead, PolicyEventData::File(_)) => {}
            (PolicyEventType::FileWrite, PolicyEventData::File(_)) => {}
            (PolicyEventType::NetworkEgress, PolicyEventData::Network(_)) => {}
            (PolicyEventType::CommandExec, PolicyEventData::Command(_)) => {}
            (PolicyEventType::PatchApply, PolicyEventData::Patch(_)) => {}
            (PolicyEventType::ToolCall, PolicyEventData::Tool(_)) => {}
            (PolicyEventType::SecretAccess, PolicyEventData::Secret(_)) => {}
            (PolicyEventType::Custom, PolicyEventData::Custom(_)) => {}
            (PolicyEventType::RemoteSessionConnect, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::RemoteSessionDisconnect, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::RemoteSessionReconnect, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::InputInject, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::ClipboardTransfer, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::FileTransfer, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::RemoteAudio, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::RemoteDriveMapping, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::RemotePrinting, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::SessionShare, PolicyEventData::Cua(_)) => {}
            (PolicyEventType::Other(_), _) => {}
            (event_type, data) => {
                anyhow::bail!(
                    "eventType {} does not match data.type {}",
                    event_type,
                    data.data_type_key()
                );
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn to_guard_context(&self) -> GuardContext {
        let mut ctx = GuardContext::new();
        ctx.session_id = self.session_id.clone();
        ctx.agent_id = extract_metadata_string(
            self.metadata.as_ref(),
            &[
                "endpointAgentId",
                "endpoint_agent_id",
                "agentId",
                "agent_id",
            ],
        );
        ctx.metadata = merge_context_into_metadata(self.metadata.as_ref(), self.context.as_ref());

        // Optional identity/session enrichment (best-effort; never fails closed here).
        if let Some(serde_json::Value::Object(obj)) = ctx.metadata.as_ref() {
            if let Some(value) = obj.get("identity") {
                if let Ok(principal) = serde_json::from_value::<IdentityPrincipal>(value.clone()) {
                    ctx.identity = Some(principal);
                }
            }

            if let Some(value) = obj.get("organization") {
                if let Ok(org) = serde_json::from_value::<OrganizationContext>(value.clone()) {
                    ctx.organization = Some(org);
                }
            }

            if let Some(value) = obj.get("request") {
                if let Ok(req) = serde_json::from_value::<RequestContext>(value.clone()) {
                    ctx.request = Some(req);
                }
            }

            if let Some(value) = obj.get("session") {
                if let Ok(session) = serde_json::from_value::<SessionContext>(value.clone()) {
                    ctx.session = Some(session);
                }
            }

            if let Some(value) = obj.get("origin").or_else(|| obj.get("originContext")) {
                if let Ok(origin) = serde_json::from_value::<OriginContext>(value.clone()) {
                    ctx.origin = Some(origin);
                }
            }

            if let Some(value) = obj.get("roles") {
                if let Some(roles) = parse_string_array(value) {
                    ctx.roles = Some(roles);
                }
            }

            if let Some(value) = obj.get("permissions") {
                if let Some(permissions) = parse_string_array(value) {
                    ctx.permissions = Some(permissions);
                }
            }
        }

        ctx
    }
}

// ---------------------------------------------------------------------------
// PolicyEventData
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum PolicyEventData {
    File(FileEventData),
    Network(NetworkEventData),
    Command(CommandEventData),
    Patch(PatchEventData),
    Tool(ToolEventData),
    Secret(SecretEventData),
    Custom(CustomEventData),
    Cua(CuaEventData),
    Other {
        type_name: String,
        value: serde_json::Value,
    },
}

impl PolicyEventData {
    #[must_use]
    pub fn data_type_key(&self) -> &str {
        match self {
            Self::File(_) => "file",
            Self::Network(_) => "network",
            Self::Command(_) => "command",
            Self::Patch(_) => "patch",
            Self::Tool(_) => "tool",
            Self::Secret(_) => "secret",
            Self::Custom(_) => "custom",
            Self::Cua(_) => "cua",
            Self::Other { type_name, .. } => type_name.as_str(),
        }
    }
}

impl Serialize for PolicyEventData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let value = match self {
            Self::File(inner) => {
                serialize_typed_data("file", inner).map_err(serde::ser::Error::custom)?
            }
            Self::Network(inner) => {
                serialize_typed_data("network", inner).map_err(serde::ser::Error::custom)?
            }
            Self::Command(inner) => {
                serialize_typed_data("command", inner).map_err(serde::ser::Error::custom)?
            }
            Self::Patch(inner) => {
                serialize_typed_data("patch", inner).map_err(serde::ser::Error::custom)?
            }
            Self::Tool(inner) => {
                serialize_typed_data("tool", inner).map_err(serde::ser::Error::custom)?
            }
            Self::Secret(inner) => {
                serialize_typed_data("secret", inner).map_err(serde::ser::Error::custom)?
            }
            Self::Custom(inner) => {
                serialize_typed_data("custom", inner).map_err(serde::ser::Error::custom)?
            }
            Self::Cua(inner) => {
                serialize_typed_data("cua", inner).map_err(serde::ser::Error::custom)?
            }
            Self::Other { value, .. } => value.clone(),
        };

        value.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for PolicyEventData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let serde_json::Value::Object(obj) = &value else {
            return Err(serde::de::Error::custom("data must be an object"));
        };

        let Some(serde_json::Value::String(type_name)) = obj.get("type") else {
            return Err(serde::de::Error::custom("data.type must be a string"));
        };

        match type_name.as_str() {
            "file" => serde_json::from_value::<FileEventData>(value)
                .map(Self::File)
                .map_err(serde::de::Error::custom),
            "network" => serde_json::from_value::<NetworkEventData>(value)
                .map(Self::Network)
                .map_err(serde::de::Error::custom),
            "command" => serde_json::from_value::<CommandEventData>(value)
                .map(Self::Command)
                .map_err(serde::de::Error::custom),
            "patch" => serde_json::from_value::<PatchEventData>(value)
                .map(Self::Patch)
                .map_err(serde::de::Error::custom),
            "tool" => serde_json::from_value::<ToolEventData>(value)
                .map(Self::Tool)
                .map_err(serde::de::Error::custom),
            "secret" => serde_json::from_value::<SecretEventData>(value)
                .map(Self::Secret)
                .map_err(serde::de::Error::custom),
            "custom" => serde_json::from_value::<CustomEventData>(value)
                .map(Self::Custom)
                .map_err(serde::de::Error::custom),
            "cua" => serde_json::from_value::<CuaEventData>(value)
                .map(Self::Cua)
                .map_err(serde::de::Error::custom),
            other => Ok(Self::Other {
                type_name: other.to_string(),
                value,
            }),
        }
    }
}

fn serialize_typed_data<T: Serialize>(
    type_name: &str,
    inner: &T,
) -> anyhow::Result<serde_json::Value> {
    let value = serde_json::to_value(inner).context("serialize event data")?;
    let serde_json::Value::Object(mut obj) = value else {
        anyhow::bail!("event data must serialize to an object");
    };

    obj.insert(
        "type".to_string(),
        serde_json::Value::String(type_name.to_string()),
    );
    Ok(serde_json::Value::Object(obj))
}

// ---------------------------------------------------------------------------
// Data structs
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileEventData {
    #[serde(alias = "file_path")]
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
    #[serde(
        default,
        alias = "content_base64",
        skip_serializing_if = "Option::is_none"
    )]
    pub content_base64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(
        default,
        alias = "content_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub content_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkEventData {
    pub host: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommandEventData {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PatchEventData {
    #[serde(alias = "file_path")]
    pub file_path: String,
    #[serde(alias = "patch_content")]
    pub patch_content: String,
    #[serde(default, alias = "patch_hash", skip_serializing_if = "Option::is_none")]
    pub patch_hash: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolEventData {
    #[serde(alias = "tool_name")]
    pub tool_name: String,
    #[serde(default = "default_empty_object")]
    pub parameters: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretEventData {
    #[serde(alias = "secret_name")]
    pub secret_name: String,
    pub scope: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CustomEventData {
    #[serde(alias = "custom_type")]
    pub custom_type: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CuaEventData {
    /// CUA sub-type: connect/disconnect/reconnect/inject/clipboard/file_transfer/audio/drive/printing/session_share
    #[serde(alias = "cua_action")]
    pub cua_action: String,
    /// Direction for clipboard/file operations: read/write/upload/download
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    /// Session continuity hash from previous session (reconnect flows)
    #[serde(
        default,
        alias = "continuity_prev_session_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub continuity_prev_session_hash: Option<String>,
    /// Post-condition probe result hash
    #[serde(
        default,
        alias = "postcondition_probe_hash",
        skip_serializing_if = "Option::is_none"
    )]
    pub postcondition_probe_hash: Option<String>,
    /// Additional CUA-specific fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

// ---------------------------------------------------------------------------
// MappedGuardAction
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub enum MappedGuardAction {
    FileAccess {
        path: String,
    },
    FileWrite {
        path: String,
        content: Vec<u8>,
    },
    NetworkEgress {
        host: String,
        port: u16,
    },
    ShellCommand {
        commandline: String,
    },
    Patch {
        file_path: String,
        patch_content: String,
    },
    McpTool {
        tool_name: String,
        parameters: serde_json::Value,
    },
    Custom {
        custom_type: String,
        data: serde_json::Value,
    },
}

impl MappedGuardAction {
    #[must_use]
    pub fn as_guard_action(&self) -> GuardAction<'_> {
        match self {
            Self::FileAccess { path } => GuardAction::FileAccess(path),
            Self::FileWrite { path, content } => GuardAction::FileWrite(path, content),
            Self::NetworkEgress { host, port } => GuardAction::NetworkEgress(host, *port),
            Self::ShellCommand { commandline } => GuardAction::ShellCommand(commandline),
            Self::Patch {
                file_path,
                patch_content,
            } => GuardAction::Patch(file_path, patch_content),
            Self::McpTool {
                tool_name,
                parameters,
            } => GuardAction::McpTool(tool_name, parameters),
            Self::Custom { custom_type, data } => GuardAction::Custom(custom_type, data),
        }
    }

    #[must_use]
    pub fn action_type(&self) -> &'static str {
        match self {
            Self::FileAccess { .. } => "file_access",
            Self::FileWrite { .. } => "file_write",
            Self::NetworkEgress { .. } => "egress",
            Self::ShellCommand { .. } => "shell",
            Self::Patch { .. } => "patch",
            Self::McpTool { .. } => "mcp_tool",
            Self::Custom { .. } => "custom",
        }
    }

    #[must_use]
    pub fn target(&self) -> Option<String> {
        match self {
            Self::FileAccess { path } => Some(path.clone()),
            Self::FileWrite { path, .. } => Some(path.clone()),
            Self::NetworkEgress { host, port } => Some(format!("{}:{}", host, port)),
            Self::ShellCommand { commandline } => Some(commandline.clone()),
            Self::Patch { file_path, .. } => Some(file_path.clone()),
            Self::McpTool { tool_name, .. } => Some(tool_name.clone()),
            Self::Custom { custom_type, .. } => Some(custom_type.clone()),
        }
    }
}

#[derive(Clone, Debug)]
pub struct MappedPolicyEvent {
    pub context: GuardContext,
    pub action: MappedGuardAction,
    pub decision_reason: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EventAgentIdentity {
    endpoint_agent_id: Option<String>,
    runtime_agent_id: Option<String>,
    runtime_agent_kind: Option<String>,
}

impl EventAgentIdentity {
    fn from_metadata(metadata: Option<&serde_json::Value>) -> Self {
        Self {
            endpoint_agent_id: extract_metadata_string(
                metadata,
                &[
                    "endpointAgentId",
                    "endpoint_agent_id",
                    "agentId",
                    "agent_id",
                ],
            )
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
            runtime_agent_id: extract_metadata_string(
                metadata,
                &["runtimeAgentId", "runtime_agent_id"],
            )
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty()),
            runtime_agent_kind: extract_metadata_string(
                metadata,
                &["runtimeAgentKind", "runtime_agent_kind"],
            )
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty()),
        }
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.runtime_agent_id.is_some() ^ self.runtime_agent_kind.is_some() {
            anyhow::bail!("runtime_agent_id and runtime_agent_kind must be provided together");
        }
        if self.runtime_agent_id.is_some() && self.endpoint_agent_id.is_none() {
            anyhow::bail!(
                "endpoint_agent_id is required when runtime_agent_id/runtime_agent_kind are set"
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// map_policy_event (hush-cli version with richer context enrichment)
// ---------------------------------------------------------------------------

pub fn map_policy_event(event: &PolicyEvent) -> anyhow::Result<MappedPolicyEvent> {
    event.validate()?;
    let identity = EventAgentIdentity::from_metadata(event.metadata.as_ref());
    identity.validate()?;

    let mut context = event.to_guard_context();
    if let Some(endpoint) = identity.endpoint_agent_id.clone() {
        context.agent_id = Some(endpoint);
    }

    let data_json = serde_json::to_value(&event.data).context("serialize event data")?;

    let (action, decision_reason) = match (&event.event_type, &event.data) {
        (PolicyEventType::FileRead, PolicyEventData::File(file)) => (
            MappedGuardAction::FileAccess {
                path: file.path.clone(),
            },
            None,
        ),
        (PolicyEventType::FileWrite, PolicyEventData::File(file)) => {
            let mut decision_reason = None;
            let content = if let Some(ref b64) = file.content_base64 {
                BASE64
                    .decode(b64)
                    .with_context(|| "invalid base64 for data.contentBase64")?
            } else if let Some(ref content) = file.content {
                content.as_bytes().to_vec()
            } else {
                decision_reason = Some("missing_content_bytes".to_string());
                Vec::new()
            };

            (
                MappedGuardAction::FileWrite {
                    path: file.path.clone(),
                    content,
                },
                decision_reason,
            )
        }
        (PolicyEventType::NetworkEgress, PolicyEventData::Network(net)) => (
            MappedGuardAction::NetworkEgress {
                host: net.host.clone(),
                port: net.port,
            },
            None,
        ),
        (PolicyEventType::CommandExec, PolicyEventData::Command(cmd)) => (
            MappedGuardAction::ShellCommand {
                commandline: canonical_shell_commandline(&cmd.command, &cmd.args),
            },
            None,
        ),
        (PolicyEventType::PatchApply, PolicyEventData::Patch(patch)) => (
            MappedGuardAction::Patch {
                file_path: patch.file_path.clone(),
                patch_content: patch.patch_content.clone(),
            },
            None,
        ),
        (PolicyEventType::ToolCall, PolicyEventData::Tool(tool)) => {
            let is_mcp = metadata_tool_kind_is_mcp(event.metadata.as_ref())
                || tool.tool_name.starts_with("mcp__");

            if is_mcp {
                (
                    MappedGuardAction::McpTool {
                        tool_name: tool.tool_name.clone(),
                        parameters: tool.parameters.clone(),
                    },
                    None,
                )
            } else {
                (
                    MappedGuardAction::Custom {
                        custom_type: "tool_call".to_string(),
                        data: data_json,
                    },
                    None,
                )
            }
        }
        (PolicyEventType::SecretAccess, PolicyEventData::Secret(_secret)) => (
            MappedGuardAction::Custom {
                custom_type: "secret_access".to_string(),
                data: data_json,
            },
            None,
        ),
        (PolicyEventType::Custom, PolicyEventData::Custom(custom)) => (
            MappedGuardAction::Custom {
                custom_type: custom.custom_type.clone(),
                data: data_json,
            },
            None,
        ),
        (
            PolicyEventType::RemoteSessionConnect
            | PolicyEventType::RemoteSessionDisconnect
            | PolicyEventType::RemoteSessionReconnect
            | PolicyEventType::InputInject
            | PolicyEventType::ClipboardTransfer
            | PolicyEventType::FileTransfer
            | PolicyEventType::RemoteAudio
            | PolicyEventType::RemoteDriveMapping
            | PolicyEventType::RemotePrinting
            | PolicyEventType::SessionShare,
            PolicyEventData::Cua(_),
        ) => (
            MappedGuardAction::Custom {
                custom_type: event.event_type.as_str().to_string(),
                data: data_json,
            },
            None,
        ),
        (PolicyEventType::Other(event_type), _) => {
            anyhow::bail!("unsupported eventType: {}", event_type);
        }
        _ => {
            anyhow::bail!(
                "unsupported mapping for eventType {:?} with data.type {}",
                event.event_type,
                event.data.data_type_key()
            )
        }
    };

    // Attach small, non-sensitive helpers so guards can access richer context.
    if let Some(ref reason) = decision_reason {
        context.metadata = merge_metadata(
            context.metadata,
            serde_json::json!({ "policy_event": { "decision_reason": reason } }),
        );
    }

    if let PolicyEventData::Network(net) = &event.data {
        if let Some(ref url) = net.url {
            context.metadata = merge_metadata(
                context.metadata,
                serde_json::json!({ "policy_event": { "network": { "url": url } } }),
            );
        }
    }

    if let PolicyEventData::File(file) = &event.data {
        if let Some(ref h) = file.content_hash {
            context.metadata = merge_metadata(
                context.metadata,
                serde_json::json!({ "policy_event": { "file": { "content_hash": h } } }),
            );
        }
    }

    if identity.endpoint_agent_id.is_some()
        || identity.runtime_agent_id.is_some()
        || identity.runtime_agent_kind.is_some()
    {
        context.metadata = merge_metadata(
            context.metadata,
            serde_json::json!({
                "identity": {
                    "endpoint_agent_id": identity.endpoint_agent_id,
                    "runtime_agent_id": identity.runtime_agent_id,
                    "runtime_agent_kind": identity.runtime_agent_kind,
                }
            }),
        );
    }

    Ok(MappedPolicyEvent {
        context,
        action,
        decision_reason,
    })
}

// ---------------------------------------------------------------------------
// Canonical shell commandline
// ---------------------------------------------------------------------------

/// Canonical commandline encoding for `PolicyEvent` `command_exec` mapping.
///
/// This intentionally matches the behavior of Python's `shlex.quote` applied to each token,
/// joined with a single ASCII space.
///
/// Safe characters (not quoted): `A-Za-z0-9_@%+=:,./-`
#[must_use]
pub fn canonical_shell_commandline(command: &str, args: &[String]) -> String {
    let mut out = canonical_shell_word(command);
    for arg in args {
        out.push(' ');
        out.push_str(&canonical_shell_word(arg));
    }
    out
}

#[must_use]
pub fn canonical_shell_word(word: &str) -> String {
    if word.is_empty() {
        return "''".to_string();
    }

    if is_safe_shell_word(word) {
        return word.to_string();
    }

    let mut out = String::with_capacity(word.len() + 2);
    out.push('\'');

    for part in word.split('\'') {
        out.push_str(part);
        out.push_str("'\"'\"'");
    }

    out.truncate(out.len().saturating_sub("'\"'\"'".len()));
    out.push('\'');
    out
}

fn is_safe_shell_word(word: &str) -> bool {
    word.bytes().all(|b| {
        matches!(
            b,
            b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'_'
                | b'-'
                | b'.'
                | b'/'
                | b':'
                | b'@'
                | b'%'
                | b'+'
                | b'='
                | b','
        )
    })
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

pub fn extract_metadata_string(
    metadata: Option<&serde_json::Value>,
    keys: &[&str],
) -> Option<String> {
    let serde_json::Value::Object(obj) = metadata? else {
        return None;
    };

    for key in keys {
        if let Some(serde_json::Value::String(s)) = obj.get(*key) {
            return Some(s.clone());
        }
    }

    None
}

fn metadata_tool_kind_is_mcp(metadata: Option<&serde_json::Value>) -> bool {
    let Some(kind) = extract_metadata_string(metadata, &["toolKind", "tool_kind"]) else {
        return false;
    };
    kind.eq_ignore_ascii_case("mcp")
}

fn merge_context_into_metadata(
    metadata: Option<&serde_json::Value>,
    context: Option<&serde_json::Value>,
) -> Option<serde_json::Value> {
    let Some(context) = context else {
        return metadata.cloned();
    };

    let mut out = match metadata.cloned() {
        Some(serde_json::Value::Object(obj)) => serde_json::Value::Object(obj),
        Some(other) => serde_json::json!({ "metadata": other }),
        None => serde_json::Value::Object(serde_json::Map::new()),
    };

    if let serde_json::Value::Object(obj) = &mut out {
        obj.insert("context".to_string(), context.clone());
    }

    Some(out)
}

fn parse_string_array(value: &serde_json::Value) -> Option<Vec<String>> {
    match value {
        serde_json::Value::String(s) => Some(vec![s.clone()]),
        serde_json::Value::Array(items) => {
            let out: Vec<String> = items
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    }
}

fn merge_metadata(
    existing: Option<serde_json::Value>,
    extra: serde_json::Value,
) -> Option<serde_json::Value> {
    let mut out = match existing {
        None => serde_json::Value::Object(serde_json::Map::new()),
        Some(serde_json::Value::Object(obj)) => serde_json::Value::Object(obj),
        Some(other) => serde_json::json!({ "metadata": other }),
    };

    merge_json(&mut out, extra);

    Some(out)
}

/// Maximum recursion depth for JSON merging to prevent stack overflow from
/// crafted deeply-nested metadata/context.
const MERGE_JSON_MAX_DEPTH: u32 = 32;

fn merge_json(target: &mut serde_json::Value, source: serde_json::Value) {
    merge_json_inner(target, source, 0);
}

fn merge_json_inner(target: &mut serde_json::Value, source: serde_json::Value, depth: u32) {
    if depth >= MERGE_JSON_MAX_DEPTH {
        // Beyond depth limit: overwrite instead of merging deeper.
        *target = source;
        return;
    }

    let serde_json::Value::Object(source_obj) = source else {
        *target = source;
        return;
    };

    if !target.is_object() {
        *target = serde_json::Value::Object(serde_json::Map::new());
    }

    let Some(target_obj) = target.as_object_mut() else {
        return;
    };

    for (k, v) in source_obj {
        match (target_obj.get_mut(&k), v) {
            (Some(existing), serde_json::Value::Object(v_obj)) if existing.is_object() => {
                merge_json_inner(existing, serde_json::Value::Object(v_obj), depth + 1);
            }
            (_, v) => {
                target_obj.insert(k, v);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use chrono::Utc;

    fn cua_event(event_type: &str, cua_data: CuaEventData) -> PolicyEvent {
        PolicyEvent {
            event_id: "test-001".to_string(),
            event_type: serde_json::from_value(serde_json::Value::String(event_type.to_string()))
                .unwrap(),
            timestamp: Utc::now(),
            session_id: Some("sess-001".to_string()),
            data: PolicyEventData::Cua(cua_data),
            metadata: None,
            context: None,
        }
    }

    fn base_cua_data(cua_action: &str) -> CuaEventData {
        CuaEventData {
            cua_action: cua_action.to_string(),
            direction: None,
            continuity_prev_session_hash: None,
            postcondition_probe_hash: None,
            extra: serde_json::Map::new(),
        }
    }

    #[test]
    fn runtime_identity_requires_complete_pair() {
        let event = PolicyEvent {
            event_id: "evt-runtime-invalid".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: Some("sess-runtime-invalid".to_string()),
            data: PolicyEventData::File(FileEventData {
                path: "/tmp/test.txt".to_string(),
                operation: Some("read".to_string()),
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: Some(serde_json::json!({
                "agentId": "endpoint-a",
                "runtimeAgentId": "runtime-a"
            })),
            context: None,
        };

        let err = map_policy_event(&event).unwrap_err();
        assert!(
            err.to_string()
                .contains("runtime_agent_id and runtime_agent_kind"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn runtime_identity_enrichment_sets_endpoint_agent_context() {
        let event = PolicyEvent {
            event_id: "evt-runtime-valid".to_string(),
            event_type: PolicyEventType::FileRead,
            timestamp: Utc::now(),
            session_id: Some("sess-runtime-valid".to_string()),
            data: PolicyEventData::File(FileEventData {
                path: "/tmp/test.txt".to_string(),
                operation: Some("read".to_string()),
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: Some(serde_json::json!({
                "endpointAgentId": "endpoint-a",
                "runtimeAgentId": "runtime-a",
                "runtimeAgentKind": "claude_code"
            })),
            context: None,
        };

        let mapped = map_policy_event(&event).expect("map");
        assert_eq!(mapped.context.agent_id.as_deref(), Some("endpoint-a"));
        let identity = mapped
            .context
            .metadata
            .as_ref()
            .and_then(|value| value.get("identity"))
            .cloned()
            .unwrap_or_else(|| panic!("missing identity metadata"));
        assert_eq!(identity["endpoint_agent_id"], "endpoint-a");
        assert_eq!(identity["runtime_agent_id"], "runtime-a");
        assert_eq!(identity["runtime_agent_kind"], "claude_code");
    }

    #[test]
    fn to_guard_context_accepts_origin_context_alias() {
        let event = PolicyEvent {
            event_id: "evt-origin-context".to_string(),
            event_type: PolicyEventType::ToolCall,
            timestamp: Utc::now(),
            session_id: Some("sess-origin-context".to_string()),
            data: PolicyEventData::Tool(ToolEventData {
                tool_name: "safe_tool".to_string(),
                parameters: serde_json::json!({}),
            }),
            metadata: Some(serde_json::json!({
                "originContext": {
                    "provider": "slack",
                    "tenantId": "T123",
                    "spaceId": "C123",
                    "actorRole": "maintainer",
                    "tags": ["provider:slack"]
                }
            })),
            context: None,
        };

        let context = event.to_guard_context();
        let origin = context.origin.expect("origin context should be present");
        assert_eq!(origin.provider.to_string(), "slack");
        assert_eq!(origin.tenant_id.as_deref(), Some("T123"));
        assert_eq!(origin.space_id.as_deref(), Some("C123"));
        assert_eq!(origin.actor_role.as_deref(), Some("maintainer"));
    }

    #[test]
    fn test_cua_connect_event_maps_to_custom_action() {
        let event = cua_event("remote.session.connect", base_cua_data("connect"));
        let mapped = map_policy_event(&event).unwrap();

        match &mapped.action {
            MappedGuardAction::Custom { custom_type, data } => {
                assert_eq!(custom_type, "remote.session.connect");
                assert_eq!(data["cuaAction"], "connect");
            }
            other => panic!("expected Custom action, got {:?}", other),
        }
    }

    #[test]
    fn test_cua_reconnect_preserves_continuity_hash() {
        let mut data = base_cua_data("reconnect");
        data.continuity_prev_session_hash = Some("sha256:abc123".to_string());

        let event = cua_event("remote.session.reconnect", data);
        let mapped = map_policy_event(&event).unwrap();

        match &mapped.action {
            MappedGuardAction::Custom { custom_type, data } => {
                assert_eq!(custom_type, "remote.session.reconnect");
                assert_eq!(data["continuityPrevSessionHash"], "sha256:abc123");
            }
            other => panic!("expected Custom action, got {:?}", other),
        }
    }

    #[test]
    fn test_cua_input_preserves_probe_hash() {
        let mut data = base_cua_data("inject");
        data.postcondition_probe_hash = Some("sha256:probe999".to_string());

        let event = cua_event("input.inject", data);
        let mapped = map_policy_event(&event).unwrap();

        match &mapped.action {
            MappedGuardAction::Custom { custom_type, data } => {
                assert_eq!(custom_type, "input.inject");
                assert_eq!(data["postconditionProbeHash"], "sha256:probe999");
            }
            other => panic!("expected Custom action, got {:?}", other),
        }
    }

    #[test]
    fn test_cua_clipboard_preserves_direction() {
        let mut data = base_cua_data("clipboard");
        data.direction = Some("read".to_string());

        let event = cua_event("remote.clipboard", data);
        let mapped = map_policy_event(&event).unwrap();

        match &mapped.action {
            MappedGuardAction::Custom { custom_type, data } => {
                assert_eq!(custom_type, "remote.clipboard");
                assert_eq!(data["direction"], "read");
            }
            other => panic!("expected Custom action, got {:?}", other),
        }
    }

    #[test]
    fn test_cua_file_transfer_preserves_direction() {
        let mut data = base_cua_data("file_transfer");
        data.direction = Some("upload".to_string());

        let event = cua_event("remote.file_transfer", data);
        let mapped = map_policy_event(&event).unwrap();

        match &mapped.action {
            MappedGuardAction::Custom { custom_type, data } => {
                assert_eq!(custom_type, "remote.file_transfer");
                assert_eq!(data["direction"], "upload");
            }
            other => panic!("expected Custom action, got {:?}", other),
        }
    }

    #[test]
    fn test_cua_event_type_mismatch_rejected() {
        let event = PolicyEvent {
            event_id: "test-mismatch".to_string(),
            event_type: PolicyEventType::RemoteSessionConnect,
            timestamp: Utc::now(),
            session_id: None,
            data: PolicyEventData::File(FileEventData {
                path: "/etc/passwd".to_string(),
                operation: None,
                content_base64: None,
                content: None,
                content_hash: None,
            }),
            metadata: None,
            context: None,
        };

        let err = map_policy_event(&event).unwrap_err();
        assert!(
            err.to_string().contains("does not match"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_cua_event_roundtrip_serialization() {
        let mut data = base_cua_data("connect");
        data.direction = Some("write".to_string());
        data.continuity_prev_session_hash = Some("sha256:prev".to_string());
        data.postcondition_probe_hash = Some("sha256:probe".to_string());
        data.extra
            .insert("customField".to_string(), serde_json::json!("value"));

        let event = cua_event("remote.session.connect", data);
        let json = serde_json::to_value(&event).unwrap();
        let roundtripped: PolicyEvent = serde_json::from_value(json).unwrap();

        assert_eq!(event.event_id, roundtripped.event_id);
        assert_eq!(event.event_type, roundtripped.event_type);
        assert_eq!(event.session_id, roundtripped.session_id);

        match (&event.data, &roundtripped.data) {
            (PolicyEventData::Cua(orig), PolicyEventData::Cua(rt)) => {
                assert_eq!(orig.cua_action, rt.cua_action);
                assert_eq!(orig.direction, rt.direction);
                assert_eq!(
                    orig.continuity_prev_session_hash,
                    rt.continuity_prev_session_hash
                );
                assert_eq!(orig.postcondition_probe_hash, rt.postcondition_probe_hash);
                assert_eq!(orig.extra.get("customField"), rt.extra.get("customField"));
            }
            _ => panic!("expected Cua data in both original and roundtripped"),
        }
    }

    #[test]
    fn test_cua_event_type_as_str_roundtrips() {
        let types = vec![
            PolicyEventType::RemoteSessionConnect,
            PolicyEventType::RemoteSessionDisconnect,
            PolicyEventType::RemoteSessionReconnect,
            PolicyEventType::InputInject,
            PolicyEventType::ClipboardTransfer,
            PolicyEventType::FileTransfer,
            PolicyEventType::RemoteAudio,
            PolicyEventType::RemoteDriveMapping,
            PolicyEventType::RemotePrinting,
            PolicyEventType::SessionShare,
        ];
        let expected_strs = vec![
            "remote.session.connect",
            "remote.session.disconnect",
            "remote.session.reconnect",
            "input.inject",
            "remote.clipboard",
            "remote.file_transfer",
            "remote.audio",
            "remote.drive_mapping",
            "remote.printing",
            "remote.session_share",
        ];

        for (et, expected) in types.iter().zip(expected_strs.iter()) {
            assert_eq!(et.as_str(), *expected);
            let json = serde_json::Value::String(expected.to_string());
            let deserialized: PolicyEventType = serde_json::from_value(json).unwrap();
            assert_eq!(deserialized, *et);
        }
    }

    #[test]
    fn test_cua_data_deserializes_with_snake_case_aliases() {
        let json = serde_json::json!({
            "type": "cua",
            "cua_action": "reconnect",
            "continuity_prev_session_hash": "sha256:prev_alias",
            "postcondition_probe_hash": "sha256:probe_alias"
        });

        let data: PolicyEventData = serde_json::from_value(json).unwrap();
        match data {
            PolicyEventData::Cua(cua) => {
                assert_eq!(cua.cua_action, "reconnect");
                assert_eq!(
                    cua.continuity_prev_session_hash.as_deref(),
                    Some("sha256:prev_alias")
                );
                assert_eq!(
                    cua.postcondition_probe_hash.as_deref(),
                    Some("sha256:probe_alias")
                );
            }
            other => panic!("expected Cua data, got {:?}", other),
        }
    }
}
