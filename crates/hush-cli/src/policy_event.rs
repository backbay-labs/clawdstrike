use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use chrono::{DateTime, Utc};
use clawdstrike::guards::GuardAction;
use clawdstrike::GuardContext;
use serde::{Deserialize, Serialize};

pub enum PolicyEventType {
    FileRead,
    FileWrite,
    NetworkEgress,
    CommandExec,
    PatchApply,
    ToolCall,
    Custom,
    Other(String),
}

impl PolicyEventType {
    pub fn as_str(&self) -> &str {
        match self {
            Self::FileRead => "file_read",
            Self::FileWrite => "file_write",
            Self::NetworkEgress => "network_egress",
            Self::CommandExec => "command_exec",
            Self::PatchApply => "patch_apply",
            Self::ToolCall => "tool_call",
            Self::Custom => "custom",
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

impl Clone for PolicyEventType {
    fn clone(&self) -> Self {
        match self {
            Self::FileRead => Self::FileRead,
            Self::FileWrite => Self::FileWrite,
            Self::NetworkEgress => Self::NetworkEgress,
            Self::CommandExec => Self::CommandExec,
            Self::PatchApply => Self::PatchApply,
            Self::ToolCall => Self::ToolCall,
            Self::Custom => Self::Custom,
            Self::Other(s) => Self::Other(s.clone()),
        }
    }
}

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
            "custom" => Self::Custom,
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
            (PolicyEventType::Custom, PolicyEventData::Custom(_)) => {}
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

    pub fn to_guard_context(&self) -> GuardContext {
        let mut ctx = GuardContext::new();
        ctx.session_id = self.session_id.clone();
        ctx.agent_id = extract_metadata_string(self.metadata.as_ref(), &["agentId", "agent_id"]);
        ctx.metadata = merge_context_into_metadata(self.metadata.as_ref(), self.context.as_ref());
        ctx
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum PolicyEventData {
    File(FileEventData),
    Network(NetworkEventData),
    Command(CommandEventData),
    Patch(PatchEventData),
    Tool(ToolEventData),
    Custom(CustomEventData),
    Other {
        type_name: String,
        value: serde_json::Value,
    },
}

impl PolicyEventData {
    fn data_type_key(&self) -> &str {
        match self {
            Self::File(_) => "file",
            Self::Network(_) => "network",
            Self::Command(_) => "command",
            Self::Patch(_) => "patch",
            Self::Tool(_) => "tool",
            Self::Custom(_) => "custom",
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
            Self::Custom(inner) => {
                serialize_typed_data("custom", inner).map_err(serde::ser::Error::custom)?
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
            "custom" => serde_json::from_value::<CustomEventData>(value)
                .map(Self::Custom)
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
pub struct CustomEventData {
    #[serde(alias = "custom_type")]
    pub custom_type: String,
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::Value::Object(serde_json::Map::new())
}

fn extract_metadata_string(metadata: Option<&serde_json::Value>, keys: &[&str]) -> Option<String> {
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
}

#[derive(Clone, Debug)]
pub struct MappedPolicyEvent {
    pub context: GuardContext,
    pub action: MappedGuardAction,
    pub decision_reason: Option<String>,
}

pub fn map_policy_event(event: &PolicyEvent) -> anyhow::Result<MappedPolicyEvent> {
    event.validate()?;

    let context = event.to_guard_context();

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
                commandline: shell_join_posix(&cmd.command, &cmd.args),
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
        (PolicyEventType::Custom, PolicyEventData::Custom(custom)) => (
            MappedGuardAction::Custom {
                custom_type: custom.custom_type.clone(),
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

    Ok(MappedPolicyEvent {
        context,
        action,
        decision_reason,
    })
}

fn shell_join_posix(command: &str, args: &[String]) -> String {
    let mut out = shell_quote_posix(command);
    for arg in args {
        out.push(' ');
        out.push_str(&shell_quote_posix(arg));
    }
    out
}

fn shell_quote_posix(s: &str) -> String {
    if s.is_empty() {
        return "''".to_string();
    }

    if is_safe_shell_word(s) {
        return s.to_string();
    }

    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');

    for part in s.split('\'') {
        out.push_str(part);
        out.push_str("'\"'\"'");
    }

    // Remove the trailing escaped-quote sequence we added after the final segment.
    out.truncate(out.len().saturating_sub("'\"'\"'".len()));
    out.push('\'');
    out
}

fn is_safe_shell_word(s: &str) -> bool {
    s.bytes().all(|b| {
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
