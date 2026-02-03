use anyhow::Context as _;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clawdstrike::guards::GuardAction;
use clawdstrike::GuardContext;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyEventType {
    FileRead,
    FileWrite,
    NetworkEgress,
    CommandExec,
    PatchApply,
    ToolCall,
    Custom,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEvent {
    #[serde(alias = "event_id")]
    pub event_id: String,
    #[serde(alias = "event_type")]
    pub event_type: PolicyEventType,
    pub timestamp: String,
    #[serde(default, alias = "session_id", skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    pub data: PolicyEventData,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl PolicyEvent {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.event_id.trim().is_empty() {
            anyhow::bail!("eventId must be a non-empty string");
        }

        let matches = match (self.event_type, &self.data) {
            (PolicyEventType::FileRead, PolicyEventData::File(_)) => true,
            (PolicyEventType::FileWrite, PolicyEventData::File(_)) => true,
            (PolicyEventType::NetworkEgress, PolicyEventData::Network(_)) => true,
            (PolicyEventType::CommandExec, PolicyEventData::Command(_)) => true,
            (PolicyEventType::PatchApply, PolicyEventData::Patch(_)) => true,
            (PolicyEventType::ToolCall, PolicyEventData::Tool(_)) => true,
            (PolicyEventType::Custom, PolicyEventData::Custom(_)) => true,
            _ => false,
        };

        if !matches {
            anyhow::bail!(
                "eventType {:?} does not match data.type {}",
                self.event_type,
                self.data.data_type_name()
            );
        }

        Ok(())
    }

    pub fn to_guard_context(&self) -> GuardContext {
        let mut ctx = GuardContext::new();
        ctx.session_id = self.session_id.clone();
        ctx.agent_id = extract_metadata_string(self.metadata.as_ref(), &["agentId", "agent_id"]);
        ctx.metadata = self.metadata.clone();
        ctx
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PolicyEventData {
    File(FileEventData),
    Network(NetworkEventData),
    Command(CommandEventData),
    Patch(PatchEventData),
    Tool(ToolEventData),
    Custom(CustomEventData),
}

impl PolicyEventData {
    fn data_type_name(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Network(_) => "network",
            Self::Command(_) => "command",
            Self::Patch(_) => "patch",
            Self::Tool(_) => "tool",
            Self::Custom(_) => "custom",
        }
    }
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
    #[serde(default, alias = "content_hash", skip_serializing_if = "Option::is_none")]
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

#[derive(Clone, Debug, PartialEq)]
pub enum MappedGuardAction {
    FileAccess { path: String },
    FileWrite { path: String, content: Vec<u8> },
    NetworkEgress { host: String, port: u16 },
    ShellCommand { commandline: String },
    Patch { file_path: String, patch_content: String },
    McpTool { tool_name: String, parameters: serde_json::Value },
    Custom { custom_type: String, data: serde_json::Value },
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
        (PolicyEventType::CommandExec, PolicyEventData::Command(cmd)) => {
            let mut commandline = cmd.command.clone();
            for arg in &cmd.args {
                commandline.push(' ');
                commandline.push_str(arg);
            }
            (MappedGuardAction::ShellCommand { commandline }, None)
        }
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
        _ => {
            anyhow::bail!(
                "unsupported mapping for eventType {:?} with data.type {}",
                event.event_type,
                event.data.data_type_name()
            )
        }
    };

    Ok(MappedPolicyEvent {
        context,
        action,
        decision_reason,
    })
}
