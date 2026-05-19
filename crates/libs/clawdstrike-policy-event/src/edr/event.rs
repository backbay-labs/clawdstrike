use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::event::{
    CommandEventData, CustomEventData, FileEventData, NetworkEventData, PolicyEvent,
    PolicyEventData, PolicyEventType, SecretEventData, ToolEventData,
};
use super::process::EndpointProcess;
use super::{
    endpoint_event_from_policy_event, metadata_as_btree, process_from_metadata, stable_id,
    string_field,
};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EndpointEvent {
    ProcessExec {
        image: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        env: BTreeMap<String, String>,
    },
    FileAccess {
        operation: FileOperation,
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_url: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        content_preview: Option<String>,
    },
    NetworkFlow {
        host: String,
        port: u16,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        protocol: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        url: Option<String>,
    },
    DnsLookup {
        query: String,
        #[serde(default, alias = "recordType", skip_serializing_if = "Option::is_none")]
        record_type: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        answers: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        resolver: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        status: Option<String>,
    },
    PackageScript {
        manager: PackageManager,
        package: Option<String>,
        phase: String,
        script: String,
        working_directory: Option<String>,
    },
    DylibLoad {
        path: String,
        target_image: Option<String>,
        mechanism: Option<String>,
    },
    LaunchPersistence {
        path: String,
        label: Option<String>,
        operation: FileOperation,
    },
    BrowserExtensionInstall {
        browser: String,
        extension_id: Option<String>,
        path: String,
        source: Option<String>,
    },
    BrowserDownload {
        browser: String,
        path: String,
        source_url: Option<String>,
        #[serde(
            default,
            alias = "contentHash",
            alias = "sha256",
            alias = "fileHash",
            alias = "file_hash",
            alias = "downloadHash",
            alias = "download_hash",
            skip_serializing_if = "Option::is_none"
        )]
        content_hash: Option<String>,
        #[serde(
            default,
            alias = "byteCount",
            alias = "downloadByteCount",
            alias = "download_byte_count",
            alias = "fileSize",
            alias = "file_size",
            alias = "transferSize",
            alias = "transfer_size",
            skip_serializing_if = "Option::is_none"
        )]
        byte_count: Option<u64>,
    },
    CredentialAccess {
        kind: CredentialKind,
        path: Option<String>,
        name: Option<String>,
    },
    ToolCall {
        tool_name: String,
        #[serde(default)]
        parameters: serde_json::Value,
    },
    PolicyDecision {
        action: String,
        target: Option<String>,
        decision: String,
        guard: Option<String>,
        severity: Option<String>,
    },
    Other {
        category: String,
        #[serde(default)]
        fields: BTreeMap<String, serde_json::Value>,
    },
}

impl EndpointEvent {
    #[must_use]
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::ProcessExec { .. } => "process_exec",
            Self::FileAccess { .. } => "file_access",
            Self::NetworkFlow { .. } => "network_flow",
            Self::DnsLookup { .. } => "dns_lookup",
            Self::PackageScript { .. } => "package_script",
            Self::DylibLoad { .. } => "dylib_load",
            Self::LaunchPersistence { .. } => "launch_persistence",
            Self::BrowserExtensionInstall { .. } => "browser_extension_install",
            Self::BrowserDownload { .. } => "browser_download",
            Self::CredentialAccess { .. } => "credential_access",
            Self::ToolCall { .. } => "tool_call",
            Self::PolicyDecision { .. } => "policy_decision",
            Self::Other { .. } => "other",
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Read,
    Write,
    Create,
    Delete,
    Rename,
    Execute,
    Chmod,
    #[default]
    Unknown,
}

impl FileOperation {
    pub(crate) fn from_policy_operation(operation: Option<&str>, event_type: &PolicyEventType) -> Self {
        match operation
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("read" | "open" | "file_read") => Self::Read,
            Some("write" | "file_write") => Self::Write,
            Some("create") => Self::Create,
            Some("delete" | "unlink") => Self::Delete,
            Some("rename" | "move") => Self::Rename,
            Some("execute" | "exec") => Self::Execute,
            Some("chmod") => Self::Chmod,
            _ if *event_type == PolicyEventType::FileRead => Self::Read,
            _ if *event_type == PolicyEventType::FileWrite => Self::Write,
            _ => Self::Unknown,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Bun,
    Pip,
    Cargo,
    Brew,
    Go,
    Gem,
    Composer,
    Maven,
    Gradle,
    Uv,
    Poetry,
    Pipenv,
    Dotnet,
    Nuget,
    Swift,
    Mix,
    Other(String),
}

impl PackageManager {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Npm => "npm",
            Self::Pnpm => "pnpm",
            Self::Yarn => "yarn",
            Self::Bun => "bun",
            Self::Pip => "pip",
            Self::Cargo => "cargo",
            Self::Brew => "brew",
            Self::Go => "go",
            Self::Gem => "gem",
            Self::Composer => "composer",
            Self::Maven => "maven",
            Self::Gradle => "gradle",
            Self::Uv => "uv",
            Self::Poetry => "poetry",
            Self::Pipenv => "pipenv",
            Self::Dotnet => "dotnet",
            Self::Nuget => "nuget",
            Self::Swift => "swift",
            Self::Mix => "mix",
            Self::Other(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    SshKey,
    ApiToken,
    CloudCredential,
    PackageRegistryToken,
    BrowserCookie,
    SigningKey,
    Other(String),
}

impl CredentialKind {
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::SshKey => "ssh_key",
            Self::ApiToken => "api_token",
            Self::CloudCredential => "cloud_credential",
            Self::PackageRegistryToken => "package_registry_token",
            Self::BrowserCookie => "browser_cookie",
            Self::SigningKey => "signing_key",
            Self::Other(value) => value.as_str(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointObservation {
    pub observation_id: String,
    pub timestamp: DateTime<Utc>,
    pub host_id: Option<String>,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub process: EndpointProcess,
    pub event: EndpointEvent,
    pub metadata: BTreeMap<String, serde_json::Value>,
}

impl Default for EndpointObservation {
    fn default() -> Self {
        Self {
            observation_id: stable_id("obs", ["default"]),
            timestamp: Utc::now(),
            host_id: None,
            user_id: None,
            session_id: None,
            process: EndpointProcess::default(),
            event: EndpointEvent::Other {
                category: "unknown".to_string(),
                fields: BTreeMap::new(),
            },
            metadata: BTreeMap::new(),
        }
    }
}

impl EndpointObservation {
    #[must_use]
    pub fn event_name(&self) -> &'static str {
        self.event.kind_name()
    }

    #[must_use]
    pub fn from_policy_event(event: &PolicyEvent) -> Self {
        let metadata = metadata_as_btree(event.metadata.as_ref(), event.context.as_ref());
        let process = process_from_metadata(&metadata);
        Self {
            observation_id: event.event_id.clone(),
            timestamp: event.timestamp,
            host_id: string_field(
                &metadata,
                &[
                    "hostId",
                    "host_id",
                    "endpointHostId",
                    "endpoint_host_id",
                    "endpointId",
                    "endpoint_id",
                ],
            ),
            user_id: string_field(
                &metadata,
                &[
                    "userId",
                    "user_id",
                    "principal",
                    "principalId",
                    "principal_id",
                ],
            ),
            session_id: event
                .session_id
                .clone()
                .or_else(|| string_field(&metadata, &["sessionId", "session_id"])),
            process,
            event: endpoint_event_from_policy_event(event),
            metadata,
        }
    }

    #[must_use]
    pub fn to_policy_event_projection(&self) -> PolicyEvent {
        let metadata = policy_event_metadata_from_observation(self);
        match &self.event {
            EndpointEvent::FileAccess {
                operation,
                path,
                content_preview,
                ..
            } => {
                let Some((event_type, operation_name)) = policy_event_file_operation(operation)
                else {
                    return custom_policy_event_from_observation(self, "endpoint.file_access");
                };
                PolicyEvent {
                    event_id: self.observation_id.clone(),
                    event_type,
                    timestamp: self.timestamp,
                    session_id: self.session_id.clone(),
                    data: PolicyEventData::File(FileEventData {
                        path: path.clone(),
                        operation: Some(operation_name.to_string()),
                        content_base64: None,
                        content: content_preview.clone(),
                        content_hash: None,
                    }),
                    metadata,
                    context: None,
                }
            }
            EndpointEvent::NetworkFlow {
                host,
                port,
                protocol,
                url,
            } => PolicyEvent {
                event_id: self.observation_id.clone(),
                event_type: PolicyEventType::NetworkEgress,
                timestamp: self.timestamp,
                session_id: self.session_id.clone(),
                data: PolicyEventData::Network(NetworkEventData {
                    host: host.clone(),
                    port: *port,
                    protocol: protocol.clone(),
                    url: url.clone(),
                }),
                metadata,
                context: None,
            },
            EndpointEvent::DnsLookup { .. } => {
                custom_policy_event_from_observation(self, "endpoint.dns_lookup")
            }
            EndpointEvent::ProcessExec { image, args, .. } => PolicyEvent {
                event_id: self.observation_id.clone(),
                event_type: PolicyEventType::CommandExec,
                timestamp: self.timestamp,
                session_id: self.session_id.clone(),
                data: PolicyEventData::Command(CommandEventData {
                    command: image.clone(),
                    args: args.clone(),
                }),
                metadata,
                context: None,
            },
            EndpointEvent::ToolCall {
                tool_name,
                parameters,
            } => PolicyEvent {
                event_id: self.observation_id.clone(),
                event_type: PolicyEventType::ToolCall,
                timestamp: self.timestamp,
                session_id: self.session_id.clone(),
                data: PolicyEventData::Tool(ToolEventData {
                    tool_name: tool_name.clone(),
                    parameters: parameters.clone(),
                }),
                metadata,
                context: None,
            },
            EndpointEvent::CredentialAccess { kind, path, name } => PolicyEvent {
                event_id: self.observation_id.clone(),
                event_type: PolicyEventType::SecretAccess,
                timestamp: self.timestamp,
                session_id: self.session_id.clone(),
                data: PolicyEventData::Secret(SecretEventData {
                    secret_name: name
                        .clone()
                        .or_else(|| path.clone())
                        .unwrap_or_else(|| kind.as_str().to_string()),
                    scope: kind.as_str().to_string(),
                }),
                metadata,
                context: None,
            },
            EndpointEvent::Other { category, fields } => {
                let mut extra = serde_json::Map::new();
                for (key, value) in fields {
                    extra.insert(key.clone(), value.clone());
                }
                extra.insert(
                    "endpointEventKind".to_string(),
                    serde_json::Value::String(self.event_name().to_string()),
                );
                PolicyEvent {
                    event_id: self.observation_id.clone(),
                    event_type: PolicyEventType::Custom,
                    timestamp: self.timestamp,
                    session_id: self.session_id.clone(),
                    data: PolicyEventData::Custom(CustomEventData {
                        custom_type: category.clone(),
                        extra,
                    }),
                    metadata,
                    context: None,
                }
            }
            EndpointEvent::PackageScript { .. } => {
                custom_policy_event_from_observation(self, "endpoint.package_script")
            }
            EndpointEvent::DylibLoad { .. } => {
                custom_policy_event_from_observation(self, "endpoint.dylib_load")
            }
            EndpointEvent::LaunchPersistence { .. } => {
                custom_policy_event_from_observation(self, "endpoint.launch_persistence")
            }
            EndpointEvent::BrowserExtensionInstall { .. } => {
                custom_policy_event_from_observation(self, "endpoint.browser_extension_install")
            }
            EndpointEvent::BrowserDownload { .. } => {
                custom_policy_event_from_observation(self, "endpoint.browser_download")
            }
            EndpointEvent::PolicyDecision { .. } => {
                custom_policy_event_from_observation(self, "endpoint.policy_decision")
            }
        }
    }
}

fn policy_event_file_operation(
    operation: &FileOperation,
) -> Option<(PolicyEventType, &'static str)> {
    match operation {
        FileOperation::Read => Some((PolicyEventType::FileRead, "read")),
        FileOperation::Write => Some((PolicyEventType::FileWrite, "write")),
        FileOperation::Create => Some((PolicyEventType::FileWrite, "create")),
        FileOperation::Delete => Some((PolicyEventType::FileWrite, "delete")),
        FileOperation::Rename => Some((PolicyEventType::FileWrite, "rename")),
        FileOperation::Chmod => Some((PolicyEventType::FileWrite, "chmod")),
        FileOperation::Execute | FileOperation::Unknown => None,
    }
}

fn policy_event_metadata_from_observation(
    observation: &EndpointObservation,
) -> Option<serde_json::Value> {
    let mut metadata = serde_json::Map::new();
    for (key, value) in &observation.metadata {
        metadata.insert(key.clone(), value.clone());
    }
    if let Some(host_id) = observation.host_id.as_ref() {
        metadata
            .entry("hostId".to_string())
            .or_insert_with(|| serde_json::Value::String(host_id.clone()));
    }
    if let Some(user_id) = observation.user_id.as_ref() {
        metadata
            .entry("userId".to_string())
            .or_insert_with(|| serde_json::Value::String(user_id.clone()));
    }
    if let Ok(process) = serde_json::to_value(&observation.process) {
        metadata.entry("process".to_string()).or_insert(process);
    }
    metadata.insert(
        "endpointObservationId".to_string(),
        serde_json::Value::String(observation.observation_id.clone()),
    );
    metadata.insert(
        "endpointEventKind".to_string(),
        serde_json::Value::String(observation.event_name().to_string()),
    );

    if metadata.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(metadata))
    }
}

fn custom_policy_event_from_observation(
    observation: &EndpointObservation,
    custom_type: &str,
) -> PolicyEvent {
    let mut extra = serde_json::Map::new();
    extra.insert(
        "endpointEventKind".to_string(),
        serde_json::Value::String(observation.event_name().to_string()),
    );
    extra.insert(
        "endpointEvent".to_string(),
        serde_json::to_value(&observation.event).unwrap_or(serde_json::Value::Null),
    );

    PolicyEvent {
        event_id: observation.observation_id.clone(),
        event_type: PolicyEventType::Custom,
        timestamp: observation.timestamp,
        session_id: observation.session_id.clone(),
        data: PolicyEventData::Custom(CustomEventData {
            custom_type: custom_type.to_string(),
            extra,
        }),
        metadata: policy_event_metadata_from_observation(observation),
        context: None,
    }
}

