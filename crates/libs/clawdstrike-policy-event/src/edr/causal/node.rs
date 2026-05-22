use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalNodeKind {
    Host,
    User,
    Session,
    Agent,
    Workload,
    Approval,
    Process,
    File,
    Network,
    DnsName,
    PackageScript,
    Credential,
    BrowserDownload,
    BrowserExtension,
    PolicyDecision,
    Tool,
    DeceptionArtifact,
    Other,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalNode {
    pub node_id: String,
    pub kind: CausalNodeKind,
    pub label: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CausalEdgeKind {
    ObservedOn,
    RanAs,
    InSession,
    UsedAgent,
    UsedWorkload,
    AuthorizedBy,
    Spawned,
    Executed,
    Read,
    Wrote,
    Connected,
    ResolvedDns,
    RanScript,
    LoadedLibrary,
    CreatedPersistence,
    InstalledExtension,
    Downloaded,
    AccessedCredential,
    MadeDecision,
    InvokedTool,
    TemporalNext,
    TouchedHoney,
    Related,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CausalEdge {
    pub edge_id: String,
    pub from: String,
    pub to: String,
    pub kind: CausalEdgeKind,
    pub timestamp: DateTime<Utc>,
    pub observation_id: String,
    #[serde(default)]
    pub attributes: BTreeMap<String, serde_json::Value>,
}
