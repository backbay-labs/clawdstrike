use std::collections::HashMap;

use hush_core::PublicKey;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(String);

impl AgentId {
    pub fn new(id: impl Into<String>) -> Result<Self> {
        let id = id.into();
        if id.trim().is_empty() {
            return Err(Error::InvalidId("agent id is empty".to_string()));
        }
        Ok(Self(id))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AgentId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    Untrusted = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    System = 4,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentRole {
    Planner,
    Coder,
    Tester,
    Reviewer,
    Deployer,
    Monitor,
    Custom(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "type")]
pub enum AgentCapability {
    FileRead {
        patterns: Vec<String>,
    },
    FileWrite {
        patterns: Vec<String>,
    },
    NetworkEgress {
        hosts: Vec<String>,
    },
    CommandExec {
        commands: Vec<String>,
    },
    SecretAccess {
        secret_names: Vec<String>,
    },
    McpTool {
        tools: Vec<String>,
    },
    DeployApproval,
    AgentAdmin,
    Custom {
        name: String,
        params: serde_json::Value,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    pub id: AgentId,
    pub name: String,
    pub role: AgentRole,
    pub trust_level: TrustLevel,
    pub public_key: PublicKey,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<AgentCapability>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl AgentIdentity {
    pub fn validate_basic(&self) -> Result<()> {
        if self.name.trim().is_empty() {
            return Err(Error::InvalidClaims("agent name is empty".to_string()));
        }
        Ok(())
    }
}
