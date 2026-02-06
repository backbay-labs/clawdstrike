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

#[cfg(test)]
mod tests {
    use super::*;
    use hush_core::Keypair;

    #[test]
    fn agent_id_valid() {
        let id = AgentId::new("agent:test-1").unwrap();
        assert_eq!(id.as_str(), "agent:test-1");
        assert_eq!(id.to_string(), "agent:test-1");
    }

    #[test]
    fn agent_id_empty_rejected() {
        let result = AgentId::new("");
        assert!(result.is_err());
    }

    #[test]
    fn agent_id_whitespace_only_rejected() {
        let result = AgentId::new("   ");
        assert!(result.is_err());
    }

    #[test]
    fn trust_level_ordering() {
        assert!(TrustLevel::Untrusted < TrustLevel::Low);
        assert!(TrustLevel::Low < TrustLevel::Medium);
        assert!(TrustLevel::Medium < TrustLevel::High);
        assert!(TrustLevel::High < TrustLevel::System);
    }

    #[test]
    fn trust_level_serde_roundtrip() {
        let json = serde_json::to_string(&TrustLevel::High).unwrap();
        assert_eq!(json, "\"high\"");
        let parsed: TrustLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, TrustLevel::High);
    }

    #[test]
    fn agent_identity_valid() {
        let kp = Keypair::generate();
        let identity = AgentIdentity {
            id: AgentId::new("agent:planner").unwrap(),
            name: "Planner Agent".to_string(),
            role: AgentRole::Planner,
            trust_level: TrustLevel::Medium,
            public_key: kp.public_key(),
            capabilities: vec![AgentCapability::DeployApproval],
            metadata: HashMap::new(),
        };
        identity.validate_basic().unwrap();
    }

    #[test]
    fn agent_identity_empty_name_rejected() {
        let kp = Keypair::generate();
        let identity = AgentIdentity {
            id: AgentId::new("agent:bad").unwrap(),
            name: "   ".to_string(),
            role: AgentRole::Coder,
            trust_level: TrustLevel::Low,
            public_key: kp.public_key(),
            capabilities: vec![],
            metadata: HashMap::new(),
        };
        assert!(identity.validate_basic().is_err());
    }

    #[test]
    fn agent_identity_serde_roundtrip() {
        let kp = Keypair::generate();
        let mut meta = HashMap::new();
        meta.insert("env".to_string(), "production".to_string());

        let identity = AgentIdentity {
            id: AgentId::new("agent:test").unwrap(),
            name: "Test Agent".to_string(),
            role: AgentRole::Tester,
            trust_level: TrustLevel::High,
            public_key: kp.public_key(),
            capabilities: vec![
                AgentCapability::FileRead {
                    patterns: vec!["*.rs".to_string()],
                },
                AgentCapability::NetworkEgress {
                    hosts: vec!["api.example.com".to_string()],
                },
            ],
            metadata: meta,
        };

        let json = serde_json::to_string(&identity).unwrap();
        let parsed: AgentIdentity = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.id.as_str(), "agent:test");
        assert_eq!(parsed.name, "Test Agent");
        assert_eq!(parsed.trust_level, TrustLevel::High);
        assert_eq!(parsed.capabilities.len(), 2);
        assert_eq!(parsed.metadata.get("env").map(String::as_str), Some("production"));
    }

    #[test]
    fn capability_serde_tagged() {
        let cap = AgentCapability::FileRead {
            patterns: vec!["src/**".to_string()],
        };
        let json = serde_json::to_string(&cap).unwrap();
        assert!(json.contains("\"type\":\"file_read\""));

        let parsed: AgentCapability = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, cap);
    }

    #[test]
    fn agent_role_custom_serde() {
        let role = AgentRole::Custom("orchestrator".to_string());
        let json = serde_json::to_string(&role).unwrap();
        let parsed: AgentRole = serde_json::from_str(&json).unwrap();
        if let AgentRole::Custom(name) = parsed {
            assert_eq!(name, "orchestrator");
        } else {
            panic!("Expected Custom role");
        }
    }
}
