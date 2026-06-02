//! Built-in named rulesets backed by embedded YAML (`include_str!`).

use serde::{Deserialize, Serialize};

use super::Policy;
use crate::error::Result;

/// Named ruleset with pre-configured policies
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleSet {
    /// Ruleset identifier
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
    /// The policy
    pub policy: Policy,
}

impl RuleSet {
    pub fn yaml_by_name(name: &str) -> Option<(&'static str, String)> {
        let id = name.strip_prefix("clawdstrike:").unwrap_or(name);

        let yaml = match id {
            "default" => Some(include_str!("../../rulesets/default.yaml")),
            "strict" => Some(include_str!("../../rulesets/strict.yaml")),
            "ai-agent" => Some(include_str!("../../rulesets/ai-agent.yaml")),
            "ai-agent-posture" => Some(include_str!("../../rulesets/ai-agent-posture.yaml")),
            "cicd" => Some(include_str!("../../rulesets/cicd.yaml")),
            "permissive" => Some(include_str!("../../rulesets/permissive.yaml")),
            "remote-desktop" => Some(include_str!("../../rulesets/remote-desktop.yaml")),
            "remote-desktop-strict" => {
                Some(include_str!("../../rulesets/remote-desktop-strict.yaml"))
            }
            "remote-desktop-permissive" => Some(include_str!(
                "../../rulesets/remote-desktop-permissive.yaml"
            )),
            #[cfg(feature = "full")]
            "spider-sense" => Some(include_str!("../../rulesets/spider-sense.yaml")),
            "origin-enclaves-example" => {
                Some(include_str!("../../rulesets/origin-enclaves-example.yaml"))
            }
            _ => None,
        }?;

        Some((yaml, id.to_string()))
    }

    pub fn by_name(name: &str) -> Result<Option<Self>> {
        let Some((yaml, id)) = Self::yaml_by_name(name) else {
            return Ok(None);
        };

        let policy = Policy::from_yaml_with_extends(yaml, None)?;
        Ok(Some(Self {
            id,
            name: policy.name.clone(),
            description: policy.description.clone(),
            policy,
        }))
    }

    pub fn list() -> &'static [&'static str] {
        &[
            "default",
            "strict",
            "ai-agent",
            "ai-agent-posture",
            "cicd",
            "permissive",
            "remote-desktop",
            "remote-desktop-strict",
            "remote-desktop-permissive",
            #[cfg(feature = "full")]
            "spider-sense",
            "origin-enclaves-example",
        ]
    }
}
