use serde::{Deserialize, Serialize};

use super::stable_id;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureTrust {
    #[default]
    Unknown,
    Unsigned,
    AdHoc,
    Signed,
    Notarized,
    Invalid,
    Drifted,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct CodeSignatureStatus {
    pub trust: SignatureTrust,
    pub team_id: Option<String>,
    pub signing_id: Option<String>,
    pub cdhash: Option<String>,
    pub expected_cdhash: Option<String>,
    pub notarized: Option<bool>,
}

impl CodeSignatureStatus {
    #[must_use]
    pub fn has_drift(&self) -> bool {
        if matches!(
            self.trust,
            SignatureTrust::Invalid | SignatureTrust::Drifted
        ) {
            return true;
        }

        match (&self.cdhash, &self.expected_cdhash) {
            (Some(actual), Some(expected)) => {
                !actual.trim().is_empty() && !expected.trim().is_empty() && actual != expected
            }
            _ => false,
        }
    }

    #[must_use]
    pub fn is_untrusted_runtime_binary(&self) -> bool {
        matches!(
            self.trust,
            SignatureTrust::Unsigned | SignatureTrust::AdHoc | SignatureTrust::Invalid
        ) || self.notarized == Some(false)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointProcess {
    pub pid: Option<u32>,
    pub ppid: Option<u32>,
    pub process_guid: Option<String>,
    pub parent_process_guid: Option<String>,
    pub image: Option<String>,
    pub command_line: Option<String>,
    pub cwd: Option<String>,
    pub signing: CodeSignatureStatus,
}

impl EndpointProcess {
    #[must_use]
    pub fn stable_key(&self) -> String {
        self.durable_stable_key()
            .unwrap_or_else(|| self.weak_stable_key())
    }

    #[must_use]
    pub fn stable_key_for_observation(&self, observation_id: &str) -> String {
        self.durable_stable_key().unwrap_or_else(|| {
            let observation_id = observation_id.trim();
            if observation_id.is_empty() {
                self.weak_stable_key()
            } else {
                format!("{}:observation:{observation_id}", self.weak_stable_key())
            }
        })
    }

    #[must_use]
    pub fn has_durable_stable_key(&self) -> bool {
        self.durable_stable_key().is_some()
    }

    #[must_use]
    pub fn durable_stable_key(&self) -> Option<String> {
        self.process_guid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("guid:{value}"))
    }

    #[must_use]
    pub fn weak_stable_key(&self) -> String {
        let pid = self
            .pid
            .map(|pid| pid.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        let image = self
            .image
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown");
        let command_line = self
            .command_line
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown");
        let cwd = self
            .cwd
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown");
        let signing_id = self
            .signing
            .signing_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown");
        let cdhash = self
            .signing
            .cdhash
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or("unknown");
        format!("weak:pid:{pid}:image:{image}:cmd:{command_line}:cwd:{cwd}:signing:{signing_id}:cdhash:{cdhash}")
    }

    #[must_use]
    pub fn stable_node_id(&self) -> String {
        let key = self.stable_key();
        stable_id("node", [key.as_str()])
    }

    #[must_use]
    pub fn stable_node_id_for_observation(&self, observation_id: &str) -> String {
        let key = self.stable_key_for_observation(observation_id);
        stable_id("node", [key.as_str()])
    }
}
