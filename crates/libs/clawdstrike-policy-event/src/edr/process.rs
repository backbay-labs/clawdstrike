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
        self.process_guid
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| format!("guid:{value}"))
            .or_else(|| self.pid.map(|pid| format!("pid:{pid}")))
            .or_else(|| {
                self.image
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(|image| {
                        let command_line = self.command_line.as_deref().unwrap_or_default();
                        format!("image:{image}:{command_line}")
                    })
            })
            .unwrap_or_else(|| "process:unknown".to_string())
    }

    #[must_use]
    pub fn stable_node_id(&self) -> String {
        let key = self.stable_key();
        stable_id("node", [key.as_str()])
    }
}

