use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointDecisionAction {
    Allow,
    Observe,
    Warn,
    #[default]
    Alert,
    Block,
    RestrictEgress,
    SuspendProcessTree,
    TerminateProcessTree,
    QuarantineFile,
    RevokeGrant,
    DisablePersistence,
    CollectEvidence,
}

impl EndpointDecisionAction {
    #[must_use]
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Observe => "observe",
            Self::Warn => "warn",
            Self::Alert => "alert",
            Self::Block => "block",
            Self::RestrictEgress => "restrict_egress",
            Self::SuspendProcessTree => "suspend_process_tree",
            Self::TerminateProcessTree => "terminate_process_tree",
            Self::QuarantineFile => "quarantine_file",
            Self::RevokeGrant => "revoke_grant",
            Self::DisablePersistence => "disable_persistence",
            Self::CollectEvidence => "collect_evidence",
        }
    }
}
