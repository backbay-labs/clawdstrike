use serde::{Deserialize, Serialize};

use crate::token::DelegationClaims;
use crate::types::AgentId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationGraphNodeKind {
    Principal,
    Session,
    Grant,
    Approval,
    Event,
    ResponseAction,
}

impl DelegationGraphNodeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Principal => "principal",
            Self::Session => "session",
            Self::Grant => "grant",
            Self::Approval => "approval",
            Self::Event => "event",
            Self::ResponseAction => "response_action",
        }
    }

    pub fn node_id(self, external_id: &str) -> String {
        format!("{}:{external_id}", self.as_str())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationGraphEdgeKind {
    IssuedGrant,
    ReceivedGrant,
    DerivedFromGrant,
    SpawnedPrincipal,
    ApprovedBy,
    RevokedBy,
    ExercisedInSession,
    ExercisedInEvent,
    TriggeredResponseAction,
}

impl DelegationGraphEdgeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IssuedGrant => "issued_grant",
            Self::ReceivedGrant => "received_grant",
            Self::DerivedFromGrant => "derived_from_grant",
            Self::SpawnedPrincipal => "spawned_principal",
            Self::ApprovedBy => "approved_by",
            Self::RevokedBy => "revoked_by",
            Self::ExercisedInSession => "exercised_in_session",
            Self::ExercisedInEvent => "exercised_in_event",
            Self::TriggeredResponseAction => "triggered_response_action",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantLineageFacts {
    pub token_jti: String,
    pub parent_token_jti: Option<String>,
    pub chain: Vec<String>,
    pub depth: usize,
    pub issuer: AgentId,
    pub subject: AgentId,
}

impl GrantLineageFacts {
    pub fn from_claims(claims: &DelegationClaims) -> Self {
        let parent_token_jti = claims.chn.last().cloned();
        Self {
            token_jti: claims.jti.clone(),
            parent_token_jti,
            chain: claims.chn.clone(),
            depth: claims.chn.len(),
            issuer: claims.iss.clone(),
            subject: claims.sub.clone(),
        }
    }

    pub fn ancestor_token_ids(&self) -> &[String] {
        &self.chain
    }

    pub fn issuer_node_id(&self) -> String {
        DelegationGraphNodeKind::Principal.node_id(self.issuer.as_str())
    }

    pub fn subject_node_id(&self) -> String {
        DelegationGraphNodeKind::Principal.node_id(self.subject.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::DelegationClaims;
    use crate::types::AgentCapability;

    fn make_claims() -> DelegationClaims {
        DelegationClaims::new(
            AgentId::new("agent:issuer").unwrap(),
            AgentId::new("agent:subject").unwrap(),
            100,
            200,
            vec![AgentCapability::DeployApproval],
        )
        .unwrap()
    }

    #[test]
    fn lineage_facts_capture_root_claims() {
        let claims = make_claims();
        let facts = GrantLineageFacts::from_claims(&claims);

        assert_eq!(facts.token_jti, claims.jti);
        assert!(facts.parent_token_jti.is_none());
        assert_eq!(facts.depth, 0);
        assert_eq!(facts.issuer.as_str(), "agent:issuer");
        assert_eq!(facts.subject.as_str(), "agent:subject");
        assert_eq!(facts.issuer_node_id(), "principal:agent:issuer");
        assert_eq!(facts.subject_node_id(), "principal:agent:subject");
    }

    #[test]
    fn lineage_facts_capture_parent_chain() {
        let parent = make_claims();
        let child = DelegationClaims::redelegate(
            &parent,
            AgentId::new("agent:grandchild").unwrap(),
            120,
            180,
            vec![AgentCapability::DeployApproval],
        )
        .unwrap();

        let facts = GrantLineageFacts::from_claims(&child);
        assert_eq!(facts.parent_token_jti.as_deref(), Some(parent.jti.as_str()));
        assert_eq!(facts.ancestor_token_ids(), &[parent.jti]);
        assert_eq!(facts.depth, 1);
    }

    #[test]
    fn graph_node_and_edge_kinds_are_stable() {
        assert_eq!(DelegationGraphNodeKind::Grant.as_str(), "grant");
        assert_eq!(
            DelegationGraphEdgeKind::TriggeredResponseAction.as_str(),
            "triggered_response_action"
        );
        assert_eq!(
            DelegationGraphNodeKind::ResponseAction.node_id("ra-1"),
            "response_action:ra-1"
        );
    }
}
