//! Response-action data-transfer objects and internal control structs.

use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseTargetKind {
    Endpoint,
    Runtime,
    Session,
    Principal,
    Grant,
    Swarm,
    Project,
}

impl ResponseTargetKind {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Runtime => "runtime",
            Self::Session => "session",
            Self::Principal => "principal",
            Self::Grant => "grant",
            Self::Swarm => "swarm",
            Self::Project => "project",
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, ApiError> {
        validate_control_discriminator_len("target.kind", value.trim(), TARGET_KIND_MAX_BYTES)?;
        match value {
            "endpoint" => Ok(Self::Endpoint),
            "runtime" => Ok(Self::Runtime),
            "session" => Ok(Self::Session),
            "principal" => Ok(Self::Principal),
            "grant" => Ok(Self::Grant),
            "swarm" => Ok(Self::Swarm),
            "project" => Ok(Self::Project),
            _ => Err(ApiError::BadRequest(format!(
                "unsupported target kind; allowed values: {RESPONSE_TARGET_KIND_ALLOWLIST}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseActionType {
    TransitionPosture,
    RequestPolicyReload,
    TerminateSession,
    KillSwitch,
    QuarantinePrincipal,
    RevokeGrant,
    RevokePrincipal,
    PolicyRuleDiffValidation,
}

impl ResponseActionType {
    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::TransitionPosture => "transition_posture",
            Self::RequestPolicyReload => "request_policy_reload",
            Self::TerminateSession => "terminate_session",
            Self::KillSwitch => "kill_switch",
            Self::QuarantinePrincipal => "quarantine_principal",
            Self::RevokeGrant => "revoke_grant",
            Self::RevokePrincipal => "revoke_principal",
            Self::PolicyRuleDiffValidation => "policy_rule_diff_validation",
        }
    }

    pub(crate) fn from_str(value: &str) -> Result<Self, ApiError> {
        validate_control_discriminator_len("action_type", value.trim(), ACTION_TYPE_MAX_BYTES)?;
        match value {
            "transition_posture" => Ok(Self::TransitionPosture),
            "request_policy_reload" => Ok(Self::RequestPolicyReload),
            "terminate_session" => Ok(Self::TerminateSession),
            "kill_switch" => Ok(Self::KillSwitch),
            "quarantine_principal" => Ok(Self::QuarantinePrincipal),
            "revoke_grant" => Ok(Self::RevokeGrant),
            "revoke_principal" => Ok(Self::RevokePrincipal),
            "policy_rule_diff_validation" => Ok(Self::PolicyRuleDiffValidation),
            _ => Err(ApiError::BadRequest(format!(
                "unsupported action type; allowed values: {RESPONSE_ACTION_TYPE_ALLOWLIST}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseTarget {
    pub kind: ResponseTargetKind,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestedBy {
    pub actor_type: String,
    pub actor_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionRecord {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub action_type: String,
    pub target: ResponseTarget,
    pub requested_by: RequestedBy,
    pub requested_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub reason: String,
    pub case_id: Option<Uuid>,
    pub source_detection_id: Option<Uuid>,
    pub source_approval_id: Option<Uuid>,
    pub require_acknowledgement: bool,
    pub payload: Value,
    pub status: String,
    pub metadata: Value,
}

impl ResponseActionRecord {
    pub(crate) fn from_row(row: crate::db::PgRow) -> Result<Self, sqlx::Error> {
        let target_kind: String = row.try_get("target_kind")?;
        Ok(Self {
            id: row.try_get("id")?,
            tenant_id: row.try_get("tenant_id")?,
            action_type: row.try_get("action_type")?,
            target: ResponseTarget {
                kind: ResponseTargetKind::from_str(&target_kind)
                    .map_err(|err| sqlx::Error::Protocol(err.to_string()))?,
                id: row.try_get("target_id")?,
            },
            requested_by: RequestedBy {
                actor_type: row.try_get("requested_by_type")?,
                actor_id: row.try_get("requested_by_id")?,
            },
            requested_at: row.try_get("requested_at")?,
            expires_at: row.try_get("expires_at")?,
            reason: row.try_get("reason")?,
            case_id: row.try_get("case_id")?,
            source_detection_id: row.try_get("source_detection_id")?,
            source_approval_id: row.try_get("source_approval_id")?,
            require_acknowledgement: row.try_get("require_acknowledgement")?,
            payload: row.try_get("payload")?,
            status: row.try_get("status")?,
            metadata: row.try_get("metadata")?,
        })
    }

    pub(crate) fn to_transport_payload(&self) -> Value {
        json!({
            "actionId": self.id,
            "tenantId": self.tenant_id,
            "actionType": self.action_type,
            "target": {
                "kind": self.target.kind.as_str(),
                "id": self.target.id,
            },
            "requestedBy": {
                "actorType": self.requested_by.actor_type,
                "actorId": self.requested_by.actor_id,
            },
            "requestedAt": self.requested_at.to_rfc3339(),
            "expiresAt": self.expires_at.map(|value| value.to_rfc3339()),
            "reason": self.reason,
            "caseId": self.case_id,
            "sourceDetectionId": self.source_detection_id,
            "sourceApprovalId": self.source_approval_id,
            "requireAcknowledgement": self.require_acknowledgement,
            "payload": self.payload,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionDelivery {
    pub id: Uuid,
    pub action_id: Uuid,
    pub tenant_id: Uuid,
    pub target_kind: String,
    pub target_id: String,
    pub executor_kind: String,
    pub delivery_subject: Option<String>,
    pub status: String,
    pub attempt_count: i32,
    pub published_at: Option<DateTime<Utc>>,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub acknowledgement_deadline: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub metadata: Value,
}

impl ResponseActionDelivery {
    pub(crate) fn from_row(row: crate::db::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            action_id: row.try_get("action_id")?,
            tenant_id: row.try_get("tenant_id")?,
            target_kind: row.try_get("target_kind")?,
            target_id: row.try_get("target_id")?,
            executor_kind: row.try_get("executor_kind")?,
            delivery_subject: row.try_get("delivery_subject")?,
            status: row.try_get("status")?,
            attempt_count: row.try_get("attempt_count")?,
            published_at: row.try_get("published_at")?,
            acknowledged_at: row.try_get("acknowledged_at")?,
            acknowledgement_deadline: row.try_get("acknowledgement_deadline")?,
            last_error: row.try_get("last_error")?,
            metadata: row.try_get("metadata")?,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseActionAckRecord {
    pub id: Uuid,
    pub action_id: Uuid,
    pub tenant_id: Uuid,
    pub target_kind: String,
    pub target_id: String,
    pub observed_at: DateTime<Utc>,
    pub status: String,
    pub message: Option<String>,
    pub resulting_state: Option<String>,
    pub raw_payload: Value,
}

impl ResponseActionAckRecord {
    pub(crate) fn from_row(row: crate::db::PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            id: row.try_get("id")?,
            action_id: row.try_get("action_id")?,
            tenant_id: row.try_get("tenant_id")?,
            target_kind: row.try_get("target_kind")?,
            target_id: row.try_get("target_id")?,
            observed_at: row.try_get("observed_at")?,
            status: row.try_get("status")?,
            message: row.try_get("message")?,
            resulting_state: row.try_get("resulting_state")?,
            raw_payload: row.try_get("raw_payload")?,
        })
    }
}

#[derive(Debug, Serialize)]
pub struct ResponseActionDetail {
    pub action: ResponseActionRecord,
    pub deliveries: Vec<ResponseActionDelivery>,
    pub acknowledgements: Vec<ResponseActionAckRecord>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct CreateResponseActionRequest {
    pub action_type: String,
    pub target: ResponseTargetInput,
    pub reason: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub case_id: Option<Uuid>,
    pub source_detection_id: Option<Uuid>,
    pub source_approval_id: Option<Uuid>,
    pub require_acknowledgement: Option<bool>,
    pub payload: Option<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseTargetInput {
    pub kind: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RecordResponseAckRequest {
    pub target_kind: String,
    pub target_id: String,
    pub ack_token: String,
    pub status: String,
    pub observed_at: Option<DateTime<Utc>>,
    pub message: Option<String>,
    pub resulting_state: Option<String>,
    pub raw_payload: Option<Value>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordAgentAckResponse {
    pub accepted: bool,
    pub action_id: Uuid,
    pub target_kind: String,
    pub target_id: String,
    pub status: String,
    pub observed_at: DateTime<Utc>,
}

pub(crate) struct ValidatedCreateAction {
    pub(crate) action_type: ResponseActionType,
    pub(crate) target_kind: ResponseTargetKind,
    pub(crate) resolved_target_id: String,
    pub(crate) reason: String,
    pub(crate) expires_at: Option<DateTime<Utc>>,
    pub(crate) case_id: Option<Uuid>,
    pub(crate) source_detection_id: Option<Uuid>,
    pub(crate) source_approval_id: Option<Uuid>,
    pub(crate) require_acknowledgement: bool,
    pub(crate) payload: Value,
    pub(crate) metadata: Value,
}

pub(crate) struct AckSubmission {
    pub(crate) target_kind: ResponseTargetKind,
    pub(crate) target_id: String,
    pub(crate) ack_token: String,
    pub(crate) ack_status: &'static str,
    pub(crate) observed_at: DateTime<Utc>,
    pub(crate) message: Option<String>,
    pub(crate) resulting_state: Option<String>,
    pub(crate) raw_payload: Value,
}

pub(crate) struct AckContext {
    pub(crate) action: ResponseActionRecord,
    pub(crate) delivery_id: Uuid,
}

pub(crate) struct VerifiedEndpointDecisionReceipt {
    pub(crate) signed_receipt_hash: String,
    pub(crate) endpoint_decision: EndpointDecisionReceipt,
    pub(crate) endpoint_decision_value: Value,
}

pub(crate) struct PublishContext {
    pub(crate) action: ResponseActionRecord,
    pub(crate) delivery: ResponseActionDelivery,
}

pub(crate) struct PrincipalLifecycleTarget {
    pub(crate) principal_id: Uuid,
    pub(crate) stable_ref: String,
}

pub(crate) enum PublishPreparation {
    Ready(Box<PublishContext>),
    Expired,
}

#[derive(Debug, Clone)]
pub(crate) struct DeliveryPlan {
    pub(crate) target_kind: String,
    pub(crate) target_id: String,
    pub(crate) executor_kind: String,
    pub(crate) delivery_subject: Option<String>,
    pub(crate) acknowledgement_deadline: Option<DateTime<Utc>>,
    pub(crate) metadata: Value,
}

pub(crate) enum DeliveryExecution {
    Published,
    Acknowledged {
        observed_at: DateTime<Utc>,
        message: Option<String>,
        resulting_state: Option<String>,
        raw_payload: Value,
    },
}
