use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::types::AgentId;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CorrelationContext {
    /// 16-byte trace id encoded as 32 lowercase hex chars.
    pub trace_id: String,
    /// 8-byte span id encoded as 16 lowercase hex chars.
    pub span_id: String,
    /// Optional parent span id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_span_id: Option<String>,
}

impl CorrelationContext {
    pub fn new_root() -> Self {
        let trace = uuid::Uuid::new_v4().simple().to_string();
        let span = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
        Self {
            trace_id: trace,
            span_id: span,
            parent_span_id: None,
        }
    }

    pub fn child(&self) -> Self {
        let span = uuid::Uuid::new_v4().simple().to_string()[..16].to_string();
        Self {
            trace_id: self.trace_id.clone(),
            span_id: span,
            parent_span_id: Some(self.span_id.clone()),
        }
    }

    /// W3C traceparent: `00-<trace_id>-<span_id>-01`.
    pub fn traceparent(&self) -> Result<String> {
        self.validate()?;
        Ok(format!("00-{}-{}-01", self.trace_id, self.span_id))
    }

    pub fn from_traceparent(raw: &str) -> Result<Self> {
        let parts = raw.trim().split('-').collect::<Vec<_>>();
        if parts.len() != 4 {
            return Err(Error::InvalidClaims(
                "invalid traceparent format".to_string(),
            ));
        }
        if parts[0] != "00" {
            return Err(Error::InvalidClaims(
                "unsupported traceparent version".to_string(),
            ));
        }
        let ctx = Self {
            trace_id: parts[1].to_string(),
            span_id: parts[2].to_string(),
            parent_span_id: None,
        };
        ctx.validate()?;
        Ok(ctx)
    }

    pub fn validate(&self) -> Result<()> {
        validate_hex_len("trace_id", &self.trace_id, 32)?;
        validate_hex_len("span_id", &self.span_id, 16)?;
        if let Some(parent) = &self.parent_span_id {
            validate_hex_len("parent_span_id", parent, 16)?;
        }
        Ok(())
    }
}

fn validate_hex_len(field: &str, value: &str, expected_len: usize) -> Result<()> {
    let valid = value.len() == expected_len && value.bytes().all(|b| b.is_ascii_hexdigit());
    if !valid {
        return Err(Error::InvalidClaims(format!(
            "{field} must be {expected_len} hex chars"
        )));
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossAgentEventType {
    DelegationCreated,
    DelegationUsed,
    DelegationRevoked,
    ChannelOpened,
    ChannelClosed,
    MessageSent,
    MessageReceived,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrossAgentAuditEvent {
    pub event_type: CrossAgentEventType,
    pub actor: AgentId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<AgentId>,
    pub correlation: CorrelationContext,
    pub timestamp_unix: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegation_token_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

impl CrossAgentAuditEvent {
    pub fn validate_basic(&self) -> Result<()> {
        self.correlation.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traceparent_round_trip() {
        let root = CorrelationContext::new_root();
        let header = root.traceparent().unwrap();
        let parsed = CorrelationContext::from_traceparent(&header).unwrap();
        assert_eq!(parsed.trace_id, root.trace_id);
        assert_eq!(parsed.span_id, root.span_id);
    }

    #[test]
    fn child_context_sets_parent_span() {
        let root = CorrelationContext::new_root();
        let child = root.child();
        assert_eq!(child.trace_id, root.trace_id);
        assert_eq!(child.parent_span_id.as_deref(), Some(root.span_id.as_str()));
    }
}
