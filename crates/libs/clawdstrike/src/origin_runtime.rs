//! Runtime state for origin-aware enforcement across a session.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::enclave::ResolvedEnclave;
use crate::origin::OriginContext;
use crate::policy::OriginBudgets;
use crate::posture::PostureBudgetCounter;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginFingerprint {
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thread_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_participants: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sensitivity: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provenance_confidence: Option<String>,
}

impl From<&OriginContext> for OriginFingerprint {
    fn from(origin: &OriginContext) -> Self {
        let mut tags = origin.tags.clone();
        tags.sort();
        tags.dedup();

        Self {
            provider: origin.provider.to_string(),
            tenant_id: origin.tenant_id.clone(),
            space_id: origin.space_id.clone(),
            space_type: origin.space_type.as_ref().map(ToString::to_string),
            thread_id: origin.thread_id.clone(),
            visibility: origin.visibility.as_ref().map(ToString::to_string),
            external_participants: origin.external_participants,
            tags,
            sensitivity: origin.sensitivity.clone(),
            actor_role: origin.actor_role.clone(),
            provenance_confidence: origin
                .provenance_confidence
                .as_ref()
                .map(ToString::to_string),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginRuntimeState {
    pub current_origin: OriginContext,
    pub current_origin_fingerprint: OriginFingerprint,
    pub current_enclave: ResolvedEnclave,
    #[serde(default)]
    pub budgets: HashMap<String, PostureBudgetCounter>,
}

impl OriginRuntimeState {
    pub fn new(
        origin: OriginContext,
        enclave: ResolvedEnclave,
        budgets: HashMap<String, PostureBudgetCounter>,
    ) -> Self {
        let fingerprint = OriginFingerprint::from(&origin);
        Self {
            current_origin: origin,
            current_origin_fingerprint: fingerprint,
            current_enclave: enclave,
            budgets,
        }
    }
}

#[must_use]
pub fn origin_budget_counters(
    budgets: Option<&OriginBudgets>,
) -> HashMap<String, PostureBudgetCounter> {
    let mut counters = HashMap::new();
    let Some(budgets) = budgets else {
        return counters;
    };

    if let Some(limit) = budgets.mcp_tool_calls {
        counters.insert(
            "mcp_tool_calls".to_string(),
            PostureBudgetCounter { used: 0, limit },
        );
    }
    if let Some(limit) = budgets.egress_calls {
        counters.insert(
            "egress_calls".to_string(),
            PostureBudgetCounter { used: 0, limit },
        );
    }
    if let Some(limit) = budgets.shell_commands {
        counters.insert(
            "shell_commands".to_string(),
            PostureBudgetCounter { used: 0, limit },
        );
    }

    counters
}

pub fn normalize_origin_budgets(state: &mut OriginRuntimeState) {
    let desired = origin_budget_counters(state.current_enclave.budgets.as_ref());
    state.budgets.retain(|name, _| desired.contains_key(name));

    for (name, desired_counter) in desired {
        let counter = state.budgets.entry(name).or_insert(PostureBudgetCounter {
            used: 0,
            limit: desired_counter.limit,
        });
        counter.limit = desired_counter.limit;
        if counter.used > counter.limit {
            counter.used = counter.limit;
        }
    }
}
