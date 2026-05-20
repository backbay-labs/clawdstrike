//! Egress-restriction ledger.
//!
//! Tracks active and revoked network-egress restrictions created by
//! `block_egress` response actions. Latest-entry-wins deduplication on
//! `restriction_id` means each entry can be active or inactive.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::EndpointResponseExecutionReport;
use hush_core::sha256;
use serde::{Deserialize, Serialize};

use crate::api_server::{
    local_stable_id, EDR_MAX_STORED_FINDINGS, EDR_NETWORK_EXTENSION_EGRESS_POLICY_SCHEMA_VERSION,
};

use super::open_private_append;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EndpointEgressRestriction {
    pub(crate) restriction_id: String,
    pub(crate) execution_id: String,
    pub(crate) action_id: String,
    pub(crate) graph_slice_id: String,
    pub(crate) rollback_ref: String,
    pub(crate) target: String,
    pub(crate) target_hash: String,
    pub(crate) active: bool,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) expires_at: chrono::DateTime<chrono::Utc>,
    pub(crate) updated_at: chrono::DateTime<chrono::Utc>,
}

impl EndpointEgressRestriction {
    pub(crate) fn active(
        execution: &EndpointResponseExecutionReport,
        target: &str,
        created_at: chrono::DateTime<chrono::Utc>,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Self {
        let target_hash = sha256(target.as_bytes()).to_hex_prefixed();
        let restriction_id = local_stable_id(
            "egress_restriction",
            [
                execution.execution_id.as_str(),
                execution.action_id.as_str(),
                target,
            ],
        );
        Self {
            restriction_id,
            execution_id: execution.execution_id.clone(),
            action_id: execution.action_id.clone(),
            graph_slice_id: execution.graph_slice_id.clone(),
            rollback_ref: execution.rollback_ref.clone(),
            target: target.to_string(),
            target_hash,
            active: true,
            created_at,
            expires_at,
            updated_at: created_at,
        }
    }

    pub(crate) fn inactive_from(&self, updated_at: chrono::DateTime<chrono::Utc>) -> Self {
        let mut next = self.clone();
        next.active = false;
        next.updated_at = updated_at;
        next
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NetworkExtensionEgressPolicySnapshot {
    pub(crate) schema_version: u32,
    pub(crate) generated_at: chrono::DateTime<chrono::Utc>,
    pub(crate) restrictions: Vec<EndpointEgressRestriction>,
}

pub(crate) fn write_network_extension_egress_policy_snapshot(
    path: &FsPath,
    restrictions: &[EndpointEgressRestriction],
    generated_at: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "create network extension egress policy directory {}",
                parent.display()
            )
        })?;
    }

    let snapshot = NetworkExtensionEgressPolicySnapshot {
        schema_version: EDR_NETWORK_EXTENSION_EGRESS_POLICY_SCHEMA_VERSION,
        generated_at,
        restrictions: restrictions.to_vec(),
    };
    let mut bytes = serde_json::to_vec_pretty(&snapshot)
        .context("serialize network extension egress policy")?;
    bytes.push(b'\n');

    let tmp_path = path.with_extension("json.tmp");
    fs::write(&tmp_path, bytes).with_context(|| {
        format!(
            "write temporary network extension egress policy {}",
            tmp_path.display()
        )
    })?;
    fs::rename(&tmp_path, path).with_context(|| {
        format!(
            "replace network extension egress policy {} with {}",
            path.display(),
            tmp_path.display()
        )
    })?;
    Ok(())
}

pub(crate) struct EndpointEgressRestrictionLedger {
    path: Option<PathBuf>,
    restrictions: VecDeque<EndpointEgressRestriction>,
}

impl EndpointEgressRestrictionLedger {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let restrictions = read_egress_restriction_ledger(&path)?;
        Ok(Self {
            path: Some(path),
            restrictions: restrictions.into(),
        })
    }

    pub(crate) fn transient() -> Self {
        Self {
            path: None,
            restrictions: VecDeque::new(),
        }
    }

    pub(crate) fn append(&mut self, restrictions: &[EndpointEgressRestriction]) -> Result<()> {
        for restriction in restrictions {
            self.restrictions.push_back(restriction.clone());
        }
        while self.restrictions.len() > EDR_MAX_STORED_FINDINGS {
            let _ = self.restrictions.pop_front();
        }

        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint egress restriction ledger directory {}",
                    parent.display()
                )
            })?;
        }

        let mut file = open_private_append(path, "endpoint egress restriction ledger")?;
        for restriction in restrictions {
            serde_json::to_writer(&mut file, restriction).with_context(|| {
                format!(
                    "serialize endpoint egress restriction {}",
                    restriction.restriction_id
                )
            })?;
            file.write_all(b"\n").with_context(|| {
                format!(
                    "write endpoint egress restriction ledger {}",
                    path.display()
                )
            })?;
        }
        file.flush().with_context(|| {
            format!(
                "flush endpoint egress restriction ledger {}",
                path.display()
            )
        })?;
        Ok(())
    }

    pub(crate) fn deactivate_execution(
        &mut self,
        execution_id: &str,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<EndpointEgressRestriction>> {
        let deactivated = self
            .active_for_execution(execution_id)
            .into_iter()
            .map(|restriction| restriction.inactive_from(updated_at))
            .collect::<Vec<_>>();
        if deactivated.is_empty() {
            return Err(anyhow::anyhow!(
                "execution {execution_id} has no active egress restrictions"
            ));
        }
        self.append(&deactivated)?;
        Ok(deactivated)
    }

    pub(crate) fn deactivate_action_if_active(
        &mut self,
        action_id: &str,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<EndpointEgressRestriction>> {
        let deactivated = self
            .active_for_action(action_id)
            .into_iter()
            .map(|restriction| restriction.inactive_from(updated_at))
            .collect::<Vec<_>>();
        self.append(&deactivated)?;
        Ok(deactivated)
    }

    pub(crate) fn active_match(
        &self,
        target: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<EndpointEgressRestriction> {
        self.active_entries(now)
            .into_iter()
            .find(|restriction| restriction.target == target)
    }

    pub(crate) fn active_for_execution(
        &self,
        execution_id: &str,
    ) -> Vec<EndpointEgressRestriction> {
        self.latest_entries()
            .into_iter()
            .filter(|restriction| restriction.active && restriction.execution_id == execution_id)
            .collect()
    }

    pub(crate) fn active_for_action(&self, action_id: &str) -> Vec<EndpointEgressRestriction> {
        self.latest_entries()
            .into_iter()
            .filter(|restriction| restriction.active && restriction.action_id == action_id)
            .collect()
    }

    pub(crate) fn active_entries(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Vec<EndpointEgressRestriction> {
        self.latest_entries()
            .into_iter()
            .filter(|restriction| restriction.active && now <= restriction.expires_at)
            .collect()
    }

    pub(crate) fn latest_entries(&self) -> Vec<EndpointEgressRestriction> {
        let mut latest = BTreeMap::new();
        for restriction in &self.restrictions {
            latest.insert(restriction.restriction_id.clone(), restriction.clone());
        }
        latest.into_values().collect()
    }
}

pub(crate) fn read_egress_restriction_ledger(
    path: &FsPath,
) -> Result<Vec<EndpointEgressRestriction>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("read endpoint egress restriction ledger {}", path.display())
            });
        }
    };

    let mut latest = BTreeMap::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let restriction: EndpointEgressRestriction =
            serde_json::from_str(line).with_context(|| {
                format!(
                    "parse endpoint egress restriction ledger line {} from {}",
                    index + 1,
                    path.display()
                )
            })?;
        latest.insert(restriction.restriction_id.clone(), restriction);
    }
    Ok(latest.into_values().collect())
}
