//! Response-execution ledger.
//!
//! Append-only log of `EndpointResponseExecutionReport`s. Latest-entry-wins
//! deduplication on `(action_id, rollback_ref)` is used when computing
//! terminal transitions. The ledger also drives the expiry sweep and the
//! egress restriction activation check.

use std::collections::VecDeque;
use std::fs;
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::{
    EndpointResponseExecutionReport, EndpointResponseExecutionStatus,
};

use crate::api_server::EDR_MAX_STORED_FINDINGS;

use super::open_private_append;

pub(crate) struct EndpointResponseExecutionLedger {
    path: Option<PathBuf>,
    executions: VecDeque<EndpointResponseExecutionReport>,
}

impl EndpointResponseExecutionLedger {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let executions = read_response_execution_ledger(&path)?;
        Ok(Self {
            path: Some(path),
            executions: executions.into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn transient() -> Self {
        Self {
            path: None,
            executions: VecDeque::new(),
        }
    }

    pub(crate) fn path(&self) -> Option<&FsPath> {
        self.path.as_deref()
    }

    pub(crate) fn append(&mut self, execution: &EndpointResponseExecutionReport) -> Result<()> {
        self.executions.push_back(execution.clone());
        while self.executions.len() > EDR_MAX_STORED_FINDINGS {
            let _ = self.executions.pop_front();
        }

        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint response execution ledger directory {}",
                    parent.display()
                )
            })?;
        }

        let mut file = open_private_append(path, "endpoint response execution ledger")?;
        serde_json::to_writer(&mut file, execution).with_context(|| {
            format!(
                "serialize endpoint response execution {}",
                execution.execution_id
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!(
                "write endpoint response execution ledger {}",
                path.display()
            )
        })?;
        file.flush().with_context(|| {
            format!(
                "flush endpoint response execution ledger {}",
                path.display()
            )
        })?;
        Ok(())
    }

    pub(crate) fn read_recent(&self, limit: usize) -> Result<Vec<EndpointResponseExecutionReport>> {
        if let Some(path) = &self.path {
            let executions = read_response_execution_ledger(path)?;
            return Ok(executions
                .into_iter()
                .rev()
                .take(limit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect());
        }
        Ok(self
            .executions
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect())
    }

    pub(crate) fn active_evidence_bundle_ids(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<std::collections::BTreeSet<String>> {
        let current = self.all()?;
        Ok(current
            .iter()
            .filter(|execution| {
                matches!(
                    execution.status,
                    EndpointResponseExecutionStatus::Succeeded
                        | EndpointResponseExecutionStatus::Partial
                ) && now <= execution.expires_at()
                    && !Self::has_terminal_transition(&current, execution)
            })
            .map(|execution| execution.evidence_bundle.bundle_id.clone())
            .collect())
    }

    pub(crate) fn get(
        &self,
        execution_id: &str,
    ) -> Result<Option<EndpointResponseExecutionReport>> {
        if let Some(path) = &self.path {
            return Ok(read_response_execution_ledger(path)?
                .into_iter()
                .rev()
                .find(|execution| execution.execution_id == execution_id));
        }
        Ok(self
            .executions
            .iter()
            .rev()
            .find(|execution| execution.execution_id == execution_id)
            .cloned())
    }

    pub(crate) fn expire_due(
        &mut self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<EndpointResponseExecutionReport>> {
        let expired = self.pending_expirations(now)?;

        for execution in &expired {
            self.append(execution)?;
        }

        Ok(expired)
    }

    pub(crate) fn cancel(
        &mut self,
        execution: &EndpointResponseExecutionReport,
        reason: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<EndpointResponseExecutionReport>> {
        let current = self.all()?;
        let Some(latest) = current
            .iter()
            .rev()
            .find(|candidate| candidate.execution_id == execution.execution_id)
            .cloned()
        else {
            return Ok(None);
        };
        if latest.status != EndpointResponseExecutionStatus::Succeeded {
            return Ok(None);
        }
        if now > latest.expires_at() {
            return Ok(None);
        }
        if Self::has_terminal_transition(&current, &latest) {
            return Ok(None);
        }

        let cancelled = EndpointResponseExecutionReport::cancelled_from(&latest, reason, now);
        self.append(&cancelled)?;
        Ok(Some(cancelled))
    }

    pub(crate) fn roll_back(
        &mut self,
        execution: &EndpointResponseExecutionReport,
        reason: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<EndpointResponseExecutionReport>> {
        let current = self.all()?;
        let Some(latest) = current
            .iter()
            .rev()
            .find(|candidate| candidate.execution_id == execution.execution_id)
            .cloned()
        else {
            return Ok(None);
        };
        if !matches!(
            latest.status,
            EndpointResponseExecutionStatus::Succeeded
                | EndpointResponseExecutionStatus::Partial
                | EndpointResponseExecutionStatus::RollbackPending
                | EndpointResponseExecutionStatus::RollbackFailed
        ) {
            return Ok(None);
        }
        if Self::has_terminal_transition(&current, &latest) {
            return Ok(None);
        }

        let rolled_back = EndpointResponseExecutionReport::rolled_back_from(&latest, reason, now);
        self.append(&rolled_back)?;
        Ok(Some(rolled_back))
    }

    pub(crate) fn has_terminal_transition_for(
        &self,
        execution: &EndpointResponseExecutionReport,
    ) -> Result<bool> {
        Ok(Self::has_terminal_transition(&self.all()?, execution))
    }

    pub(crate) fn pending_expirations(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<EndpointResponseExecutionReport>> {
        Ok(self
            .pending_expiring_executions(now)?
            .into_iter()
            .map(|execution| EndpointResponseExecutionReport::expired_from(&execution, now))
            .collect())
    }

    pub(crate) fn pending_expiring_executions(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<EndpointResponseExecutionReport>> {
        let current = self.all()?;
        let mut expired = Vec::new();
        for execution in &current {
            if !Self::is_expirable_effect_state(&execution.status) {
                continue;
            }
            if now <= execution.expires_at() {
                continue;
            }
            if Self::has_later_effect_state(&current, execution) {
                continue;
            }
            if Self::has_terminal_transition(&current, execution) {
                continue;
            }
            expired.push(execution.clone());
        }

        Ok(expired)
    }

    pub(crate) fn all(&self) -> Result<Vec<EndpointResponseExecutionReport>> {
        if let Some(path) = &self.path {
            return read_response_execution_ledger(path);
        }
        Ok(self.executions.iter().cloned().collect())
    }

    pub(crate) fn has_terminal_transition(
        current: &[EndpointResponseExecutionReport],
        execution: &EndpointResponseExecutionReport,
    ) -> bool {
        let search_start = current
            .iter()
            .rposition(|candidate| candidate == execution)
            .map_or(0, |index| index + 1);
        current[search_start..].iter().any(|candidate| {
            matches!(
                candidate.status,
                EndpointResponseExecutionStatus::Expired
                    | EndpointResponseExecutionStatus::Cancelled
                    | EndpointResponseExecutionStatus::RollbackFailed
                    | EndpointResponseExecutionStatus::RolledBack
            ) && candidate.action_id == execution.action_id
                && candidate.rollback_ref == execution.rollback_ref
        })
    }

    fn has_later_effect_state(
        current: &[EndpointResponseExecutionReport],
        execution: &EndpointResponseExecutionReport,
    ) -> bool {
        let search_start = current
            .iter()
            .rposition(|candidate| candidate == execution)
            .map_or(0, |index| index + 1);
        current[search_start..].iter().any(|candidate| {
            candidate.action_id == execution.action_id
                && candidate.rollback_ref == execution.rollback_ref
                && Self::is_expirable_effect_state(&candidate.status)
        })
    }

    fn is_expirable_effect_state(status: &EndpointResponseExecutionStatus) -> bool {
        matches!(
            status,
            EndpointResponseExecutionStatus::Succeeded | EndpointResponseExecutionStatus::Partial
        )
    }
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::items_after_test_module,
    clippy::unwrap_used
)]
mod tests {
    use super::*;
    use chrono::Utc;
    use clawdstrike_policy_event::edr::{
        EndpointDecisionAction, EndpointEvidenceBundleReference, EndpointResponseExecutionReport,
        EndpointResponseExecutionStatus,
    };

    fn execution(
        execution_id: &str,
        status: EndpointResponseExecutionStatus,
    ) -> EndpointResponseExecutionReport {
        let now = Utc::now();
        EndpointResponseExecutionReport {
            execution_id: execution_id.to_string(),
            action_id: "response-action-1".to_string(),
            action: EndpointDecisionAction::QuarantineFile,
            status,
            dry_run: false,
            root_node_id: "node-1".to_string(),
            graph_slice_id: "graph-slice-1".to_string(),
            ttl_seconds: 60,
            rollback_ref: "rollback:response-action-1".to_string(),
            reason: "test response execution".to_string(),
            started_at: now,
            completed_at: now,
            evidence_bundle: EndpointEvidenceBundleReference {
                bundle_id: format!("bundle-{execution_id}"),
                graph_slice_id: "graph-slice-1".to_string(),
                content_hash: "0xabc".to_string(),
                node_count: 1,
                edge_count: 0,
                created_at: now,
            },
            actor: None,
            effects: Vec::new(),
            summary: "test response execution".to_string(),
        }
    }

    #[test]
    fn failed_execution_does_not_terminate_prior_partial_intent() {
        let partial = execution(
            "response_execution_partial:1",
            EndpointResponseExecutionStatus::Partial,
        );
        let failed = execution(
            "response_execution_failed:1",
            EndpointResponseExecutionStatus::Failed,
        );

        assert!(!EndpointResponseExecutionLedger::has_terminal_transition(
            &[partial.clone(), failed],
            &partial,
        ));
    }

    #[test]
    fn succeeded_execution_supersedes_prior_partial_intent_for_expiration() {
        let partial = execution(
            "response_execution_partial:ttl",
            EndpointResponseExecutionStatus::Partial,
        );
        let mut succeeded = partial.clone();
        succeeded.execution_id = "response_execution_succeeded:ttl".to_string();
        succeeded.status = EndpointResponseExecutionStatus::Succeeded;
        succeeded.completed_at = partial.completed_at + chrono::Duration::seconds(1);
        let now = partial.completed_at
            + chrono::Duration::seconds(i64::try_from(partial.ttl_seconds + 1).unwrap());
        let mut ledger = EndpointResponseExecutionLedger::transient();
        ledger.append(&partial).unwrap();
        ledger.append(&succeeded).unwrap();

        let pending = ledger.pending_expiring_executions(now).unwrap();

        assert_eq!(pending, vec![succeeded]);
    }

    #[test]
    fn partial_execution_is_pending_when_ttl_expires() {
        let partial = execution(
            "response_execution_partial:ttl",
            EndpointResponseExecutionStatus::Partial,
        );
        let now = partial.completed_at
            + chrono::Duration::seconds(i64::try_from(partial.ttl_seconds + 1).unwrap());
        let mut ledger = EndpointResponseExecutionLedger::transient();
        ledger.append(&partial).unwrap();

        let pending = ledger.pending_expiring_executions(now).unwrap();

        assert_eq!(pending, vec![partial]);
    }

    #[test]
    fn partial_execution_can_roll_back_to_terminal_transition() {
        let partial = execution(
            "response_execution_partial:rollback",
            EndpointResponseExecutionStatus::Partial,
        );
        let mut ledger = EndpointResponseExecutionLedger::transient();
        ledger.append(&partial).unwrap();

        let rolled_back = ledger
            .roll_back(&partial, "partial rollback", partial.completed_at)
            .unwrap()
            .expect("partial rollback transition");

        assert_eq!(
            rolled_back.status,
            EndpointResponseExecutionStatus::RolledBack
        );
    }
}

pub(crate) fn read_response_execution_ledger(
    path: &FsPath,
) -> Result<Vec<EndpointResponseExecutionReport>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("read endpoint response execution ledger {}", path.display())
            });
        }
    };

    let mut executions = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let execution: EndpointResponseExecutionReport =
            serde_json::from_str(line).with_context(|| {
                format!(
                    "parse endpoint response execution ledger line {} from {}",
                    index + 1,
                    path.display()
                )
            })?;
        executions.push(execution);
    }
    Ok(executions)
}
