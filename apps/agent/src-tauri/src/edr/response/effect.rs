//! Pure helpers for endpoint response execution effect extraction.

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::{
    EndpointResponseExecutionEffect, EndpointResponseExecutionReport,
};
use hush_core::sha256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProcessTreeEffectSignalTarget {
    pub(crate) pid: u32,
    pub(crate) process_identity_key: Option<String>,
}

pub(crate) fn quarantine_file_effect(
    execution: &EndpointResponseExecutionReport,
) -> Result<&EndpointResponseExecutionEffect> {
    execution
        .effects
        .iter()
        .find(|effect| effect.effect_type == "quarantine_file")
        .ok_or_else(|| anyhow::anyhow!("execution has no quarantine_file effect"))
}

pub(crate) fn disable_persistence_effect(
    execution: &EndpointResponseExecutionReport,
) -> Result<&EndpointResponseExecutionEffect> {
    execution
        .effects
        .iter()
        .find(|effect| effect.effect_type == "disable_persistence")
        .ok_or_else(|| anyhow::anyhow!("execution has no disable_persistence effect"))
}

pub(crate) fn suspend_process_tree_effect(
    execution: &EndpointResponseExecutionReport,
) -> Result<&EndpointResponseExecutionEffect> {
    execution
        .effects
        .iter()
        .find(|effect| effect.effect_type == "suspend_process_tree")
        .ok_or_else(|| anyhow::anyhow!("execution has no suspend_process_tree effect"))
}

#[cfg(test)]
pub(crate) fn process_tree_effect_pids(
    effect: &EndpointResponseExecutionEffect,
) -> Result<Vec<u32>> {
    Ok(process_tree_effect_signal_targets(effect)?
        .into_iter()
        .map(|target| target.pid)
        .collect())
}

pub(crate) fn process_tree_effect_signal_targets(
    effect: &EndpointResponseExecutionEffect,
) -> Result<Vec<ProcessTreeEffectSignalTarget>> {
    let artifact = effect
        .artifact
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("process tree effect is missing pid artifact"))?;
    let mut targets = Vec::new();
    let mut canonical_entries = Vec::new();
    for item in artifact.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let (pid_text, identity) = match item.split_once('=') {
            Some((pid, identity)) => (pid.trim(), Some(identity.trim().to_string())),
            None => (item, None),
        };
        let pid = pid_text
            .parse::<u32>()
            .with_context(|| format!("parse process tree effect pid {pid_text}"))?;
        if identity.as_deref().is_some_and(str::is_empty) {
            return Err(anyhow::anyhow!(
                "process tree effect identity binding for pid {pid} is empty"
            ));
        }
        targets.push(ProcessTreeEffectSignalTarget {
            pid,
            process_identity_key: identity.clone(),
        });
        canonical_entries.push((pid, identity));
    }
    if targets.is_empty() {
        return Err(anyhow::anyhow!("process tree effect contains no pids"));
    }
    if let Some(expected) = effect.byte_count {
        if targets.len() as u64 != expected {
            return Err(anyhow::anyhow!(
                "process tree effect pid count mismatch: expected {expected}, got {}",
                targets.len()
            ));
        }
    }
    canonical_entries.sort();
    canonical_entries.dedup();
    if canonical_entries.len() != targets.len() {
        return Err(anyhow::anyhow!(
            "process tree effect contains duplicate pids"
        ));
    }
    let canonical_pid_list = canonical_entries
        .iter()
        .map(|(pid, identity)| match identity {
            Some(identity) => format!("{pid}={identity}"),
            None => pid.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",");
    let actual_hash = sha256(canonical_pid_list.as_bytes()).to_hex_prefixed();
    if effect.content_hash.as_deref() != Some(actual_hash.as_str()) {
        return Err(anyhow::anyhow!(
            "process tree effect pid hash does not match content hash"
        ));
    }
    Ok(targets)
}
