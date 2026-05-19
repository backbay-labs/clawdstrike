//! Pure helpers for endpoint response execution effect extraction.

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::{EndpointResponseExecutionEffect, EndpointResponseExecutionReport};
use hush_core::sha256;

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

pub(crate) fn process_tree_effect_pids(effect: &EndpointResponseExecutionEffect) -> Result<Vec<u32>> {
    let artifact = effect
        .artifact
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("process tree effect is missing pid artifact"))?;
    let mut pids = Vec::new();
    for item in artifact.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        pids.push(
            item.parse::<u32>()
                .with_context(|| format!("parse process tree effect pid {item}"))?,
        );
    }
    if pids.is_empty() {
        return Err(anyhow::anyhow!("process tree effect contains no pids"));
    }
    if let Some(expected) = effect.byte_count {
        if pids.len() as u64 != expected {
            return Err(anyhow::anyhow!(
                "process tree effect pid count mismatch: expected {expected}, got {}",
                pids.len()
            ));
        }
    }
    let mut canonical_pids = pids.clone();
    canonical_pids.sort_unstable();
    canonical_pids.dedup();
    if canonical_pids.len() != pids.len() {
        return Err(anyhow::anyhow!(
            "process tree effect contains duplicate pids"
        ));
    }
    let canonical_pid_list = canonical_pids
        .iter()
        .map(u32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let actual_hash = sha256(canonical_pid_list.as_bytes()).to_hex_prefixed();
    if effect.content_hash.as_deref() != Some(actual_hash.as_str()) {
        return Err(anyhow::anyhow!(
            "process tree effect pid hash does not match content hash"
        ));
    }
    Ok(pids)
}
