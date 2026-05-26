//! Rollback effect proof contract reconstruction and validation.

use super::super::*;

pub(crate) fn expected_response_rollback_effects(
    execution: &EndpointResponseExecutionReport,
) -> Result<Vec<EndpointResponseExecutionEffect>, (StatusCode, String)> {
    match execution.action {
        EndpointDecisionAction::RestrictEgress => {
            let effect = require_execution_effect_for_rollback(execution, "restrict_egress")?;
            let primary_target =
                effect
                    .target
                    .strip_prefix("egress:")
                    .ok_or_else(|| {
                        response_proof_contract_conflict(
                            "response rollback receipt target does not match response execution proof contract",
                        )
                    })?;
            let targets = response_proof_contract_string_artifact(effect)?;
            let rollback_effect =
                EndpointResponseExecutionEffect::restore_egress(primary_target, &targets);
            verify_rollback_effect_matches_execution_effect(&rollback_effect, effect)?;
            Ok(vec![rollback_effect])
        }
        EndpointDecisionAction::QuarantineFile => {
            let effect = require_execution_effect_for_rollback(execution, "quarantine_file")?;
            let artifact = response_proof_contract_required_effect_field(
                effect.artifact.as_deref(),
                "response rollback receipt artifact does not match response execution proof contract",
            )?;
            let content_hash = response_proof_contract_required_effect_field(
                effect.content_hash.as_deref(),
                "response rollback receipt content hash does not match response execution proof contract",
            )?;
            let byte_count = effect.byte_count.ok_or_else(|| {
                response_proof_contract_conflict(
                    "response rollback receipt byte count does not match response execution proof contract",
                )
            })?;
            Ok(vec![
                EndpointResponseExecutionEffect::restore_quarantine_file(
                    effect.target.as_str(),
                    artifact,
                    content_hash,
                    byte_count,
                ),
            ])
        }
        EndpointDecisionAction::DisablePersistence => {
            let effect = require_execution_effect_for_rollback(execution, "disable_persistence")?;
            let artifact = response_proof_contract_required_effect_field(
                effect.artifact.as_deref(),
                "response rollback receipt artifact does not match response execution proof contract",
            )?;
            let content_hash = response_proof_contract_required_effect_field(
                effect.content_hash.as_deref(),
                "response rollback receipt content hash does not match response execution proof contract",
            )?;
            let byte_count = effect.byte_count.ok_or_else(|| {
                response_proof_contract_conflict(
                    "response rollback receipt byte count does not match response execution proof contract",
                )
            })?;
            Ok(vec![
                EndpointResponseExecutionEffect::restore_persistence_file(
                    effect.target.as_str(),
                    artifact,
                    content_hash,
                    byte_count,
                ),
            ])
        }
        EndpointDecisionAction::SuspendProcessTree => {
            let effect = require_execution_effect_for_rollback(execution, "suspend_process_tree")?;
            let root_pid = effect
                .target
                .strip_prefix("pid:")
                .ok_or_else(|| {
                    response_proof_contract_conflict(
                        "response rollback receipt target does not match response execution proof contract",
                    )
                })?
                .parse::<u32>()
                .map_err(|_| {
                    response_proof_contract_conflict(
                        "response rollback receipt target does not match response execution proof contract",
                    )
                })?;
            let artifact = response_proof_contract_required_effect_field(
                effect.artifact.as_deref(),
                "response rollback receipt artifact does not match response execution proof contract",
            )?;
            let rollback_effect =
                EndpointResponseExecutionEffect::resume_process_tree_from_artifact(
                    root_pid, artifact,
                );
            verify_rollback_effect_matches_execution_effect(&rollback_effect, effect)?;
            Ok(vec![rollback_effect])
        }
        _ => Err(response_proof_contract_conflict(
            "response rollback receipt is not valid for this response execution action",
        )),
    }
}

pub(crate) fn require_execution_effect_for_rollback<'a>(
    execution: &'a EndpointResponseExecutionReport,
    effect_type: &str,
) -> Result<&'a EndpointResponseExecutionEffect, (StatusCode, String)> {
    execution
        .effects
        .iter()
        .find(|effect| effect.effect_type == effect_type)
        .ok_or_else(|| {
            response_proof_contract_conflict(
                "response rollback receipt effect does not match response execution proof contract",
            )
        })
}

pub(crate) fn response_proof_contract_string_artifact(
    effect: &EndpointResponseExecutionEffect,
) -> Result<Vec<String>, (StatusCode, String)> {
    let artifact = response_proof_contract_required_effect_field(
        effect.artifact.as_deref(),
        "response rollback receipt artifact does not match response execution proof contract",
    )?;
    let values = artifact
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Err(response_proof_contract_conflict(
            "response rollback receipt artifact does not match response execution proof contract",
        ));
    }
    Ok(values)
}

pub(crate) fn response_proof_contract_required_effect_field<'a>(
    value: Option<&'a str>,
    message: &'static str,
) -> Result<&'a str, (StatusCode, String)> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| response_proof_contract_conflict(message))
}

pub(crate) fn verify_rollback_effect_matches_execution_effect(
    rollback_effect: &EndpointResponseExecutionEffect,
    execution_effect: &EndpointResponseExecutionEffect,
) -> Result<(), (StatusCode, String)> {
    if rollback_effect.target == execution_effect.target
        && rollback_effect.artifact == execution_effect.artifact
        && rollback_effect.content_hash == execution_effect.content_hash
        && rollback_effect.byte_count == execution_effect.byte_count
    {
        return Ok(());
    }
    Err(response_proof_contract_conflict(
        "response rollback receipt effect does not match response execution proof contract",
    ))
}
