//! NetworkExtension egress policy reload coordination.
//!
//! Writes the active egress restriction snapshot to disk and asks the macOS
//! NetworkExtension provider to reload it, polling provider status until the
//! reload is acknowledged or the configured timeout elapses. Also folds local
//! policy egress blocks into the snapshot for policy delta applies and
//! provides rollback helpers for failed reloads.

use super::*;

pub(crate) async fn append_edr_egress_restrictions(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    targets: &[String],
) -> Result<NetworkExtensionReloadRequestProof, (StatusCode, String)> {
    let now = execution.completed_at;
    let expires_at = execution.expires_at();
    let restrictions = targets
        .iter()
        .map(|target| EndpointEgressRestriction::active(execution, target, now, expires_at))
        .collect::<Vec<_>>();
    {
        let mut ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger.append(&restrictions).map_err(internal_error)?;
    }
    let reload_proof = match sync_edr_network_extension_egress_policy(state, now).await {
        Ok(reload_proof) => reload_proof,
        Err(err) => {
            rollback_egress_restrictions_after_failed_reload(state, execution, now).await?;
            return Err(err);
        }
    };
    if let Err(message) = ensure_network_extension_reload_proof_succeeded(&reload_proof) {
        rollback_egress_restrictions_after_failed_reload(state, execution, now).await?;
        return Err((
            StatusCode::CONFLICT,
            format!("NetworkExtension egress policy reload failed: {message}"),
        ));
    }
    Ok(reload_proof)
}

async fn rollback_egress_restrictions_after_failed_reload(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), (StatusCode, String)> {
    {
        let mut ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger
            .deactivate_execution(&execution.execution_id, now)
            .map_err(internal_error)?;
    }
    match sync_edr_network_extension_egress_policy(state, now).await {
        Ok(rollback_proof) => {
            if let Err(message) = ensure_network_extension_reload_proof_succeeded(&rollback_proof) {
                tracing::warn!(
                    execution_id = %execution.execution_id,
                    action_id = %execution.action_id,
                    error = %message,
                    "NetworkExtension egress restriction rollback snapshot was written but reload did not acknowledge"
                );
            }
        }
        Err((status, message)) => {
            tracing::warn!(
                execution_id = %execution.execution_id,
                action_id = %execution.action_id,
                status = %status,
                error = %message,
                "NetworkExtension egress restriction rollback sync failed"
            );
        }
    }
    Ok(())
}

pub(crate) fn ensure_network_extension_reload_proof_succeeded(
    proof: &NetworkExtensionReloadRequestProof,
) -> Result<(), String> {
    if proof.requested
        && proof.saved
        && proof.error.is_none()
        && proof.provider_reload_matched
        && proof.provider_policy_synced == Some(true)
        && proof.provider_enforcement_ready == Some(true)
    {
        return Ok(());
    }
    let reason = proof
        .error
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("reload request was not acknowledged by the provider");
    Err(format!(
        "requested={}, saved={}, observed={}, matched={}, policy_synced={:?}, enforcement_ready={:?}, generation={}, reason={reason}",
        proof.requested,
        proof.saved,
        proof.provider_reload_observed,
        proof.provider_reload_matched,
        proof.provider_policy_synced,
        proof.provider_enforcement_ready,
        proof.generation
    ))
}

pub(crate) async fn deactivate_expired_egress_restrictions(
    state: &AgentApiState,
    expired: &[EndpointResponseExecutionReport],
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), (StatusCode, String)> {
    for execution in expired {
        if execution.action == EndpointDecisionAction::RestrictEgress {
            deactivate_egress_restrictions_if_active(state, &execution.action_id, now).await?;
        }
    }
    Ok(())
}

pub(crate) async fn deactivate_egress_restrictions_if_active(
    state: &AgentApiState,
    action_id: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), (StatusCode, String)> {
    {
        let mut ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger
            .deactivate_action_if_active(action_id, now)
            .map_err(internal_error)?;
    }
    sync_edr_network_extension_egress_policy(state, now)
        .await
        .map(|_| ())
}

pub(crate) async fn sync_edr_network_extension_egress_policy(
    state: &AgentApiState,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<NetworkExtensionReloadRequestProof, (StatusCode, String)> {
    let restrictions = active_network_extension_egress_restrictions(state, now, Vec::new()).await;
    write_network_extension_egress_policy_snapshot(
        state.edr_network_extension_egress_policy_path.as_ref(),
        &restrictions,
        now,
    )
    .map_err(internal_error)?;
    Ok(request_network_extension_egress_policy_reload(state, now).await)
}

async fn request_network_extension_egress_policy_reload(
    state: &AgentApiState,
    now: chrono::DateTime<chrono::Utc>,
) -> NetworkExtensionReloadRequestProof {
    let generation = network_extension_reload_generation(now);
    request_network_extension_reload_for_path(
        state,
        state
            .edr_network_extension_egress_policy_path
            .as_ref()
            .clone(),
        generation,
        Duration::from_millis(EDR_DEFAULT_PROVIDER_ACK_TIMEOUT_MS),
        "egress policy sync",
    )
    .await
}

pub(crate) async fn request_policy_delta_network_extension_reload(
    state: &AgentApiState,
    settings: &Settings,
    local_policy: &EndpointPolicySnapshot,
    policy_delta_artifact: Option<&EdrPolicyDeltaArtifact>,
    timeout_ms: u64,
) -> Result<NetworkExtensionReloadRequestProof> {
    let now = chrono::Utc::now();
    let policy_restrictions =
        policy_egress_block_restrictions_from_settings(settings, local_policy, now)?;
    ensure_policy_delta_network_extension_target_represented(
        policy_delta_artifact,
        &policy_restrictions,
    )?;
    let restrictions =
        active_network_extension_egress_restrictions(state, now, policy_restrictions).await;
    write_network_extension_egress_policy_snapshot(
        state.edr_network_extension_egress_policy_path.as_ref(),
        &restrictions,
        now,
    )?;
    let generation = network_extension_reload_generation(now);
    Ok(request_network_extension_reload_for_path(
        state,
        state
            .edr_network_extension_egress_policy_path
            .as_ref()
            .clone(),
        generation,
        Duration::from_millis(timeout_ms),
        "policy delta apply",
    )
    .await)
}

async fn active_network_extension_egress_restrictions(
    state: &AgentApiState,
    now: chrono::DateTime<chrono::Utc>,
    policy_restrictions: Vec<EndpointEgressRestriction>,
) -> Vec<EndpointEgressRestriction> {
    let mut restrictions = {
        let ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger.active_entries(now)
    };
    let mut targets = restrictions
        .iter()
        .map(|restriction| restriction.target.clone())
        .collect::<BTreeSet<_>>();
    for restriction in policy_restrictions {
        if targets.insert(restriction.target.clone()) {
            restrictions.push(restriction);
        }
    }
    restrictions
}

fn policy_egress_block_restrictions_from_settings(
    settings: &Settings,
    local_policy: &EndpointPolicySnapshot,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Vec<EndpointEgressRestriction>> {
    let policy_bytes = fs::read(&settings.policy_path).with_context(|| {
        format!(
            "read local policy for NetworkExtension egress snapshot {}",
            settings.policy_path.display()
        )
    })?;
    let targets = policy_egress_block_targets_from_policy_bytes(&policy_bytes)?;
    let epoch = local_policy.policy_epoch.to_string();
    let policy_id = local_stable_id(
        "policy_egress",
        [
            local_policy.policy_hash.as_str(),
            epoch.as_str(),
            local_policy.policy_version.as_str(),
        ],
    );
    let expires_at = now + chrono::Duration::days(3650);
    Ok(targets
        .into_iter()
        .map(|target| {
            let restriction_id = local_stable_id(
                "policy_egress_restriction",
                [
                    local_policy.policy_hash.as_str(),
                    epoch.as_str(),
                    target.as_str(),
                ],
            );
            EndpointEgressRestriction {
                restriction_id,
                execution_id: policy_id.clone(),
                action_id: policy_id.clone(),
                graph_slice_id: "local-policy-egress-allowlist".to_string(),
                rollback_ref: format!(
                    "policy:{}@{}",
                    local_policy.policy_version, local_policy.policy_epoch
                ),
                target_hash: sha256(target.as_bytes()).to_hex_prefixed(),
                target,
                active: true,
                created_at: now,
                expires_at,
                updated_at: now,
            }
        })
        .collect())
}

fn policy_egress_block_targets_from_policy_bytes(policy_bytes: &[u8]) -> Result<Vec<String>> {
    let policy: serde_yaml::Value = serde_yaml::from_slice(policy_bytes)
        .context("parse local policy yaml for NetworkExtension egress snapshot")?;
    let Some(egress_allowlist) = policy
        .get("guards")
        .and_then(|guards| guards.get("egress_allowlist"))
    else {
        return Ok(Vec::new());
    };

    let mut targets = Vec::new();
    collect_policy_egress_targets(
        egress_allowlist.get("block"),
        "guards.egress_allowlist.block",
        &mut targets,
    )?;
    collect_policy_egress_targets(
        egress_allowlist.get("additional_block"),
        "guards.egress_allowlist.additional_block",
        &mut targets,
    )?;
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn collect_policy_egress_targets(
    value: Option<&serde_yaml::Value>,
    path: &str,
    targets: &mut Vec<String>,
) -> Result<()> {
    let Some(value) = value else {
        return Ok(());
    };
    match value {
        serde_yaml::Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_policy_egress_target(item, format!("{path}[{index}]").as_str(), targets)?;
            }
            Ok(())
        }
        serde_yaml::Value::Null => Ok(()),
        _ => collect_policy_egress_target(value, path, targets),
    }
}

fn collect_policy_egress_target(
    value: &serde_yaml::Value,
    path: &str,
    targets: &mut Vec<String>,
) -> Result<()> {
    let Some(raw_target) = value
        .as_str()
        .map(str::trim)
        .filter(|target| !target.is_empty())
    else {
        return Err(anyhow::anyhow!(
            "{path} must contain string egress targets for NetworkExtension policy sync"
        ));
    };
    match normalize_egress_target(raw_target) {
        Ok(target) => {
            targets.push(target);
        }
        Err(err) => {
            tracing::debug!(
                path,
                target = raw_target,
                error = %err,
                "skipping policy egress target that cannot be represented as a literal NetworkExtension restriction"
            );
        }
    }
    Ok(())
}

fn ensure_policy_delta_network_extension_target_represented(
    artifact: Option<&EdrPolicyDeltaArtifact>,
    restrictions: &[EndpointEgressRestriction],
) -> Result<()> {
    let Some(artifact) = artifact else {
        return Ok(());
    };
    if !matches!(
        (&artifact.candidate.root_kind, &artifact.rollout.action),
        (
            CausalNodeKind::Network,
            EndpointDecisionAction::RestrictEgress | EndpointDecisionAction::Block
        )
    ) {
        return Ok(());
    }

    let target =
        normalize_egress_target(artifact.candidate.root_label.as_str()).with_context(|| {
            format!(
                "normalize policy delta NetworkExtension egress target {}",
                artifact.candidate.root_label
            )
        })?;
    if restrictions
        .iter()
        .any(|restriction| restriction.active && restriction.target == target)
    {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "policy delta NetworkExtension snapshot does not contain enforced egress target {target}"
    ))
}

async fn request_network_extension_reload_for_path(
    state: &AgentApiState,
    policy_snapshot_path: PathBuf,
    generation: u64,
    timeout: Duration,
    context: &str,
) -> NetworkExtensionReloadRequestProof {
    let policy_snapshot_path_display = policy_snapshot_path.display().to_string();
    match state
        .macos_host
        .request_network_extension_reload(policy_snapshot_path, generation, timeout)
        .await
    {
        Ok(result) => {
            let mut proof = NetworkExtensionReloadRequestProof {
                requested: result.requested,
                saved: result.saved,
                request_id: Some(result.request_id),
                policy_snapshot_path: result.policy_snapshot_path,
                generation: result.generation,
                provider_reload_observed: false,
                provider_reload_matched: false,
                provider_reload_request_id_matches: false,
                provider_reload_generation_matches: false,
                provider_reload_policy_snapshot_path_matches: false,
                provider_reloaded: None,
                provider_policy_synced: None,
                provider_enforcement_ready: None,
                provider_reload_elapsed_ms: 0,
                provider_reload_attempts: 0,
                error: None,
            };
            if proof.requested && proof.saved {
                wait_for_network_extension_reload_delivery(state, &mut proof, timeout).await;
            }
            proof
        }
        Err(err) => {
            tracing::warn!(
                error = %err,
                policy_snapshot_path = %policy_snapshot_path_display,
                generation,
                context,
                "NetworkExtension reload request failed"
            );
            NetworkExtensionReloadRequestProof {
                requested: false,
                saved: false,
                request_id: None,
                policy_snapshot_path: policy_snapshot_path_display,
                generation,
                provider_reload_observed: false,
                provider_reload_matched: false,
                provider_reload_request_id_matches: false,
                provider_reload_generation_matches: false,
                provider_reload_policy_snapshot_path_matches: false,
                provider_reloaded: None,
                provider_policy_synced: None,
                provider_enforcement_ready: None,
                provider_reload_elapsed_ms: 0,
                provider_reload_attempts: 0,
                error: Some(err.to_string()),
            }
        }
    }
}

async fn wait_for_network_extension_reload_delivery(
    state: &AgentApiState,
    proof: &mut NetworkExtensionReloadRequestProof,
    timeout: Duration,
) {
    let started = Instant::now();
    let mut attempts = 0u64;

    loop {
        attempts = attempts.saturating_add(1);
        let elapsed = started.elapsed();
        let remaining = timeout.saturating_sub(elapsed);
        let status = match state
            .macos_host
            .request_refresh(remaining.min(EDR_PROVIDER_ACK_POLL_INTERVAL))
            .await
        {
            Ok(status) => status,
            Err(_) => state.macos_host.snapshot().await,
        };
        update_network_extension_reload_delivery(proof, &status, started.elapsed(), attempts);

        if proof.provider_reload_matched || started.elapsed() >= timeout {
            return;
        }

        let remaining = timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return;
        }
        tokio::time::sleep(remaining.min(EDR_PROVIDER_ACK_POLL_INTERVAL)).await;
    }
}

fn update_network_extension_reload_delivery(
    proof: &mut NetworkExtensionReloadRequestProof,
    status: &CombinedSystemExtensionStatus,
    elapsed: Duration,
    attempts: u64,
) {
    let provider = &status.network_extension;
    let observation = provider.last_reload_observation.as_ref();
    let request_id_matches = observation
        .and_then(|observation| observation.request_id.as_deref())
        .zip(proof.request_id.as_deref())
        .is_some_and(|(observed, expected)| observed == expected);
    let generation_matches = observation
        .and_then(|observation| observation.generation)
        .is_some_and(|observed| observed == proof.generation);
    let policy_snapshot_path_matches = observation
        .and_then(|observation| observation.policy_snapshot_path.as_deref())
        .is_some_and(|observed| observed == proof.policy_snapshot_path);
    let provider_reloaded = observation.and_then(|observation| observation.reloaded);
    proof.provider_reload_observed = observation.is_some();
    proof.provider_reload_request_id_matches = request_id_matches;
    proof.provider_reload_generation_matches = generation_matches;
    proof.provider_reload_policy_snapshot_path_matches = policy_snapshot_path_matches;
    proof.provider_reloaded = provider_reloaded;
    proof.provider_policy_synced = provider.policy_synced;
    proof.provider_enforcement_ready = provider.enforcement_ready;
    proof.provider_reload_elapsed_ms = elapsed.as_millis().min(u128::from(u64::MAX)) as u64;
    proof.provider_reload_attempts = attempts;
    proof.provider_reload_matched = proof.requested
        && proof.saved
        && proof.error.is_none()
        && request_id_matches
        && generation_matches
        && policy_snapshot_path_matches
        && provider_reloaded == Some(true)
        && provider.policy_synced == Some(true)
        && provider.enforcement_ready == Some(true);
}

fn network_extension_reload_generation(now: chrono::DateTime<chrono::Utc>) -> u64 {
    u64::try_from(now.timestamp_millis()).unwrap_or(0)
}
