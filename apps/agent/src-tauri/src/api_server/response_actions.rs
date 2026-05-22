use super::*;

pub(crate) fn supported_edr_simulation_action(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::Block
            | EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
    )
}

pub(crate) fn validate_response_action_actor(
    actor: Option<&EdrResponseActionActorInput>,
) -> Result<(), (StatusCode, String)> {
    let Some(actor) = actor else {
        return Err((
            StatusCode::BAD_REQUEST,
            "live response execution requires actor identity".to_string(),
        ));
    };
    if !response_action_actor_identity_present(actor) {
        return Err((
            StatusCode::BAD_REQUEST,
            "live response execution actor must include userId, sessionId, agentId, workloadId, or approvalId".to_string(),
        ));
    }
    if non_empty(actor.approval_id.as_deref()).is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "live response execution requires actor approvalId".to_string(),
        ));
    }
    Ok(())
}

fn response_action_actor_identity_present(actor: &EdrResponseActionActorInput) -> bool {
    [
        actor.user_id.as_deref(),
        actor.session_id.as_deref(),
        actor.agent_id.as_deref(),
        actor.workload_id.as_deref(),
        actor.approval_id.as_deref(),
    ]
    .into_iter()
    .any(|value| non_empty(value).is_some())
}

pub(crate) fn validate_response_action_actor_fields(
    actor: Option<&EdrResponseActionActorInput>,
) -> Result<(), (StatusCode, String)> {
    let Some(actor) = actor else {
        return Ok(());
    };
    for (field, value) in [
        (
            "actor.endpointId",
            non_empty(Some(actor.endpoint_id.as_str())),
        ),
        ("actor.hostId", non_empty(actor.host_id.as_deref())),
        ("actor.userId", non_empty(actor.user_id.as_deref())),
        ("actor.sessionId", non_empty(actor.session_id.as_deref())),
        ("actor.posture", non_empty(actor.posture.as_deref())),
        ("actor.agentId", non_empty(actor.agent_id.as_deref())),
        ("actor.workloadId", non_empty(actor.workload_id.as_deref())),
        ("actor.approvalId", non_empty(actor.approval_id.as_deref())),
    ] {
        if value.is_some_and(|value| value.len() > EDR_MAX_RESPONSE_ACTOR_FIELD_BYTES) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("{field} must be at most {EDR_MAX_RESPONSE_ACTOR_FIELD_BYTES} bytes"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_response_action_ttl_seconds(
    ttl_seconds: Option<u64>,
) -> Result<u64, (StatusCode, String)> {
    let ttl_seconds = ttl_seconds.unwrap_or(EDR_DEFAULT_RESPONSE_TTL_SECONDS);
    if (1..=EDR_MAX_RESPONSE_TTL_SECONDS).contains(&ttl_seconds) {
        return Ok(ttl_seconds);
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("ttlSeconds must be between 1 and {EDR_MAX_RESPONSE_TTL_SECONDS} seconds"),
    ))
}

pub(crate) fn validate_response_reason(
    field: &str,
    reason: Option<&str>,
    default_reason: &'static str,
) -> Result<String, (StatusCode, String)> {
    let reason = reason
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(default_reason);
    if reason.len() <= EDR_MAX_RESPONSE_REASON_BYTES {
        return Ok(reason.to_string());
    }
    Err((
        StatusCode::BAD_REQUEST,
        format!("{field} reason must be at most {EDR_MAX_RESPONSE_REASON_BYTES} bytes"),
    ))
}

pub(crate) fn default_response_action_reason(
    action: &EndpointDecisionAction,
    dry_run: bool,
) -> &'static str {
    if dry_run {
        return "endpoint response dry run";
    }
    match action {
        EndpointDecisionAction::CollectEvidence => "collect endpoint evidence",
        EndpointDecisionAction::RestrictEgress => "restrict endpoint egress",
        EndpointDecisionAction::QuarantineFile => "quarantine endpoint file",
        EndpointDecisionAction::DisablePersistence => "disable endpoint persistence item",
        EndpointDecisionAction::RevokeGrant => "revoke local endpoint grant",
        EndpointDecisionAction::SuspendProcessTree => "suspend endpoint process tree",
        EndpointDecisionAction::TerminateProcessTree => "terminate endpoint process tree",
        _ => "execute endpoint response",
    }
}

pub(crate) async fn execute_edr_response_action(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    match plan.action {
        EndpointDecisionAction::CollectEvidence => {
            execute_collect_evidence_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::RestrictEgress => {
            execute_restrict_egress_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::QuarantineFile => {
            execute_quarantine_file_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::DisablePersistence => {
            execute_disable_persistence_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::RevokeGrant => {
            execute_revoke_grant_response(state, plan, graph, actor).await
        }
        EndpointDecisionAction::SuspendProcessTree => {
            execute_suspend_process_tree_response(state, plan, graph, actor).await
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "unsupported endpoint response action for live executor: {}",
                plan.action.as_str()
            ),
        )),
    }
}

pub(crate) async fn record_failed_edr_response_execution(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
    failure: &str,
) -> Result<(String, Option<String>), String> {
    let execution = EndpointResponseExecutionReport::failed(plan, graph, failure)
        .map_err(|err| format!("build failed response execution report: {err}"))?;
    let (execution, _stored_bundle, receipt, _bundle_receipt) =
        persist_edr_response_execution(state, execution, graph, actor)
            .await
            .map_err(|(_status, err)| err)?;
    Ok((execution.execution_id, receipt.receipt.receipt_id.clone()))
}

pub(crate) fn response_action_failure_error(
    status: StatusCode,
    message: String,
    failure_record: Result<(String, Option<String>), String>,
) -> (StatusCode, String) {
    match failure_record {
        Ok((execution_id, receipt_id)) => {
            let receipt = receipt_id.unwrap_or_else(|| "unknown".to_string());
            (
                status,
                format!(
                    "{message}; failed response execution recorded as {execution_id} with receipt {receipt}"
                ),
            )
        }
        Err(err) => (
            status,
            format!("{message}; failed to record response failure receipt: {err}"),
        ),
    }
}

pub(crate) fn sanitize_response_execution_failure(message: &str) -> String {
    let redacted = redact_developer_activity_command_line(message.trim());
    truncate_delivery_error(&redact_response_failure_secret_like_fragments(&redacted))
}

pub(crate) fn sanitize_provider_status_reason(reason: &str) -> String {
    sanitize_response_execution_failure(reason)
}

fn redact_response_failure_secret_like_fragments(message: &str) -> String {
    let bytes = message.as_bytes();
    let mut redacted = String::with_capacity(message.len());
    let mut index = 0;
    while index < bytes.len() {
        if let Some((start, end)) = response_failure_secret_like_range(message, index) {
            debug_assert_eq!(start, index);
            redacted.push_str("[REDACTED]");
            index = end;
            continue;
        }
        let Some(ch) = message[index..].chars().next() else {
            break;
        };
        redacted.push(ch);
        index += ch.len_utf8();
    }
    redacted
}

fn response_failure_secret_like_range(message: &str, index: usize) -> Option<(usize, usize)> {
    for prefix in [
        "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "sk-", "xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-",
    ] {
        if !message[index..].starts_with(prefix) {
            continue;
        }
        let mut end = index + prefix.len();
        while end < message.len()
            && message
                .as_bytes()
                .get(end)
                .is_some_and(|byte| response_failure_token_byte(*byte))
        {
            end += 1;
        }
        if developer_activity_secret_like_value(&message[index..end]) {
            return Some((index, end));
        }
    }

    if message[index..].starts_with("AKIA") {
        let mut end = index + "AKIA".len();
        while end < message.len()
            && message
                .as_bytes()
                .get(end)
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
        {
            end += 1;
        }
        if developer_activity_secret_like_value(&message[index..end]) {
            return Some((index, end));
        }
    }

    None
}

fn response_failure_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

async fn execute_collect_evidence_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let execution =
        EndpointResponseExecutionReport::collect_evidence(plan, graph).map_err(internal_error)?;
    persist_edr_response_execution(state, execution, graph, actor).await
}

async fn execute_restrict_egress_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let targets = restrict_egress_targets(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid egress restriction target: {err}"),
        )
    })?;
    ensure_network_extension_ready_for_restrict_egress(state).await?;
    let execution = EndpointResponseExecutionReport::restrict_egress(plan, graph, &targets)
        .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_restrict_egress",
    )
    .await?;
    let reload_proof = append_edr_egress_restrictions(state, &execution, &targets).await?;
    ensure_network_extension_reload_proof_succeeded(&reload_proof).map_err(|message| {
        (
            StatusCode::CONFLICT,
            format!("NetworkExtension did not activate egress restrictions: {message}"),
        )
    })?;
    let additional_evidence = network_extension_reload_request_evidence(&reload_proof);
    persist_edr_response_execution_with_evidence(
        state,
        execution,
        graph,
        actor,
        &additional_evidence,
    )
    .await
}

async fn execute_quarantine_file_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let source_path = quarantine_file_target_path(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid quarantine target: {err}"),
        )
    })?;
    validate_quarantine_source_path(&source_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe quarantine target: {err}"),
        )
    })?;
    let bytes = fs::read(&source_path)
        .with_context(|| format!("read quarantine target {}", source_path.display()))
        .map_err(internal_error)?;
    let byte_count = bytes.len() as u64;
    let content_hash = sha256(&bytes).to_hex_prefixed();
    let quarantine_root = state.edr_quarantine_root.as_ref();
    fs::create_dir_all(quarantine_root)
        .with_context(|| format!("create quarantine directory {}", quarantine_root.display()))
        .map_err(internal_error)?;
    let quarantine_path =
        quarantine_destination_path(quarantine_root, plan, &source_path, &content_hash);
    if quarantine_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "quarantine artifact already exists: {}",
                quarantine_path.display()
            ),
        ));
    }
    let mut execution = EndpointResponseExecutionReport::quarantine_file(
        plan,
        graph,
        source_path.display().to_string(),
        quarantine_path.display().to_string(),
        &content_hash,
        byte_count,
    )
    .map_err(internal_error)?;
    execution.actor = Some(actor.clone());
    let stored_bundle = state
        .edr_evidence_bundle_store
        .lock()
        .await
        .store(&execution.evidence_bundle, graph)
        .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_quarantine_file",
    )
    .await?;
    fs::rename(&source_path, &quarantine_path)
        .with_context(|| {
            format!(
                "move quarantine target {} to {}",
                source_path.display(),
                quarantine_path.display()
            )
        })
        .map_err(internal_error)?;
    let (execution_receipt, evidence_bundle_receipt) =
        append_and_receipt_edr_response_execution(state, &execution, graph, Some(actor), &[])
            .await?;
    Ok((
        execution,
        stored_bundle,
        execution_receipt,
        evidence_bundle_receipt,
    ))
}

async fn execute_disable_persistence_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let source_path = disable_persistence_target_path(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid persistence target: {err}"),
        )
    })?;
    validate_disable_persistence_source_path(&source_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe persistence target: {err}"),
        )
    })?;
    let bytes = fs::read(&source_path)
        .with_context(|| format!("read persistence target {}", source_path.display()))
        .map_err(internal_error)?;
    let byte_count = bytes.len() as u64;
    let content_hash = sha256(&bytes).to_hex_prefixed();
    let quarantine_root = state.edr_quarantine_root.as_ref();
    fs::create_dir_all(quarantine_root)
        .with_context(|| {
            format!(
                "create persistence disable directory {}",
                quarantine_root.display()
            )
        })
        .map_err(internal_error)?;
    let disabled_path =
        persistence_disable_destination_path(quarantine_root, plan, &source_path, &content_hash);
    if disabled_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "disabled persistence artifact already exists: {}",
                disabled_path.display()
            ),
        ));
    }
    let mut execution = EndpointResponseExecutionReport::disable_persistence(
        plan,
        graph,
        source_path.display().to_string(),
        disabled_path.display().to_string(),
        &content_hash,
        byte_count,
    )
    .map_err(internal_error)?;
    execution.actor = Some(actor.clone());
    let stored_bundle = state
        .edr_evidence_bundle_store
        .lock()
        .await
        .store(&execution.evidence_bundle, graph)
        .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_disable_persistence",
    )
    .await?;
    fs::rename(&source_path, &disabled_path)
        .with_context(|| {
            format!(
                "move persistence target {} to {}",
                source_path.display(),
                disabled_path.display()
            )
        })
        .map_err(internal_error)?;
    let (execution_receipt, evidence_bundle_receipt) =
        append_and_receipt_edr_response_execution(state, &execution, graph, Some(actor), &[])
            .await?;
    Ok((
        execution,
        stored_bundle,
        execution_receipt,
        evidence_bundle_receipt,
    ))
}

async fn execute_revoke_grant_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let grant_target = revoke_grant_target(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid revoke grant target: {err}"),
        )
    })?;
    let (grant_target, revoked_grant_hash) = match grant_target {
        RevokeGrantTarget::LocalApiAuthToken => {
            return Err((
                StatusCode::CONFLICT,
                "local API auth token revocation is not safe for autonomous response without durable replacement-token handoff and recovery"
                    .to_string(),
            ));
        }
        RevokeGrantTarget::BrokerCapability { capability_id } => {
            let revocation = revoke_broker_capability_grant(state, &capability_id).await?;
            let revoked_grant_hash =
                canonical_json_hash(&revocation, "broker capability revoke result")
                    .map_err(internal_error)?;
            (
                format!("broker_capability:{capability_id}"),
                revoked_grant_hash,
            )
        }
        RevokeGrantTarget::LocalIntegrationSecret { secret } => {
            let revocation = revoke_local_integration_secret_grant(state, secret).await?;
            let revoked_grant_hash =
                canonical_json_hash(&revocation, "local integration secret revoke result")
                    .map_err(internal_error)?;
            (
                format!("local_integration_secret:{}", secret.target_suffix()),
                revoked_grant_hash,
            )
        }
    };
    let execution = EndpointResponseExecutionReport::revoke_grant(
        plan,
        graph,
        grant_target,
        revoked_grant_hash,
    )
    .map_err(internal_error)?;
    persist_edr_response_execution(state, execution, graph, actor).await
}

async fn execute_suspend_process_tree_response(
    state: &AgentApiState,
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    let targets = suspend_process_tree_targets(plan, graph).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid process tree target: {err}"),
        )
    })?;
    validate_process_signal_targets(&targets).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe process tree target: {err}"),
        )
    })?;
    for target in &targets {
        validate_process_signal_target_before_signal(target).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!("process {} cannot be signalled safely: {err}", target.pid),
            )
        })?;
    }

    let root_pid = targets.first().map(|target| target.pid).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "process tree target is empty".to_string(),
        )
    })?;
    let identity_bindings = targets
        .iter()
        .map(|target| EndpointResponseProcessIdentityBinding {
            pid: target.pid,
            process_identity_key: target.process_identity_key.clone(),
        })
        .collect::<Vec<_>>();
    let execution = EndpointResponseExecutionReport::suspend_process_tree_with_identity_bindings(
        plan,
        graph,
        root_pid,
        &identity_bindings,
    )
    .map_err(internal_error)?;
    emit_pre_effect_response_execution_receipt(
        state,
        &execution,
        graph,
        actor.clone(),
        "pre_effect_suspend_process_tree",
    )
    .await?;

    let mut suspended = Vec::new();
    for target in targets.iter().rev() {
        validate_process_signal_target_before_signal(target).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!(
                    "process {} identity changed before suspend signal: {err}",
                    target.pid
                ),
            )
        })?;
        if let Err(err) = signal_process(target.pid, process_suspend_signal()) {
            let mut resume_errors = Vec::new();
            for pid in &suspended {
                if let Err(resume_err) = signal_process(*pid, process_resume_signal()) {
                    resume_errors.push(format!(
                        "failed to resume partially suspended pid {pid}: {resume_err}"
                    ));
                }
            }
            let cleanup_reason = format!(
                "suspend process tree failed while signalling pid {}; partial suspend cleanup ran",
                target.pid
            );
            if resume_errors.is_empty() {
                let compensated = EndpointResponseExecutionReport::rolled_back_from(
                    &execution,
                    cleanup_reason.as_str(),
                    chrono::Utc::now(),
                );
                {
                    let mut ledger = state.edr_response_execution_ledger.lock().await;
                    ledger.append(&compensated).map_err(internal_error)?;
                }
                let _ = emit_edr_response_execution_receipt(
                    state,
                    &compensated,
                    graph,
                    compensated.actor.clone(),
                    &[EndpointReceiptEvidence::hashed(
                        "partialSuspendCleanupForExecutionId",
                        execution.execution_id.as_str(),
                    )],
                )
                .await;
            } else {
                let failure = resume_errors.join("; ");
                let _ = record_edr_response_rollback_failure(
                    state,
                    &execution,
                    cleanup_reason.as_str(),
                    failure.as_str(),
                    graph,
                )
                .await;
            }
            let cleanup_suffix = if resume_errors.is_empty() {
                "; partially suspended processes were resumed and a rollback transition was recorded".to_string()
            } else {
                format!(
                    "; partial suspend cleanup failed and remains rollbackable: {}",
                    resume_errors.join("; ")
                )
            };
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "failed to suspend process {}: {err}{cleanup_suffix}",
                    target.pid
                ),
            ));
        }
        suspended.push(target.pid);
    }
    persist_edr_response_execution(state, execution, graph, actor).await
}

pub(crate) async fn execute_restrict_egress_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let rollback =
        EndpointResponseRollbackReport::restrict_egress(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    {
        let mut ledger = state.edr_egress_restriction_ledger.lock().await;
        ledger
            .deactivate_execution(&execution.execution_id, rollback.completed_at)
            .map_err(internal_error)?;
    }
    sync_edr_network_extension_egress_policy(state, rollback.completed_at).await?;
    Ok(rollback)
}

pub(crate) fn response_execution_expires_with_rollback(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        &EndpointDecisionAction::RestrictEgress
            | &EndpointDecisionAction::QuarantineFile
            | &EndpointDecisionAction::DisablePersistence
            | &EndpointDecisionAction::SuspendProcessTree
    )
}

pub(crate) async fn execute_response_expiration_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let reason = format!("response execution {} TTL expired", execution.execution_id);
    match execution.action {
        EndpointDecisionAction::RestrictEgress => {
            execute_restrict_egress_rollback(state, execution, &reason).await
        }
        EndpointDecisionAction::QuarantineFile => {
            execute_quarantine_file_rollback(state, execution, &reason)
        }
        EndpointDecisionAction::DisablePersistence => {
            execute_disable_persistence_rollback(state, execution, &reason)
        }
        EndpointDecisionAction::SuspendProcessTree => {
            execute_suspend_process_tree_rollback(execution, &reason)
        }
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!(
                "response execution {} is not rollback-capable at expiration time",
                execution.execution_id
            ),
        )),
    }
}

pub(crate) fn execute_quarantine_file_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let effect = quarantine_file_effect(execution).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid quarantine execution effect: {err}"),
        )
    })?;
    let target_path = PathBuf::from(effect.target.as_str());
    validate_quarantine_restore_target_path(&target_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe rollback target: {err}"),
        )
    })?;
    if target_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "rollback target already exists, refusing overwrite: {}",
                target_path.display()
            ),
        ));
    }
    let artifact_path = effect
        .artifact
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "quarantine effect is missing artifact path".to_string(),
            )
        })?;
    validate_quarantine_artifact_path(state.edr_quarantine_root.as_ref(), &artifact_path)?;
    let artifact_bytes = fs::read(&artifact_path)
        .with_context(|| format!("read quarantine artifact {}", artifact_path.display()))
        .map_err(internal_error)?;
    let artifact_hash = sha256(&artifact_bytes).to_hex_prefixed();
    let expected_hash = effect.content_hash.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "quarantine effect is missing content hash".to_string(),
        )
    })?;
    if artifact_hash != expected_hash {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "quarantine artifact hash mismatch: expected {expected_hash}, got {artifact_hash}"
            ),
        ));
    }
    if let Some(expected_bytes) = effect.byte_count {
        if artifact_bytes.len() as u64 != expected_bytes {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "quarantine artifact byte count mismatch: expected {expected_bytes}, got {}",
                    artifact_bytes.len()
                ),
            ));
        }
    }
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create rollback target directory {}", parent.display()))
            .map_err(internal_error)?;
    }
    let rollback =
        EndpointResponseRollbackReport::quarantine_file(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    fs::rename(&artifact_path, &target_path)
        .with_context(|| {
            format!(
                "restore quarantine artifact {} to {}",
                artifact_path.display(),
                target_path.display()
            )
        })
        .map_err(internal_error)?;
    Ok(rollback)
}

pub(crate) fn execute_disable_persistence_rollback(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let effect = disable_persistence_effect(execution).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid persistence execution effect: {err}"),
        )
    })?;
    let target_path = PathBuf::from(effect.target.as_str());
    validate_disable_persistence_restore_target_path(&target_path).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("unsafe persistence rollback target: {err}"),
        )
    })?;
    if target_path.exists() {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "persistence rollback target already exists, refusing overwrite: {}",
                target_path.display()
            ),
        ));
    }
    let artifact_path = effect
        .artifact
        .as_deref()
        .map(PathBuf::from)
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "disable_persistence effect is missing artifact path".to_string(),
            )
        })?;
    validate_quarantine_artifact_path(state.edr_quarantine_root.as_ref(), &artifact_path)?;
    let artifact_bytes = fs::read(&artifact_path)
        .with_context(|| {
            format!(
                "read disabled persistence artifact {}",
                artifact_path.display()
            )
        })
        .map_err(internal_error)?;
    let artifact_hash = sha256(&artifact_bytes).to_hex_prefixed();
    let expected_hash = effect.content_hash.as_deref().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            "disable_persistence effect is missing content hash".to_string(),
        )
    })?;
    if artifact_hash != expected_hash {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "disabled persistence artifact hash mismatch: expected {expected_hash}, got {artifact_hash}"
            ),
        ));
    }
    if let Some(expected_bytes) = effect.byte_count {
        if artifact_bytes.len() as u64 != expected_bytes {
            return Err((
                StatusCode::CONFLICT,
                format!(
                    "disabled persistence artifact byte count mismatch: expected {expected_bytes}, got {}",
                    artifact_bytes.len()
                ),
            ));
        }
    }
    if let Some(parent) = target_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| {
                format!(
                    "create persistence rollback target directory {}",
                    parent.display()
                )
            })
            .map_err(internal_error)?;
    }
    let rollback =
        EndpointResponseRollbackReport::disable_persistence(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    fs::rename(&artifact_path, &target_path)
        .with_context(|| {
            format!(
                "restore disabled persistence artifact {} to {}",
                artifact_path.display(),
                target_path.display()
            )
        })
        .map_err(internal_error)?;
    Ok(rollback)
}

pub(crate) fn execute_suspend_process_tree_rollback(
    execution: &EndpointResponseExecutionReport,
    reason: &str,
) -> Result<EndpointResponseRollbackReport, (StatusCode, String)> {
    let effect = suspend_process_tree_effect(execution).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid process tree execution effect: {err}"),
        )
    })?;
    let targets = process_tree_effect_signal_targets(effect).map_err(|err| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid process tree pid set: {err}"),
        )
    })?;
    let rollback =
        EndpointResponseRollbackReport::suspend_process_tree(execution, reason, chrono::Utc::now())
            .map_err(internal_error)?;
    for target in &targets {
        validate_process_effect_signal_target_before_signal(target).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!(
                    "process {} identity changed before resume signal: {err}",
                    target.pid
                ),
            )
        })?;
        signal_process(target.pid, process_resume_signal()).map_err(|err| {
            (
                StatusCode::CONFLICT,
                format!("failed to resume suspended process {}: {err}", target.pid),
            )
        })?;
    }
    Ok(rollback)
}

async fn persist_edr_response_execution(
    state: &AgentApiState,
    execution: EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    persist_edr_response_execution_with_evidence(state, execution, graph, actor, &[]).await
}

async fn emit_pre_effect_response_execution_receipt(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
    phase: &str,
) -> Result<SignedReceipt, (StatusCode, String)> {
    let mut prepared = execution.clone();
    prepared.status = EndpointResponseExecutionStatus::Partial;
    prepared.completed_at = chrono::Utc::now();
    prepared.summary = format!(
        "Durably recorded {} response execution intent before local side effects.",
        execution.action.as_str()
    );
    let reason_hash = sha256(prepared.reason.as_bytes()).to_hex_prefixed();
    prepared.execution_id = response_execution_transition_id(
        "response_execution_partial",
        prepared.action_id.as_str(),
        prepared.evidence_bundle.bundle_id.as_str(),
        prepared.rollback_ref.as_str(),
        reason_hash.as_str(),
    );
    let evidence = [EndpointReceiptEvidence::hashed("executionPhase", phase)];
    state
        .edr_response_execution_ledger
        .lock()
        .await
        .append(&prepared)
        .map_err(internal_error)?;
    emit_edr_response_execution_receipt(state, &prepared, graph, Some(actor), &evidence)
        .await
        .map_err(internal_error)
}

pub(crate) async fn record_edr_response_rollback_intent(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
    graph: &CausalGraph,
) -> Result<(EndpointResponseExecutionReport, SignedReceipt), (StatusCode, String)> {
    let pending = EndpointResponseExecutionReport::rollback_pending_from(
        execution,
        reason,
        chrono::Utc::now(),
    );
    {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger.append(&pending).map_err(internal_error)?;
    }
    let receipt = emit_edr_response_execution_receipt(
        state,
        &pending,
        graph,
        pending.actor.clone(),
        &[EndpointReceiptEvidence::hashed(
            "rollbackIntentForExecutionId",
            execution.execution_id.as_str(),
        )],
    )
    .await
    .map_err(internal_error)?;
    Ok((pending, receipt))
}

pub(crate) async fn record_edr_response_rollback_failure(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    reason: &str,
    failure: &str,
    graph: &CausalGraph,
) -> Result<(EndpointResponseExecutionReport, SignedReceipt), (StatusCode, String)> {
    let failed = EndpointResponseExecutionReport::rollback_failed_from(
        execution,
        reason,
        failure,
        chrono::Utc::now(),
    );
    {
        let mut ledger = state.edr_response_execution_ledger.lock().await;
        ledger.append(&failed).map_err(internal_error)?;
    }
    let receipt = emit_edr_response_execution_receipt(
        state,
        &failed,
        graph,
        failed.actor.clone(),
        &[EndpointReceiptEvidence::hashed(
            "rollbackFailureForExecutionId",
            execution.execution_id.as_str(),
        )],
    )
    .await
    .map_err(internal_error)?;
    Ok((failed, receipt))
}

fn response_execution_transition_id(
    prefix: &str,
    response_action_id: &str,
    evidence_bundle_id: &str,
    rollback_ref: &str,
    reason_hash: &str,
) -> String {
    edr_fnv_stable_id(
        prefix,
        [
            response_action_id,
            evidence_bundle_id,
            rollback_ref,
            reason_hash,
        ],
    )
}

fn edr_fnv_stable_id<'a>(prefix: &str, parts: impl IntoIterator<Item = &'a str>) -> String {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = FNV_OFFSET;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(FNV_PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    format!("{prefix}:{hash:016x}")
}

async fn persist_edr_response_execution_with_evidence(
    state: &AgentApiState,
    mut execution: EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: EndpointDecisionActor,
    additional_evidence: &[EndpointReceiptEvidence],
) -> Result<
    (
        EndpointResponseExecutionReport,
        StoredEndpointEvidenceBundle,
        SignedReceipt,
        SignedReceipt,
    ),
    (StatusCode, String),
> {
    execution.actor = Some(actor.clone());
    let stored_bundle = state
        .edr_evidence_bundle_store
        .lock()
        .await
        .store(&execution.evidence_bundle, graph)
        .map_err(internal_error)?;
    let (execution_receipt, evidence_bundle_receipt) = append_and_receipt_edr_response_execution(
        state,
        &execution,
        graph,
        Some(actor),
        additional_evidence,
    )
    .await?;
    Ok((
        execution,
        stored_bundle,
        execution_receipt,
        evidence_bundle_receipt,
    ))
}

async fn append_and_receipt_edr_response_execution(
    state: &AgentApiState,
    execution: &EndpointResponseExecutionReport,
    graph: &CausalGraph,
    actor: Option<EndpointDecisionActor>,
    additional_evidence: &[EndpointReceiptEvidence],
) -> Result<(SignedReceipt, SignedReceipt), (StatusCode, String)> {
    state
        .edr_response_execution_ledger
        .lock()
        .await
        .append(execution)
        .map_err(internal_error)?;
    let receipt =
        emit_edr_response_execution_receipt(state, execution, graph, actor, additional_evidence)
            .await
            .map_err(internal_error)?;
    let bundle_receipt = emit_edr_evidence_bundle_manifest_receipt(state, execution, graph)
        .await
        .map_err(internal_error)?;
    Ok((receipt, bundle_receipt))
}

pub(crate) async fn append_edr_response_acknowledgement(
    state: &AgentApiState,
    acknowledgement: &EndpointResponseAcknowledgementReport,
) -> Result<Option<String>, (StatusCode, String)> {
    let mut ledger = state.edr_response_acknowledgement_ledger.lock().await;
    let path = ledger.path().map(|path| path.display().to_string());
    ledger.append(acknowledgement).map_err(internal_error)?;
    Ok(path)
}

async fn append_edr_egress_restrictions(
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

pub(crate) async fn active_egress_restriction_for_policy_check(
    state: &AgentApiState,
    input: &PolicyCheckInput,
) -> Option<EndpointEgressRestriction> {
    let target = normalize_egress_policy_target(&input.action_type, &input.target)?;
    let ledger = state.edr_egress_restriction_ledger.lock().await;
    ledger.active_match(&target, chrono::Utc::now())
}

pub(crate) fn policy_output_for_active_egress_restriction(
    restriction: &EndpointEgressRestriction,
) -> PolicyCheckOutput {
    PolicyCheckOutput {
        allowed: false,
        guard: Some("edr_restrict_egress".to_string()),
        severity: Some("high".to_string()),
        message: Some(format!(
            "Egress to {} denied by active EDR response execution {}",
            restriction.target, restriction.execution_id
        )),
        details: Some(serde_json::json!({
            "reason": "active_edr_egress_restriction",
            "target": restriction.target.clone(),
            "executionId": restriction.execution_id.clone(),
            "actionId": restriction.action_id.clone(),
            "rollbackRef": restriction.rollback_ref.clone(),
            "graphSliceId": restriction.graph_slice_id.clone(),
            "expiresAt": restriction.expires_at,
        })),
    }
}

fn restrict_egress_targets(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<Vec<String>> {
    let root = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    let root_target = if root.kind == CausalNodeKind::Network {
        Some(egress_target_from_node(root)?)
    } else {
        None
    };

    let mut targets = graph
        .nodes
        .values()
        .filter(|node| node.kind == CausalNodeKind::Network)
        .map(egress_target_from_node)
        .collect::<Result<Vec<_>>>()?;
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "restrict_egress requires at least one network node in the graph slice"
        ));
    }
    if let Some(root_target) = root_target {
        targets.retain(|target| target != &root_target);
        targets.insert(0, root_target);
    }
    Ok(targets)
}

fn egress_target_from_node(node: &clawdstrike_policy_event::edr::CausalNode) -> Result<String> {
    normalize_egress_target(node.label.as_str())
        .with_context(|| format!("normalize network node target {}", node.label))
}

fn normalize_egress_policy_target(action_type: &str, target: &str) -> Option<String> {
    let action = action_type.trim().to_ascii_lowercase();
    if action != "egress" && action != "network" {
        return None;
    }
    let target = target.trim();
    let lower = target.to_ascii_lowercase();
    let target = if lower.starts_with("http://")
        || lower.starts_with("https://")
        || lower.starts_with("ws://")
        || lower.starts_with("wss://")
    {
        let url = reqwest::Url::parse(target).ok()?;
        let host = url.host_str()?;
        let port = url.port_or_known_default()?;
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    } else {
        target.to_string()
    };
    normalize_egress_target(target.as_str()).ok()
}

fn normalize_egress_target(target: &str) -> Result<String> {
    let target = target.trim();
    if target.is_empty() {
        return Err(anyhow::anyhow!("egress target must not be empty"));
    }
    if target.len() > 512 {
        return Err(anyhow::anyhow!("egress target must be at most 512 bytes"));
    }
    if target
        .chars()
        .any(|ch| ch.is_ascii_whitespace() || matches!(ch, '*' | ',' | '/'))
    {
        return Err(anyhow::anyhow!(
            "egress target must be a literal host:port without wildcards or paths"
        ));
    }
    let (host, port) = split_egress_host_port(target)?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("parse egress target port {port}"))?;
    if port == 0 {
        return Err(anyhow::anyhow!("egress target port must be non-zero"));
    }
    let normalized_host = host.trim_matches(['[', ']']).to_ascii_lowercase();
    if normalized_host.is_empty() {
        return Err(anyhow::anyhow!("egress target host must not be empty"));
    }
    if matches!(
        normalized_host.as_str(),
        "localhost" | "localhost.localdomain"
    ) {
        return Err(anyhow::anyhow!("refusing to restrict local host egress"));
    }
    if let Ok(ip) = normalized_host.parse::<IpAddr>() {
        validate_egress_restriction_ip(ip)?;
    }
    if normalized_host.contains(':') {
        Ok(format!("[{normalized_host}]:{port}"))
    } else {
        Ok(format!("{normalized_host}:{port}"))
    }
}

fn split_egress_host_port(target: &str) -> Result<(&str, &str)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, port) = rest
            .split_once("]:")
            .ok_or_else(|| anyhow::anyhow!("bracketed egress target must be [host]:port"))?;
        return Ok((host, port));
    }
    target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("egress target must include a port"))
}

fn validate_egress_restriction_ip(ip: IpAddr) -> Result<()> {
    let blocked = match ip {
        IpAddr::V4(ip) => {
            ip.is_loopback()
                || ip.is_private()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.is_unspecified()
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ipv6_is_unique_local(&ip)
                || ipv6_is_unicast_link_local(&ip)
                || ip.is_multicast()
        }
    };
    if blocked {
        return Err(anyhow::anyhow!(
            "refusing to restrict local, private, link-local, multicast, or documentation egress target {ip}"
        ));
    }
    Ok(())
}

fn ipv6_is_unique_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xfe00) == 0xfc00
}

fn ipv6_is_unicast_link_local(ip: &std::net::Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

// quarantine_file_target_path moved to crate::edr::response
fn disable_persistence_target_path(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<PathBuf> {
    let node = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    let path = match node.kind {
        CausalNodeKind::File => PathBuf::from(node.label.trim()),
        CausalNodeKind::BrowserExtension => {
            browser_extension_manifest_target_path(PathBuf::from(node.label.trim()))
        }
        _ => {
            return Err(anyhow::anyhow!(
                "root node must be a file or browser_extension node for disable_persistence, got {:?}",
                node.kind
            ));
        }
    };
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "persistence target path must be absolute: {}",
            node.label
        ));
    }
    if !path_is_bounded_persistence_target(&path) {
        return Err(anyhow::anyhow!(
            "persistence target must be a bounded LaunchAgent/LaunchDaemon plist, systemd user/system unit or drop-in, XDG autostart desktop entry, KDE Plasma env/autostart script, shell startup file, system profile drop-in, user cron spool file, system cron drop-in, or browser extension manifest: {}",
            path.display()
        ));
    }
    Ok(path)
}

fn browser_extension_manifest_target_path(path: PathBuf) -> PathBuf {
    if path
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|file_name| file_name.eq_ignore_ascii_case("manifest.json"))
    {
        path
    } else {
        path.join("manifest.json")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RevokeGrantTarget {
    LocalApiAuthToken,
    BrokerCapability { capability_id: String },
    LocalIntegrationSecret { secret: LocalIntegrationSecretKind },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct BrokerCapabilityRevokeReport {
    pub(crate) capability_id: String,
    pub(crate) revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) provider_revocation: Option<BrokerProviderTokenRevocationReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) struct BrokerProviderTokenRevocationReport {
    pub(crate) provider: String,
    pub(crate) secret_ref_id: String,
    pub(crate) attempted: bool,
    pub(crate) supported: bool,
    pub(crate) revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) provider_token_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) response_body_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LocalIntegrationSecretKind {
    #[serde(rename = "siem.api_key")]
    SiemApiKey,
    #[serde(rename = "webhooks.secret")]
    WebhooksSecret,
}

impl LocalIntegrationSecretKind {
    fn target_suffix(self) -> &'static str {
        match self {
            Self::SiemApiKey => "siem.api_key",
            Self::WebhooksSecret => "webhooks.secret",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LocalIntegrationSecretRevokeReport {
    pub(crate) secret: LocalIntegrationSecretKind,
    pub(crate) previous_secret_hash: String,
    pub(crate) integration_disabled: bool,
    pub(crate) revoked: bool,
}

pub(crate) fn revoke_grant_target(
    plan: &EndpointResponsePlan,
    graph: &CausalGraph,
) -> Result<RevokeGrantTarget> {
    let root = graph
        .nodes
        .get(&plan.root_node_id)
        .ok_or_else(|| anyhow::anyhow!("root node not found: {}", plan.root_node_id))?;
    if let Some(root_target) = revoke_grant_target_from_credential_node(root) {
        return Ok(root_target);
    }

    let mut targets = Vec::new();
    for node in graph.nodes.values() {
        let Some(target) = revoke_grant_target_from_credential_node(node) else {
            continue;
        };
        if !targets.contains(&target) {
            targets.push(target);
        }
    }
    if targets.len() == 1 {
        return Ok(targets.remove(0));
    }
    if targets.len() > 1 {
        return Err(anyhow::anyhow!(
            "ambiguous live revoke_grant target: graph contains multiple revocable credential targets; select the specific credential root node"
        ));
    }

    Err(anyhow::anyhow!(
        "live revoke_grant currently supports graph targets containing a local agent API token credential, local broker capability credential, or local integration secret credential"
    ))
}

fn revoke_grant_target_from_credential_node(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Option<RevokeGrantTarget> {
    if credential_node_is_local_api_grant(node) {
        return Some(RevokeGrantTarget::LocalApiAuthToken);
    }
    if let Some(capability_id) = broker_capability_id_from_credential_node(node) {
        return Some(RevokeGrantTarget::BrokerCapability { capability_id });
    }
    local_integration_secret_from_credential_node(node)
        .map(|secret| RevokeGrantTarget::LocalIntegrationSecret { secret })
}

fn credential_node_is_local_api_grant(node: &clawdstrike_policy_event::edr::CausalNode) -> bool {
    if node.kind != CausalNodeKind::Credential {
        return false;
    }
    let mut values = vec![node.label.as_str()];
    for key in ["path", "name", "credentialKind"] {
        if let Some(value) = node.attributes.get(key).and_then(Value::as_str) {
            values.push(value);
        }
    }
    values.iter().any(|value| {
        let normalized = value.to_ascii_lowercase();
        normalized.contains("agent-local-token")
            || normalized.contains("clawdstrike_agent_auth")
            || normalized.contains("clawdstrike-local-api-token")
            || normalized.contains("local_api_auth_token")
    })
}

fn broker_capability_id_from_credential_node(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Option<String> {
    if node.kind != CausalNodeKind::Credential {
        return None;
    }

    for key in ["capabilityId", "capability_id", "brokerCapabilityId"] {
        if let Some(value) = node.attributes.get(key).and_then(Value::as_str) {
            if let Some(capability_id) = normalize_broker_capability_id(value) {
                return Some(capability_id);
            }
        }
    }

    let values = credential_node_string_values(node);
    for value in &values {
        if let Some(capability_id) = extract_prefixed_broker_capability_id(value) {
            return Some(capability_id);
        }
    }

    let credential_kind = node
        .attributes
        .get("credentialKind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase()
        .replace(['-', ' '], "_");
    let is_broker_capability = matches!(
        credential_kind.as_str(),
        "broker_capability" | "clawdstrike_broker_capability" | "brokerd_capability"
    );
    if !is_broker_capability {
        return None;
    }

    values
        .iter()
        .filter(|value| !broker_capability_value_is_kind_sentinel(value))
        .find_map(|value| normalize_broker_capability_id(value))
}

fn credential_node_string_values(node: &clawdstrike_policy_event::edr::CausalNode) -> Vec<String> {
    let mut values = vec![node.label.clone()];
    for key in ["path", "name"] {
        if let Some(value) = node.attributes.get(key).and_then(Value::as_str) {
            values.push(value.to_string());
        }
    }
    values
}

fn local_integration_secret_from_credential_node(
    node: &clawdstrike_policy_event::edr::CausalNode,
) -> Option<LocalIntegrationSecretKind> {
    if node.kind != CausalNodeKind::Credential {
        return None;
    }

    if let Some(secret) = local_integration_secret_kind_from_structured_attributes(&node.attributes)
    {
        return Some(secret);
    }

    let values = credential_node_string_values(node);
    values
        .iter()
        .find_map(|value| local_integration_secret_kind_from_value(value))
}

fn local_integration_secret_kind_from_structured_attributes(
    attributes: &BTreeMap<String, Value>,
) -> Option<LocalIntegrationSecretKind> {
    const STRUCTURED_SECRET_KEYS: &[&str] = &[
        "credentialKind",
        "credential_kind",
        "integrationSecret",
        "integration_secret",
        "integrationSecretKind",
        "integration_secret_kind",
        "localIntegrationSecret",
        "local_integration_secret",
        "settingKey",
        "setting_key",
        "settingsKey",
        "settings_key",
        "configKey",
        "config_key",
        "secretRef",
        "secret_ref",
        "secretRefId",
        "secret_ref_id",
    ];

    STRUCTURED_SECRET_KEYS
        .iter()
        .filter_map(|key| attributes.get(*key))
        .find_map(local_integration_secret_kind_from_attribute_value)
}

fn local_integration_secret_kind_from_attribute_value(
    value: &Value,
) -> Option<LocalIntegrationSecretKind> {
    match value {
        Value::String(value) => local_integration_secret_kind_from_value(value),
        Value::Array(items) => items
            .iter()
            .find_map(local_integration_secret_kind_from_attribute_value),
        Value::Object(object) => [
            "kind",
            "secretKind",
            "secret_kind",
            "settingKey",
            "setting_key",
            "settingsKey",
            "settings_key",
            "configKey",
            "config_key",
            "ref",
            "id",
            "name",
            "path",
        ]
        .iter()
        .filter_map(|key| object.get(*key))
        .find_map(local_integration_secret_kind_from_attribute_value),
        _ => None,
    }
}

fn local_integration_secret_kind_from_value(value: &str) -> Option<LocalIntegrationSecretKind> {
    let normalized = normalize_secret_identifier(value);
    if matches!(
        normalized.as_str(),
        "siem_api_key"
            | "integrations_siem_api_key"
            | "integration_siem_api_key"
            | "clawdstrike_integrations_siem_api_key"
    ) || normalized.contains("clawdstrike_integrations_siem_api_key")
        || normalized.contains("agent_integrations_siem_api_key")
        || normalized.contains("integration_siem_api_key")
        || normalized.contains("integrations_siem_api_key")
        || normalized.contains("local_siem_api_key")
        || normalized.contains("clawdstrike_siem_api_key")
        || normalized.contains("datadog_api_key")
        || normalized.contains("splunk_token")
        || normalized.contains("elastic_api_key")
    {
        return Some(LocalIntegrationSecretKind::SiemApiKey);
    }
    if matches!(
        normalized.as_str(),
        "webhook_secret"
            | "webhooks_secret"
            | "integrations_webhook_secret"
            | "integrations_webhooks_secret"
            | "clawdstrike_integrations_webhooks_secret"
    ) || normalized.contains("clawdstrike_integrations_webhooks_secret")
        || normalized.contains("agent_integrations_webhooks_secret")
        || normalized.contains("integration_webhook_secret")
        || normalized.contains("integrations_webhook_secret")
        || normalized.contains("integrations_webhooks_secret")
        || normalized.contains("local_webhook_secret")
        || normalized.contains("clawdstrike_webhook_secret")
        || normalized.contains("webhook_signing_secret")
        || normalized.contains("webhook_secret")
    {
        return Some(LocalIntegrationSecretKind::WebhooksSecret);
    }
    None
}

fn normalize_secret_identifier(value: &str) -> String {
    let mut normalized = String::with_capacity(value.len());
    let mut last_was_separator = false;
    for byte in value.bytes() {
        let next = if byte.is_ascii_alphanumeric() {
            last_was_separator = false;
            Some(byte.to_ascii_lowercase() as char)
        } else if !last_was_separator {
            last_was_separator = true;
            Some('_')
        } else {
            None
        };
        if let Some(next) = next {
            normalized.push(next);
        }
    }
    normalized.trim_matches('_').to_string()
}

fn extract_prefixed_broker_capability_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    let normalized = trimmed.to_ascii_lowercase();
    for prefix in [
        "credential:broker-capability:",
        "credential:broker_capability:",
        "broker-capability:",
        "broker_capability:",
        "broker capability:",
        "capability:",
    ] {
        if normalized.starts_with(prefix) {
            return normalize_broker_capability_id(&trimmed[prefix.len()..]);
        }
    }
    None
}

fn normalize_broker_capability_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if !broker_capability_id_is_safe_for_path(trimmed) {
        return None;
    }
    Some(trimmed.to_string())
}

fn broker_capability_value_is_kind_sentinel(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase().replace(['-', ' '], "_");
    matches!(
        normalized.as_str(),
        "broker_capability" | "clawdstrike_broker_capability" | "brokerd_capability"
    )
}

fn broker_capability_id_is_safe_for_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

pub(crate) async fn revoke_broker_capability_grant(
    state: &AgentApiState,
    capability_id: &str,
) -> Result<BrokerCapabilityRevokeReport, (StatusCode, String)> {
    if !broker_capability_id_is_safe_for_path(capability_id) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("unsafe broker capability id for revoke_grant: {capability_id}"),
        ));
    }

    let (enabled, port, admin_token) = {
        let settings = state.settings.read().await;
        (
            settings.brokerd.enabled,
            settings.brokerd.port,
            settings.brokerd.admin_token.clone(),
        )
    };
    if !enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            "brokerd is disabled; cannot revoke broker capability grant".to_string(),
        ));
    }

    let url = format!("http://127.0.0.1:{port}/v1/capabilities/{capability_id}/revoke");
    let mut request = state.http_client.post(url);
    if let Some(token) = admin_token
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        request = request.header(AUTHORIZATION.as_str(), format!("Bearer {token}"));
    }

    let response = request.send().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("brokerd capability revoke request failed: {err}"),
        )
    })?;
    let status =
        StatusCode::from_u16(response.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    if !status.is_success() {
        let body = response.text().await.unwrap_or_else(|_| String::new());
        let detail = if body.trim().is_empty() {
            format!("brokerd capability revoke returned HTTP {status}")
        } else {
            format!(
                "brokerd capability revoke returned HTTP {status}: {}",
                sanitize_brokerd_error_body(&body)
            )
        };
        return Err((status, detail));
    }

    let body = response.text().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("brokerd capability revoke response body could not be read: {err}"),
        )
    })?;
    serde_json::from_str::<BrokerCapabilityRevokeReport>(&body).map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            format!("brokerd capability revoke response was invalid: {err}"),
        )
    })
}

fn sanitize_brokerd_error_body(body: &str) -> String {
    sanitize_response_execution_failure(body)
}

pub(crate) async fn revoke_local_integration_secret_grant(
    state: &AgentApiState,
    secret: LocalIntegrationSecretKind,
) -> Result<LocalIntegrationSecretRevokeReport, (StatusCode, String)> {
    let mut settings = state.settings.write().await;
    let mut next_integrations = settings.integrations.clone();
    let (previous_secret, integration_disabled) = match secret {
        LocalIntegrationSecretKind::SiemApiKey => {
            let previous_secret = next_integrations.siem.api_key.trim().to_string();
            let integration_disabled = next_integrations.siem.enabled;
            next_integrations.siem.api_key.clear();
            next_integrations.siem.enabled = false;
            (previous_secret, integration_disabled)
        }
        LocalIntegrationSecretKind::WebhooksSecret => {
            let previous_secret = next_integrations.webhooks.secret.trim().to_string();
            let integration_disabled = next_integrations.webhooks.enabled;
            next_integrations.webhooks.secret.clear();
            next_integrations.webhooks.enabled = false;
            (previous_secret, integration_disabled)
        }
    };

    if previous_secret.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "local integration secret {} is not configured; cannot revoke grant",
                secret.target_suffix()
            ),
        ));
    }

    let previous_secret_hash = sha256(previous_secret.as_bytes()).to_hex_prefixed();
    let mut next_settings = settings.clone();
    next_settings.integrations = next_integrations.clone();
    next_settings
        .save()
        .map_err(|err| (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()))?;
    settings.integrations = next_integrations;

    Ok(LocalIntegrationSecretRevokeReport {
        secret,
        previous_secret_hash,
        integration_disabled,
        revoked: true,
    })
}

// ProcessSignalTarget, suspend_process_tree_targets moved to crate::edr::response
// process_node_pid moved to crate::edr::response
fn validate_process_signal_targets(targets: &[ProcessSignalTarget]) -> Result<()> {
    if targets.is_empty() {
        return Err(anyhow::anyhow!(
            "process tree has no signalable process nodes"
        ));
    }
    let current_pid = std::process::id();
    let parent_pid = current_parent_pid();
    for target in targets {
        if target.pid == 0 || target.pid == 1 {
            return Err(anyhow::anyhow!(
                "refusing to signal protected pid {}",
                target.pid
            ));
        }
        if target.pid == current_pid {
            return Err(anyhow::anyhow!("refusing to signal current agent process"));
        }
        if Some(target.pid) == parent_pid {
            return Err(anyhow::anyhow!("refusing to signal parent process"));
        }
        if process_label_is_protected(&target.label) {
            return Err(anyhow::anyhow!(
                "refusing to signal protected process label {}",
                target.label
            ));
        }
    }
    Ok(())
}

fn validate_process_signal_target_before_signal(target: &ProcessSignalTarget) -> Result<()> {
    validate_process_identity_binding(target.pid, Some(target.process_identity_key.as_str()))?;
    check_process_signalable(target.pid)
}

fn validate_process_effect_signal_target_before_signal(
    target: &ProcessTreeEffectSignalTarget,
) -> Result<()> {
    validate_process_identity_binding(target.pid, target.process_identity_key.as_deref())?;
    check_process_signalable(target.pid)
}

pub(crate) fn validate_process_identity_binding(
    pid: u32,
    identity_key: Option<&str>,
) -> Result<()> {
    let identity_key = identity_key
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing durable process identity binding"))?;
    if !identity_key.starts_with("guid:") {
        return Err(anyhow::anyhow!(
            "process identity binding is not durable: {identity_key}"
        ));
    }
    if let Some(rest) = identity_key.strip_prefix("guid:macos:") {
        let Some(identity_pid) = rest.split(':').next() else {
            return Err(anyhow::anyhow!("macOS process identity is missing pid"));
        };
        let identity_pid = identity_pid
            .parse::<u32>()
            .with_context(|| format!("parse macOS process identity pid {identity_pid}"))?;
        if identity_pid != pid {
            return Err(anyhow::anyhow!(
                "macOS process identity pid {identity_pid} does not match live target pid {pid}"
            ));
        }
    }
    Ok(())
}

fn process_label_is_protected(label: &str) -> bool {
    let normalized = label.to_ascii_lowercase();
    [
        "kernel_task",
        "launchd",
        "loginwindow",
        "windowserver",
        "systemuiserver",
        "tccd",
        "syspolicyd",
        "systemextensiond",
        "networkextensiond",
        "clawdstrike",
    ]
    .iter()
    .any(|protected| normalized.contains(protected))
}

#[cfg(unix)]
fn current_parent_pid() -> Option<u32> {
    let pid = unsafe { libc::getppid() };
    u32::try_from(pid).ok()
}

#[cfg(not(unix))]
fn current_parent_pid() -> Option<u32> {
    None
}

#[cfg(unix)]
fn process_suspend_signal() -> i32 {
    libc::SIGSTOP
}

#[cfg(not(unix))]
fn process_suspend_signal() -> i32 {
    0
}

#[cfg(unix)]
fn process_resume_signal() -> i32 {
    libc::SIGCONT
}

#[cfg(not(unix))]
fn process_resume_signal() -> i32 {
    0
}

#[cfg(unix)]
fn check_process_signalable(pid: u32) -> Result<()> {
    signal_process(pid, 0)
}

#[cfg(not(unix))]
fn check_process_signalable(_pid: u32) -> Result<()> {
    Err(anyhow::anyhow!(
        "process signalling is only supported on Unix platforms"
    ))
}

#[cfg(unix)]
fn signal_process(pid: u32, signal: i32) -> Result<()> {
    let pid = i32::try_from(pid).context("pid exceeds platform signal range")?;
    let result = unsafe { libc::kill(pid, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).with_context(|| {
            if signal == 0 {
                format!("check signal permission for pid {pid}")
            } else {
                format!("send signal {signal} to pid {pid}")
            }
        })
    }
}

#[cfg(not(unix))]
fn signal_process(_pid: u32, _signal: i32) -> Result<()> {
    Err(anyhow::anyhow!(
        "process signalling is only supported on Unix platforms"
    ))
}

fn validate_quarantine_source_path(path: &FsPath) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat quarantine target {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "quarantine target must not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow::anyhow!(
            "quarantine target must be a regular file: {}",
            path.display()
        ));
    }
    if !path_is_bounded_quarantine_source(path) {
        return Err(anyhow::anyhow!(
            "quarantine target must be in a temp, download, cache, node_modules, or build-output path: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_disable_persistence_source_path(path: &FsPath) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("stat persistence target {}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(anyhow::anyhow!(
            "persistence target must not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(anyhow::anyhow!(
            "persistence target must be a regular file: {}",
            path.display()
        ));
    }
    if !path_is_bounded_persistence_target(path) {
        return Err(anyhow::anyhow!(
            "persistence target must be a bounded LaunchAgent/LaunchDaemon plist, systemd user/system unit or drop-in, XDG autostart desktop entry, KDE Plasma env/autostart script, shell startup file, system profile drop-in, user cron spool file, system cron drop-in, or browser extension manifest: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_disable_persistence_restore_target_path(path: &FsPath) -> Result<()> {
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "persistence rollback target path must be absolute: {}",
            path.display()
        ));
    }
    if !path_is_bounded_persistence_target(path) {
        return Err(anyhow::anyhow!(
            "persistence rollback target must be a bounded LaunchAgent/LaunchDaemon plist, systemd user/system unit or drop-in, XDG autostart desktop entry, KDE Plasma env/autostart script, shell startup file, system profile drop-in, user cron spool file, system cron drop-in, or browser extension manifest: {}",
            path.display()
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "persistence rollback target must not be a symlink: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_quarantine_restore_target_path(path: &FsPath) -> Result<()> {
    if !path.is_absolute() {
        return Err(anyhow::anyhow!(
            "rollback target path must be absolute: {}",
            path.display()
        ));
    }
    if !path_is_bounded_quarantine_source(path) {
        return Err(anyhow::anyhow!(
            "rollback target must be in a temp, download, cache, node_modules, or build-output path: {}",
            path.display()
        ));
    }
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink() {
            return Err(anyhow::anyhow!(
                "rollback target must not be a symlink: {}",
                path.display()
            ));
        }
    }
    Ok(())
}

fn validate_quarantine_artifact_path(
    quarantine_root: &FsPath,
    artifact_path: &FsPath,
) -> Result<(), (StatusCode, String)> {
    let root = fs::canonicalize(quarantine_root)
        .with_context(|| format!("canonicalize quarantine root {}", quarantine_root.display()))
        .map_err(internal_error)?;
    let artifact = fs::canonicalize(artifact_path)
        .with_context(|| {
            format!(
                "canonicalize quarantine artifact {}",
                artifact_path.display()
            )
        })
        .map_err(internal_error)?;
    if !artifact.starts_with(root.as_path()) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "quarantine artifact is outside quarantine root: {}",
                artifact_path.display()
            ),
        ));
    }
    let metadata = fs::symlink_metadata(artifact_path)
        .with_context(|| format!("stat quarantine artifact {}", artifact_path.display()))
        .map_err(internal_error)?;
    if metadata.file_type().is_symlink() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "quarantine artifact must not be a symlink: {}",
                artifact_path.display()
            ),
        ));
    }
    if !metadata.is_file() {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "quarantine artifact must be a regular file: {}",
                artifact_path.display()
            ),
        ));
    }
    Ok(())
}

fn path_is_bounded_quarantine_source(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.contains("/Downloads/")
        || normalized.contains("/Library/Caches/")
        || normalized.contains("/.cache/")
        || normalized.contains("/node_modules/")
        || normalized.contains("/target/debug/")
        || normalized.contains("/target/release/")
}

pub(crate) fn path_is_bounded_persistence_target(path: &FsPath) -> bool {
    path_is_bounded_launch_persistence_target(path)
        || path_is_bounded_systemd_user_persistence_target(path)
        || path_is_bounded_systemd_system_persistence_target(path)
        || path_is_bounded_systemd_user_dropin_persistence_target(path)
        || path_is_bounded_systemd_system_dropin_persistence_target(path)
        || path_is_bounded_xdg_autostart_persistence_target(path)
        || path_is_bounded_plasma_env_persistence_target(path)
        || path_is_bounded_kde_autostart_script_persistence_target(path)
        || path_is_bounded_shell_startup_persistence_target(path)
        || path_is_bounded_profile_d_persistence_target(path)
        || path_is_bounded_cron_persistence_target(path)
        || path_is_bounded_system_cron_dropin_persistence_target(path)
        || path_is_bounded_browser_extension_manifest_target(path)
}

fn path_is_bounded_launch_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if !normalized.ends_with(".plist")
        || !normalized.contains("/Library/LaunchAgents/")
            && !normalized.contains("/Library/LaunchDaemons/")
    {
        return false;
    }
    if let Some(file_name) = path.file_name().and_then(|value| value.to_str()) {
        let normalized_file = file_name.to_ascii_lowercase();
        if normalized_file.starts_with("com.apple.")
            || normalized_file.starts_with("com.clawdstrike.")
            || normalized_file.starts_with("io.clawdstrike.")
        {
            return false;
        }
    }
    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.starts_with("/Library/LaunchAgents/")
        || normalized.starts_with("/Library/LaunchDaemons/")
        || (normalized.starts_with("/Users/") && !normalized.contains("/../"))
}

fn path_is_bounded_systemd_user_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_unit_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    systemd_user_unit_components_are_bounded(&components, file_name)
}

fn systemd_user_unit_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 6 {
        return false;
    }
    let base = components.len() - 6;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "systemd"
        && components[base + 4] == "user"
        && components[base + 5] == file_name
}

fn path_is_bounded_systemd_user_dropin_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_dropin_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    systemd_user_dropin_components_are_bounded(&components, file_name)
}

fn systemd_user_dropin_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 7 {
        return false;
    }
    let base = components.len() - 7;
    let home_component = components[base];
    let user = components[base + 1];
    let unit_dir = components[base + 5];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "systemd"
        && components[base + 4] == "user"
        && systemd_unit_dropin_dir_name_is_safe(unit_dir)
        && components[base + 6] == file_name
}

fn path_is_bounded_systemd_system_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_system_unit_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_unit_like = normalized.starts_with("/etc/systemd/system/");
    if !temp_like && !system_unit_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["etc", "systemd", "system", file_name])
}

fn path_is_bounded_systemd_system_dropin_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !systemd_dropin_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_unit_like = normalized.starts_with("/etc/systemd/system/");
    if !temp_like && !system_unit_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    systemd_system_dropin_components_are_bounded(&components, file_name)
}

fn systemd_system_dropin_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 5 {
        return false;
    }
    let base = components.len() - 5;
    let unit_dir = components[base + 3];
    components[base] == "etc"
        && components[base + 1] == "systemd"
        && components[base + 2] == "system"
        && systemd_system_unit_dropin_dir_name_is_safe(unit_dir)
        && components[base + 4] == file_name
}

fn systemd_unit_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    matches!(extension, "service" | "timer" | "socket")
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
}

fn systemd_unit_dropin_dir_name_is_safe(dir_name: &str) -> bool {
    dir_name
        .strip_suffix(".d")
        .is_some_and(systemd_unit_file_name_is_safe)
}

fn systemd_system_unit_dropin_dir_name_is_safe(dir_name: &str) -> bool {
    dir_name
        .strip_suffix(".d")
        .is_some_and(systemd_system_unit_file_name_is_safe)
}

fn systemd_dropin_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "conf"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@'))
}

fn systemd_system_unit_file_name_is_safe(file_name: &str) -> bool {
    if !systemd_unit_file_name_is_safe(file_name) {
        return false;
    }
    let stem = file_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(file_name);
    let normalized_stem = stem.to_ascii_lowercase();
    if normalized_stem.starts_with("systemd")
        || normalized_stem.starts_with("getty")
        || normalized_stem.starts_with("serial-getty")
        || normalized_stem.starts_with("clawdstrike")
        || normalized_stem.starts_with("com.clawdstrike")
        || normalized_stem.starts_with("io.clawdstrike")
    {
        return false;
    }
    !matches!(
        normalized_stem.as_str(),
        "ssh"
            | "sshd"
            | "cron"
            | "crond"
            | "dbus"
            | "networkmanager"
            | "networking"
            | "containerd"
            | "docker"
            | "kubelet"
            | "login"
            | "sudo"
            | "polkit"
    )
}

fn path_is_bounded_xdg_autostart_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !xdg_autostart_desktop_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    let system_autostart_like = normalized.starts_with("/etc/xdg/autostart/");
    if !temp_like && !user_home_like && !system_autostart_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    xdg_user_autostart_components_are_bounded(&components, file_name)
        || xdg_system_autostart_components_are_bounded(&components, file_name)
}

fn xdg_user_autostart_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 5 {
        return false;
    }
    let base = components.len() - 5;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "autostart"
        && components[base + 4] == file_name
}

fn xdg_system_autostart_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    cron_spool_components_end_with(components, &["etc", "xdg", "autostart", file_name])
        && xdg_system_autostart_desktop_file_name_is_safe(file_name)
}

fn xdg_autostart_desktop_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "desktop"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn xdg_system_autostart_desktop_file_name_is_safe(file_name: &str) -> bool {
    if !xdg_autostart_desktop_file_name_is_safe(file_name) {
        return false;
    }
    let stem = file_name
        .rsplit_once('.')
        .map(|(stem, _)| stem)
        .unwrap_or(file_name)
        .to_ascii_lowercase();
    if stem.starts_with("org.gnome.")
        || stem.starts_with("org.kde.")
        || stem.starts_with("org.freedesktop.")
        || stem.starts_with("gnome-keyring")
        || stem.starts_with("clawdstrike")
    {
        return false;
    }
    !matches!(
        stem.as_str(),
        "polkit" | "dbus" | "ssh-agent" | "at-spi-dbus-bus" | "xdg-user-dirs" | "nm-applet"
    )
}

fn path_is_bounded_plasma_env_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !plasma_env_script_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    plasma_env_components_are_bounded(&components, file_name)
}

fn plasma_env_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 6 {
        return false;
    }
    let base = components.len() - 6;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "plasma-workspace"
        && components[base + 4] == "env"
        && components[base + 5] == file_name
}

fn plasma_env_script_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "sh"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn path_is_bounded_kde_autostart_script_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !plasma_env_script_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/home/") || normalized.starts_with("/Users/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    kde_autostart_script_components_are_bounded(&components, file_name)
}

fn kde_autostart_script_components_are_bounded(components: &[&str], file_name: &str) -> bool {
    if components.len() < 5 {
        return false;
    }
    let base = components.len() - 5;
    let home_component = components[base];
    let user = components[base + 1];
    matches!(home_component, "home" | "Users")
        && cron_spool_user_name_is_safe(user)
        && components[base + 2] == ".config"
        && components[base + 3] == "autostart-scripts"
        && components[base + 4] == file_name
}

fn path_is_bounded_shell_startup_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let user_home_like = normalized.starts_with("/Users/") || normalized.starts_with("/home/");
    if !temp_like && !user_home_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    shell_startup_components_are_bounded(&components)
}

fn shell_startup_components_are_bounded(components: &[&str]) -> bool {
    let home_shell_file = if components.len() >= 3 {
        let base = components.len() - 3;
        let home_component = components[base];
        let user = components[base + 1];
        let file = components[base + 2];
        matches!(home_component, "Users" | "home")
            && cron_spool_user_name_is_safe(user)
            && matches!(
                file,
                ".bashrc" | ".bash_profile" | ".zshrc" | ".zprofile" | ".profile"
            )
    } else {
        false
    };
    let fish_config = if components.len() >= 5 {
        let base = components.len() - 5;
        let home_component = components[base];
        let user = components[base + 1];
        matches!(home_component, "Users" | "home")
            && cron_spool_user_name_is_safe(user)
            && components[base + 2] == ".config"
            && components[base + 3] == "fish"
            && components[base + 4] == "config.fish"
    } else {
        false
    };
    let fish_conf_d = if components.len() >= 6 {
        let base = components.len() - 6;
        let home_component = components[base];
        let user = components[base + 1];
        let file = components[base + 5];
        matches!(home_component, "Users" | "home")
            && cron_spool_user_name_is_safe(user)
            && components[base + 2] == ".config"
            && components[base + 3] == "fish"
            && components[base + 4] == "conf.d"
            && fish_conf_d_file_name_is_safe(file)
    } else {
        false
    };

    home_shell_file || fish_config || fish_conf_d
}

fn fish_conf_d_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    extension == "fish"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !matches!(stem.to_ascii_lowercase().as_str(), "config" | "conf")
        && !stem.to_ascii_lowercase().starts_with("clawdstrike.")
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn path_is_bounded_profile_d_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !profile_d_script_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_profile_like = normalized.starts_with("/etc/profile.d/");
    if !temp_like && !system_profile_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["etc", "profile.d", file_name])
}

fn path_is_bounded_cron_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(user) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !cron_spool_user_name_is_safe(user) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_cron_like =
        normalized.starts_with("/var/spool/cron/") || normalized.starts_with("/usr/lib/cron/tabs/");
    if !temp_like && !system_cron_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["var", "spool", "cron", "crontabs", user])
        || cron_spool_components_end_with(&components, &["var", "spool", "cron", user])
        || cron_spool_components_end_with(&components, &["usr", "lib", "cron", "tabs", user])
}

fn path_is_bounded_system_cron_dropin_persistence_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !cron_dropin_file_name_is_safe(file_name) {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let temp_like = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/");
    let system_cron_dropin_like = normalized.starts_with("/etc/cron.d/");
    if !temp_like && !system_cron_dropin_like {
        return false;
    }

    let components = normalized
        .trim_start_matches('/')
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    cron_spool_components_end_with(&components, &["etc", "cron.d", file_name])
}

fn path_is_bounded_browser_extension_manifest_target(path: &FsPath) -> bool {
    let normalized = path.display().to_string().replace('\\', "/");
    if normalized.contains("/../") {
        return false;
    }
    let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    if !file_name.eq_ignore_ascii_case("manifest.json") {
        return false;
    }

    let temp_dir = std::env::temp_dir()
        .display()
        .to_string()
        .replace('\\', "/");
    let allowed_root = normalized.starts_with(temp_dir.as_str())
        || normalized.starts_with("/tmp/")
        || normalized.starts_with("/private/tmp/")
        || normalized.starts_with("/var/folders/")
        || normalized.starts_with("/home/")
        || normalized.starts_with("/Users/");
    if !allowed_root {
        return false;
    }

    let chromium_manifest = [
        "/Library/Application Support/Google/Chrome/",
        "/Library/Application Support/Chromium/",
        "/Library/Application Support/Microsoft Edge/",
        "/Library/Application Support/BraveSoftware/Brave-Browser/",
    ]
    .iter()
    .any(|marker| normalized.contains(marker))
        && normalized.contains("/Extensions/")
        && chromium_browser_extension_manifest_components_are_bounded(&normalized);
    let firefox_manifest = [
        "/Library/Application Support/Firefox/Profiles/",
        "/.mozilla/firefox/",
    ]
    .iter()
    .any(|marker| firefox_browser_extension_manifest_components_are_bounded(&normalized, marker));

    chromium_manifest || firefox_manifest
}

fn chromium_browser_extension_manifest_components_are_bounded(normalized: &str) -> bool {
    let Some((_, extension_suffix)) = normalized.rsplit_once("/Extensions/") else {
        return false;
    };
    let components = extension_suffix
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    components.len() == 3
        && components.last() == Some(&"manifest.json")
        && browser_extension_path_component_is_safe(components[0])
        && browser_extension_path_component_is_safe(components[1])
}

fn firefox_browser_extension_manifest_components_are_bounded(
    normalized: &str,
    profile_marker: &str,
) -> bool {
    let Some((_, profile_suffix)) = normalized.rsplit_once(profile_marker) else {
        return false;
    };
    let components = profile_suffix
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    components.len() == 4
        && components[1] == "extensions"
        && components[3].eq_ignore_ascii_case("manifest.json")
        && browser_extension_path_component_is_safe(components[0])
        && firefox_extension_path_component_is_safe(components[2])
}

fn browser_extension_path_component_is_safe(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 128
        && !component.starts_with('.')
        && component
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn firefox_extension_path_component_is_safe(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= 128
        && !component.starts_with('.')
        && component.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'@' | b'{' | b'}')
        })
}

fn cron_spool_components_end_with(components: &[&str], suffix: &[&str]) -> bool {
    components.len() >= suffix.len()
        && components[components.len() - suffix.len()..]
            .iter()
            .zip(suffix.iter())
            .all(|(left, right)| left == right)
}

fn cron_spool_user_name_is_safe(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 64
        && !user.starts_with('.')
        && !matches!(user, "root" | "daemon" | "nobody")
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn cron_dropin_file_name_is_safe(file_name: &str) -> bool {
    let normalized = file_name.to_ascii_lowercase();
    !file_name.is_empty()
        && file_name.len() <= 128
        && !file_name.starts_with('.')
        && !matches!(
            normalized.as_str(),
            "0hourly" | "anacron" | "cron" | "cronie" | "clawdstrike"
        )
        && !normalized.starts_with("clawdstrike.")
        && !normalized.starts_with("com.clawdstrike.")
        && file_name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn profile_d_script_file_name_is_safe(file_name: &str) -> bool {
    let Some((stem, extension)) = file_name.rsplit_once('.') else {
        return false;
    };
    let normalized_stem = stem.to_ascii_lowercase();
    extension == "sh"
        && !stem.is_empty()
        && stem.len() <= 128
        && !stem.starts_with('.')
        && !stem.eq_ignore_ascii_case("clawdstrike")
        && !normalized_stem.starts_with("clawdstrike.")
        && !normalized_stem.starts_with("com.clawdstrike.")
        && !matches!(
            normalized_stem.as_str(),
            "bash_completion"
                | "colorgrep"
                | "colorls"
                | "lang"
                | "locale"
                | "proxy"
                | "ssh-agent"
                | "systemd"
        )
        && stem
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

// quarantine_file_effect, disable_persistence_effect, suspend_process_tree_effect,
// process_tree_effect_pids moved to crate::edr::response
// quarantine_destination_path, safe_filename_fragment moved to crate::edr::response

fn persistence_disable_destination_path(
    quarantine_root: &FsPath,
    plan: &EndpointResponsePlan,
    source_path: &FsPath,
    content_hash: &str,
) -> PathBuf {
    let hash_fragment = content_hash
        .trim_start_matches("0x")
        .chars()
        .take(16)
        .collect::<String>();
    let source_name = source_path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("launch-agent.plist");
    quarantine_root.join(format!(
        "{}-{}-{}.disabled-persistence",
        safe_filename_fragment(&plan.action_id),
        safe_filename_fragment(&hash_fragment),
        safe_filename_fragment(source_name)
    ))
}

pub(crate) fn supported_edr_response_action(action: &EndpointDecisionAction) -> bool {
    matches!(
        action,
        EndpointDecisionAction::RestrictEgress
            | EndpointDecisionAction::SuspendProcessTree
            | EndpointDecisionAction::TerminateProcessTree
            | EndpointDecisionAction::QuarantineFile
            | EndpointDecisionAction::RevokeGrant
            | EndpointDecisionAction::DisablePersistence
            | EndpointDecisionAction::CollectEvidence
    )
}

// endpoint_security_event_* helpers moved to crate::edr::conversion::endpoint_security
