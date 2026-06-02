//! Direct policy deploy/preview handlers and active-policy distribution glue.

use super::*;

pub(crate) struct PolicyDeploymentOutcome {
    pub(crate) deployment_id: Uuid,
    pub(crate) nats_subject: String,
    pub(crate) agent_count: i64,
    pub(crate) kv_write_failures: i64,
}

pub(crate) struct PreparedPolicyDeployment {
    pub(crate) deployment_id: Uuid,
    pub(crate) nats_subject: String,
    pub(crate) agent_count: i64,
    pub(crate) effective_policies: Vec<policy_distribution::EffectiveAgentPolicy>,
    pub(crate) distribution_policy_yaml: String,
}

pub(crate) async fn deploy_policy(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<DeployPolicyRequest>,
) -> Result<Json<DeployPolicyResponse>, ApiError> {
    ensure_policy_deployer(&auth)?;
    let break_glass_reason = require_direct_policy_deploy_break_glass(&req)?;

    // Validate the policy YAML before it becomes tenant distribution state.
    policy_distribution::validate_policy_document(&req.policy_yaml)
        .map_err(ApiError::BadRequest)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let current_active =
        policy_distribution::fetch_active_policy_by_tenant_id_for_update_with_executor(
            &mut *tx,
            auth.tenant_id,
        )
        .await
        .map_err(ApiError::Database)?;
    let base_policy_version = current_active
        .as_ref()
        .map(|policy| policy.version)
        .unwrap_or(0);
    let candidate_policy = active_policy_candidate_from_base(
        auth.tenant_id,
        &auth.slug,
        &req.policy_yaml,
        req.description.as_deref(),
        base_policy_version,
    )?;
    let deployment_id = Uuid::new_v4();
    let deployment_plan = prepare_active_policy_deployment(
        &state,
        auth.tenant_id,
        &auth.slug,
        &candidate_policy,
        deployment_id,
    )
    .await?;
    let active_policy = policy_distribution::upsert_active_policy_after_version_with_executor(
        &mut *tx,
        auth.tenant_id,
        &req.policy_yaml,
        req.description.as_deref(),
        base_policy_version,
    )
    .await
    .map_err(ApiError::Database)?
    .ok_or_else(|| {
        ApiError::Conflict(format!(
            "policy deployment {deployment_id} was based on active policy version {base_policy_version}, but the active policy changed before deployment could be recorded; retry the deployment"
        ))
    })?;
    if active_policy.version != candidate_policy.version {
        return Err(ApiError::Conflict(format!(
            "policy deployment {deployment_id} expected active policy version {}, but recorded version {}; retry the deployment",
            candidate_policy.version, active_policy.version
        )));
    }
    tx.commit().await.map_err(ApiError::Database)?;
    let deployment = distribute_prepared_policy_to_fleet(&state, &auth.slug, deployment_plan).await;
    if deployment.kv_write_failures > 0 {
        tracing::warn!(
            deployment_id = %deployment.deployment_id,
            tenant = %auth.slug,
            kv_write_failures = deployment.kv_write_failures,
            "Policy deployment committed with fleet KV retry debt"
        );
    }

    tracing::info!(
        deployment_id = %deployment.deployment_id,
        tenant = %auth.slug,
        actor = %auth.actor_id(),
        break_glass_reason = %break_glass_reason,
        policy_version = active_policy.version,
        agents = deployment.agent_count,
        kv_write_failures = deployment.kv_write_failures,
        "Break-glass policy deployed to tenant fleet"
    );

    Ok(Json(DeployPolicyResponse {
        deployment_id: deployment.deployment_id,
        tenant_slug: auth.slug,
        nats_subject: deployment.nats_subject,
        agent_count: deployment.agent_count,
        kv_write_failures: deployment.kv_write_failures,
    }))
}

pub(crate) async fn preview_policy(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<PreviewPolicyRequest>,
) -> Result<Json<PreviewPolicyResponse>, ApiError> {
    if auth.role == "viewer" {
        return Err(ApiError::Forbidden);
    }

    let candidate = policy_distribution::preview_active_policy_candidate(
        &state.db,
        auth.tenant_id,
        &req.policy_yaml,
        req.description.as_deref(),
    )
    .await
    .map_err(policy_preview_error)?;
    let distribution_policy_yaml =
        policy_distribution::distribution_policy_yaml(&candidate).map_err(ApiError::Internal)?;
    let distribution_policy_sha256 =
        policy_distribution::policy_yaml_checksum_sha256(&distribution_policy_yaml);
    let agent_effective_policy = if let Some(agent_id) = req.agent_id.as_deref() {
        let Some(effective_policy) =
            policy_distribution::preview_effective_policy_candidate_for_agent(
                &state.db,
                auth.tenant_id,
                agent_id,
                &candidate,
            )
            .await
            .map_err(policy_preview_error)?
        else {
            return Err(ApiError::NotFound);
        };
        Some(PreviewEffectivePolicyResponse::from(effective_policy))
    } else {
        None
    };
    let deploy_allowed = auth.role == "admin" || auth.role == "owner";

    Ok(Json(PreviewPolicyResponse {
        preview_id: Uuid::new_v4(),
        tenant_slug: auth.slug,
        status: "valid".to_string(),
        would_deploy_version: candidate.version,
        policy_yaml_sha256: candidate.checksum_sha256,
        distribution_policy_yaml,
        distribution_policy_sha256,
        deploy_allowed,
        requires_deploy_approval: !deploy_allowed,
        agent_effective_policy,
    }))
}

pub(crate) async fn get_active_policy(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<serde_json::Value>, ApiError> {
    let active = policy_distribution::fetch_active_policy_by_tenant_id(&state.db, auth.tenant_id)
        .await
        .map_err(ApiError::Database)?;

    if let Some(policy) = active {
        return Ok(Json(serde_json::json!({
            "tenant": auth.slug,
            "status": "active",
            "version": policy.version,
            "checksum_sha256": policy.checksum_sha256,
            "description": policy.description,
            "updated_at": policy.updated_at,
            "policy_yaml": policy.policy_yaml,
        })));
    }

    Ok(Json(serde_json::json!({
        "tenant": auth.slug,
        "status": "no active policy",
    })))
}

pub(crate) async fn prepare_active_policy_deployment(
    state: &AppState,
    tenant_id: Uuid,
    tenant_slug: &str,
    active_policy: &policy_distribution::ActiveTenantPolicy,
    deployment_id: Uuid,
) -> Result<PreparedPolicyDeployment, ApiError> {
    // Enumerate all non-revoked agents (active + inactive lifecycle states).
    // This avoids only targeting currently-active agents during deploy.
    let agent_rows = sqlx::query::query(
        r#"SELECT agent_id
           FROM agents
           WHERE tenant_id = $1
             AND status IN ('active', 'inactive', 'stale', 'dead')
           ORDER BY created_at ASC"#,
    )
    .bind(tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let agent_ids: Vec<String> = agent_rows
        .into_iter()
        .map(|row| row.try_get("agent_id"))
        .collect::<Result<_, _>>()
        .map_err(ApiError::Database)?;
    let agent_count = agent_ids.len() as i64;

    // Prepare the exact effective policies before committing the DB row, but
    // do not publish them yet. KV is a side effect and must not get ahead of
    // the committed active-policy source of truth.
    let mut effective_policies = Vec::new();
    for agent_id in &agent_ids {
        let effective_policy = policy_distribution::preview_effective_policy_candidate_for_agent(
            &state.db,
            tenant_id,
            agent_id,
            active_policy,
        )
        .await
        .map_err(|err| {
            ApiError::Conflict(format!(
                "policy deployment {deployment_id} failed to build effective policy for agent {agent_id}: {err}"
            ))
        })?;
        if let Some(effective_policy) = effective_policy {
            effective_policies.push(effective_policy);
        }
    }

    let subject = policy_distribution::policy_update_subject(tenant_slug);
    let distribution_policy_yaml =
        policy_distribution::distribution_policy_yaml(active_policy).map_err(ApiError::Internal)?;
    Ok(PreparedPolicyDeployment {
        deployment_id,
        nats_subject: subject,
        agent_count,
        effective_policies,
        distribution_policy_yaml,
    })
}

pub(crate) async fn distribute_prepared_policy_to_fleet(
    state: &AppState,
    tenant_slug: &str,
    prepared: PreparedPolicyDeployment,
) -> PolicyDeploymentOutcome {
    let PreparedPolicyDeployment {
        deployment_id,
        nats_subject,
        agent_count,
        effective_policies,
        distribution_policy_yaml,
    } = prepared;
    let mut kv_write_failures = 0_i64;
    for effective_policy in &effective_policies {
        if let Err(err) =
            policy_distribution::put_effective_policy_for_agent(&state.nats, effective_policy).await
        {
            kv_write_failures += 1;
            tracing::warn!(
                error = %err,
                tenant = %tenant_slug,
                agent_id = %effective_policy.agent_id,
                policy_version = effective_policy.policy_epoch,
                deployment_id = %deployment_id,
                "Failed to push committed policy to agent KV bucket; heartbeat reconciliation will retry from the active-policy database"
            );
        }
    }

    // Best-effort compatibility broadcast for legacy subscribers.
    if let Err(err) = state
        .nats
        .publish(
            nats_subject.clone(),
            distribution_policy_yaml.into_bytes().into(),
        )
        .await
    {
        tracing::warn!(
            error = %err,
            subject = %nats_subject,
            "Legacy policy update publish failed after committed policy deployment"
        );
    }

    PolicyDeploymentOutcome {
        deployment_id,
        nats_subject,
        agent_count,
        kv_write_failures,
    }
}
