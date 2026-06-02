//! Policy-proposal lifecycle handlers and row conversion.

use super::*;

pub(crate) struct PolicyProposalRow {
    pub(crate) id: Uuid,
    pub(crate) tenant_id: Uuid,
    pub(crate) policy_yaml: String,
    pub(crate) checksum_sha256: String,
    pub(crate) description: Option<String>,
    pub(crate) status: String,
    pub(crate) base_active_policy_version: i64,
    pub(crate) proposed_policy_version: i64,
    pub(crate) preview: serde_json::Value,
    pub(crate) required_approvals: i32,
    pub(crate) approved_by: Vec<String>,
    pub(crate) approval_notes: serde_json::Value,
    pub(crate) impact: Option<serde_json::Value>,
    pub(crate) impact_attached_by: Option<String>,
    pub(crate) impact_attached_at: Option<DateTime<Utc>>,
    pub(crate) deployed_policy_version: Option<i64>,
    pub(crate) deployment_id: Option<Uuid>,
    pub(crate) submitted_by: String,
    pub(crate) reviewed_by: Option<String>,
    pub(crate) review_note: Option<String>,
    pub(crate) created_at: DateTime<Utc>,
    pub(crate) updated_at: DateTime<Utc>,
    pub(crate) reviewed_at: Option<DateTime<Utc>>,
    pub(crate) deployed_at: Option<DateTime<Utc>>,
}

pub(crate) async fn create_policy_proposal(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Json(req): Json<CreatePolicyProposalRequest>,
) -> Result<Json<CreatePolicyProposalResponse>, ApiError> {
    ensure_policy_author(&auth)?;

    let candidate = policy_distribution::preview_active_policy_candidate(
        &state.db,
        auth.tenant_id,
        &req.policy_yaml,
        req.description.as_deref(),
    )
    .await
    .map_err(policy_preview_error)?;
    let base_active_policy_version = candidate.version - 1;
    let current_active =
        policy_distribution::fetch_active_policy_by_tenant_id(&state.db, auth.tenant_id)
            .await
            .map_err(ApiError::Database)?;
    let preview = build_policy_proposal_preview(
        &state.db,
        auth.tenant_id,
        &candidate,
        current_active.as_ref(),
    )
    .await?;
    let submitted_by = auth.actor_id();

    let row = sqlx::query::query(
        r#"INSERT INTO policy_proposals (
               tenant_id,
               policy_yaml,
               checksum_sha256,
               description,
               base_active_policy_version,
               proposed_policy_version,
               preview,
               submitted_by
           )
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(&candidate.policy_yaml)
    .bind(&candidate.checksum_sha256)
    .bind(candidate.description.as_deref())
    .bind(base_active_policy_version)
    .bind(candidate.version)
    .bind(&preview)
    .bind(&submitted_by)
    .fetch_one(&state.db)
    .await
    .map_err(ApiError::Database)?;

    Ok(Json(CreatePolicyProposalResponse {
        proposal: proposal_response_from_row(row, &auth.slug)?,
    }))
}

pub(crate) async fn list_policy_proposals(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
) -> Result<Json<Vec<PolicyProposalResponse>>, ApiError> {
    let rows = sqlx::query::query(
        r#"SELECT *
           FROM policy_proposals
           WHERE tenant_id = $1
           ORDER BY created_at DESC, id DESC"#,
    )
    .bind(auth.tenant_id)
    .fetch_all(&state.db)
    .await
    .map_err(ApiError::Database)?;

    let proposals = rows
        .into_iter()
        .map(|row| proposal_response_from_row(row, &auth.slug))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Json(proposals))
}

pub(crate) async fn get_policy_proposal(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
) -> Result<Json<PolicyProposalResponse>, ApiError> {
    let row = fetch_policy_proposal_row(&state, auth.tenant_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;

    Ok(Json(row.into_response(&auth.slug)))
}

pub(crate) async fn reject_policy_proposal(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<ReviewPolicyProposalRequest>,
) -> Result<Json<PolicyProposalResponse>, ApiError> {
    ensure_policy_deployer(&auth)?;

    let reviewed_by = auth.actor_id();
    let row = sqlx::query::query(
        r#"UPDATE policy_proposals
           SET status = 'rejected',
               reviewed_by = $3,
               review_note = $4,
               reviewed_at = now(),
               updated_at = now()
           WHERE tenant_id = $1
             AND id = $2
             AND status = 'pending'
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(id)
    .bind(&reviewed_by)
    .bind(req.note.as_deref())
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?
    .ok_or(ApiError::NotFound)?;

    Ok(Json(proposal_response_from_row(row, &auth.slug)?))
}

pub(crate) async fn approve_policy_proposal(
    State(state): State<AppState>,
    auth: AuthenticatedTenant,
    Path(id): Path<Uuid>,
    Json(req): Json<ReviewPolicyProposalRequest>,
) -> Result<Json<ApprovePolicyProposalResponse>, ApiError> {
    ensure_policy_deployer(&auth)?;

    let mut tx = state.db.begin().await.map_err(ApiError::Database)?;
    let proposal = fetch_policy_proposal_row_for_update(&mut tx, auth.tenant_id, id)
        .await?
        .ok_or(ApiError::NotFound)?;
    if proposal.status != "pending" {
        return Err(ApiError::NotFound);
    }

    let current_active =
        policy_distribution::fetch_active_policy_by_tenant_id_for_update_with_executor(
            &mut *tx,
            auth.tenant_id,
        )
        .await
        .map_err(ApiError::Database)?;
    let current_version = current_active
        .as_ref()
        .map(|policy| policy.version)
        .unwrap_or(0);
    if current_version != proposal.base_active_policy_version {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} was based on active policy version {}, but current active policy version is {}; resubmit the proposal",
            proposal.id, proposal.base_active_policy_version, current_version
        )));
    }

    let reviewed_by = auth.actor_id();
    if reviewed_by == proposal.submitted_by {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} must be approved by someone other than its submitter",
            proposal.id
        )));
    }
    if proposal
        .approved_by
        .iter()
        .any(|approver| approver == &reviewed_by)
    {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} has already been approved by this actor",
            proposal.id
        )));
    }

    let mut approved_by = proposal.approved_by.clone();
    approved_by.push(reviewed_by.clone());
    let approval_notes = append_policy_proposal_approval_note(
        &proposal.approval_notes,
        &reviewed_by,
        req.note.as_deref(),
    );
    let approvals_remaining = proposal.required_approvals - approved_by.len() as i32;
    if approvals_remaining > 0 {
        let row = sqlx::query::query(
            r#"UPDATE policy_proposals
               SET approved_by = $3,
                   approval_notes = $4,
                   updated_at = now()
               WHERE tenant_id = $1
                 AND id = $2
                 AND status = 'pending'
               RETURNING *"#,
        )
        .bind(auth.tenant_id)
        .bind(id)
        .bind(&approved_by)
        .bind(&approval_notes)
        .fetch_optional(&mut *tx)
        .await
        .map_err(ApiError::Database)?
        .ok_or_else(|| {
            ApiError::Conflict(format!(
                "policy proposal {} was changed before approval could be recorded",
                proposal.id
            ))
        })?;
        tx.commit().await.map_err(ApiError::Database)?;

        return Ok(Json(ApprovePolicyProposalResponse {
            proposal: proposal_response_from_row(row, &auth.slug)?,
            deployment: None,
            approvals_remaining,
        }));
    }

    ensure_policy_proposal_deployable_impact(&proposal)?;

    let deployment_id = Uuid::new_v4();
    let candidate_policy = active_policy_candidate_from_base(
        auth.tenant_id,
        &auth.slug,
        &proposal.policy_yaml,
        proposal.description.as_deref(),
        proposal.base_active_policy_version,
    )?;
    let deployment_plan = prepare_active_policy_deployment(
        &state,
        auth.tenant_id,
        &auth.slug,
        &candidate_policy,
        deployment_id,
    )
    .await
    .map_err(|err| {
        tracing::warn!(
            error = %err,
            deployment_id = %deployment_id,
            tenant = %auth.slug,
            policy_version = candidate_policy.version,
            "Policy proposal deployment preparation failed before deployed state was committed"
        );
        err
    })?;

    let active_policy = policy_distribution::upsert_active_policy_after_version_with_executor(
        &mut *tx,
        auth.tenant_id,
        &proposal.policy_yaml,
        proposal.description.as_deref(),
        proposal.base_active_policy_version,
    )
    .await
    .map_err(ApiError::Database)?
    .ok_or_else(|| {
        ApiError::Conflict(format!(
            "policy proposal {} was based on active policy version {}, but the active policy changed before deployment could be recorded; resubmit the proposal",
            proposal.id, proposal.base_active_policy_version
        ))
    })?;
    if active_policy.version != candidate_policy.version {
        return Err(ApiError::Conflict(format!(
            "policy proposal {} expected deployed policy version {}, but recorded version {}; retry the proposal deployment",
            proposal.id, candidate_policy.version, active_policy.version
        )));
    }

    let row = sqlx::query::query(
        r#"UPDATE policy_proposals
           SET status = 'deployed',
               approved_by = $7,
               approval_notes = $8,
               reviewed_by = $3,
               review_note = $4,
               reviewed_at = now(),
               deployed_at = now(),
               deployed_policy_version = $5,
               deployment_id = $6,
               updated_at = now()
           WHERE tenant_id = $1
             AND id = $2
             AND status = 'pending'
           RETURNING *"#,
    )
    .bind(auth.tenant_id)
    .bind(id)
    .bind(&reviewed_by)
    .bind(req.note.as_deref())
    .bind(active_policy.version)
    .bind(deployment_id)
    .bind(&approved_by)
    .bind(&approval_notes)
    .fetch_optional(&mut *tx)
    .await
    .map_err(ApiError::Database)?
    .ok_or_else(|| {
        ApiError::Conflict(format!(
            "policy proposal {} was changed before deployment could be recorded",
            proposal.id
        ))
    })?;
    tx.commit().await.map_err(ApiError::Database)?;
    let deployment_outcome =
        distribute_prepared_policy_to_fleet(&state, &auth.slug, deployment_plan).await;
    if deployment_outcome.kv_write_failures > 0 {
        tracing::warn!(
            deployment_id = %deployment_outcome.deployment_id,
            tenant = %auth.slug,
            kv_write_failures = deployment_outcome.kv_write_failures,
            proposal_id = %proposal.id,
            "Approved policy proposal committed with fleet KV retry debt"
        );
    }
    let deployment = Some(DeployPolicyResponse {
        deployment_id: deployment_outcome.deployment_id,
        tenant_slug: auth.slug.clone(),
        nats_subject: deployment_outcome.nats_subject,
        agent_count: deployment_outcome.agent_count,
        kv_write_failures: deployment_outcome.kv_write_failures,
    });

    Ok(Json(ApprovePolicyProposalResponse {
        proposal: proposal_response_from_row(row, &auth.slug)?,
        deployment,
        approvals_remaining: 0,
    }))
}

pub(crate) async fn fetch_policy_proposal_row(
    state: &AppState,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<PolicyProposalRow>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT *
           FROM policy_proposals
           WHERE tenant_id = $1
             AND id = $2"#,
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(&state.db)
    .await
    .map_err(ApiError::Database)?;

    row.map(policy_proposal_from_row)
        .transpose()
        .map_err(ApiError::Database)
}

pub(crate) async fn fetch_policy_proposal_row_for_update(
    tx: &mut sqlx::transaction::Transaction<'_, sqlx_postgres::Postgres>,
    tenant_id: Uuid,
    id: Uuid,
) -> Result<Option<PolicyProposalRow>, ApiError> {
    let row = sqlx::query::query(
        r#"SELECT *
           FROM policy_proposals
           WHERE tenant_id = $1
             AND id = $2
           FOR UPDATE"#,
    )
    .bind(tenant_id)
    .bind(id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(ApiError::Database)?;

    row.map(policy_proposal_from_row)
        .transpose()
        .map_err(ApiError::Database)
}

pub(crate) fn proposal_response_from_row(
    row: sqlx_postgres::PgRow,
    tenant_slug: &str,
) -> Result<PolicyProposalResponse, ApiError> {
    Ok(policy_proposal_from_row(row)
        .map_err(ApiError::Database)?
        .into_response(tenant_slug))
}

pub(crate) fn policy_proposal_from_row(
    row: sqlx_postgres::PgRow,
) -> Result<PolicyProposalRow, sqlx::error::Error> {
    Ok(PolicyProposalRow {
        id: row.try_get("id")?,
        tenant_id: row.try_get("tenant_id")?,
        policy_yaml: row.try_get("policy_yaml")?,
        checksum_sha256: row.try_get("checksum_sha256")?,
        description: row.try_get("description")?,
        status: row.try_get("status")?,
        base_active_policy_version: row.try_get("base_active_policy_version")?,
        proposed_policy_version: row.try_get("proposed_policy_version")?,
        preview: row.try_get("preview")?,
        required_approvals: row.try_get("required_approvals")?,
        approved_by: row.try_get("approved_by")?,
        approval_notes: row.try_get("approval_notes")?,
        impact: row.try_get("impact")?,
        impact_attached_by: row.try_get("impact_attached_by")?,
        impact_attached_at: row.try_get("impact_attached_at")?,
        deployed_policy_version: row.try_get("deployed_policy_version")?,
        deployment_id: row.try_get("deployment_id")?,
        submitted_by: row.try_get("submitted_by")?,
        reviewed_by: row.try_get("reviewed_by")?,
        review_note: row.try_get("review_note")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        reviewed_at: row.try_get("reviewed_at")?,
        deployed_at: row.try_get("deployed_at")?,
    })
}

impl PolicyProposalRow {
    pub(crate) fn into_response(self, tenant_slug: &str) -> PolicyProposalResponse {
        let approval_count = self.approved_by.len() as i32;
        let approvals_remaining = (self.required_approvals - approval_count).max(0);
        PolicyProposalResponse {
            id: self.id,
            tenant_id: self.tenant_id,
            tenant_slug: tenant_slug.to_string(),
            policy_yaml: self.policy_yaml,
            checksum_sha256: self.checksum_sha256,
            description: self.description,
            status: self.status,
            base_active_policy_version: self.base_active_policy_version,
            proposed_policy_version: self.proposed_policy_version,
            preview: self.preview,
            required_approvals: self.required_approvals,
            approval_count,
            approvals_remaining,
            approved_by: self.approved_by,
            approval_notes: self.approval_notes,
            impact: self.impact,
            impact_attached_by: self.impact_attached_by,
            impact_attached_at: self.impact_attached_at,
            deployed_policy_version: self.deployed_policy_version,
            deployment_id: self.deployment_id,
            submitted_by: self.submitted_by,
            reviewed_by: self.reviewed_by,
            review_note: self.review_note,
            created_at: self.created_at,
            updated_at: self.updated_at,
            reviewed_at: self.reviewed_at,
            deployed_at: self.deployed_at,
        }
    }
}
