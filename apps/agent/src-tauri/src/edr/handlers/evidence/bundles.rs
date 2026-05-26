//! Evidence bundle lookup, fleet publish, archive, archive verify, list, compact.
#[allow(unused_imports, clippy::wildcard_imports)]
use crate::api_server::*;
#[allow(unused_imports)]
use axum::extract::{Path, Query, State};
#[allow(unused_imports)]
use axum::http::{HeaderMap, StatusCode};
#[allow(unused_imports)]
use axum::Json;
#[allow(unused_imports)]
use clawdstrike_policy_event::edr::*;
#[allow(unused_imports)]
use std::sync::Arc;

pub(crate) async fn agent_edr_evidence_bundle(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(bundle_id): Path<String>,
) -> Result<Json<EdrEvidenceBundleResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let bundle_id = bundle_id.trim();
    if bundle_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "evidence bundle id must not be empty".to_string(),
        ));
    }

    let mut store = state.edr_evidence_bundle_store.lock().await;
    let stored = store
        .load(bundle_id)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("evidence bundle not found: {bundle_id}"),
            )
        })?;

    Ok(Json(EdrEvidenceBundleResponse {
        bundle: stored.bundle,
        path: stored.path,
        byte_count: stored.byte_count,
        graph: stored.graph,
    }))
}

pub(crate) async fn agent_edr_evidence_bundle_fleet_publish(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(bundle_id): Path<String>,
    Query(input): Query<EdrRawArtifactApprovalInput>,
) -> Result<(StatusCode, Json<EdrEvidenceBundleFleetPublishResponse>), (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let approval_resource =
        raw_artifact_approval_resource_for_evidence_bundle_fleet_publish(&bundle_id);
    let raw_artifact_approval = validate_resolved_raw_artifact_approval(
        &state,
        validate_raw_artifact_approval_fields(
            input.raw_artifact_approval_id.as_deref(),
            input.raw_artifact_approval_reason.as_deref(),
        )?,
        &approval_resource,
    )
    .await?;
    let publish_identity = fleet_hunt_event_identity(state.as_ref()).await?;
    let archive_response = evidence_bundle_archive_response(state.as_ref(), &bundle_id).await?;
    if !archive_response.verification.verified {
        return Err((
            StatusCode::CONFLICT,
            "evidence bundle archive verification failed; refusing fleet publish".to_string(),
        ));
    }

    let event = fleet_hunt_event_for_evidence_bundle_archive(
        &archive_response.archive_id,
        &archive_response.archive_hash,
        &archive_response.archive,
        &archive_response.verification,
        &publish_identity.tenant_id,
        &publish_identity.endpoint_agent_id,
    );
    let event_id = event
        .get("eventId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let raw_ref = event
        .get("evidence")
        .and_then(|evidence| evidence.get("rawRef"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let control_upload = post_control_endpoint_evidence_archive(
        state.as_ref(),
        &archive_response,
        &publish_identity.endpoint_agent_id,
        &event_id,
        &raw_ref,
        "fleet_publish",
        raw_artifact_approval.as_ref(),
    )
    .await?;
    let payload = serde_json::to_vec(&event).map_err(|err| {
        internal_error(anyhow::anyhow!(
            "serialize evidence bundle archive hunt event: {err}"
        ))
    })?;
    if let Some(publisher) = publish_identity.publisher {
        match publisher.publish_hunt_event(&payload).await {
            Ok(()) => {
                return Ok((
                    StatusCode::OK,
                    Json(EdrEvidenceBundleFleetPublishResponse {
                        bundle_id: archive_response.archive.bundle.bundle_id,
                        archive_id: archive_response.archive_id,
                        archive_hash: archive_response.archive_hash,
                        published: true,
                        queued: false,
                        control_upload,
                        outbox_id: None,
                        next_retry_at: None,
                        event_id,
                        raw_ref,
                    }),
                ));
            }
            Err(err) => {
                let error = truncate_delivery_error(&err.to_string());
                let (outbox_id, next_retry_at) =
                    enqueue_fleet_hunt_event_outbox(state.as_ref(), event, Some(error.as_str()))
                        .await?;
                return Ok((
                    StatusCode::ACCEPTED,
                    Json(EdrEvidenceBundleFleetPublishResponse {
                        bundle_id: archive_response.archive.bundle.bundle_id,
                        archive_id: archive_response.archive_id,
                        archive_hash: archive_response.archive_hash,
                        published: false,
                        queued: true,
                        control_upload,
                        outbox_id: Some(outbox_id),
                        next_retry_at: Some(next_retry_at),
                        event_id,
                        raw_ref,
                    }),
                ));
            }
        }
    }

    let (outbox_id, next_retry_at) = enqueue_fleet_hunt_event_outbox(
        state.as_ref(),
        event,
        Some("fleet hunt publisher is unavailable because NATS is not connected"),
    )
    .await?;
    Ok((
        StatusCode::ACCEPTED,
        Json(EdrEvidenceBundleFleetPublishResponse {
            bundle_id: archive_response.archive.bundle.bundle_id,
            archive_id: archive_response.archive_id,
            archive_hash: archive_response.archive_hash,
            published: false,
            queued: true,
            control_upload,
            outbox_id: Some(outbox_id),
            next_retry_at: Some(next_retry_at),
            event_id,
            raw_ref,
        }),
    ))
}

pub(crate) async fn agent_edr_evidence_bundle_archive(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Path(bundle_id): Path<String>,
) -> Result<Json<EdrEvidenceBundleArchiveResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let archive = evidence_bundle_archive_response(state.as_ref(), &bundle_id).await?;

    Ok(Json(archive))
}

pub(crate) async fn agent_edr_evidence_bundle_archive_verify(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrEvidenceBundleArchiveVerifyInput>,
) -> Result<Json<EdrEvidenceBundleArchiveVerifyResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let expected_archive_hash = input.archive_hash.trim().to_string();
    if expected_archive_hash.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "archiveHash must not be empty".to_string(),
        ));
    }

    let archive_hash = canonical_json_hash(&input.archive, "endpoint evidence bundle archive")
        .map_err(internal_error)?;
    let archive_hash_matches = archive_hash == expected_archive_hash;
    let expected_archive_id = local_stable_id(
        "evidence_bundle_archive",
        [
            input.archive.bundle.bundle_id.as_str(),
            input.archive.bundle.content_hash.as_str(),
            archive_hash.as_str(),
        ],
    );
    let archive_id_matches = input
        .archive_id
        .as_deref()
        .map_or(true, |archive_id| archive_id == expected_archive_id);
    let receipt_count_matches = input.receipt_count.map_or(true, |receipt_count| {
        receipt_count == input.archive.receipts.len()
    });
    let trusted_signer_public_key = input
        .trusted_signer_public_key
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string);
    if input.trusted_signer_public_key.is_some() && trusted_signer_public_key.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "trustedSignerPublicKey must not be empty".to_string(),
        ));
    }
    if let Some(trusted_signer_public_key) = trusted_signer_public_key.as_deref() {
        hush_core::PublicKey::from_hex(trusted_signer_public_key).map_err(|err| {
            (
                StatusCode::BAD_REQUEST,
                format!("trustedSignerPublicKey must be a valid public key: {err}"),
            )
        })?;
    }
    let signer_trust_matches = trusted_signer_public_key
        .as_deref()
        .map_or(true, |trusted| {
            !input.archive.receipts.is_empty()
                && input.archive.receipts.iter().all(|receipt| {
                    receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
                        == Some(trusted)
                })
        });
    let verification =
        evidence_bundle_archive_verification(&input.archive).map_err(internal_error)?;
    let verification_matches = input
        .verification
        .as_ref()
        .map_or(true, |supplied| supplied == &verification);
    let newest_receipt_timestamp = archive_newest_receipt_timestamp(&input.archive);
    let generated_at_covers_receipts = input.generated_at.map_or(true, |generated_at| {
        newest_receipt_timestamp.is_some_and(|newest| generated_at >= newest)
    });
    let verified = archive_hash_matches
        && archive_id_matches
        && receipt_count_matches
        && verification_matches
        && generated_at_covers_receipts
        && signer_trust_matches
        && verification.verified;

    Ok(Json(EdrEvidenceBundleArchiveVerifyResponse {
        verified,
        expected_archive_id,
        archive_id_matches,
        expected_archive_hash,
        archive_hash,
        archive_hash_matches,
        receipt_count_matches,
        verification_matches,
        generated_at_covers_receipts,
        newest_receipt_timestamp,
        trusted_signer_public_key,
        signer_trust_matches,
        verification,
    }))
}

pub(crate) async fn agent_edr_evidence_bundles(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Query(query): Query<EdrEvidenceBundleQuery>,
) -> Result<Json<EdrEvidenceBundlesResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    let limit = bounded_request_limit("limit", query.limit, 100, EDR_MAX_STORED_FINDINGS)?;
    let now = chrono::Utc::now();
    let protected_bundle_ids = active_response_evidence_bundle_ids(&state, now).await?;
    let (root, bundles) = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        let root = store.root_path().map(|path| path.display().to_string());
        let bundles = store.list().map_err(internal_error)?;
        (root, bundles)
    };
    let protected_count = bundles
        .iter()
        .filter(|stored| protected_bundle_ids.contains(&stored.bundle.bundle_id))
        .count();
    let records = bundles
        .into_iter()
        .take(limit)
        .map(|stored| evidence_bundle_record(stored, now, &protected_bundle_ids))
        .collect::<Vec<_>>();

    Ok(Json(EdrEvidenceBundlesResponse {
        root,
        bundle_count: records.len(),
        protected_count,
        bundles: records,
    }))
}

pub(crate) async fn agent_edr_evidence_bundles_compact(
    State(state): State<Arc<AgentApiState>>,
    headers: HeaderMap,
    Json(input): Json<EdrEvidenceBundleCompactionInput>,
) -> Result<Json<EdrEvidenceBundleCompactionResponse>, (StatusCode, String)> {
    require_auth(&headers, &state)?;
    if input.max_bundles.is_none() && input.min_age_seconds.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            "max_bundles or min_age_seconds must be provided".to_string(),
        ));
    }
    let dry_run = input.dry_run.unwrap_or(true);
    let min_age_seconds = input.min_age_seconds.unwrap_or(0);
    let now = chrono::Utc::now();
    let protected_bundle_ids = active_response_evidence_bundle_ids(&state, now).await?;
    let (root, bundles) = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        let root = store.root_path().map(|path| path.display().to_string());
        let bundles = store.list().map_err(internal_error)?;
        (root, bundles)
    };
    let bundle_count = bundles.len();
    let protected_count = bundles
        .iter()
        .filter(|stored| protected_bundle_ids.contains(&stored.bundle.bundle_id))
        .count();
    let mut records = Vec::new();
    for (index, stored) in bundles.iter().enumerate() {
        let age_seconds = evidence_bundle_age_seconds(stored, now);
        let protected = protected_bundle_ids.contains(&stored.bundle.bundle_id);
        let beyond_limit = input
            .max_bundles
            .is_some_and(|max_bundles| index >= max_bundles);
        let old_enough = age_seconds >= min_age_seconds;
        if protected || !beyond_limit && input.max_bundles.is_some() || !old_enough {
            continue;
        }
        let reason = if beyond_limit {
            format!(
                "bundle exceeds max_bundles {} and is at least {min_age_seconds}s old",
                input.max_bundles.unwrap_or_default()
            )
        } else {
            format!("bundle is at least {min_age_seconds}s old")
        };
        records.push(EdrEvidenceBundleCompactionRecord {
            bundle_id: stored.bundle.bundle_id.clone(),
            graph_slice_id: stored.bundle.graph_slice_id.clone(),
            path: stored.path.clone(),
            byte_count: stored.byte_count,
            age_seconds,
            protected_by_active_response: protected,
            removed: false,
            reason,
        });
    }

    if !dry_run {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        for record in &mut records {
            if store
                .remove(&record.bundle_id)
                .map_err(internal_error)?
                .is_some()
            {
                record.removed = true;
            }
        }
    }
    let removed_count = records.iter().filter(|record| record.removed).count();

    Ok(Json(EdrEvidenceBundleCompactionResponse {
        root,
        dry_run,
        max_bundles: input.max_bundles,
        min_age_seconds,
        bundle_count,
        candidate_count: records.len(),
        removed_count,
        protected_count,
        records,
    }))
}
