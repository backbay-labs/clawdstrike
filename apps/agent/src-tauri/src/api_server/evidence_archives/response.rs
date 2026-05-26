use super::*;

pub(crate) async fn evidence_bundle_archive_response(
    state: &AgentApiState,
    bundle_id: &str,
) -> Result<EdrEvidenceBundleArchiveResponse, (StatusCode, String)> {
    let bundle_id = bundle_id.trim();
    if bundle_id.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "evidence bundle id must not be empty".to_string(),
        ));
    }

    let stored = {
        let mut store = state.edr_evidence_bundle_store.lock().await;
        store
            .load(bundle_id)
            .map_err(internal_error)?
            .ok_or_else(|| {
                (
                    StatusCode::NOT_FOUND,
                    format!("evidence bundle not found: {bundle_id}"),
                )
            })?
    };
    let receipts = evidence_bundle_archive_receipts(state, &stored).await?;
    let archive = EdrEvidenceBundleArchive {
        bundle: stored.bundle.clone(),
        artifact: crate::edr::dto::evidence_bundle_artifact_from_stored(&stored),
        graph: stored.graph,
        receipts,
    };
    let verification = evidence_bundle_archive_verification(&archive).map_err(internal_error)?;
    let archive_hash = canonical_json_hash(&archive, "endpoint evidence bundle archive")
        .map_err(internal_error)?;
    let archive_id = local_stable_id(
        "evidence_bundle_archive",
        [
            archive.bundle.bundle_id.as_str(),
            archive.bundle.content_hash.as_str(),
            archive_hash.as_str(),
        ],
    );

    Ok(EdrEvidenceBundleArchiveResponse {
        archive_id,
        generated_at: chrono::Utc::now(),
        archive_hash,
        receipt_count: archive.receipts.len(),
        verification,
        archive,
    })
}

pub(crate) fn archive_newest_receipt_timestamp(
    archive: &EdrEvidenceBundleArchive,
) -> Option<chrono::DateTime<chrono::Utc>> {
    archive
        .receipts
        .iter()
        .map(|receipt| {
            chrono::DateTime::parse_from_rfc3339(&receipt.receipt.timestamp)
                .map(|timestamp| timestamp.with_timezone(&chrono::Utc))
                .ok()
        })
        .collect::<Option<Vec<_>>>()
        .and_then(|timestamps| timestamps.into_iter().max())
}

pub(crate) async fn active_response_evidence_bundle_ids(
    state: &AgentApiState,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<BTreeSet<String>, (StatusCode, String)> {
    let ledger = state.edr_response_execution_ledger.lock().await;
    ledger
        .active_evidence_bundle_ids(now)
        .map_err(internal_error)
}

pub(crate) async fn evidence_bundle_archive_receipts(
    state: &AgentApiState,
    stored: &StoredEndpointEvidenceBundle,
) -> Result<Vec<SignedReceipt>, (StatusCode, String)> {
    let ledger = state.edr_receipt_ledger.lock().await;
    let mut receipts = Vec::new();
    let mut seen_receipt_ids = BTreeSet::new();
    let filters = [
        EdrReceiptFilter {
            graph_slice_id: Some(stored.bundle.graph_slice_id.as_str()),
            ..EdrReceiptFilter::default()
        },
        EdrReceiptFilter {
            family: Some("evidence_bundle_manifest"),
            finding_id: Some(stored.bundle.bundle_id.as_str()),
            ..EdrReceiptFilter::default()
        },
    ];

    for filter in filters {
        for receipt in ledger
            .read_recent(EDR_MAX_RECEIPT_QUERY_LIMIT, filter)
            .map_err(internal_error)?
        {
            let receipt_key = receipt.receipt.receipt_id.clone().unwrap_or_else(|| {
                format!(
                    "missing-receipt-id:{}:{}",
                    receipt.receipt.timestamp,
                    receipts.len()
                )
            });
            if seen_receipt_ids.insert(receipt_key) {
                receipts.push(receipt);
            }
        }
    }
    receipts.sort_by(|left, right| {
        left.receipt
            .timestamp
            .cmp(&right.receipt.timestamp)
            .then_with(|| left.receipt.receipt_id.cmp(&right.receipt.receipt_id))
    });
    Ok(receipts)
}
