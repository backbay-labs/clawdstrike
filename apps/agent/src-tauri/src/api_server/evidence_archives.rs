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
        artifact: EdrEvidenceBundleArtifact::from_stored(&stored),
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

pub(crate) fn evidence_bundle_archive_verification(
    archive: &EdrEvidenceBundleArchive,
) -> Result<EdrEvidenceBundleArchiveVerification> {
    let canonical_graph = canonical_evidence_graph(&archive.graph)?;
    let graph_content_hash = canonical_graph.content_hash.clone();
    let content_hash_matches = graph_content_hash == archive.bundle.content_hash;
    let expected_bundle_id_evidence = sha256(archive.bundle.bundle_id.as_bytes()).to_hex_prefixed();
    let expected_content_hash_evidence =
        sha256(archive.bundle.content_hash.as_bytes()).to_hex_prefixed();
    let expected_node_count_evidence = archive.bundle.node_count.to_string();
    let expected_edge_count_evidence = archive.bundle.edge_count.to_string();
    let mut receipt_failures = Vec::new();
    let mut matching_content_hash_receipts = 0usize;
    let mut receipt_families = BTreeSet::new();
    let mut receipt_family_counts = BTreeMap::new();
    let mut response_actor_hashes = Vec::new();
    let mut receipt_endpoint_ids = BTreeSet::new();
    let mut receipt_root_node_ids = BTreeSet::new();
    let mut policy_hashes = Vec::new();
    let mut sensor_provider_sets = Vec::new();
    let mut receipt_ids = BTreeSet::new();
    let mut receipt_local_sequences = BTreeSet::new();
    let mut receipt_sequence_timestamps = BTreeMap::new();
    let mut receipt_signer_public_keys = BTreeSet::new();
    let actual_node_count = archive.graph.nodes.len();
    let actual_edge_count = archive.graph.edges.len();
    if archive.bundle.node_count != actual_node_count {
        receipt_failures.push(format!(
            "bundle_node_count_mismatch:{}:{actual_node_count}",
            archive.bundle.node_count
        ));
    }
    if archive.bundle.edge_count != actual_edge_count {
        receipt_failures.push(format!(
            "bundle_edge_count_mismatch:{}:{actual_edge_count}",
            archive.bundle.edge_count
        ));
    }
    if archive.artifact.bundle_id != archive.bundle.bundle_id {
        receipt_failures.push(format!(
            "artifact_bundle_id_mismatch:{}",
            archive.artifact.bundle_id
        ));
    }
    if archive.artifact.content_hash != archive.bundle.content_hash {
        receipt_failures.push(format!(
            "artifact_content_hash_mismatch:{}",
            archive.artifact.content_hash
        ));
    }
    if archive.artifact.byte_count != canonical_graph.byte_count {
        receipt_failures.push(format!(
            "artifact_byte_count_mismatch:{}:{}",
            archive.artifact.byte_count, canonical_graph.byte_count
        ));
    }

    for receipt in &archive.receipts {
        let receipt_label = receipt
            .receipt
            .receipt_id
            .as_deref()
            .unwrap_or("<missing-receipt-id>");
        match receipt
            .receipt
            .receipt_id
            .as_deref()
            .map(str::trim)
            .filter(|receipt_id| !receipt_id.is_empty())
        {
            Some(receipt_id) => {
                if !receipt_ids.insert(receipt_id.to_string()) {
                    receipt_failures.push(format!("duplicate_receipt_id:{receipt_id}"));
                }
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_receipt_id")),
        }
        let receipt_sequence = receipt_local_sequence(receipt);
        let receipt_timestamp =
            match chrono::DateTime::parse_from_rfc3339(&receipt.receipt.timestamp) {
                Ok(timestamp) => Some(timestamp.with_timezone(&chrono::Utc)),
                Err(_) => {
                    receipt_failures.push(format!("{receipt_label}:invalid_receipt_timestamp"));
                    None
                }
            };
        match receipt_sequence {
            Some(local_sequence) => {
                if !receipt_local_sequences.insert(local_sequence) {
                    receipt_failures
                        .push(format!("duplicate_receipt_local_sequence:{local_sequence}"));
                }
                if let Some(timestamp) = receipt_timestamp {
                    receipt_sequence_timestamps.insert(local_sequence, timestamp);
                }
            }
            None => {
                receipt_failures.push(format!("{receipt_label}:missing_receipt_local_sequence"))
            }
        }
        match receipt_endpoint_decision_str(receipt, &["actor", "endpointId"])
            .map(str::trim)
            .filter(|endpoint_id| !endpoint_id.is_empty())
        {
            Some(endpoint_id) => {
                receipt_endpoint_ids.insert(endpoint_id.to_string());
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_actor_endpoint_id")),
        }
        let receipt_root_node_id =
            receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
                .map(str::trim)
                .filter(|root_node_id| !root_node_id.is_empty());
        match receipt_root_node_id {
            Some(root_node_id) => {
                receipt_root_node_ids.insert(root_node_id.to_string());
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_root_node")),
        }
        let receipt_family = receipt_endpoint_decision_str(receipt, &["receiptFamily"]);
        match receipt_family {
            Some(
                family @ ("graph_slice"
                | "evidence_bundle_manifest"
                | "response_request"
                | "response_execution"
                | "response_rollback"
                | "response_acknowledgement"),
            ) => {
                receipt_families.insert(family.to_string());
                *receipt_family_counts.entry(family.to_string()).or_insert(0) += 1;
                if let Some(root_node_id) = receipt_root_node_id {
                    if family != "evidence_bundle_manifest" {
                        push_archive_receipt_evidence_hash_failure(
                            &mut receipt_failures,
                            receipt,
                            receipt_label,
                            "rootNodeId",
                            root_node_id,
                            "root_node",
                        );
                    }
                }
                push_archive_policy_failures(
                    &mut receipt_failures,
                    &mut policy_hashes,
                    receipt,
                    receipt_label,
                    family,
                )?;
                push_archive_sensor_state_failures(
                    &mut receipt_failures,
                    &mut sensor_provider_sets,
                    receipt,
                    receipt_label,
                    family,
                )?;
                if family == "evidence_bundle_manifest" {
                    match receipt_endpoint_decision_str(receipt, &["decision", "findingId"]) {
                        Some(actual) if actual == archive.bundle.bundle_id => {}
                        Some(actual) => receipt_failures.push(format!(
                            "{receipt_label}:manifest_finding_id_mismatch:{actual}"
                        )),
                        None => receipt_failures
                            .push(format!("{receipt_label}:missing_manifest_finding_id")),
                    }
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "graphSliceId",
                        &archive.bundle.graph_slice_id,
                        "graph_slice_evidence",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "contentHash",
                        &archive.bundle.content_hash,
                        "content_hash",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "nodeCount",
                        &expected_node_count_evidence,
                        "node_count",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "edgeCount",
                        &expected_edge_count_evidence,
                        "edge_count",
                    );
                }
                if family == "graph_slice" {
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "graphSliceId",
                        &archive.bundle.graph_slice_id,
                        "graph_slice_evidence",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "contentHash",
                        &archive.bundle.content_hash,
                        "content_hash",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "nodeCount",
                        &expected_node_count_evidence,
                        "node_count",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "edgeCount",
                        &expected_edge_count_evidence,
                        "edge_count",
                    );
                }
                if family == "response_request" {
                    push_archive_response_actor_failures(
                        &mut receipt_failures,
                        &mut response_actor_hashes,
                        receipt,
                        receipt_label,
                        family,
                        &["actorHash"],
                    )?;
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "graphSliceId",
                        &archive.bundle.graph_slice_id,
                        "graph_slice_evidence",
                    );
                }
                if family == "response_execution" {
                    push_archive_response_actor_failures(
                        &mut receipt_failures,
                        &mut response_actor_hashes,
                        receipt,
                        receipt_label,
                        family,
                        &["actorHash", "executionActorHash"],
                    )?;
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "graphSliceId",
                        &archive.bundle.graph_slice_id,
                        "graph_slice_evidence",
                    );
                    push_archive_receipt_evidence_hash_failure(
                        &mut receipt_failures,
                        receipt,
                        receipt_label,
                        "evidenceBundleContentHash",
                        &archive.bundle.content_hash,
                        "content_hash",
                    );
                }
            }
            Some(actual) => {
                receipt_failures.push(format!(
                    "{receipt_label}:unexpected_receipt_family:{actual}"
                ));
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_receipt_family")),
        }
        match receipt_evidence_hash_value(receipt, "evidenceBundleId") {
            Some(actual) if actual == expected_bundle_id_evidence => {}
            Some(actual) => receipt_failures.push(format!(
                "{receipt_label}:evidence_bundle_id_mismatch:{actual}"
            )),
            None => {
                if matches!(
                    receipt_family,
                    Some("evidence_bundle_manifest" | "response_execution")
                ) {
                    receipt_failures.push(format!("{receipt_label}:missing_evidence_bundle_id"));
                }
            }
        }
        let signer_public_key =
            receipt_endpoint_decision_str(receipt, &["signer", "signerPublicKey"])
                .map(str::trim)
                .filter(|signer_public_key| !signer_public_key.is_empty());
        match signer_public_key {
            Some(signer_public_key) => {
                receipt_signer_public_keys.insert(signer_public_key.to_string());
                match hush_core::PublicKey::from_hex(signer_public_key) {
                    Ok(public_key) => {
                        let verification =
                            receipt.verify(&hush_core::receipt::PublicKeySet::new(public_key));
                        if !verification.valid {
                            receipt_failures.push(format!("{receipt_label}:signature_invalid"));
                        }
                    }
                    Err(_) => {
                        receipt_failures.push(format!("{receipt_label}:invalid_signer_public_key"));
                    }
                }
                if let Err(reason) =
                    verify_endpoint_receipt_signature(receipt, receipt_label, signer_public_key)
                {
                    receipt_failures.push(format!(
                        "{receipt_label}:endpoint_decision_binding_invalid:{reason}"
                    ));
                }
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_signer_public_key")),
        }
        match receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"]) {
            Some(actual) if actual == archive.bundle.graph_slice_id => {}
            Some(actual) => {
                receipt_failures.push(format!("{receipt_label}:graph_slice_mismatch:{actual}"))
            }
            None => receipt_failures.push(format!("{receipt_label}:missing_graph_slice")),
        }
        if let Some(evidence) =
            receipt_endpoint_decision_value(receipt, &["evidence"]).and_then(Value::as_array)
        {
            for item in evidence.iter().filter(|item| {
                item.get("key")
                    .and_then(Value::as_str)
                    .is_some_and(|key| key == "contentHash" || key == "evidenceBundleContentHash")
            }) {
                match item.get("valueHash").and_then(Value::as_str) {
                    Some(actual) if actual == expected_content_hash_evidence => {
                        matching_content_hash_receipts =
                            matching_content_hash_receipts.saturating_add(1);
                    }
                    Some(actual) => receipt_failures
                        .push(format!("{receipt_label}:content_hash_mismatch:{actual}")),
                    None => receipt_failures.push(format!("{receipt_label}:missing_content_hash")),
                }
            }
        }
    }

    if archive.receipts.is_empty() {
        receipt_failures.push("missing_archive_receipts".to_string());
    }
    if receipt_signer_public_keys.is_empty() {
        receipt_failures.push("missing_receipt_signer_public_key_set".to_string());
    } else if receipt_signer_public_keys.len() > 1 {
        receipt_failures.push(format!(
            "receipt_signer_continuity_mismatch:{}",
            receipt_signer_public_keys.len()
        ));
    }
    if receipt_endpoint_ids.is_empty() {
        receipt_failures.push("missing_receipt_endpoint_identity_set".to_string());
    } else if receipt_endpoint_ids.len() > 1 {
        receipt_failures.push(format!(
            "receipt_endpoint_identity_mismatch:{}",
            receipt_endpoint_ids.len()
        ));
    }
    if receipt_root_node_ids.is_empty() {
        receipt_failures.push("missing_receipt_root_node_set".to_string());
    } else if receipt_root_node_ids.len() > 1 {
        receipt_failures.push(format!(
            "receipt_root_node_continuity_mismatch:{}",
            receipt_root_node_ids.len()
        ));
    }
    for (family, count) in &receipt_family_counts {
        if *count > 1 && !receipt_family_allows_multiple_archive_members(family) {
            receipt_failures.push(format!("duplicate_receipt_family:{family}:{count}"));
        }
    }
    let mut previous_sequence_timestamp = None;
    for (sequence, timestamp) in &receipt_sequence_timestamps {
        if let Some((previous_sequence, previous_timestamp)) = previous_sequence_timestamp {
            if timestamp < previous_timestamp {
                receipt_failures.push(format!(
                    "receipt_chronology_inversion:{previous_sequence}:{sequence}"
                ));
                break;
            }
        }
        previous_sequence_timestamp = Some((*sequence, timestamp));
    }

    let distinct_response_actor_hashes = response_actor_hashes
        .iter()
        .map(|(_, actor_hash)| actor_hash)
        .collect::<BTreeSet<_>>();
    if distinct_response_actor_hashes.len() > 1 {
        let actor_families = response_actor_hashes
            .iter()
            .map(|(family, _)| family.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        receipt_failures.push(format!(
            "response_actor_continuity_mismatch:{actor_families}"
        ));
    }
    let distinct_policy_hashes = policy_hashes
        .iter()
        .map(|(_, policy_hash)| policy_hash)
        .collect::<BTreeSet<_>>();
    if distinct_policy_hashes.len() > 1 {
        let policy_families = policy_hashes
            .iter()
            .map(|(family, _)| family.as_str())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join(",");
        receipt_failures.push(format!("policy_continuity_mismatch:{policy_families}"));
    }
    if let Some((_, execution_providers)) = sensor_provider_sets
        .iter()
        .find(|(family, _)| family == "response_execution")
    {
        for (family, providers) in &sensor_provider_sets {
            if family != "response_execution" && !providers.is_subset(execution_providers) {
                receipt_failures.push(format!("sensor_state_continuity_mismatch:{family}"));
            }
        }
    }

    receipt_failures.sort();
    receipt_failures.dedup();
    let receipt_count = archive.receipts.len();
    let receipt_families_valid = !receipt_failures
        .iter()
        .any(|failure| failure.contains("receipt_family"));
    let present_receipt_families = receipt_families.iter().cloned().collect::<Vec<_>>();
    let receipt_family_cardinality_valid = !receipt_failures
        .iter()
        .any(|failure| failure.starts_with("duplicate_receipt_family:"));
    let mut required_receipt_families = Vec::new();
    let mut missing_required_receipt_families = Vec::new();
    let mut required_receipt_family_contract_known = true;
    match required_archive_receipt_families(&archive.bundle.bundle_id) {
        Some(required_family_contract) => {
            required_receipt_families = required_family_contract
                .iter()
                .map(|family| (*family).to_string())
                .collect();
            for family in required_family_contract {
                if !receipt_families.contains(family) {
                    receipt_failures.push(format!("missing_required_family:{family}"));
                    missing_required_receipt_families.push(family.to_string());
                }
            }
        }
        None => {
            required_receipt_family_contract_known = false;
            receipt_failures.push(format!(
                "unknown_required_family_contract:{}",
                archive.bundle.bundle_id
            ));
        }
    }
    receipt_failures.sort();
    receipt_failures.dedup();
    let required_receipt_families_present =
        required_receipt_family_contract_known && missing_required_receipt_families.is_empty();
    let artifact_matches_bundle = !receipt_failures
        .iter()
        .any(|failure| failure.contains("artifact_"));
    let artifact_byte_count_matches = !receipt_failures
        .iter()
        .any(|failure| failure.contains("artifact_byte_count_mismatch"));
    let receipts_bind_bundle_id = !receipt_failures.iter().any(|failure| {
        failure.contains("evidence_bundle_id") || failure.contains("manifest_finding_id")
    });
    let receipts_bind_actor = !receipt_failures.iter().any(|failure| {
        failure.contains("actor_hash")
            || failure.contains("execution_actor_hash")
            || failure.contains("actor_decode")
            || failure.contains("response_actor_continuity")
    });
    let receipts_bind_policy = !receipt_failures.iter().any(|failure| {
        failure.contains("policy_decode")
            || failure.contains("invalid_policy")
            || failure.contains("policy_continuity")
    });
    let receipts_bind_sensor_state = !receipt_failures.iter().any(|failure| {
        failure.contains("sensor_state_decode")
            || failure.contains("sensor_state_missing")
            || failure.contains("sensor_state_continuity")
    });
    let receipts_bind_endpoint_decision = !receipt_failures
        .iter()
        .any(|failure| failure.contains("endpoint_decision_binding"));
    let receipt_endpoint_ids = receipt_endpoint_ids.into_iter().collect::<Vec<_>>();
    let receipts_bind_endpoint_identity = receipt_count > 0
        && receipt_endpoint_ids.len() == 1
        && !receipt_failures.iter().any(|failure| {
            failure.contains("actor_endpoint_id") || failure.contains("receipt_endpoint_identity")
        });
    let receipt_root_node_ids = receipt_root_node_ids.into_iter().collect::<Vec<_>>();
    let receipts_bind_root_node = receipt_count > 0
        && receipt_root_node_ids.len() == 1
        && !receipt_failures
            .iter()
            .any(|failure| failure.contains("root_node") || failure.contains("missing_root_node"));
    let graph_counts_match = !receipt_failures.iter().any(|failure| {
        failure.starts_with("bundle_node_count_mismatch")
            || failure.starts_with("bundle_edge_count_mismatch")
            || failure.contains(":node_count")
            || failure.contains(":edge_count")
    });
    let receipt_ids_unique = !receipt_failures.iter().any(|failure| {
        failure.starts_with("duplicate_receipt_id:") || failure.contains(":missing_receipt_id")
    });
    let receipt_local_sequences = receipt_local_sequences.into_iter().collect::<Vec<_>>();
    let receipt_local_sequences_present = receipt_count > 0
        && !receipt_failures
            .iter()
            .any(|failure| failure.contains(":missing_receipt_local_sequence"));
    let receipt_local_sequences_unique = receipt_count > 0
        && receipt_local_sequences.len() == receipt_count
        && !receipt_failures
            .iter()
            .any(|failure| failure.starts_with("duplicate_receipt_local_sequence:"));
    let receipt_timestamps_parse = receipt_count > 0
        && !receipt_failures
            .iter()
            .any(|failure| failure.contains(":invalid_receipt_timestamp"));
    let receipt_chronology_consistent = receipt_timestamps_parse
        && receipt_local_sequences_unique
        && receipt_sequence_timestamps.len() == receipt_count
        && !receipt_failures
            .iter()
            .any(|failure| failure.starts_with("receipt_chronology_inversion:"));
    let receipt_signatures_valid = !receipt_failures
        .iter()
        .any(|failure| failure.contains("signature") || failure.contains("signer_public_key"));
    let receipt_signers_consistent =
        receipt_signer_public_keys.len() == 1 && receipt_signatures_valid;
    let receipts_bind_graph_slice = !receipt_failures.iter().any(|failure| {
        failure.contains(":graph_slice_mismatch")
            || failure.contains(":missing_graph_slice")
            || failure.contains(":graph_slice_evidence_mismatch")
            || failure.contains(":missing_graph_slice_evidence")
    });
    let receipts_bind_content_hash = matching_content_hash_receipts > 0
        && !receipt_failures
            .iter()
            .any(|failure| failure.contains("content_hash"));
    let verified = content_hash_matches
        && artifact_matches_bundle
        && artifact_byte_count_matches
        && receipts_bind_bundle_id
        && receipts_bind_actor
        && receipts_bind_policy
        && receipts_bind_sensor_state
        && receipts_bind_endpoint_decision
        && receipts_bind_endpoint_identity
        && receipts_bind_root_node
        && graph_counts_match
        && receipt_count > 0
        && receipt_ids_unique
        && receipt_local_sequences_present
        && receipt_local_sequences_unique
        && receipt_timestamps_parse
        && receipt_chronology_consistent
        && receipt_families_valid
        && receipt_family_cardinality_valid
        && required_receipt_families_present
        && receipt_signatures_valid
        && receipt_signers_consistent
        && receipts_bind_graph_slice
        && receipts_bind_content_hash;

    Ok(EdrEvidenceBundleArchiveVerification {
        verified,
        graph_content_hash,
        content_hash_matches,
        artifact_matches_bundle,
        artifact_byte_count_matches,
        receipts_bind_bundle_id,
        receipts_bind_actor,
        receipts_bind_policy,
        receipts_bind_sensor_state,
        receipts_bind_endpoint_decision,
        receipt_endpoint_ids,
        receipts_bind_endpoint_identity,
        receipt_root_node_ids,
        receipts_bind_root_node,
        graph_counts_match,
        receipt_count,
        receipt_ids_unique,
        receipt_local_sequences,
        receipt_local_sequences_present,
        receipt_local_sequences_unique,
        receipt_timestamps_parse,
        receipt_chronology_consistent,
        receipt_families_valid,
        present_receipt_families,
        receipt_family_counts,
        receipt_family_cardinality_valid,
        required_receipt_families,
        required_receipt_families_present,
        missing_required_receipt_families,
        receipt_signatures_valid,
        receipt_signers_consistent,
        receipts_bind_graph_slice,
        receipts_bind_content_hash,
        receipt_failure_count: receipt_failures.len(),
        receipt_failures,
    })
}

pub(crate) fn receipt_family_allows_multiple_archive_members(family: &str) -> bool {
    family == "response_execution"
}

pub(crate) fn push_archive_receipt_evidence_hash_failure(
    receipt_failures: &mut Vec<String>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    key: &str,
    raw_value: &str,
    failure_key: &str,
) {
    let expected_hash = sha256(raw_value.as_bytes()).to_hex_prefixed();
    match receipt_evidence_hash_value(receipt, key) {
        Some(actual) if actual == expected_hash => {}
        Some(actual) => {
            receipt_failures.push(format!("{receipt_label}:{failure_key}_mismatch:{actual}"));
        }
        None => receipt_failures.push(format!("{receipt_label}:missing_{failure_key}")),
    }
}

pub(crate) fn push_archive_response_actor_failures(
    receipt_failures: &mut Vec<String>,
    response_actor_hashes: &mut Vec<(String, String)>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    receipt_family: &str,
    required_hash_keys: &[&str],
) -> Result<()> {
    let actor = match receipt_endpoint_decision_actor(receipt) {
        Ok(actor) => actor,
        Err(reason) => {
            receipt_failures.push(format!("{receipt_label}:actor_decode_failed:{reason}"));
            return Ok(());
        }
    };
    let actor_hash = canonical_json_hash(&actor, "archive response receipt actor")?;
    response_actor_hashes.push((receipt_family.to_string(), actor_hash.clone()));
    for key in required_hash_keys {
        push_archive_receipt_evidence_hash_failure(
            receipt_failures,
            receipt,
            receipt_label,
            key,
            &actor_hash,
            &archive_actor_failure_key(key),
        );
    }
    Ok(())
}

pub(crate) fn push_archive_policy_failures(
    receipt_failures: &mut Vec<String>,
    policy_hashes: &mut Vec<(String, String)>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    receipt_family: &str,
) -> Result<()> {
    let policy = match receipt_endpoint_decision_policy(receipt) {
        Ok(policy) => policy,
        Err(reason) => {
            receipt_failures.push(format!("{receipt_label}:policy_decode_failed:{reason}"));
            return Ok(());
        }
    };
    if policy.policy_version.trim().is_empty() {
        receipt_failures.push(format!("{receipt_label}:invalid_policy_version"));
    }
    if !policy.policy_hash.starts_with("0x") {
        receipt_failures.push(format!(
            "{receipt_label}:invalid_policy_hash:{}",
            policy.policy_hash
        ));
    }
    if policy.policy_epoch == 0 {
        receipt_failures.push(format!("{receipt_label}:invalid_policy_epoch"));
    }
    let policy_hash = canonical_json_hash(&policy, "archive receipt policy snapshot")?;
    policy_hashes.push((receipt_family.to_string(), policy_hash));
    Ok(())
}

pub(crate) fn push_archive_sensor_state_failures(
    receipt_failures: &mut Vec<String>,
    sensor_provider_sets: &mut Vec<(String, BTreeSet<String>)>,
    receipt: &SignedReceipt,
    receipt_label: &str,
    receipt_family: &str,
) -> Result<()> {
    let sensor_state = match receipt_endpoint_decision_sensor_state(receipt) {
        Ok(sensor_state) => sensor_state,
        Err(reason) => {
            receipt_failures.push(format!(
                "{receipt_label}:sensor_state_decode_failed:{reason}"
            ));
            return Ok(());
        }
    };
    if sensor_state.providers.is_empty() {
        receipt_failures.push(format!("{receipt_label}:sensor_state_missing_providers"));
    }
    let mut providers = BTreeSet::new();
    for provider in &sensor_state.providers {
        if provider.provider_id.trim().is_empty() {
            receipt_failures.push(format!("{receipt_label}:sensor_state_missing_provider_id"));
        } else {
            providers.insert(provider.provider_id.clone());
        }
    }
    sensor_provider_sets.push((receipt_family.to_string(), providers));
    Ok(())
}

pub(crate) fn archive_actor_failure_key(key: &str) -> String {
    let mut failure_key = String::new();
    for (index, ch) in key.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if index > 0 {
                failure_key.push('_');
            }
            failure_key.push(ch.to_ascii_lowercase());
        } else {
            failure_key.push(ch);
        }
    }
    failure_key
}

pub(crate) fn required_archive_receipt_families(bundle_id: &str) -> Option<Vec<&'static str>> {
    if bundle_id.starts_with("evidence_bundle:") {
        Some(vec![
            "response_request",
            "response_execution",
            "evidence_bundle_manifest",
        ])
    } else if bundle_id.starts_with("evidence_bundle-") {
        Some(vec!["graph_slice"])
    } else {
        None
    }
}

pub(crate) fn evidence_bundle_record(
    stored: StoredEndpointEvidenceBundle,
    now: chrono::DateTime<chrono::Utc>,
    protected_bundle_ids: &BTreeSet<String>,
) -> EdrEvidenceBundleRecord {
    let protected_by_active_response = protected_bundle_ids.contains(&stored.bundle.bundle_id);
    EdrEvidenceBundleRecord {
        age_seconds: evidence_bundle_age_seconds(&stored, now),
        bundle: stored.bundle,
        path: stored.path,
        byte_count: stored.byte_count,
        protected_by_active_response,
    }
}

pub(crate) fn evidence_bundle_age_seconds(
    stored: &StoredEndpointEvidenceBundle,
    now: chrono::DateTime<chrono::Utc>,
) -> u64 {
    now.signed_duration_since(stored.bundle.created_at)
        .num_seconds()
        .max(0) as u64
}
