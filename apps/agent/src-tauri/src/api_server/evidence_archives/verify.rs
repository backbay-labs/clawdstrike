use super::*;

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

    append_cross_receipt_continuity_failures(
        &mut receipt_failures,
        &response_actor_hashes,
        &policy_hashes,
        &sensor_provider_sets,
    );

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
