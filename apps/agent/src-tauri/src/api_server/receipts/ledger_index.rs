//! JSONL receipt ledger persistence and sidecar index file.
//!
//! Maintains an append-only signed-receipt ledger file plus a parallel
//! `.index.jsonl` that records byte-offset + filterable metadata for each
//! entry. The index is rebuilt on demand when missing, stale, or corrupt
//! so callers never see an inconsistent view.

use super::super::*;

pub(crate) fn next_receipt_sequence(path: &FsPath) -> Result<u64> {
    Ok(read_endpoint_receipt_ledger(path)?
        .iter()
        .filter_map(receipt_local_sequence)
        .max()
        .unwrap_or(0)
        .saturating_add(1)
        .max(1))
}

pub(crate) fn read_endpoint_receipt_ledger(path: &FsPath) -> Result<Vec<SignedReceipt>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint receipt ledger {}", path.display()));
        }
    };
    let mut receipts = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let receipt: SignedReceipt = serde_json::from_str(line).with_context(|| {
            format!(
                "parse endpoint receipt ledger line {} from {}",
                index + 1,
                path.display()
            )
        })?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

pub(crate) fn endpoint_receipt_index_path(path: &FsPath) -> PathBuf {
    let mut filename = path
        .file_name()
        .map(|value| value.to_os_string())
        .unwrap_or_else(|| "decision-receipts.jsonl".into());
    filename.push(".index.jsonl");
    path.with_file_name(filename)
}

pub(crate) fn read_endpoint_receipt_index(
    path: &FsPath,
) -> Result<Vec<EndpointReceiptIndexRecord>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint receipt index {}", path.display()));
        }
    };
    let mut records = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let record: EndpointReceiptIndexRecord = serde_json::from_str(line).with_context(|| {
            format!(
                "parse endpoint receipt index line {} from {}",
                index + 1,
                path.display()
            )
        })?;
        records.push(record);
    }
    Ok(records)
}

pub(crate) fn read_recent_indexed_endpoint_receipts(
    path: &FsPath,
    limit: usize,
    filter: EdrReceiptFilter<'_>,
) -> Result<Option<Vec<SignedReceipt>>> {
    let index_path = endpoint_receipt_index_path(path);
    if !index_path.exists() {
        if !path.exists() {
            return Ok(None);
        }
        rebuild_endpoint_receipt_index(path)?;
    }
    let mut records = read_endpoint_receipt_index_or_rebuild(path, &index_path)?;
    if records.is_empty() {
        if endpoint_receipt_ledger_len(path)? > 0 {
            rebuild_endpoint_receipt_index(path)?;
            records = read_endpoint_receipt_index(&index_path)?;
            if !records.is_empty() {
                return read_recent_indexed_endpoint_receipts_from_records(
                    path, limit, filter, records,
                )
                .map(Some);
            }
        }
        return Ok(Some(Vec::new()));
    }
    if !endpoint_receipt_index_is_current(path, &records)? {
        rebuild_endpoint_receipt_index(path)?;
        records = read_endpoint_receipt_index(&index_path)?;
        if records.is_empty() {
            return Ok(Some(Vec::new()));
        }
    }
    read_recent_indexed_endpoint_receipts_from_records(path, limit, filter, records).map(Some)
}

pub(crate) fn read_endpoint_receipt_index_or_rebuild(
    path: &FsPath,
    index_path: &FsPath,
) -> Result<Vec<EndpointReceiptIndexRecord>> {
    match read_endpoint_receipt_index(index_path) {
        Ok(records) => Ok(records),
        Err(index_error) => {
            let index_error = index_error.to_string();
            rebuild_endpoint_receipt_index(path).with_context(|| {
                format!("rebuild endpoint receipt index after index read failed: {index_error}")
            })?;
            read_endpoint_receipt_index(index_path).with_context(|| {
                format!("read endpoint receipt index after rebuilding corrupt index: {index_error}")
            })
        }
    }
}

pub(crate) fn read_recent_indexed_endpoint_receipts_from_records(
    path: &FsPath,
    limit: usize,
    filter: EdrReceiptFilter<'_>,
    records: Vec<EndpointReceiptIndexRecord>,
) -> Result<Vec<SignedReceipt>> {
    let records = match validate_endpoint_receipt_index_records(path, records) {
        Ok(records) => records,
        Err(index_error) => {
            let index_error = index_error.to_string();
            let rebuild_error_context =
                format!("rebuild endpoint receipt index after validation failed: {index_error}");
            rebuild_endpoint_receipt_index(path).with_context(|| rebuild_error_context)?;
            read_endpoint_receipt_index(&endpoint_receipt_index_path(path)).with_context(|| {
                format!("read endpoint receipt index after rebuilding stale index: {index_error}")
            })?
        }
    };
    let selected = select_endpoint_receipt_index_records(records, limit, filter);
    match read_endpoint_receipts_by_index(path, &selected) {
        Ok(receipts) => Ok(receipts),
        Err(index_error) => {
            let index_error = index_error.to_string();
            let rebuild_error_context =
                format!("rebuild endpoint receipt index after indexed read failed: {index_error}");
            rebuild_endpoint_receipt_index(path).with_context(|| rebuild_error_context)?;
            let rebuilt_records = read_endpoint_receipt_index(&endpoint_receipt_index_path(path))?;
            let selected = select_endpoint_receipt_index_records(rebuilt_records, limit, filter);
            let read_error_context = format!(
                "read endpoint receipts after rebuilding corrupt receipt index: {index_error}"
            );
            read_endpoint_receipts_by_index(path, &selected).with_context(|| read_error_context)
        }
    }
}

pub(crate) fn validate_endpoint_receipt_index_records(
    path: &FsPath,
    records: Vec<EndpointReceiptIndexRecord>,
) -> Result<Vec<EndpointReceiptIndexRecord>> {
    read_endpoint_receipts_by_index(path, &records)?;
    Ok(records)
}

pub(crate) fn select_endpoint_receipt_index_records(
    records: Vec<EndpointReceiptIndexRecord>,
    limit: usize,
    filter: EdrReceiptFilter<'_>,
) -> Vec<EndpointReceiptIndexRecord> {
    records
        .into_iter()
        .filter(|record| receipt_index_matches_filter(record, filter))
        .rev()
        .take(limit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
}

pub(crate) fn endpoint_receipt_ledger_len(path: &FsPath) -> Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(err) => {
            Err(err).with_context(|| format!("stat endpoint receipt ledger {}", path.display()))
        }
    }
}

pub(crate) fn endpoint_receipt_index_is_current(
    path: &FsPath,
    records: &[EndpointReceiptIndexRecord],
) -> Result<bool> {
    let ledger_len = endpoint_receipt_ledger_len(path)?;
    let Some(last) = records.last() else {
        return Ok(ledger_len == 0);
    };
    let last_record_end = last.byte_offset.saturating_add(last.byte_len);
    Ok(ledger_len == last_record_end || ledger_len == last_record_end.saturating_add(1))
}

pub(crate) fn read_endpoint_receipts_by_index(
    path: &FsPath,
    records: &[EndpointReceiptIndexRecord],
) -> Result<Vec<SignedReceipt>> {
    let mut file = fs::File::open(path)
        .with_context(|| format!("open endpoint receipt ledger {}", path.display()))?;
    let mut receipts = Vec::with_capacity(records.len());
    for record in records {
        file.seek(SeekFrom::Start(record.byte_offset))
            .with_context(|| format!("seek endpoint receipt ledger {}", path.display()))?;
        let mut bytes = vec![0u8; record.byte_len as usize];
        file.read_exact(&mut bytes)
            .with_context(|| format!("read endpoint receipt ledger {}", path.display()))?;
        let receipt: SignedReceipt = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "parse endpoint receipt {} at byte offset {} from {}",
                record
                    .receipt_id
                    .as_deref()
                    .unwrap_or("<missing-receipt-id>"),
                record.byte_offset,
                path.display()
            )
        })?;
        validate_endpoint_receipt_index_record(path, record, &receipt)?;
        receipts.push(receipt);
    }
    Ok(receipts)
}

pub(crate) fn validate_endpoint_receipt_index_record(
    path: &FsPath,
    record: &EndpointReceiptIndexRecord,
    receipt: &SignedReceipt,
) -> Result<()> {
    let actual = endpoint_receipt_index_record(receipt, record.byte_offset, record.byte_len);
    if actual != *record {
        return Err(anyhow::anyhow!(
            "endpoint receipt index metadata mismatch at {} byte offset {}: expected receipt {:?} family {:?}, found receipt {:?} family {:?}",
            path.display(),
            record.byte_offset,
            record.receipt_id,
            record.family,
            actual.receipt_id,
            actual.family
        ));
    }
    Ok(())
}

pub(crate) fn rebuild_endpoint_receipt_index(path: &FsPath) -> Result<()> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let _ = fs::remove_file(endpoint_receipt_index_path(path));
            return Ok(());
        }
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read endpoint receipt ledger {}", path.display()));
        }
    };
    let mut records = Vec::new();
    let mut byte_offset = 0u64;
    for segment in contents.split_inclusive('\n') {
        let line_without_newline = segment.trim_end_matches('\n');
        let line = line_without_newline.trim();
        if !line.is_empty() {
            let receipt: SignedReceipt = serde_json::from_str(line).with_context(|| {
                format!(
                    "parse endpoint receipt ledger at byte offset {} from {}",
                    byte_offset,
                    path.display()
                )
            })?;
            records.push(endpoint_receipt_index_record(
                &receipt,
                byte_offset,
                line_without_newline.len() as u64,
            ));
        }
        byte_offset = byte_offset.saturating_add(segment.len() as u64);
    }
    let mut contents = String::new();
    for record in &records {
        let line =
            serde_json::to_string(record).context("serialize endpoint receipt index record")?;
        contents.push_str(&line);
        contents.push('\n');
    }
    let index_path = endpoint_receipt_index_path(path);
    crate::security::fs::write_private_atomic(
        &index_path,
        contents.as_bytes(),
        "endpoint receipt index",
    )
}

pub(crate) fn endpoint_receipt_index_record(
    receipt: &SignedReceipt,
    byte_offset: u64,
    byte_len: u64,
) -> EndpointReceiptIndexRecord {
    let family = receipt_family(receipt).map(ToString::to_string);
    let finding_id =
        receipt_endpoint_decision_str(receipt, &["decision", "findingId"]).map(ToString::to_string);
    EndpointReceiptIndexRecord {
        receipt_id: receipt.receipt.receipt_id.clone(),
        timestamp: receipt.receipt.timestamp.clone(),
        family: family.clone(),
        action: receipt_endpoint_decision_str(receipt, &["decision", "action"])
            .map(ToString::to_string),
        finding_id: finding_id.clone(),
        rule_id: receipt_endpoint_decision_str(receipt, &["decision", "ruleId"])
            .map(ToString::to_string),
        graph_slice_id: receipt_endpoint_decision_str(receipt, &["graph", "graphSliceId"])
            .map(ToString::to_string),
        root_node_id: receipt_endpoint_decision_str(receipt, &["graph", "processNodeId"])
            .map(ToString::to_string),
        execution_id: (family.as_deref() == Some("response_execution"))
            .then(|| finding_id.clone())
            .flatten(),
        execution_status: response_execution_status_from_receipt(receipt),
        actor_endpoint_id: receipt_endpoint_decision_str(receipt, &["actor", "endpointId"])
            .map(ToString::to_string),
        actor_user_id: receipt_endpoint_decision_str(receipt, &["actor", "userId"])
            .map(ToString::to_string),
        actor_session_id: receipt_endpoint_decision_str(receipt, &["actor", "sessionId"])
            .map(ToString::to_string),
        actor_agent_id: receipt_endpoint_decision_str(receipt, &["actor", "agentId"])
            .map(ToString::to_string),
        actor_workload_id: receipt_endpoint_decision_str(receipt, &["actor", "workloadId"])
            .map(ToString::to_string),
        actor_approval_id: receipt_endpoint_decision_str(receipt, &["actor", "approvalId"])
            .map(ToString::to_string),
        local_sequence: receipt_local_sequence(receipt),
        byte_offset,
        byte_len,
    }
}

pub(crate) fn response_execution_status_from_receipt(receipt: &SignedReceipt) -> Option<String> {
    [
        "succeeded",
        "failed",
        "partial",
        "rollback_pending",
        "rollback_failed",
        "expired",
        "cancelled",
        "rolled_back",
    ]
    .into_iter()
    .find(|status| receipt_evidence_hash_matches(receipt, "executionStatus", status))
    .map(ToString::to_string)
}

pub(crate) fn receipt_index_matches_filter(
    record: &EndpointReceiptIndexRecord,
    filter: EdrReceiptFilter<'_>,
) -> bool {
    string_filter_matches(record.receipt_id.as_deref(), filter.receipt_id)
        && string_filter_matches(record.family.as_deref(), filter.family)
        && string_filter_matches(record.action.as_deref(), filter.action)
        && string_filter_matches(record.finding_id.as_deref(), filter.finding_id)
        && string_filter_matches(record.rule_id.as_deref(), filter.rule_id)
        && string_filter_matches(record.graph_slice_id.as_deref(), filter.graph_slice_id)
        && string_filter_matches(record.root_node_id.as_deref(), filter.root_node_id)
        && string_filter_matches(record.execution_id.as_deref(), filter.execution_id)
        && string_filter_matches(record.execution_status.as_deref(), filter.status)
        && string_filter_matches(
            record.actor_endpoint_id.as_deref(),
            filter.actor_endpoint_id,
        )
        && string_filter_matches(record.actor_user_id.as_deref(), filter.actor_user_id)
        && string_filter_matches(record.actor_session_id.as_deref(), filter.actor_session_id)
        && string_filter_matches(record.actor_agent_id.as_deref(), filter.actor_agent_id)
        && string_filter_matches(
            record.actor_workload_id.as_deref(),
            filter.actor_workload_id,
        )
        && string_filter_matches(
            record.actor_approval_id.as_deref(),
            filter.actor_approval_id,
        )
        && filter
            .local_sequence
            .map_or(true, |expected| record.local_sequence == Some(expected))
}

pub(crate) fn string_filter_matches(actual: Option<&str>, expected: Option<&str>) -> bool {
    expected.map_or(true, |expected| actual == Some(expected))
}
