//! `impl EndpointReceiptLedger::compact` and the compaction manifest record.

use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use hush_core::{canonicalize_json, sha256, SignedReceipt};
use serde::Serialize;

use super::EndpointReceiptLedger;
use crate::api_server::{
    receipt_age_seconds, receipt_compaction_record, receipt_family, receipt_local_sequence,
    EdrReceiptCompactionRecord,
};

pub(crate) struct ReceiptCompactionReport {
    pub(crate) receipt_count: usize,
    pub(crate) retained_count: usize,
    pub(crate) records: Vec<EdrReceiptCompactionRecord>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptCompactionManifest {
    schema_version: &'static str,
    compacted_at: String,
    ledger_path: String,
    max_receipts: Option<usize>,
    min_age_seconds: u64,
    pre_ledger_sha256: String,
    post_ledger_sha256: String,
    pre_receipt_count: usize,
    post_receipt_count: usize,
    retained: Vec<ReceiptCompactionManifestEntry>,
    removed: Vec<ReceiptCompactionManifestEntry>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptCompactionManifestEntry {
    receipt_id: Option<String>,
    family: Option<String>,
    local_sequence: Option<u64>,
    signed_receipt_sha256: String,
}

impl EndpointReceiptLedger {
    pub(crate) fn compact(
        &mut self,
        max_receipts: Option<usize>,
        min_age_seconds: u64,
        dry_run: bool,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ReceiptCompactionReport> {
        let receipts = self.all()?;
        let receipt_count = receipts.len();
        let mut retained = Vec::with_capacity(receipts.len());
        let mut removed_receipts = Vec::new();
        let mut records = Vec::new();
        for (index, receipt) in receipts.iter().enumerate() {
            let age_seconds = receipt_age_seconds(receipt, now);
            let beyond_limit =
                max_receipts.is_some_and(|max| receipts.len().saturating_sub(index) > max);
            let old_enough = age_seconds >= min_age_seconds;
            if !old_enough || max_receipts.is_some() && !beyond_limit {
                retained.push(receipt.clone());
                continue;
            }
            let reason = if beyond_limit {
                format!(
                    "receipt exceeds max_receipts {} and is at least {min_age_seconds}s old",
                    max_receipts.unwrap_or_default()
                )
            } else {
                format!("receipt is at least {min_age_seconds}s old")
            };
            records.push(receipt_compaction_record(
                receipt,
                age_seconds,
                !dry_run,
                reason,
            ));
            if dry_run {
                retained.push(receipt.clone());
            } else {
                removed_receipts.push(receipt.clone());
            }
        }

        if !dry_run {
            let manifest = self.receipt_compaction_manifest(
                &receipts,
                &retained,
                &removed_receipts,
                max_receipts,
                min_age_seconds,
                now,
            )?;
            self.rewrite(&retained)?;
            self.append_compaction_manifest(&manifest)?;
        }
        self.next_sequence = receipts
            .iter()
            .filter_map(receipt_local_sequence)
            .max()
            .unwrap_or(0)
            .saturating_add(1)
            .max(self.next_sequence);

        Ok(ReceiptCompactionReport {
            receipt_count,
            retained_count: retained.len(),
            records,
        })
    }

    fn receipt_compaction_manifest(
        &self,
        pre_receipts: &[SignedReceipt],
        post_receipts: &[SignedReceipt],
        removed_receipts: &[SignedReceipt],
        max_receipts: Option<usize>,
        min_age_seconds: u64,
        compacted_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ReceiptCompactionManifest> {
        let ledger_path = self
            .path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<transient>".to_string());
        Ok(ReceiptCompactionManifest {
            schema_version: "clawdstrike.endpoint_receipt_compaction.v1",
            compacted_at: compacted_at.to_rfc3339(),
            ledger_path,
            max_receipts,
            min_age_seconds,
            pre_ledger_sha256: receipt_ledger_sha256(pre_receipts)?,
            post_ledger_sha256: receipt_ledger_sha256(post_receipts)?,
            pre_receipt_count: pre_receipts.len(),
            post_receipt_count: post_receipts.len(),
            retained: post_receipts
                .iter()
                .map(receipt_compaction_manifest_entry)
                .collect::<Result<Vec<_>>>()?,
            removed: removed_receipts
                .iter()
                .map(receipt_compaction_manifest_entry)
                .collect::<Result<Vec<_>>>()?,
        })
    }

    fn append_compaction_manifest(&self, manifest: &ReceiptCompactionManifest) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let manifest_path = endpoint_receipt_compaction_manifest_path(path);
        if let Some(parent) = manifest_path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint receipt compaction manifest directory {}",
                    parent.display()
                )
            })?;
        }
        let mut options = OpenOptions::new();
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .create(true)
            .append(true)
            .open(&manifest_path)
            .with_context(|| {
                format!(
                    "open endpoint receipt compaction manifest {}",
                    manifest_path.display()
                )
            })?;
        crate::settings::enforce_private_mode(
            &manifest_path,
            "endpoint receipt compaction manifest",
        )?;
        let line = serde_json::to_vec(manifest)
            .context("serialize endpoint receipt compaction manifest")?;
        file.write_all(&line).with_context(|| {
            format!(
                "write endpoint receipt compaction manifest {}",
                manifest_path.display()
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!(
                "write endpoint receipt compaction manifest {}",
                manifest_path.display()
            )
        })?;
        file.flush().with_context(|| {
            format!(
                "flush endpoint receipt compaction manifest {}",
                manifest_path.display()
            )
        })?;
        Ok(())
    }
}

pub(crate) fn endpoint_receipt_compaction_manifest_path(path: &FsPath) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".compaction.jsonl");
    PathBuf::from(value)
}

fn receipt_ledger_sha256(receipts: &[SignedReceipt]) -> Result<String> {
    let bytes = receipt_ledger_bytes(receipts)?;
    Ok(sha256(&bytes).to_hex_prefixed())
}

fn receipt_ledger_bytes(receipts: &[SignedReceipt]) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for receipt in receipts {
        let line = serde_json::to_vec(receipt).with_context(|| {
            format!(
                "serialize endpoint receipt {}",
                receipt
                    .receipt
                    .receipt_id
                    .as_deref()
                    .unwrap_or("<missing-receipt-id>")
            )
        })?;
        bytes.extend_from_slice(&line);
        bytes.push(b'\n');
    }
    Ok(bytes)
}

fn receipt_compaction_manifest_entry(
    receipt: &SignedReceipt,
) -> Result<ReceiptCompactionManifestEntry> {
    let receipt_value = serde_json::to_value(receipt)
        .context("serialize endpoint receipt for compaction manifest")?;
    let canonical = canonicalize_json(&receipt_value)
        .context("canonicalize endpoint receipt for compaction manifest")?;
    Ok(ReceiptCompactionManifestEntry {
        receipt_id: receipt.receipt.receipt_id.clone(),
        family: receipt_family(receipt).map(ToString::to_string),
        local_sequence: receipt_local_sequence(receipt),
        signed_receipt_sha256: sha256(canonical.as_bytes()).to_hex_prefixed(),
    })
}
