//! `impl EndpointReceiptLedger` — read / write / append / rebuild-index
//! storage layer (durable JSONL).

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::{Seek as _, SeekFrom, Write as _};

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use anyhow::{Context, Result};
use hush_core::SignedReceipt;

use super::EndpointReceiptLedger;
use crate::api_server::{
    endpoint_receipt_index_path, endpoint_receipt_index_record, read_endpoint_receipt_ledger,
    read_recent_indexed_endpoint_receipts, rebuild_endpoint_receipt_index, receipt_matches_filter,
    EdrReceiptFilter,
};

impl EndpointReceiptLedger {
    pub(crate) fn read_recent(
        &self,
        limit: usize,
        filter: EdrReceiptFilter<'_>,
    ) -> Result<Vec<SignedReceipt>> {
        if let Some(path) = &self.path {
            if let Some(receipts) = read_recent_indexed_endpoint_receipts(path, limit, filter)? {
                return Ok(receipts);
            }
        }

        let mut receipts = VecDeque::new();
        for receipt in self.all()? {
            if !receipt_matches_filter(&receipt, filter) {
                continue;
            }
            receipts.push_back(receipt);
            while receipts.len() > limit {
                let _ = receipts.pop_front();
            }
        }

        Ok(receipts.into_iter().collect())
    }

    pub(crate) fn all(&self) -> Result<Vec<SignedReceipt>> {
        let Some(path) = &self.path else {
            return Ok(Vec::new());
        };
        read_endpoint_receipt_ledger(path)
    }

    pub(crate) fn rewrite(&self, receipts: &[SignedReceipt]) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint receipt ledger directory {}",
                    parent.display()
                )
            })?;
        }
        let mut contents = String::new();
        for receipt in receipts {
            let line = serde_json::to_string(receipt).context("serialize endpoint receipt")?;
            contents.push_str(&line);
            contents.push('\n');
        }
        crate::security::fs::write_private_atomic(
            path,
            contents.as_bytes(),
            "endpoint receipt ledger",
        )?;
        self.rebuild_index()
    }

    pub(crate) fn append(&self, receipts: &[SignedReceipt]) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint receipt ledger directory {}",
                    parent.display()
                )
            })?;
        }

        let mut ledger_options = OpenOptions::new();
        #[cfg(unix)]
        ledger_options.mode(0o600);
        let mut file = ledger_options
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("open endpoint receipt ledger {}", path.display()))?;
        crate::settings::enforce_private_mode(path, "endpoint receipt ledger")?;

        let index_path = endpoint_receipt_index_path(path);
        let mut index_options = OpenOptions::new();
        #[cfg(unix)]
        index_options.mode(0o600);
        let mut index_file = index_options
            .create(true)
            .append(true)
            .open(&index_path)
            .with_context(|| format!("open endpoint receipt index {}", index_path.display()))?;
        crate::settings::enforce_private_mode(&index_path, "endpoint receipt index")?;
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
            let byte_offset = file
                .seek(SeekFrom::End(0))
                .with_context(|| format!("seek endpoint receipt ledger {}", path.display()))?;
            file.write_all(&line)
                .with_context(|| format!("write endpoint receipt to {}", path.display()))?;
            file.write_all(b"\n")
                .with_context(|| format!("write endpoint receipt to {}", path.display()))?;
            let record = endpoint_receipt_index_record(receipt, byte_offset, line.len() as u64);
            serde_json::to_writer(&mut index_file, &record).with_context(|| {
                format!(
                    "serialize endpoint receipt index {}",
                    receipt
                        .receipt
                        .receipt_id
                        .as_deref()
                        .unwrap_or("<missing-receipt-id>")
                )
            })?;
            index_file.write_all(b"\n").with_context(|| {
                format!("write endpoint receipt index {}", index_path.display())
            })?;
        }
        file.flush()
            .with_context(|| format!("flush endpoint receipt ledger {}", path.display()))?;
        index_file
            .flush()
            .with_context(|| format!("flush endpoint receipt index {}", index_path.display()))?;
        Ok(())
    }

    pub(crate) fn rebuild_index(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        rebuild_endpoint_receipt_index(path)
    }
}
