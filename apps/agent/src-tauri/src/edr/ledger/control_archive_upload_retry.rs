//! Control-API archive upload retry ledger.
//!
//! Durable queue for evidence bundle archives pending upload to the control
//! plane. Entries are retried with exponential backoff until confirmed
//! uploaded.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::api_server::{
    control_ack_retry_backoff_seconds, EDR_MAX_CONTROL_ARCHIVE_UPLOAD_RETRIES,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EndpointControlArchiveUploadRetry {
    pub(crate) retry_id: String,
    pub(crate) control_api_url: String,
    pub(crate) archive_id: String,
    pub(crate) archive_hash: String,
    pub(crate) raw_ref: String,
    pub(crate) bundle_id: String,
    pub(crate) payload: serde_json::Value,
    pub(crate) attempt_count: u32,
    pub(crate) next_attempt_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_response_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_error_hash: Option<String>,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) updated_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) struct EndpointControlArchiveUploadRetryLedger {
    path: Option<PathBuf>,
    retries: VecDeque<EndpointControlArchiveUploadRetry>,
}

impl EndpointControlArchiveUploadRetryLedger {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let retries = read_control_archive_upload_retry_ledger(&path)?;
        if path.exists() {
            crate::settings::enforce_private_mode(
                &path,
                "endpoint Control API archive upload retry queue",
            )?;
        }
        Ok(Self {
            path: Some(path),
            retries: retries.into(),
        })
    }

    pub(crate) fn transient() -> Self {
        Self {
            path: None,
            retries: VecDeque::new(),
        }
    }

    pub(crate) fn path(&self) -> Option<&FsPath> {
        self.path.as_deref()
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.retries.len()
    }

    pub(crate) fn append(&mut self, retry: EndpointControlArchiveUploadRetry) -> Result<()> {
        self.retries
            .retain(|existing| existing.retry_id != retry.retry_id);
        self.retries.push_back(retry);
        while self.retries.len() > EDR_MAX_CONTROL_ARCHIVE_UPLOAD_RETRIES {
            let _ = self.retries.pop_front();
        }
        self.persist()
    }

    pub(crate) fn due(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: usize,
        force: bool,
    ) -> Vec<EndpointControlArchiveUploadRetry> {
        self.retries
            .iter()
            .filter(|retry| force || retry.next_attempt_at <= now)
            .take(limit)
            .cloned()
            .collect()
    }

    pub(crate) fn mark_delivered(
        &mut self,
        retry_id: &str,
    ) -> Result<Option<EndpointControlArchiveUploadRetry>> {
        let Some(index) = self
            .retries
            .iter()
            .position(|retry| retry.retry_id == retry_id)
        else {
            return Ok(None);
        };
        let removed = self.retries.remove(index);
        self.persist()?;
        Ok(removed)
    }

    pub(crate) fn mark_failed(
        &mut self,
        retry_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        http_status: Option<u16>,
        response_hash: Option<String>,
        error_hash: Option<String>,
    ) -> Result<Option<EndpointControlArchiveUploadRetry>> {
        let Some(retry) = self
            .retries
            .iter_mut()
            .find(|retry| retry.retry_id == retry_id)
        else {
            return Ok(None);
        };
        retry.attempt_count = retry.attempt_count.saturating_add(1);
        retry.last_attempt_at = Some(now);
        retry.last_http_status = http_status;
        retry.last_response_hash = response_hash;
        retry.last_error_hash = error_hash;
        retry.updated_at = now;
        retry.next_attempt_at =
            now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(retry.attempt_count));
        let updated = retry.clone();
        self.persist()?;
        Ok(Some(updated))
    }

    fn persist(&self) -> Result<()> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint Control API archive upload retry queue directory {}",
                    parent.display()
                )
            })?;
        }

        let mut options = OpenOptions::new();
        options.create(true).write(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path).with_context(|| {
            format!(
                "open endpoint Control API archive upload retry queue {}",
                path.display()
            )
        })?;
        let retries = self.retries.iter().cloned().collect::<Vec<_>>();
        serde_json::to_writer_pretty(&mut file, &retries).with_context(|| {
            format!(
                "serialize endpoint Control API archive upload retry queue {}",
                path.display()
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!(
                "write endpoint Control API archive upload retry queue {}",
                path.display()
            )
        })?;
        file.flush().with_context(|| {
            format!(
                "flush endpoint Control API archive upload retry queue {}",
                path.display()
            )
        })?;
        crate::settings::enforce_private_mode(
            path,
            "endpoint Control API archive upload retry queue",
        )?;
        Ok(())
    }
}

pub(crate) fn read_control_archive_upload_retry_ledger(
    path: &FsPath,
) -> Result<Vec<EndpointControlArchiveUploadRetry>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "read endpoint Control API archive upload retry queue {}",
                    path.display()
                )
            });
        }
    };
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed).with_context(|| {
        format!(
            "parse endpoint Control API archive upload retry queue {}",
            path.display()
        )
    })
}
