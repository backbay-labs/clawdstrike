//! Fleet hunt-event outbox ledger.
//!
//! Durable queue for fleet hunt events pending delivery to the control plane.
//! Entries are retried with exponential backoff until confirmed delivered.

use std::collections::VecDeque;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::api_server::{control_ack_retry_backoff_seconds, EDR_MAX_FLEET_HUNT_EVENT_OUTBOX};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EndpointFleetHuntEventOutboxEntry {
    pub(crate) outbox_id: String,
    pub(crate) event_id: String,
    pub(crate) raw_ref: String,
    pub(crate) event: serde_json::Value,
    pub(crate) attempt_count: u32,
    pub(crate) next_attempt_at: chrono::DateTime<chrono::Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_attempt_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) last_error_hash: Option<String>,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) updated_at: chrono::DateTime<chrono::Utc>,
}

pub(crate) struct EndpointFleetHuntEventOutbox {
    path: Option<PathBuf>,
    events: VecDeque<EndpointFleetHuntEventOutboxEntry>,
}

impl EndpointFleetHuntEventOutbox {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let events = read_fleet_hunt_event_outbox(&path)?;
        if path.exists() {
            crate::settings::enforce_private_mode(&path, "endpoint fleet hunt-event outbox")?;
        }
        Ok(Self {
            path: Some(path),
            events: events.into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn transient() -> Self {
        Self {
            path: None,
            events: VecDeque::new(),
        }
    }

    pub(crate) fn path(&self) -> Option<&FsPath> {
        self.path.as_deref()
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.events.len()
    }

    pub(crate) fn append(&mut self, event: EndpointFleetHuntEventOutboxEntry) -> Result<()> {
        self.events
            .retain(|existing| existing.outbox_id != event.outbox_id);
        self.events.push_back(event);
        while self.events.len() > EDR_MAX_FLEET_HUNT_EVENT_OUTBOX {
            let _ = self.events.pop_front();
        }
        self.persist()
    }

    pub(crate) fn due(
        &self,
        now: chrono::DateTime<chrono::Utc>,
        limit: usize,
        force: bool,
    ) -> Vec<EndpointFleetHuntEventOutboxEntry> {
        self.events
            .iter()
            .filter(|event| force || event.next_attempt_at <= now)
            .take(limit)
            .cloned()
            .collect()
    }

    pub(crate) fn mark_delivered(
        &mut self,
        outbox_id: &str,
    ) -> Result<Option<EndpointFleetHuntEventOutboxEntry>> {
        let Some(index) = self
            .events
            .iter()
            .position(|event| event.outbox_id == outbox_id)
        else {
            return Ok(None);
        };
        let removed = self.events.remove(index);
        self.persist()?;
        Ok(removed)
    }

    pub(crate) fn mark_failed(
        &mut self,
        outbox_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        error_hash: Option<String>,
    ) -> Result<Option<EndpointFleetHuntEventOutboxEntry>> {
        let Some(event) = self
            .events
            .iter_mut()
            .find(|event| event.outbox_id == outbox_id)
        else {
            return Ok(None);
        };
        event.attempt_count = event.attempt_count.saturating_add(1);
        event.last_attempt_at = Some(now);
        event.last_error_hash = error_hash;
        event.updated_at = now;
        event.next_attempt_at =
            now + chrono::Duration::seconds(control_ack_retry_backoff_seconds(event.attempt_count));
        let updated = event.clone();
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
                    "create endpoint fleet hunt-event outbox directory {}",
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
        let mut file = options
            .open(path)
            .with_context(|| format!("open endpoint fleet hunt-event outbox {}", path.display()))?;
        let events = self.events.iter().cloned().collect::<Vec<_>>();
        serde_json::to_writer_pretty(&mut file, &events).with_context(|| {
            format!(
                "serialize endpoint fleet hunt-event outbox {}",
                path.display()
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!("write endpoint fleet hunt-event outbox {}", path.display())
        })?;
        file.flush().with_context(|| {
            format!("flush endpoint fleet hunt-event outbox {}", path.display())
        })?;
        crate::settings::enforce_private_mode(path, "endpoint fleet hunt-event outbox")?;
        Ok(())
    }
}

pub(crate) fn read_fleet_hunt_event_outbox(
    path: &FsPath,
) -> Result<Vec<EndpointFleetHuntEventOutboxEntry>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("read endpoint fleet hunt-event outbox {}", path.display())
            });
        }
    };
    let trimmed = contents.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    serde_json::from_str(trimmed)
        .with_context(|| format!("parse endpoint fleet hunt-event outbox {}", path.display()))
}
