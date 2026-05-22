//! Response-acknowledgement ledger.
//!
//! Appends `EndpointResponseAcknowledgementReport`s (one per operator ACK
//! postback) so the response handler can query recent acknowledgements and
//! confirm each ACK was received.

use std::collections::VecDeque;
use std::fs;
use std::io::Write as _;
use std::path::{Path as FsPath, PathBuf};

use anyhow::{Context, Result};
use clawdstrike_policy_event::edr::EndpointResponseAcknowledgementReport;

use crate::api_server::EDR_MAX_STORED_FINDINGS;

use super::open_private_append;

pub(crate) struct EndpointResponseAcknowledgementLedger {
    path: Option<PathBuf>,
    acknowledgements: VecDeque<EndpointResponseAcknowledgementReport>,
}

impl EndpointResponseAcknowledgementLedger {
    pub(crate) fn open(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let acknowledgements = read_response_acknowledgement_ledger(&path)?;
        Ok(Self {
            path: Some(path),
            acknowledgements: acknowledgements.into(),
        })
    }

    #[cfg(test)]
    pub(crate) fn transient() -> Self {
        Self {
            path: None,
            acknowledgements: VecDeque::new(),
        }
    }

    pub(crate) fn path(&self) -> Option<&FsPath> {
        self.path.as_deref()
    }

    pub(crate) fn append(
        &mut self,
        acknowledgement: &EndpointResponseAcknowledgementReport,
    ) -> Result<()> {
        self.acknowledgements.push_back(acknowledgement.clone());
        while self.acknowledgements.len() > EDR_MAX_STORED_FINDINGS {
            let _ = self.acknowledgements.pop_front();
        }

        let Some(path) = &self.path else {
            return Ok(());
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "create endpoint response acknowledgement ledger directory {}",
                    parent.display()
                )
            })?;
        }

        let mut file = open_private_append(path, "endpoint response acknowledgement ledger")?;
        serde_json::to_writer(&mut file, acknowledgement).with_context(|| {
            format!(
                "serialize endpoint response acknowledgement {}",
                acknowledgement.acknowledgement_id
            )
        })?;
        file.write_all(b"\n").with_context(|| {
            format!(
                "write endpoint response acknowledgement ledger {}",
                path.display()
            )
        })?;
        file.flush().with_context(|| {
            format!(
                "flush endpoint response acknowledgement ledger {}",
                path.display()
            )
        })?;
        Ok(())
    }

    pub(crate) fn read_recent(
        &self,
        limit: usize,
    ) -> Result<Vec<EndpointResponseAcknowledgementReport>> {
        if let Some(path) = &self.path {
            let acknowledgements = read_response_acknowledgement_ledger(path)?;
            return Ok(acknowledgements
                .into_iter()
                .rev()
                .take(limit)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect());
        }
        Ok(self
            .acknowledgements
            .iter()
            .rev()
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect())
    }
}

pub(crate) fn read_response_acknowledgement_ledger(
    path: &FsPath,
) -> Result<Vec<EndpointResponseAcknowledgementReport>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "read endpoint response acknowledgement ledger {}",
                    path.display()
                )
            });
        }
    };

    let mut acknowledgements = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let acknowledgement: EndpointResponseAcknowledgementReport = serde_json::from_str(line)
            .with_context(|| {
                format!(
                    "parse endpoint response acknowledgement ledger line {} from {}",
                    index + 1,
                    path.display()
                )
            })?;
        acknowledgements.push(acknowledgement);
    }
    Ok(acknowledgements)
}
