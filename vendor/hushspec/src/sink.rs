use crate::evaluate::Decision;
use crate::receipt::DecisionReceipt;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum SinkError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

pub trait ReceiptSink: Send + Sync {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError>;
}

/// Appends receipts as JSON Lines to a file.
pub struct FileReceiptSink {
    path: PathBuf,
}

impl FileReceiptSink {
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl ReceiptSink for FileReceiptSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let json = serde_json::to_string(receipt)?;
        writeln!(file, "{}", json)?;
        Ok(())
    }
}

/// Pretty-prints receipts to stderr, prefixed with `[hushspec]`.
pub struct StderrReceiptSink;

impl ReceiptSink for StderrReceiptSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        let json = serde_json::to_string_pretty(receipt)?;
        eprintln!("[hushspec] {}", json);
        Ok(())
    }
}

/// Only forwards receipts matching configured decisions.
pub struct FilteredSink {
    inner: Box<dyn ReceiptSink>,
    decisions: Vec<Decision>,
}

impl FilteredSink {
    pub fn new(sink: Box<dyn ReceiptSink>, decisions: Vec<Decision>) -> Self {
        Self {
            inner: sink,
            decisions,
        }
    }

    pub fn deny_only(sink: Box<dyn ReceiptSink>) -> Self {
        Self::new(sink, vec![Decision::Deny])
    }
}

impl ReceiptSink for FilteredSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        if self.decisions.contains(&receipt.decision) {
            self.inner.send(receipt)
        } else {
            Ok(())
        }
    }
}

/// Fans out to multiple sinks. Returns the first error but invokes all sinks.
pub struct MultiSink {
    sinks: Vec<Box<dyn ReceiptSink>>,
}

impl MultiSink {
    pub fn new(sinks: Vec<Box<dyn ReceiptSink>>) -> Self {
        Self { sinks }
    }
}

impl ReceiptSink for MultiSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        let mut first_error: Option<SinkError> = None;
        for sink in &self.sinks {
            if let Err(e) = sink.send(receipt)
                && first_error.is_none()
            {
                first_error = Some(e);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

/// No-op sink. `send()` always succeeds.
pub struct NullSink;

impl ReceiptSink for NullSink {
    fn send(&self, _receipt: &DecisionReceipt) -> Result<(), SinkError> {
        Ok(())
    }
}

type SinkCallback = dyn Fn(&DecisionReceipt) -> Result<(), SinkError> + Send + Sync;

/// Invokes a closure for each receipt.
pub struct CallbackSink {
    callback: Box<SinkCallback>,
}

impl CallbackSink {
    pub fn new(
        callback: impl Fn(&DecisionReceipt) -> Result<(), SinkError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            callback: Box::new(callback),
        }
    }
}

impl ReceiptSink for CallbackSink {
    fn send(&self, receipt: &DecisionReceipt) -> Result<(), SinkError> {
        (self.callback)(receipt)
    }
}
