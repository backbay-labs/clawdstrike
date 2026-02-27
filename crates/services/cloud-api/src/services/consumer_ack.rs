//! Shared JetStream ack behavior for pull consumers.

/// Classifies whether a processing failure should be retried or terminated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessingFailureKind {
    Retryable,
    Permanent,
}

/// Structured processing error used by pull consumers.
#[derive(Debug, Clone)]
pub struct ProcessingError {
    kind: ProcessingFailureKind,
    message: String,
}

impl ProcessingError {
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            kind: ProcessingFailureKind::Retryable,
            message: message.into(),
        }
    }

    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            kind: ProcessingFailureKind::Permanent,
            message: message.into(),
        }
    }

    pub fn kind(&self) -> ProcessingFailureKind {
        self.kind
    }
}

impl std::fmt::Display for ProcessingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProcessingError {}

/// Select `ACK` for success, `NAK` for retryable failures, and `TERM` for
/// permanently malformed/unprocessable messages.
pub fn ack_kind_for_processing_result(
    result: &Result<(), ProcessingError>,
) -> async_nats::jetstream::AckKind {
    match result {
        Ok(()) => async_nats::jetstream::AckKind::Ack,
        Err(err) => match err.kind() {
            ProcessingFailureKind::Retryable => async_nats::jetstream::AckKind::Nak(None),
            ProcessingFailureKind::Permanent => async_nats::jetstream::AckKind::Term,
        },
    }
}

/// Log processing failures and acknowledge with the appropriate ack kind.
pub async fn acknowledge_after_processing(
    msg: &async_nats::jetstream::Message,
    processing_result: Result<(), ProcessingError>,
    message_kind: &str,
) {
    if let Err(err) = &processing_result {
        let ack_action = match err.kind() {
            ProcessingFailureKind::Retryable => "redelivery",
            ProcessingFailureKind::Permanent => "terminal ack",
        };
        tracing::warn!(
            error = %err,
            subject = %msg.subject,
            message_kind = message_kind,
            ack_action = ack_action,
            "Message processing failed"
        );
    }

    let ack_kind = ack_kind_for_processing_result(&processing_result);
    if let Err(err) = msg.ack_with(ack_kind).await {
        tracing::warn!(
            error = %err,
            subject = %msg.subject,
            message_kind = message_kind,
            "Failed to acknowledge JetStream message"
        );
    }
}
