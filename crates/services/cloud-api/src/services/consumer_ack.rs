//! Shared JetStream ack behavior for pull consumers.

/// Select `ACK` for success and `NAK` for processing failure.
pub fn ack_kind_for_processing_result<E>(result: &Result<(), E>) -> async_nats::jetstream::AckKind {
    if result.is_ok() {
        async_nats::jetstream::AckKind::Ack
    } else {
        async_nats::jetstream::AckKind::Nak(None)
    }
}

/// Log processing failures and acknowledge with the appropriate ack kind.
pub async fn acknowledge_after_processing<E: std::fmt::Display>(
    msg: &async_nats::jetstream::Message,
    processing_result: Result<(), E>,
    message_kind: &str,
) {
    if let Err(err) = &processing_result {
        tracing::warn!(
            error = %err,
            subject = %msg.subject,
            message_kind = message_kind,
            "Message processing failed; requesting JetStream redelivery"
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
