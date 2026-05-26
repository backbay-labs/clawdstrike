//! Internal types backing in-flight gateway sessions.

use serde_json::Value;
use std::time::Instant;
use tokio::sync::{mpsc, oneshot};

pub(super) enum SessionCommand {
    Request {
        method: String,
        params: Option<Value>,
        timeout_ms: u64,
        response_tx: oneshot::Sender<Result<Value, String>>,
    },
    Disconnect,
}

#[derive(Clone)]
pub(super) struct GatewayHandle {
    pub(super) tx: mpsc::Sender<SessionCommand>,
    pub(super) session_id: u64,
}

pub(super) struct PendingResponse {
    pub(super) tx: oneshot::Sender<Result<Value, String>>,
    pub(super) expires_at: Instant,
}
