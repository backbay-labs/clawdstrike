//! Tetragon gRPC client and generated event types.

use tonic::transport::Channel;
use tracing::{debug, info};

use crate::error::{Error, Result};

/// Re-export generated protobuf types.
pub mod proto {
    tonic::include_proto!("tetragon");
}

pub use proto::fine_guidance_sensors_client::FineGuidanceSensorsClient;
pub use proto::{
    EventType, GetEventsRequest, GetEventsResponse, ProcessExec, ProcessExit, ProcessKprobe,
};

/// Wrapper around the Tetragon gRPC export client.
pub struct TetragonClient {
    inner: FineGuidanceSensorsClient<Channel>,
}

impl TetragonClient {
    /// Connect to the Tetragon gRPC export endpoint.
    pub async fn connect(endpoint: &str) -> Result<Self> {
        info!(endpoint, "connecting to Tetragon gRPC");
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| Error::Grpc(format!("invalid endpoint: {e}")))?
            .connect()
            .await
            .map_err(|e| Error::Grpc(format!("failed to connect: {e}")))?;
        debug!("Tetragon gRPC channel established");
        Ok(Self {
            inner: FineGuidanceSensorsClient::new(channel),
        })
    }

    /// Open the `GetEvents` server-streaming RPC.
    ///
    /// Returns a tonic streaming response. The caller is responsible for
    /// iterating the stream and handling individual events.
    pub async fn get_events(
        &mut self,
        allow_list: Vec<EventType>,
        deny_list: Vec<EventType>,
    ) -> Result<tonic::Streaming<GetEventsResponse>> {
        let request = GetEventsRequest {
            allow_list: allow_list.into_iter().map(|e| e.into()).collect(),
            deny_list: deny_list.into_iter().map(|e| e.into()).collect(),
            aggregation_options: None,
            field_filters: vec![],
        };
        let response = self
            .inner
            .get_events(request)
            .await
            .map_err(|e| Error::Grpc(format!("GetEvents RPC failed: {e}")))?;
        Ok(response.into_inner())
    }
}

/// Classify which variant the response carries so callers can pattern-match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TetragonEventKind {
    ProcessExec,
    ProcessExit,
    ProcessKprobe,
    Unknown,
}

impl TetragonEventKind {
    /// Human-readable subject suffix for NATS.
    pub fn subject_suffix(&self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::ProcessExit => "process_exit",
            Self::ProcessKprobe => "process_kprobe",
            Self::Unknown => "unknown",
        }
    }
}

/// Determine the event kind from a `GetEventsResponse`.
pub fn classify_event(resp: &GetEventsResponse) -> TetragonEventKind {
    match &resp.event {
        Some(proto::get_events_response::Event::ProcessExec(_)) => TetragonEventKind::ProcessExec,
        Some(proto::get_events_response::Event::ProcessExit(_)) => TetragonEventKind::ProcessExit,
        Some(proto::get_events_response::Event::ProcessKprobe(_)) => {
            TetragonEventKind::ProcessKprobe
        }
        None => TetragonEventKind::Unknown,
    }
}
