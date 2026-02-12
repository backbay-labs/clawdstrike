//! Hubble gRPC client and generated flow types.

use tonic::transport::Channel;
use tracing::{debug, info};

use crate::error::{Error, Result};

/// Re-export generated protobuf types.
pub mod proto {
    tonic::include_proto!("flow");
}

pub use proto::observer_client::ObserverClient;
pub use proto::{Flow, FlowFilter, GetFlowsRequest, GetFlowsResponse, Verdict};

/// Wrapper around the Hubble Relay gRPC Observer client.
pub struct HubbleClient {
    inner: ObserverClient<Channel>,
}

impl HubbleClient {
    /// Connect to the Hubble Relay gRPC endpoint.
    pub async fn connect(endpoint: &str) -> Result<Self> {
        info!(endpoint, "connecting to Hubble Relay gRPC");
        let channel = Channel::from_shared(endpoint.to_string())
            .map_err(|e| Error::Grpc(format!("invalid endpoint: {e}")))?
            .connect()
            .await
            .map_err(|e| Error::Grpc(format!("failed to connect: {e}")))?;
        debug!("Hubble Relay gRPC channel established");
        Ok(Self {
            inner: ObserverClient::new(channel),
        })
    }

    /// Open the `GetFlows` server-streaming RPC.
    ///
    /// Returns a tonic streaming response. The caller is responsible for
    /// iterating the stream and handling individual flows.
    pub async fn get_flows(
        &mut self,
        whitelist: Vec<FlowFilter>,
        blacklist: Vec<FlowFilter>,
        follow: bool,
    ) -> Result<tonic::Streaming<GetFlowsResponse>> {
        let request = GetFlowsRequest {
            number: 0, // 0 = no limit when following
            follow,
            whitelist,
            blacklist,
            since: None,
            until: None,
        };
        let response = self
            .inner
            .get_flows(request)
            .await
            .map_err(|e| Error::Grpc(format!("GetFlows RPC failed: {e}")))?;
        Ok(response.into_inner())
    }
}

/// Classify the verdict of a flow for filtering and NATS subject routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowVerdict {
    Forwarded,
    Dropped,
    Error,
    Audit,
    Redirected,
    Unknown,
}

impl FlowVerdict {
    /// NATS subject suffix for this verdict.
    pub fn subject_suffix(&self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Dropped => "dropped",
            Self::Error => "error",
            Self::Audit => "audit",
            Self::Redirected => "redirected",
            Self::Unknown => "unknown",
        }
    }
}

/// Determine the flow verdict from a Hubble flow.
pub fn classify_verdict(flow: &Flow) -> FlowVerdict {
    match Verdict::try_from(flow.verdict) {
        Ok(Verdict::Forwarded) => FlowVerdict::Forwarded,
        Ok(Verdict::Dropped) => FlowVerdict::Dropped,
        Ok(Verdict::Error) => FlowVerdict::Error,
        Ok(Verdict::Audit) => FlowVerdict::Audit,
        Ok(Verdict::Redirected) => FlowVerdict::Redirected,
        _ => FlowVerdict::Unknown,
    }
}
