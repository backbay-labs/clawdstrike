#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! # hubble-bridge
//!
//! Connects to the Cilium Hubble Relay gRPC API and publishes network flow
//! events as signed Spine envelopes to NATS JetStream.
//!
//! ## Architecture
//!
//! ```text
//! Hubble Relay (gRPC) -> HubbleClient -> mapper -> Spine envelope -> NATS
//! ```
//!
//! The bridge:
//! 1. Opens a streaming `GetFlows` RPC to Hubble Relay
//! 2. For each flow, maps it to a Spine fact via [`mapper`]
//! 3. Signs the fact into a [`spine::envelope`] using an Ed25519 keypair
//! 4. Publishes to NATS subject `clawdstrike.spine.envelope.hubble.flow.v1`
//!
//! Filtering is configurable: verdicts can be included/excluded, and
//! namespace-level allowlists keep noisy clusters quiet.

pub mod error;
pub mod hubble;
pub mod mapper;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use hush_core::Keypair;
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};
use crate::hubble::{classify_verdict, FlowVerdict, HubbleClient};
use crate::mapper::map_flow;

/// NATS subject for all Hubble bridge envelopes.
const NATS_SUBJECT: &str = "clawdstrike.spine.envelope.hubble.flow.v1";

/// NATS JetStream stream name.
const STREAM_NAME: &str = "CLAWDSTRIKE_HUBBLE";

/// Configuration for the bridge.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Hubble Relay gRPC endpoint (e.g. `http://hubble-relay.kube-system.svc.cluster.local:4245`).
    pub hubble_endpoint: String,
    /// NATS server URL (e.g. `nats://localhost:4222`).
    pub nats_url: String,
    /// Hex-encoded Ed25519 seed for signing envelopes.
    /// If empty, a random keypair is generated.
    pub signing_key_hex: Option<String>,
    /// Only forward flows involving these Kubernetes namespaces (comma-separated).
    /// If empty, flows from all namespaces are forwarded.
    pub namespace_allowlist: Vec<String>,
    /// Verdicts to include. If empty, all verdicts are forwarded.
    pub verdict_filter: Vec<FlowVerdict>,
    /// Number of JetStream replicas for the stream.
    pub stream_replicas: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            hubble_endpoint: "http://hubble-relay.kube-system.svc.cluster.local:4245".to_string(),
            nats_url: "nats://localhost:4222".to_string(),
            signing_key_hex: None,
            namespace_allowlist: Vec::new(),
            verdict_filter: Vec::new(),
            stream_replicas: 1,
        }
    }
}

/// The Hubble-to-NATS bridge.
///
/// Holds the signing keypair, NATS client, and envelope sequence state.
pub struct Bridge {
    keypair: Keypair,
    nats_client: async_nats::Client,
    #[allow(dead_code)]
    js: async_nats::jetstream::Context,
    config: BridgeConfig,
    seq: AtomicU64,
    prev_hash: Mutex<Option<String>>,
}

impl Bridge {
    /// Create a new bridge from the given config.
    pub async fn new(config: BridgeConfig) -> Result<Self> {
        let keypair = match &config.signing_key_hex {
            Some(hex) if !hex.is_empty() => Keypair::from_hex(hex)?,
            _ => {
                info!("no signing key provided, generating ephemeral keypair");
                Keypair::generate()
            }
        };

        info!(
            issuer = %spine::issuer_from_keypair(&keypair),
            "bridge identity"
        );

        let nats_client = spine::nats_transport::connect(&config.nats_url).await?;
        let js = spine::nats_transport::jetstream(nats_client.clone());

        // Ensure the JetStream stream exists.
        let subjects = vec![format!("{NATS_SUBJECT}")];
        spine::nats_transport::ensure_stream(
            &js,
            STREAM_NAME,
            subjects,
            config.stream_replicas,
        )
        .await?;

        Ok(Self {
            keypair,
            nats_client,
            js,
            config,
            seq: AtomicU64::new(1),
            prev_hash: Mutex::new(None),
        })
    }

    /// Run the bridge event loop.
    ///
    /// Connects to Hubble Relay, subscribes to the flow stream, and publishes
    /// signed envelopes until the stream ends or an unrecoverable error occurs.
    pub async fn run(&self) -> Result<()> {
        let mut client = HubbleClient::connect(&self.config.hubble_endpoint).await?;

        let mut stream = client.get_flows(vec![], vec![], true).await?;

        info!("flow stream open, processing flows");

        loop {
            match stream.message().await {
                Ok(Some(resp)) => {
                    if let Err(e) = self.handle_flow(&resp).await {
                        error!(error = %e, "failed to handle flow");
                    }
                }
                Ok(None) => {
                    warn!("Hubble flow stream ended");
                    break;
                }
                Err(e) => {
                    error!(error = %e, "gRPC stream error");
                    return Err(Error::Grpc(format!("stream error: {e}")));
                }
            }
        }

        Ok(())
    }

    /// Handle a single Hubble flow: classify, filter, map, sign, publish.
    async fn handle_flow(
        &self,
        resp: &hubble::proto::GetFlowsResponse,
    ) -> Result<()> {
        // Extract flow to check verdict and namespace.
        let flow = match &resp.response_types {
            Some(hubble::proto::get_flows_response::ResponseTypes::Flow(f)) => f,
            None => {
                debug!("skipping response with no flow");
                return Ok(());
            }
        };

        // Verdict filter: if configured, only forward matching verdicts.
        let verdict = classify_verdict(flow);
        if !self.config.verdict_filter.is_empty()
            && !self.config.verdict_filter.contains(&verdict)
        {
            debug!(verdict = verdict.subject_suffix(), "skipping filtered verdict");
            return Ok(());
        }

        // Namespace filter: if the allowlist is non-empty, only forward flows
        // involving an allowed namespace.
        if !self.config.namespace_allowlist.is_empty()
            && !self.flow_matches_namespace(flow)
        {
            debug!("skipping flow outside namespace allowlist");
            return Ok(());
        }

        // Map to fact JSON.
        let fact = match map_flow(resp) {
            Some(f) => f,
            None => {
                debug!("mapper returned None, skipping");
                return Ok(());
            }
        };

        // Build and sign the Spine envelope.
        let seq = self.seq.fetch_add(1, Ordering::SeqCst);
        let prev_hash = {
            let guard = self.prev_hash.lock().map_err(|e| {
                Error::Config(format!("prev_hash lock poisoned: {e}"))
            })?;
            guard.clone()
        };

        let envelope = spine::build_signed_envelope(
            &self.keypair,
            seq,
            prev_hash,
            fact,
            spine::now_rfc3339(),
        )?;

        // Update prev_hash for chain integrity.
        if let Some(hash) = envelope.get("envelope_hash").and_then(|v| v.as_str()) {
            let mut guard = self.prev_hash.lock().map_err(|e| {
                Error::Config(format!("prev_hash lock poisoned: {e}"))
            })?;
            *guard = Some(hash.to_string());
        }

        // Publish to NATS.
        let payload = serde_json::to_vec(&envelope)?;

        self.nats_client
            .publish(NATS_SUBJECT.to_string(), payload.into())
            .await
            .map_err(|e| Error::Nats(format!("publish failed: {e}")))?;

        debug!(
            subject = NATS_SUBJECT,
            seq,
            verdict = verdict.subject_suffix(),
            "published envelope"
        );

        Ok(())
    }

    /// Check whether a flow's source or destination is in the namespace allowlist.
    fn flow_matches_namespace(&self, flow: &hubble::proto::Flow) -> bool {
        let check_ep = |ep: Option<&hubble::proto::Endpoint>| -> bool {
            let Some(ep) = ep else {
                return false;
            };
            self.config
                .namespace_allowlist
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&ep.namespace))
        };

        check_ep(flow.source.as_ref()) || check_ep(flow.destination.as_ref())
    }

    /// Get the NATS JetStream context (for testing or advanced usage).
    pub fn jetstream(&self) -> &async_nats::jetstream::Context {
        &self.js
    }

    /// Get the keypair issuer string.
    pub fn issuer(&self) -> String {
        spine::issuer_from_keypair(&self.keypair)
    }
}
