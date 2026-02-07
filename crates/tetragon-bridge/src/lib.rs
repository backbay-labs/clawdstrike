#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

//! # tetragon-bridge
//!
//! Connects to the Tetragon gRPC export API and publishes runtime security
//! events as signed Spine envelopes to NATS JetStream.
//!
//! ## Architecture
//!
//! ```text
//! Tetragon (gRPC) ─► TetragonClient ─► mapper ─► Spine envelope ─► NATS
//! ```
//!
//! The bridge:
//! 1. Opens a streaming `GetEvents` RPC to Tetragon
//! 2. For each event, maps it to a Spine fact via [`mapper`]
//! 3. Signs the fact into a [`spine::envelope`] using an Ed25519 keypair
//! 4. Publishes to NATS subject `clawdstrike.spine.envelope.tetragon.{event_type}.v1`
//!
//! Filtering is configurable: event types can be included/excluded, and
//! namespace-level allowlists keep noisy clusters quiet.

pub mod error;
pub mod mapper;
pub mod tetragon;

use std::sync::Mutex;
use std::time::Duration;

use hush_core::Keypair;
use tracing::{debug, error, info, warn};

use crate::error::{Error, Result};
use crate::mapper::map_event;
use crate::tetragon::{classify_event, TetragonClient, TetragonEventKind};

/// NATS subject prefix for all Tetragon bridge envelopes.
const NATS_SUBJECT_PREFIX: &str = "clawdstrike.spine.envelope.tetragon";

/// NATS JetStream stream name.
const STREAM_NAME: &str = "CLAWDSTRIKE_TETRAGON";

/// Configuration for the bridge.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Tetragon gRPC endpoint (e.g. `http://localhost:54321`).
    pub tetragon_endpoint: String,
    /// NATS server URL (e.g. `nats://localhost:4222`).
    pub nats_url: String,
    /// Hex-encoded Ed25519 seed for signing envelopes.
    /// If empty, a random keypair is generated.
    pub signing_key_hex: Option<String>,
    /// Only forward events from these namespaces.
    /// If empty, all namespaces are forwarded.
    pub namespace_allowlist: Vec<String>,
    /// Event types to subscribe to (defaults to all three).
    pub event_types: Vec<TetragonEventKind>,
    /// Number of JetStream replicas for the stream.
    pub stream_replicas: usize,
    /// Maximum consecutive handle_event errors before run() returns an error.
    pub max_consecutive_errors: u64,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            tetragon_endpoint: "http://localhost:54321".to_string(),
            nats_url: "nats://localhost:4222".to_string(),
            signing_key_hex: None,
            namespace_allowlist: Vec::new(),
            event_types: vec![
                TetragonEventKind::ProcessExec,
                TetragonEventKind::ProcessExit,
                TetragonEventKind::ProcessKprobe,
            ],
            stream_replicas: 1,
            max_consecutive_errors: 50,
        }
    }
}

/// Combined sequence + hash state protected by a single lock.
struct ChainState {
    seq: u64,
    prev_hash: Option<String>,
}

/// The Tetragon-to-NATS bridge.
///
/// Holds the signing keypair, NATS client, and envelope sequence state.
pub struct Bridge {
    keypair: Keypair,
    nats_client: async_nats::Client,
    js: async_nats::jetstream::Context,
    config: BridgeConfig,
    chain_state: Mutex<ChainState>,
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
        let subjects = vec![format!("{NATS_SUBJECT_PREFIX}.>")];
        spine::nats_transport::ensure_stream(&js, STREAM_NAME, subjects, config.stream_replicas)
            .await?;

        Ok(Self {
            keypair,
            nats_client,
            js,
            config,
            chain_state: Mutex::new(ChainState {
                seq: 1,
                prev_hash: None,
            }),
        })
    }

    /// Run the bridge event loop.
    ///
    /// Connects to Tetragon, subscribes to the event stream, and publishes
    /// signed envelopes until the stream ends or an unrecoverable error occurs.
    pub async fn run(&self) -> Result<()> {
        let mut client = TetragonClient::connect(&self.config.tetragon_endpoint).await?;

        // Map configured event kinds to Tetragon proto EventType for the
        // allow_list filter. We use the proto values directly.
        let allow_list: Vec<tetragon::proto::EventType> = self
            .config
            .event_types
            .iter()
            .map(|k| match k {
                TetragonEventKind::ProcessExec => tetragon::proto::EventType::ProcessExec,
                TetragonEventKind::ProcessExit => tetragon::proto::EventType::ProcessExit,
                TetragonEventKind::ProcessKprobe => tetragon::proto::EventType::ProcessKprobe,
                TetragonEventKind::Unknown => tetragon::proto::EventType::Undef,
            })
            .collect();

        let mut stream = client.get_events(allow_list, vec![]).await?;

        info!("event stream open, processing events");

        let mut consecutive_errors: u64 = 0;
        let mut backoff = Duration::from_millis(100);
        let max_backoff = Duration::from_secs(30);

        loop {
            match stream.message().await {
                Ok(Some(resp)) => {
                    if let Err(e) = self.handle_event(&resp).await {
                        consecutive_errors += 1;
                        warn!(
                            error = %e,
                            consecutive_errors,
                            "failed to handle event"
                        );
                        if consecutive_errors >= self.config.max_consecutive_errors {
                            return Err(Error::Config(format!(
                                "too many consecutive errors ({consecutive_errors}), giving up"
                            )));
                        }
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(max_backoff);
                    } else {
                        consecutive_errors = 0;
                        backoff = Duration::from_millis(100);
                    }
                }
                Ok(None) => {
                    warn!("Tetragon event stream ended");
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

    /// Handle a single Tetragon event: classify, filter, map, sign, publish.
    async fn handle_event(&self, resp: &tetragon::proto::GetEventsResponse) -> Result<()> {
        let kind = classify_event(resp);
        if kind == TetragonEventKind::Unknown {
            debug!("skipping unknown event type");
            return Ok(());
        }

        // Namespace filter: if the allowlist is non-empty, only forward events
        // from processes whose pod is in an allowed namespace.
        if !self.config.namespace_allowlist.is_empty() && !self.event_matches_namespace(resp) {
            debug!("skipping event outside namespace allowlist");
            return Ok(());
        }

        // Map to fact JSON.
        let fact = match map_event(resp) {
            Some(f) => f,
            None => {
                debug!("mapper returned None, skipping");
                return Ok(());
            }
        };

        // Build and sign the Spine envelope under a single lock, then drop the
        // guard before the async NATS publish.
        let (envelope, seq) = {
            let mut state = self.chain_state.lock().unwrap_or_else(|poisoned| {
                tracing::warn!("chain_state mutex was poisoned, recovering");
                poisoned.into_inner()
            });
            let seq = state.seq;
            let prev_hash = state.prev_hash.clone();

            let envelope = spine::build_signed_envelope(
                &self.keypair,
                seq,
                prev_hash,
                fact,
                spine::now_rfc3339(),
            )?;

            // Update chain state atomically.
            state.seq += 1;
            if let Some(hash) = envelope.get("envelope_hash").and_then(|v| v.as_str()) {
                state.prev_hash = Some(hash.to_string());
            }
            (envelope, seq)
        };

        // Publish to NATS.
        let subject = format!("{NATS_SUBJECT_PREFIX}.{}.v1", kind.subject_suffix());

        if subject.is_empty()
            || !subject.is_ascii()
            || subject.contains(' ')
            || subject.contains('\n')
        {
            tracing::error!(subject = %subject, "invalid NATS subject, skipping publish");
            return Err(Error::Config(format!("invalid NATS subject: {subject}")));
        }

        let payload = serde_json::to_vec(&envelope)?;

        self.nats_client
            .publish(subject.clone(), payload.into())
            .await
            .map_err(|e| Error::Nats(format!("publish failed: {e}")))?;

        debug!(
            subject,
            seq,
            event_type = kind.subject_suffix(),
            "published envelope"
        );

        Ok(())
    }

    /// Check whether the event's process pod is in the namespace allowlist.
    fn event_matches_namespace(&self, resp: &tetragon::proto::GetEventsResponse) -> bool {
        let process = match &resp.event {
            Some(tetragon::proto::get_events_response::Event::ProcessExec(e)) => e.process.as_ref(),
            Some(tetragon::proto::get_events_response::Event::ProcessExit(e)) => e.process.as_ref(),
            Some(tetragon::proto::get_events_response::Event::ProcessKprobe(e)) => {
                e.process.as_ref()
            }
            None => return false,
        };

        let Some(process) = process else {
            return false;
        };

        let Some(pod) = &process.pod else {
            // No pod info — cannot match, skip.
            return false;
        };

        let Some(ns) = &pod.namespace else {
            return false;
        };

        self.config
            .namespace_allowlist
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(&ns.value))
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
