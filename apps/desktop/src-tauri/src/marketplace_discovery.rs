//! Optional P2P discovery for marketplace feed sources.
//!
//! This is deliberately low-trust: discovery only gossips potential feed URIs (e.g. `ipfs://...`).
//! The desktop marketplace still verifies feed and bundle signatures before showing/installing.

use std::collections::HashSet;
use std::time::Duration;

use libp2p::core::upgrade;
use libp2p::futures::StreamExt;
use libp2p::gossipsub::{self, IdentTopic, MessageAuthenticity, ValidationMode};
use libp2p::identity;
use libp2p::mdns;
use libp2p::noise;
use libp2p::swarm::{NetworkBehaviour, Swarm, SwarmEvent};
use libp2p::tcp;
use libp2p::yamux;
use libp2p::{Multiaddr, PeerId, Transport};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, Runtime};
use tokio::sync::{mpsc, oneshot, RwLock};

pub const MARKETPLACE_DISCOVERY_EVENT: &str = "marketplace_discovery";
pub const DEFAULT_MARKETPLACE_DISCOVERY_TOPIC: &str = "clawdstrike/marketplace/v1/discovery";

const DISCOVERY_PROTOCOL_VERSION: u8 = 2;
const MAX_ANNOUNCEMENT_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketplaceDiscoveryAnnouncement {
    #[serde(default = "default_discovery_version")]
    pub v: u8,
    /// Feed URI (recommended: `ipfs://<CID>`).
    pub feed_uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub feed_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_public_key: Option<String>,
    // --- Spine-aware fields (v2) ---
    /// Spine head hash for anti-entropy (peers compare to local state).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head_hash: Option<String>,
    /// Spine issuer ID of the curator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub spine_issuer: Option<String>,
    /// Checkpoint reference for verifiable freshness bound.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_ref: Option<CheckpointRefDto>,
}

/// Lightweight checkpoint reference for discovery announcements.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointRefDto {
    pub log_id: String,
    pub checkpoint_seq: u64,
    pub envelope_hash: String,
}

fn default_discovery_version() -> u8 {
    DISCOVERY_PROTOCOL_VERSION
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketplaceDiscoveryEvent {
    pub received_at: String,
    pub from_peer_id: String,
    pub announcement: MarketplaceDiscoveryAnnouncement,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketplaceDiscoveryConfig {
    /// TCP port to listen on. If omitted, an ephemeral port is chosen.
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Multiaddrs to dial for discovery outside the local network.
    #[serde(default)]
    pub bootstrap: Vec<String>,
    /// Gossipsub topic to publish/subscribe to.
    #[serde(default)]
    pub topic: Option<String>,
}

impl Default for MarketplaceDiscoveryConfig {
    fn default() -> Self {
        Self {
            listen_port: None,
            bootstrap: Vec::new(),
            topic: None,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MarketplaceDiscoveryStatus {
    pub running: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub listen_addrs: Vec<String>,
    pub topic: String,
    #[serde(default)]
    pub connected_peers: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

impl MarketplaceDiscoveryStatus {
    fn stopped() -> Self {
        Self {
            running: false,
            peer_id: None,
            listen_addrs: Vec::new(),
            topic: DEFAULT_MARKETPLACE_DISCOVERY_TOPIC.to_string(),
            connected_peers: 0,
            last_error: None,
        }
    }
}

pub struct MarketplaceDiscoveryManager {
    inner: RwLock<DiscoveryInner>,
}

struct DiscoveryInner {
    handle: Option<DiscoveryHandle>,
    status: std::sync::Arc<RwLock<MarketplaceDiscoveryStatus>>,
}

struct DiscoveryHandle {
    cmd_tx: mpsc::Sender<DiscoveryCommand>,
    join: tauri::async_runtime::JoinHandle<()>,
}

enum DiscoveryCommand {
    Announce {
        announcement: MarketplaceDiscoveryAnnouncement,
        resp: oneshot::Sender<Result<(), String>>,
    },
    Stop {
        resp: oneshot::Sender<()>,
    },
}

impl MarketplaceDiscoveryManager {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(DiscoveryInner {
                handle: None,
                status: std::sync::Arc::new(RwLock::new(MarketplaceDiscoveryStatus::stopped())),
            }),
        }
    }

    pub async fn start<R: Runtime>(
        &self,
        app: AppHandle<R>,
        config: MarketplaceDiscoveryConfig,
    ) -> Result<MarketplaceDiscoveryStatus, String> {
        let mut inner = self.inner.write().await;
        if let Some(handle) = inner.handle.as_ref() {
            // If the task has exited (e.g. failed to bind/listen), clear the stale handle so
            // callers can restart discovery without needing to explicitly call `stop`.
            if !handle.join.inner().is_finished() {
                return Ok(inner.status().await);
            }
            inner.handle = None;
        }

        let status = inner.status.clone();

        let topic = config
            .topic
            .clone()
            .unwrap_or_else(|| DEFAULT_MARKETPLACE_DISCOVERY_TOPIC.to_string());

        {
            let mut s = status.write().await;
            s.running = true;
            s.peer_id = None;
            s.listen_addrs.clear();
            s.topic = topic.clone();
            s.connected_peers = 0;
            s.last_error = None;
        }

        let (cmd_tx, cmd_rx) = mpsc::channel::<DiscoveryCommand>(32);
        let join = tauri::async_runtime::spawn(run_discovery(app, config, cmd_rx, status.clone()));

        inner.handle = Some(DiscoveryHandle { cmd_tx, join });
        Ok(inner.status().await)
    }

    pub async fn stop(&self) -> Result<(), String> {
        let handle = {
            let mut inner = self.inner.write().await;
            inner.handle.take()
        };

        let Some(handle) = handle else {
            return Ok(());
        };

        let (tx, rx) = oneshot::channel();
        handle
            .cmd_tx
            .send(DiscoveryCommand::Stop { resp: tx })
            .await
            .map_err(|_| "Discovery task not running".to_string())?;
        let _ = rx.await;

        handle
            .join
            .await
            .map_err(|e| format!("Failed to stop discovery task: {e}"))?;

        Ok(())
    }

    pub async fn status(&self) -> MarketplaceDiscoveryStatus {
        let inner = self.inner.read().await;
        inner.status().await
    }

    pub async fn announce(
        &self,
        announcement: MarketplaceDiscoveryAnnouncement,
    ) -> Result<(), String> {
        let cmd_tx = {
            let inner = self.inner.read().await;
            inner
                .handle
                .as_ref()
                .map(|h| h.cmd_tx.clone())
                .ok_or_else(|| "Marketplace discovery is not running".to_string())?
        };

        let (tx, rx) = oneshot::channel();
        cmd_tx
            .send(DiscoveryCommand::Announce {
                announcement,
                resp: tx,
            })
            .await
            .map_err(|_| "Discovery task not running".to_string())?;

        rx.await
            .map_err(|_| "Discovery task dropped response".to_string())?
    }
}

impl Default for MarketplaceDiscoveryManager {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscoveryInner {
    async fn status(&self) -> MarketplaceDiscoveryStatus {
        self.status.read().await.clone()
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "DiscoveryBehaviourEvent")]
struct DiscoveryBehaviour {
    gossipsub: gossipsub::Behaviour,
    mdns: mdns::tokio::Behaviour,
}

#[derive(Debug)]
enum DiscoveryBehaviourEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
}

impl From<gossipsub::Event> for DiscoveryBehaviourEvent {
    fn from(value: gossipsub::Event) -> Self {
        Self::Gossipsub(value)
    }
}

impl From<mdns::Event> for DiscoveryBehaviourEvent {
    fn from(value: mdns::Event) -> Self {
        Self::Mdns(value)
    }
}

async fn run_discovery<R: Runtime>(
    app: AppHandle<R>,
    config: MarketplaceDiscoveryConfig,
    mut cmd_rx: mpsc::Receiver<DiscoveryCommand>,
    status: std::sync::Arc<RwLock<MarketplaceDiscoveryStatus>>,
) {
    let topic_name = config
        .topic
        .clone()
        .unwrap_or_else(|| DEFAULT_MARKETPLACE_DISCOVERY_TOPIC.to_string());
    let topic = IdentTopic::new(topic_name.clone());

    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());

    {
        let mut s = status.write().await;
        s.peer_id = Some(local_peer_id.to_string());
    }

    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1Lazy)
        .authenticate(match noise::Config::new(&local_key) {
            Ok(v) => v,
            Err(e) => {
                set_fatal_error(&status, format!("Failed to configure Noise: {e}")).await;
                return;
            }
        })
        .multiplex(yamux::Config::default())
        .boxed();

    let gossipsub_config = match gossipsub::ConfigBuilder::default()
        .validation_mode(ValidationMode::Strict)
        .heartbeat_interval(Duration::from_secs(1))
        .build()
    {
        Ok(v) => v,
        Err(e) => {
            set_fatal_error(&status, format!("Failed to configure gossipsub: {e}")).await;
            return;
        }
    };

    let mut gossipsub = match gossipsub::Behaviour::new(
        MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    ) {
        Ok(v) => v,
        Err(e) => {
            set_fatal_error(&status, format!("Failed to create gossipsub: {e}")).await;
            return;
        }
    };

    if let Err(e) = gossipsub.subscribe(&topic) {
        set_fatal_error(
            &status,
            format!("Failed to subscribe to discovery topic: {e}"),
        )
        .await;
        return;
    }

    let mdns = match mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id) {
        Ok(v) => v,
        Err(e) => {
            set_fatal_error(&status, format!("Failed to start mDNS: {e}")).await;
            return;
        }
    };

    let behaviour = DiscoveryBehaviour { gossipsub, mdns };

    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor(),
    );

    let port = config.listen_port.unwrap_or(0);
    let listen_addr: Multiaddr = match format!("/ip4/0.0.0.0/tcp/{port}").parse() {
        Ok(v) => v,
        Err(e) => {
            set_fatal_error(&status, format!("Failed to parse listen addr: {e}")).await;
            return;
        }
    };
    if let Err(e) = swarm.listen_on(listen_addr) {
        set_fatal_error(&status, format!("Failed to listen: {e}")).await;
        return;
    }

    for addr in &config.bootstrap {
        match addr.parse::<Multiaddr>() {
            Ok(multiaddr) => {
                if let Err(e) = swarm.dial(multiaddr) {
                    set_error(&status, format!("Failed to dial bootstrap {addr}: {e}")).await;
                }
            }
            Err(e) => {
                set_error(&status, format!("Invalid bootstrap multiaddr {addr}: {e}")).await;
            }
        }
    }

    let mut connected: HashSet<PeerId> = HashSet::new();

    loop {
        tokio::select! {
            swarm_event = swarm.select_next_some() => match swarm_event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    let addr_str = address.to_string();
                    let mut s = status.write().await;
                    if !s.listen_addrs.iter().any(|a| a == &addr_str) {
                        s.listen_addrs.push(addr_str);
                    }
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    connected.insert(peer_id);
                    status.write().await.connected_peers = connected.len();
                }
                SwarmEvent::ConnectionClosed { peer_id, .. } => {
                    connected.remove(&peer_id);
                    status.write().await.connected_peers = connected.len();
                }
                SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Mdns(event)) => match event {
                    mdns::Event::Discovered(list) => {
                        for (peer_id, _addr) in list {
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        }
                    }
                    mdns::Event::Expired(list) => {
                        for (peer_id, _addr) in list {
                            swarm.behaviour_mut().gossipsub.remove_explicit_peer(&peer_id);
                        }
                    }
                },
                SwarmEvent::Behaviour(DiscoveryBehaviourEvent::Gossipsub(event)) => {
                    if let gossipsub::Event::Message { propagation_source, message, .. } = event {
                        handle_gossipsub_message(&app, &status, propagation_source, &message.data).await;
                    }
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                    set_error(&status, format!("Outgoing connection error ({peer_id:?}): {error}")).await;
                }
                SwarmEvent::IncomingConnectionError { error, .. } => {
                    set_error(&status, format!("Incoming connection error: {error}")).await;
                }
                _ => {}
            },
            cmd = cmd_rx.recv() => match cmd {
                Some(DiscoveryCommand::Announce { announcement, resp }) => {
                    let result = publish_announcement(&mut swarm, &topic, announcement).await;
                    let _ = resp.send(result);
                }
                Some(DiscoveryCommand::Stop { resp }) => {
                    {
                        let mut s = status.write().await;
                        s.running = false;
                    }
                    let _ = resp.send(());
                    break;
                }
                None => {
                    break;
                }
            }
        }
    }

    // If we exit without an explicit Stop command (e.g. task dropped or init failed in a later
    // stage), ensure status reflects the stopped state.
    status.write().await.running = false;
}

async fn publish_announcement(
    swarm: &mut Swarm<DiscoveryBehaviour>,
    topic: &IdentTopic,
    announcement: MarketplaceDiscoveryAnnouncement,
) -> Result<(), String> {
    if announcement.v != 1 && announcement.v != 2 {
        return Err("Unsupported announcement version".to_string());
    }

    validate_feed_uri(&announcement.feed_uri)?;

    let bytes = serde_json::to_vec(&announcement)
        .map_err(|e| format!("Failed to encode announcement: {e}"))?;
    if bytes.len() > MAX_ANNOUNCEMENT_BYTES {
        return Err("Announcement too large".to_string());
    }

    swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic.clone(), bytes)
        .map_err(|e| format!("Failed to publish announcement: {e}"))?;

    Ok(())
}

async fn handle_gossipsub_message<R: Runtime>(
    app: &AppHandle<R>,
    status: &std::sync::Arc<RwLock<MarketplaceDiscoveryStatus>>,
    from: PeerId,
    data: &[u8],
) {
    if data.len() > MAX_ANNOUNCEMENT_BYTES {
        return;
    }

    let announcement: MarketplaceDiscoveryAnnouncement = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    if announcement.v != 1 && announcement.v != 2 {
        return;
    }

    if validate_feed_uri(&announcement.feed_uri).is_err() {
        return;
    }

    let payload = MarketplaceDiscoveryEvent {
        received_at: chrono::Utc::now().to_rfc3339(),
        from_peer_id: from.to_string(),
        announcement,
    };

    if let Err(e) = app.emit(MARKETPLACE_DISCOVERY_EVENT, payload) {
        set_error(status, format!("Failed to emit discovery event: {e}")).await;
    }
}

fn validate_feed_uri(feed_uri: &str) -> Result<(), String> {
    let trimmed = feed_uri.trim();
    if trimmed.starts_with("ipfs://") || trimmed.starts_with("https://") {
        return Ok(());
    }

    if trimmed.starts_with("http://") {
        let url = reqwest::Url::parse(trimmed).map_err(|e| format!("Invalid feed_uri: {e}"))?;
        let host = url.host_str().unwrap_or("").to_ascii_lowercase();
        let is_local = matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1");
        if is_local && cfg!(debug_assertions) {
            return Ok(());
        }
    }

    Err("Unsupported feed_uri scheme (expected ipfs:// or https://)".to_string())
}

async fn set_error(status: &std::sync::Arc<RwLock<MarketplaceDiscoveryStatus>>, err: String) {
    let mut s = status.write().await;
    s.last_error = Some(err);
}

async fn set_fatal_error(status: &std::sync::Arc<RwLock<MarketplaceDiscoveryStatus>>, err: String) {
    let mut s = status.write().await;
    s.last_error = Some(err);
    s.running = false;
    s.connected_peers = 0;
    s.listen_addrs.clear();
}

#[cfg(test)]
mod discovery_manager_tests {
    use super::*;
    use std::net::TcpListener;

    #[tokio::test]
    async fn start_can_restart_after_failed_launch() {
        let app = tauri::test::mock_app();
        let handle = app.handle().clone();

        let manager = MarketplaceDiscoveryManager::new();

        // Reserve a port so discovery fails to listen.
        let listener = TcpListener::bind("0.0.0.0:0").expect("bind");
        let port = listener.local_addr().expect("local_addr").port();

        manager
            .start(
                handle.clone(),
                MarketplaceDiscoveryConfig {
                    listen_port: Some(port),
                    bootstrap: Vec::new(),
                    topic: None,
                },
            )
            .await
            .expect("start");

        let first_peer = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let st = manager.status().await;
                if let Some(peer) = st.peer_id.clone() {
                    return peer;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("peer_id should be set");

        // Let the discovery task fail and stop.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let st = manager.status().await;
                if !st.running {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("discovery should stop after failed listen");

        drop(listener);

        manager
            .start(
                handle,
                MarketplaceDiscoveryConfig {
                    listen_port: None,
                    bootstrap: Vec::new(),
                    topic: None,
                },
            )
            .await
            .expect("restart start");

        let second_peer = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let st = manager.status().await;
                if let Some(peer) = st.peer_id.clone() {
                    return peer;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("peer_id should be set after restart");

        assert_ne!(
            first_peer, second_peer,
            "restart should spawn a new discovery task"
        );

        let _ = manager.stop().await;
    }
}
