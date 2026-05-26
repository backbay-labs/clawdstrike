//! macOS system-extension status collector.
//!
//! Polls the bundled endpoint-security and network-extension status helpers,
//! merges their samples into a [`CombinedSystemExtensionStatus`], and feeds
//! refreshes back through [`MacosHostService`].

mod merge;
mod paths;
mod reload;
mod resolve;
mod samples;
mod tool;

#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::time::Duration;

use tauri::{AppHandle, Runtime};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::host::{MacosHostRefreshRequest, MacosHostService, MacosNetworkExtensionReloadRequest};
use super::status::CombinedSystemExtensionStatus;

use self::merge::collect_combined_status;
use self::reload::request_network_extension_reload;
use self::resolve::resolve_status_tool;
use self::tool::{
    ToolInvocation, ENDPOINT_SECURITY_TOOL_ENV, ENDPOINT_SECURITY_TOOL_NAME,
    NETWORK_EXTENSION_TOOL_ENV, NETWORK_EXTENSION_TOOL_NAME,
};

const STATUS_POLL_INTERVAL: Duration = Duration::from_secs(60);

pub fn start_status_collector<R: Runtime + 'static>(
    app: AppHandle<R>,
    macos_host: Arc<MacosHostService>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let endpoint_tool = resolve_status_tool(
        &app,
        ENDPOINT_SECURITY_TOOL_ENV,
        "macos/system-extension/endpoint-security",
        ENDPOINT_SECURITY_TOOL_NAME,
    );
    let network_tool = resolve_status_tool(
        &app,
        NETWORK_EXTENSION_TOOL_ENV,
        "macos/system-extension/network-extension",
        NETWORK_EXTENSION_TOOL_NAME,
    );

    if endpoint_tool.is_none() {
        tracing::warn!(
            "macOS endpoint-security status helper is unavailable; host health will remain unknown until the helper can be executed"
        );
    }
    if network_tool.is_none() {
        tracing::warn!(
            "macOS network-extension status helper is unavailable; host health will remain unknown until the helper can be executed"
        );
    }

    let (refresh_tx, mut refresh_rx) = mpsc::channel::<super::host::MacosHostRefreshRequest>(4);
    let (network_reload_tx, mut network_reload_rx) =
        mpsc::channel::<super::host::MacosNetworkExtensionReloadRequest>(4);
    tokio::spawn(async move {
        macos_host.reset_unknown_state().await;
        macos_host.install_refresh_channel(refresh_tx).await;
        macos_host
            .install_network_extension_reload_channel(network_reload_tx)
            .await;

        let (status_tx, mut status_rx) = mpsc::channel::<(u64, CombinedSystemExtensionStatus)>(1);
        let mut next_poll = Box::pin(tokio::time::sleep(Duration::ZERO));
        let mut status_poll_generation = 0_u64;
        let mut active_status_probe_generation = None;
        let mut active_status_probe: Option<JoinHandle<()>> = None;
        let mut pending_refresh_replies = Vec::<MacosHostRefreshRequest>::new();
        let mut active_reload_requests = Vec::<JoinHandle<()>>::new();

        loop {
            tokio::select! {
                biased;

                _ = shutdown.recv() => break,
                request = network_reload_rx.recv() => {
                    abort_status_probe(
                        &mut active_status_probe,
                        &mut active_status_probe_generation,
                        &mut status_rx,
                    );
                    let Some(request) = request else {
                        break;
                    };
                    active_reload_requests.retain(|handle| !handle.is_finished());
                    active_reload_requests.push(spawn_network_extension_reload(
                        network_tool.clone(),
                        request,
                    ));
                    retain_open_refresh_replies(&mut pending_refresh_replies);
                    if !pending_refresh_replies.is_empty() {
                        status_poll_generation = status_poll_generation.wrapping_add(1);
                        active_status_probe_generation = Some(status_poll_generation);
                        active_status_probe = Some(spawn_status_probe(
                            endpoint_tool.clone(),
                            network_tool.clone(),
                            status_tx.clone(),
                            status_poll_generation,
                        ));
                    }
                    next_poll.as_mut().reset(Instant::now() + STATUS_POLL_INTERVAL);
                }
                request = refresh_rx.recv() => {
                    let Some(reply_tx) = request else {
                        break;
                    };
                    retain_open_refresh_replies(&mut pending_refresh_replies);
                    pending_refresh_replies.push(reply_tx);
                    if active_status_probe_generation.is_none() {
                        status_poll_generation = status_poll_generation.wrapping_add(1);
                        active_status_probe_generation = Some(status_poll_generation);
                        active_status_probe = Some(spawn_status_probe(
                            endpoint_tool.clone(),
                            network_tool.clone(),
                            status_tx.clone(),
                            status_poll_generation,
                        ));
                    }
                }
                Some((generation, combined)) = status_rx.recv() => {
                    if active_status_probe_generation == Some(generation) {
                        let refresh_reply = combined.clone();
                        macos_host.replace_status(combined).await;
                        reply_to_pending_refreshes(&mut pending_refresh_replies, refresh_reply);
                        active_status_probe_generation = None;
                        active_status_probe = None;
                        next_poll.as_mut().reset(Instant::now() + STATUS_POLL_INTERVAL);
                    }
                }
                _ = &mut next_poll, if active_status_probe_generation.is_none() => {
                    status_poll_generation = status_poll_generation.wrapping_add(1);
                    active_status_probe_generation = Some(status_poll_generation);
                    active_status_probe = Some(spawn_status_probe(
                        endpoint_tool.clone(),
                        network_tool.clone(),
                        status_tx.clone(),
                        status_poll_generation,
                    ));
                }
            }
        }
        if let Some(handle) = active_status_probe {
            handle.abort();
        }
        for handle in active_reload_requests {
            handle.abort();
        }
    });
}

fn spawn_status_probe(
    endpoint_tool: Option<ToolInvocation>,
    network_tool: Option<ToolInvocation>,
    status_tx: mpsc::Sender<(u64, CombinedSystemExtensionStatus)>,
    generation: u64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let combined = collect_combined_status(endpoint_tool.as_ref(), network_tool.as_ref()).await;
        let _ = status_tx.send((generation, combined)).await;
    })
}

fn spawn_network_extension_reload(
    network_tool: Option<ToolInvocation>,
    request: MacosNetworkExtensionReloadRequest,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let result = request_network_extension_reload(
            network_tool.as_ref(),
            &request.policy_snapshot_path,
            request.generation,
            request.timeout_duration,
        )
        .await;
        let _ = request.reply_tx.send(result);
    })
}

fn abort_status_probe(
    active_status_probe: &mut Option<JoinHandle<()>>,
    active_status_probe_generation: &mut Option<u64>,
    status_rx: &mut mpsc::Receiver<(u64, CombinedSystemExtensionStatus)>,
) {
    if let Some(handle) = active_status_probe.take() {
        handle.abort();
    }
    *active_status_probe_generation = None;
    while status_rx.try_recv().is_ok() {}
}

fn reply_to_pending_refreshes(
    pending_refresh_replies: &mut Vec<MacosHostRefreshRequest>,
    combined: CombinedSystemExtensionStatus,
) {
    for reply_tx in pending_refresh_replies.drain(..) {
        let _ = reply_tx.send(combined.clone());
    }
}

fn retain_open_refresh_replies(refresh_replies: &mut Vec<MacosHostRefreshRequest>) {
    refresh_replies.retain(|reply_tx| !reply_tx.is_closed());
}
