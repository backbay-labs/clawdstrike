import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  fetchBrokerCapabilities,
  fetchBrokerCapability,
  fetchFrozenBrokerProviders,
  freezeBrokerProvider,
  replayBrokerCapability,
  revokeAllBrokerCapabilities,
  revokeBrokerCapability,
  type BrokerCapabilityDetailResponse,
  type BrokerCapabilityStatus,
  type BrokerExecutionEvidence,
  type BrokerFrozenProviderStatus,
  type BrokerProvider,
  type BrokerReplayResponse,
  unfreezeBrokerProvider,
} from "../api/client";
import { GlassButton, NoiseGrain, Stamp } from "../components/ui";
import { useSharedSSE } from "../context/SSEContext";
import {
  Banner,
  DetailItem,
  HintBlock,
  MetricCard,
  PanelHeader,
  executionVariant,
  formatDateTime,
  formatRelative,
  replayVariant,
  statusVariant,
  uniqueProviders,
} from "./broker-utils";

const REPLAY_PANEL_STYLE = {
  padding: 12,
  border: "1px solid rgba(27,34,48,0.8)",
  background: "rgba(11,13,16,0.88)",
} as const;

export function BrokerWallet(_props: { windowId?: string }) {
  const { events } = useSharedSSE();
  const latestBrokerEventId = useMemo(
    () => events.find((event) => event.event_type.startsWith("broker_"))?._id ?? 0,
    [events],
  );
  const [capabilities, setCapabilities] = useState<BrokerCapabilityStatus[]>([]);
  const [detail, setDetail] = useState<BrokerCapabilityDetailResponse | null>(null);
  const [frozenProviders, setFrozenProviders] = useState<BrokerFrozenProviderStatus[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const selectedIdRef = useRef(selectedId);
  selectedIdRef.current = selectedId;
  const [freezeReason, setFreezeReason] = useState("operator maintenance");
  const [replay, setReplay] = useState<BrokerReplayResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const loadWallet = useCallback(async () => {
    const [capabilityResponse, frozenResponse] = await Promise.all([
      fetchBrokerCapabilities({ limit: 200 }),
      fetchFrozenBrokerProviders(),
    ]);
    setCapabilities(capabilityResponse.capabilities);
    setFrozenProviders(frozenResponse.frozen_providers);
    setSelectedId((current) => {
      if (
        current &&
        capabilityResponse.capabilities.some((item) => item.capability_id === current)
      ) {
        return current;
      }
      return capabilityResponse.capabilities[0]?.capability_id ?? null;
    });
  }, []);

  const loadDetail = useCallback(async (capabilityId: string) => {
    setDetailLoading(true);
    try {
      setDetail(await fetchBrokerCapability(capabilityId));
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to load broker capability detail");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      await loadWallet();
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to load broker state");
    } finally {
      setLoading(false);
    }
  }, [loadWallet]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    if (!selectedId) {
      setDetail(null);
      setReplay(null);
      return;
    }
    void loadDetail(selectedId);
  }, [loadDetail, selectedId]);

  useEffect(() => {
    if (!latestBrokerEventId) return;
    void loadWallet();
    const currentId = selectedIdRef.current;
    if (currentId) {
      void loadDetail(currentId);
    }
  }, [latestBrokerEventId, loadDetail, loadWallet]);

  const providerSet = useMemo(
    () => uniqueProviders(capabilities, frozenProviders),
    [capabilities, frozenProviders],
  );
  const frozenProviderIds = useMemo(
    () => new Set(frozenProviders.map((provider) => provider.provider)),
    [frozenProviders],
  );
  const selectedCapability =
    (detail?.capability.capability_id === selectedId ? detail?.capability : null) ??
    capabilities.find((item) => item.capability_id === selectedId) ??
    null;
  const executions: BrokerExecutionEvidence[] = detail?.executions ?? [];

  const counts = useMemo(() => {
    let active = 0;
    let frozen = 0;
    let revoked = 0;
    let expired = 0;
    for (const capability of capabilities) {
      if (capability.state === "active") active += 1;
      if (capability.state === "frozen") frozen += 1;
      if (capability.state === "revoked") revoked += 1;
      if (capability.state === "expired") expired += 1;
    }
    return { active, frozen, revoked, expired };
  }, [capabilities]);

  const withAction = useCallback(async (actionId: string, run: () => Promise<void>) => {
    setActionBusy(actionId);
    try {
      await run();
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Broker action failed");
    } finally {
      setActionBusy(null);
    }
  }, []);

  const handleProviderToggle = useCallback(
    async (provider: BrokerProvider) => {
      await withAction(`provider:${provider}`, async () => {
        if (frozenProviderIds.has(provider)) {
          await unfreezeBrokerProvider(provider);
        } else {
          await freezeBrokerProvider(provider, freezeReason.trim() || "operator maintenance");
        }
        await loadWallet();
        if (selectedId) {
          await loadDetail(selectedId);
        }
      });
    },
    [freezeReason, frozenProviderIds, loadDetail, loadWallet, selectedId, withAction],
  );

  const handleRevoke = useCallback(async () => {
    if (!selectedId) return;
    await withAction(`revoke:${selectedId}`, async () => {
      await revokeBrokerCapability(selectedId, "manual revoke from broker wallet");
      await loadWallet();
      await loadDetail(selectedId);
      setReplay(null);
    });
  }, [loadDetail, loadWallet, selectedId, withAction]);

  const handleReplay = useCallback(async () => {
    if (!selectedId) return;
    await withAction(`replay:${selectedId}`, async () => {
      setReplay(await replayBrokerCapability(selectedId));
    });
  }, [selectedId, withAction]);

  const handlePanicRevoke = useCallback(async () => {
    await withAction("panic-revoke", async () => {
      await revokeAllBrokerCapabilities("panic revoke from broker wallet");
      await loadWallet();
      if (selectedId) {
        await loadDetail(selectedId);
      }
      setReplay(null);
    });
  }, [loadDetail, loadWallet, selectedId, withAction]);

  return (
    <div
      className="space-y-4"
      style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="font-display text-2xl" style={{ letterSpacing: "-0.02em" }}>
            Broker Wallet
          </div>
          <div className="font-mono text-xs" style={{ color: "rgba(154,167,181,0.7)" }}>
            Capability inventory, replay, freeze control, and execution timeline
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <GlassButton onClick={() => void refresh()} disabled={loading}>
            Refresh
          </GlassButton>
          <GlassButton onClick={() => void handlePanicRevoke()} disabled={actionBusy !== null}>
            Panic Revoke
          </GlassButton>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        <MetricCard label="Active" value={counts.active} variant="allowed" />
        <MetricCard label="Frozen" value={counts.frozen} variant="warn" />
        <MetricCard label="Revoked" value={counts.revoked} variant="blocked" />
        <MetricCard label="Expired" value={counts.expired} variant="warn" />
      </div>

      {error && <Banner variant="blocked">{error}</Banner>}

      <div className="grid gap-4 xl:grid-cols-[1.1fr_1.4fr]">
        <div className="glass-panel" style={{ minHeight: 520 }}>
          <NoiseGrain />
          <PanelHeader title="Capability Inventory" meta={`${capabilities.length} tracked`} />
          <div style={{ maxHeight: 470, overflow: "auto" }}>
            {loading ? (
              <HintBlock>Loading capabilities...</HintBlock>
            ) : capabilities.length === 0 ? (
              <HintBlock>No broker capabilities recorded yet.</HintBlock>
            ) : (
              capabilities.map((capability) => {
                const selected = capability.capability_id === selectedId;
                return (
                  <button
                    key={capability.capability_id}
                    type="button"
                    className="hover-row"
                    onClick={() => setSelectedId(capability.capability_id)}
                    style={{
                      width: "100%",
                      textAlign: "left",
                      padding: 14,
                      border: "none",
                      borderBottom: "1px solid rgba(27,34,48,0.55)",
                      background: selected ? "rgba(214,177,90,0.08)" : "transparent",
                      cursor: "pointer",
                    }}
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="font-mono text-sm" style={{ color: "var(--text)" }}>
                          {capability.provider}
                        </div>
                        <div
                          className="font-mono text-[11px]"
                          style={{ color: "rgba(154,167,181,0.75)" }}
                        >
                          {capability.capability_id}
                        </div>
                      </div>
                      <Stamp variant={statusVariant(capability.state)}>{capability.state}</Stamp>
                    </div>
                    <div className="mt-2 text-sm" style={{ color: "rgba(154,167,181,0.75)" }}>
                      {capability.url}
                    </div>
                    <div
                      className="mt-2 flex flex-wrap items-center gap-3 font-mono text-[11px]"
                      style={{ color: "rgba(154,167,181,0.65)" }}
                    >
                      <span>{capability.execution_count} executions</span>
                      <span>expires {formatRelative(capability.expires_at)}</span>
                      <span>
                        {capability.last_status_code
                          ? `last ${capability.last_status_code}`
                          : "idle"}
                      </span>
                    </div>
                  </button>
                );
              })
            )}
          </div>
        </div>

        <div className="space-y-4">
          <div className="glass-panel" style={{ padding: 16 }}>
            <NoiseGrain />
            <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
              <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
                Provider Freeze Control
              </div>
              <input
                className="glass-input font-mono rounded-md px-3 py-2 text-xs outline-none"
                value={freezeReason}
                onChange={(event) => setFreezeReason(event.target.value)}
                placeholder="Freeze reason"
                style={{ minWidth: 220, color: "var(--text)" }}
              />
            </div>
            <div className="flex flex-wrap gap-2">
              {providerSet.map((provider) => {
                const frozen = frozenProviderIds.has(provider);
                return (
                  <button
                    key={provider}
                    type="button"
                    className="hover-glass-button font-mono rounded-md"
                    onClick={() => void handleProviderToggle(provider)}
                    disabled={actionBusy !== null}
                    style={{
                      padding: "8px 12px",
                      border: `1px solid ${
                        frozen ? "rgba(210,163,75,0.35)" : "rgba(27,34,48,0.8)"
                      }`,
                      background: frozen ? "rgba(210,163,75,0.08)" : "rgba(11,13,16,0.92)",
                      color: frozen ? "var(--stamp-warn)" : "var(--text)",
                    }}
                  >
                    {provider} {frozen ? "unfreeze" : "freeze"}
                  </button>
                );
              })}
            </div>
            {frozenProviders.length > 0 && (
              <div className="mt-3 space-y-1">
                {frozenProviders.map((provider) => (
                  <div
                    key={provider.provider}
                    className="font-mono text-[11px]"
                    style={{ color: "rgba(154,167,181,0.78)" }}
                  >
                    {provider.provider}: {provider.reason}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="glass-panel" style={{ padding: 16 }}>
            <NoiseGrain />
            <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
                  Selected Capability
                </div>
                {selectedCapability ? (
                  <div className="mt-2 space-y-1">
                    <div className="font-display text-xl">{selectedCapability.provider}</div>
                    <div
                      className="font-mono text-xs"
                      style={{ color: "rgba(154,167,181,0.75)" }}
                    >
                      {selectedCapability.capability_id}
                    </div>
                  </div>
                ) : (
                  <HintBlock>Select a capability from the wallet.</HintBlock>
                )}
              </div>
              {selectedCapability && (
                <div className="flex flex-wrap gap-2">
                  <GlassButton onClick={() => void handleReplay()} disabled={actionBusy !== null}>
                    Replay
                  </GlassButton>
                  <GlassButton onClick={() => void handleRevoke()} disabled={actionBusy !== null}>
                    Revoke
                  </GlassButton>
                </div>
              )}
            </div>

            {selectedCapability && (
              <div className="grid gap-3 md:grid-cols-2">
                <DetailItem label="State">
                  <Stamp variant={statusVariant(selectedCapability.state)}>
                    {selectedCapability.state}
                  </Stamp>
                </DetailItem>
                <DetailItem label="Expires">
                  <span className="text-sm">{formatDateTime(selectedCapability.expires_at)}</span>
                </DetailItem>
                <DetailItem label="Policy Hash">
                  <span className="font-mono text-xs">{selectedCapability.policy_hash}</span>
                </DetailItem>
                <DetailItem label="Secret Ref">
                  <span className="font-mono text-xs">{selectedCapability.secret_ref_id}</span>
                </DetailItem>
                <DetailItem label="Session">
                  <span className="font-mono text-xs">{selectedCapability.session_id ?? "-"}</span>
                </DetailItem>
                <DetailItem label="Endpoint Agent">
                  <span className="font-mono text-xs">
                    {selectedCapability.endpoint_agent_id ?? "-"}
                  </span>
                </DetailItem>
                <DetailItem label="Runtime Agent">
                  <span className="font-mono text-xs">
                    {selectedCapability.runtime_agent_id ?? "-"}
                  </span>
                </DetailItem>
                <DetailItem label="Origin Fingerprint">
                  <span className="font-mono text-xs">
                    {selectedCapability.origin_fingerprint ?? "-"}
                  </span>
                </DetailItem>
                <div style={{ gridColumn: "1 / -1" }}>
                  <DetailItem label="URL">
                    <span className="font-mono text-xs" style={{ color: "rgba(154,167,181,0.85)" }}>
                      {selectedCapability.url}
                    </span>
                  </DetailItem>
                </div>
                <DetailItem label="Reason">
                  <span className="text-sm">{selectedCapability.state_reason ?? "-"}</span>
                </DetailItem>
                <DetailItem label="Last Outcome">
                  <span className="text-sm">{selectedCapability.last_outcome ?? "-"}</span>
                </DetailItem>
              </div>
            )}

            {replay && (
              <div className="mt-4 rounded-lg" style={REPLAY_PANEL_STYLE}>
                <div className="mb-2 flex items-center justify-between">
                  <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
                    Replay Result
                  </div>
                  <Stamp variant={replayVariant(replay)}>
                    {replay.would_allow ? "would allow" : "blocked"}
                  </Stamp>
                </div>
                <div className="text-sm">{replay.reason}</div>
                <div
                  className="mt-2 flex flex-wrap gap-3 font-mono text-[11px]"
                  style={{ color: "rgba(154,167,181,0.75)" }}
                >
                  <span>state {replay.current_state}</span>
                  <span>egress {String(replay.egress_allowed)}</span>
                  <span>policy {String(replay.provider_allowed)}</span>
                  <span>frozen {String(replay.provider_frozen)}</span>
                </div>
                {replay.notes?.length ? (
                  <ul
                    className="mt-3 space-y-1"
                    style={{ margin: 0, paddingLeft: 18, color: "rgba(154,167,181,0.85)" }}
                  >
                    {replay.notes.map((note) => (
                      <li key={note} className="text-sm">
                        {note}
                      </li>
                    ))}
                  </ul>
                ) : null}
              </div>
            )}
          </div>

          <div className="glass-panel" style={{ minHeight: 260 }}>
            <NoiseGrain />
            <PanelHeader
              title="Execution Timeline"
              meta={detailLoading ? "refreshing..." : `${executions.length} events`}
            />
            <div style={{ maxHeight: 320, overflow: "auto" }}>
              {selectedId === null ? (
                <HintBlock>Select a capability to inspect its timeline.</HintBlock>
              ) : executions.length === 0 ? (
                <HintBlock>No execution evidence recorded yet.</HintBlock>
              ) : (
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr>
                      {["Phase", "Time", "Status", "Transfer", "Outcome"].map((label) => (
                        <th
                          key={label}
                          className="font-mono px-4 py-3 text-[10px] uppercase"
                          style={{ letterSpacing: "0.1em", color: "rgba(154,167,181,0.6)" }}
                        >
                          {label}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {executions.map((execution) => (
                      <tr
                        key={`${execution.execution_id}-${execution.phase}-${execution.executed_at}`}
                        className="hover-row"
                      >
                        <td className="px-4 py-3">
                          <Stamp variant={executionVariant(execution.phase, execution.outcome)}>
                            {execution.phase}
                          </Stamp>
                        </td>
                        <td className="font-mono px-4 py-3 text-xs">
                          {formatDateTime(execution.executed_at)}
                        </td>
                        <td className="px-4 py-3 text-sm">{execution.status_code ?? "-"}</td>
                        <td className="px-4 py-3 text-sm">
                          {execution.bytes_sent}/{execution.bytes_received}
                        </td>
                        <td className="px-4 py-3 text-sm">{execution.outcome ?? "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

