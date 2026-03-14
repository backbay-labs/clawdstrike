import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  approveBrokerPreview,
  exportBrokerCompletionBundle,
  fetchBrokerCapabilities,
  fetchBrokerCapability,
  fetchBrokerPreview,
  fetchBrokerPreviews,
  fetchFrozenBrokerProviders,
  replayBrokerCapability,
  type BrokerApprovalState,
  type BrokerCapabilityDetailResponse,
  type BrokerCapabilityStatus,
  type BrokerCompletionBundleResponse,
  type BrokerDelegationLineage,
  type BrokerExecutionEvidence,
  type BrokerFrozenProviderStatus,
  type BrokerIntentPreview,
  type BrokerIntentRiskLevel,
  type BrokerMintedIdentity,
  type BrokerReplayResponse,
} from "../api/client";
import { GlassButton, NoiseGrain, Stamp } from "../components/ui";
import { useSharedSSE } from "../context/SSEContext";
import {
  Banner,
  DetailItem,
  HintBlock,
  MetricCard,
  PanelHeader,
  Stack,
  Tag,
  executionVariant,
  formatCost,
  formatDateTime,
  formatRelative,
  replayVariant,
  shortValue,
  statusVariant,
  uniqueProviders,
} from "./broker-utils";

function sortNewest<T>(items: T[], select: (item: T) => string | undefined): T[] {
  return [...items].sort((left, right) => {
    const l = select(left);
    const r = select(right);
    return (r ? new Date(r).getTime() : 0) - (l ? new Date(l).getTime() : 0);
  });
}

function approvalVariant(state: BrokerApprovalState): "allowed" | "blocked" | "warn" {
  if (state === "approved" || state === "not_required") return "allowed";
  if (state === "pending") return "warn";
  return "blocked";
}

function riskVariant(level: BrokerIntentRiskLevel): "allowed" | "blocked" | "warn" {
  if (level === "low") return "allowed";
  if (level === "medium") return "warn";
  return "blocked";
}

function downloadBundle(capabilityId: string, payload: BrokerCompletionBundleResponse): void {
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `broker-completion-${capabilityId}.json`;
  document.body.append(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export function BrokerMissionControl(_props: { windowId?: string }) {

  const { events } = useSharedSSE();
  const latestSelection = useRef<{ capabilityId: string | null; previewId: string | null }>({
    capabilityId: null,
    previewId: null,
  });
  const latestBrokerEventId = useMemo(
    () => events.find((event) => event.event_type.startsWith("broker_"))?._id ?? 0,
    [events],
  );
  const [capabilities, setCapabilities] = useState<BrokerCapabilityStatus[]>([]);
  const [detail, setDetail] = useState<BrokerCapabilityDetailResponse | null>(null);
  const [previews, setPreviews] = useState<BrokerIntentPreview[]>([]);
  const [previewDetail, setPreviewDetail] = useState<BrokerIntentPreview | null>(null);
  const [frozenProviders, setFrozenProviders] = useState<BrokerFrozenProviderStatus[]>([]);
  const [selectedCapabilityId, setSelectedCapabilityId] = useState<string | null>(null);
  const [selectedPreviewId, setSelectedPreviewId] = useState<string | null>(null);
  const [replay, setReplay] = useState<BrokerReplayResponse | null>(null);
  const [bundle, setBundle] = useState<BrokerCompletionBundleResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const loadingRef = useRef(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [previewLoading, setPreviewLoading] = useState(false);
  const [actionBusy, setActionBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusMessage, setStatusMessage] = useState<string | null>(null);
  useEffect(() => {
    latestSelection.current = {
      capabilityId: selectedCapabilityId,
      previewId: selectedPreviewId,
    };
  }, [selectedCapabilityId, selectedPreviewId]);

  const loadMission = useCallback(async () => {
    const selection = latestSelection.current;
    const [capabilityResponse, previewResponse, frozenResponse] = await Promise.all([
      fetchBrokerCapabilities({ limit: 200 }),
      fetchBrokerPreviews({ limit: 200 }),
      fetchFrozenBrokerProviders(),
    ]);
    const nextCapabilities = sortNewest(capabilityResponse.capabilities, (item) => item.issued_at);
    const nextPreviews = sortNewest(previewResponse.previews, (item) => item.created_at).sort(
      (left, right) => {
        const leftRank = left.approval_state === "pending" ? 0 : 1;
        const rightRank = right.approval_state === "pending" ? 0 : 1;
        return leftRank - rightRank;
      },
    );
    setCapabilities(nextCapabilities);
    setPreviews(nextPreviews);
    setFrozenProviders(frozenResponse.frozen_providers);
    const nextSelectedCapabilityId =
      selection.capabilityId &&
      nextCapabilities.some((capability) => capability.capability_id === selection.capabilityId)
        ? selection.capabilityId
        : nextCapabilities[0]?.capability_id ?? null;
    const pendingPreview = nextPreviews.find(
      (preview) => preview.approval_required && preview.approval_state === "pending",
    );
    const attachedPreview = nextCapabilities.find((capability) => capability.intent_preview)
      ?.intent_preview?.preview_id;
    const nextSelectedPreviewId =
      selection.previewId && nextPreviews.some((preview) => preview.preview_id === selection.previewId)
        ? selection.previewId
        : pendingPreview?.preview_id ?? attachedPreview ?? nextPreviews[0]?.preview_id ?? null;
    setSelectedCapabilityId(nextSelectedCapabilityId);
    setSelectedPreviewId(nextSelectedPreviewId);
    return {
      capabilityId: nextSelectedCapabilityId,
      previewId: nextSelectedPreviewId,
    };
  }, []);

  const loadDetail = useCallback(async (capabilityId: string) => {
    setDetailLoading(true);
    try {
      const response = await fetchBrokerCapability(capabilityId);
      setDetail(response);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to load broker mission detail");
    } finally {
      setDetailLoading(false);
    }
  }, []);

  const loadPreview = useCallback(async (previewId: string) => {
    setPreviewLoading(true);
    try {
      const response = await fetchBrokerPreview(previewId);
      setPreviewDetail(response.preview);
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to load broker preview");
    } finally {
      setPreviewLoading(false);
    }
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    loadingRef.current = true;
    try {
      const prev = latestSelection.current;
      const selection = await loadMission();
      // Only fetch detail/preview explicitly if the selection didn't change,
      // because the useEffect hooks will handle it when the IDs change.
      if (selection.capabilityId && selection.capabilityId === prev.capabilityId) {
        await loadDetail(selection.capabilityId);
      }
      if (selection.previewId && selection.previewId === prev.previewId) {
        await loadPreview(selection.previewId);
      }
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to load broker mission state");
    } finally {
      setLoading(false);
      loadingRef.current = false;
    }
  }, [loadDetail, loadMission, loadPreview]);

  useEffect(() => {
    let cancelled = false;
    const run = async () => {
      setLoading(true);
      try {
        await loadMission();
        if (!cancelled) {
          setError(null);
        }
      } catch (cause) {
        if (!cancelled) {
          setError(
            cause instanceof Error ? cause.message : "Failed to load broker mission state",
          );
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
          loadingRef.current = false;
        }
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [loadMission]);

  useEffect(() => {
    if (!selectedCapabilityId) {
      setDetail(null);
      setReplay(null);
      setBundle(null);
      return;
    }
    void loadDetail(selectedCapabilityId);
  }, [loadDetail, selectedCapabilityId]);

  useEffect(() => {
    if (!selectedPreviewId) {
      setPreviewDetail(null);
      return;
    }
    void loadPreview(selectedPreviewId);
  }, [loadPreview, selectedPreviewId]);

  useEffect(() => {
    const attachedPreviewId = detail?.capability.intent_preview?.preview_id;
    if (!attachedPreviewId) return;
    setSelectedPreviewId((current) => (current === attachedPreviewId ? current : attachedPreviewId));
  }, [detail?.capability.intent_preview?.preview_id]);

  useEffect(() => {
    if (!latestBrokerEventId || loadingRef.current) return;
    void refresh();
  }, [latestBrokerEventId, refresh]);

  const selectedCapability =
    (detail?.capability.capability_id === selectedCapabilityId ? detail.capability : null) ??
    capabilities.find((capability) => capability.capability_id === selectedCapabilityId) ??
    null;
  const selectedPreview =
    (previewDetail?.preview_id === selectedPreviewId ? previewDetail : null) ??
    previews.find((preview) => preview.preview_id === selectedPreviewId) ??
    selectedCapability?.intent_preview ??
    null;
  const executions = useMemo(
    () => sortNewest(detail?.executions ?? [], (execution) => execution.executed_at),
    [detail?.executions],
  );
  const missionIdentity =
    selectedCapability?.minted_identity ??
    executions.find((execution) => execution.minted_identity)?.minted_identity ??
    null;
  const missionLineage =
    selectedCapability?.lineage ??
    executions.find((execution) => execution.lineage)?.lineage ??
    null;
  const pendingPreviews = useMemo(
    () =>
      previews.filter(
        (preview) => preview.approval_required && preview.approval_state === "pending",
      ),
    [previews],
  );
  const providerSet = useMemo(
    () => uniqueProviders(capabilities, frozenProviders, previews),
    [capabilities, frozenProviders, previews],
  );
  const counts = useMemo(() => {
    return {
      pendingApprovals: pendingPreviews.length,
      activeCapabilities: capabilities.filter((capability) => capability.state === "active").length,
      frozenProviders: frozenProviders.length,
      delegatedChains: capabilities.filter((capability) => capability.lineage != null).length,
      suspiciousArtifacts: capabilities.filter((capability) => capability.suspicion_reason).length,
      mintedIdentities: capabilities.filter((capability) => capability.minted_identity != null).length,
    };
  }, [capabilities, frozenProviders.length, pendingPreviews.length]);

  const withAction = useCallback(async (actionId: string, run: () => Promise<void>) => {
    setActionBusy(actionId);
    try {
      await run();
      setError(null);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Broker mission action failed");
    } finally {
      setActionBusy(null);
    }
  }, []);

  const handleSelectCapability = useCallback((capabilityId: string) => {
    setSelectedCapabilityId(capabilityId);
    setReplay(null);
    setBundle(null);
  }, []);

  const handleSelectPreview = useCallback((previewId: string) => {
    setSelectedPreviewId(previewId);
  }, []);

  const handleApprovePreview = useCallback(
    async (previewId: string) => {
      await withAction(`approve:${previewId}`, async () => {
        const updated = await approveBrokerPreview(previewId, "operator:mission-control");
        setPreviews((current) =>
          sortNewest(
            current.map((preview) => (preview.preview_id === previewId ? updated : preview)),
            (preview) => preview.created_at,
          ).sort((a, b) =>
            (a.approval_state === "pending" ? 0 : 1) - (b.approval_state === "pending" ? 0 : 1),
          ),
        );
        setPreviewDetail(updated);
        setStatusMessage(`Preview ${previewId} approved.`);
        const prev = latestSelection.current;
        const selection = await loadMission();
        if (selection.capabilityId && selection.capabilityId === prev.capabilityId) {
          await loadDetail(selection.capabilityId);
        }
      });
    },
    [loadDetail, loadMission, withAction],
  );

  const handleReplay = useCallback(async () => {
    if (!selectedCapabilityId) return;
    await withAction(`replay:${selectedCapabilityId}`, async () => {
      const result = await replayBrokerCapability(selectedCapabilityId);
      setReplay(result);
      setStatusMessage(`Replay completed for ${selectedCapabilityId}.`);
    });
  }, [selectedCapabilityId, withAction]);

  const handleExportBundle = useCallback(async () => {
    if (!selectedCapabilityId) return;
    await withAction(`bundle:${selectedCapabilityId}`, async () => {
      const response = await exportBrokerCompletionBundle(selectedCapabilityId);
      setBundle(response);
      downloadBundle(selectedCapabilityId, response);
      setStatusMessage(`Completion bundle exported for ${selectedCapabilityId}.`);
    });
  }, [selectedCapabilityId, withAction]);

  const handleCopyEnvelope = useCallback(async () => {
    if (!bundle) return;
    if (!navigator.clipboard?.writeText) {
      setError("Clipboard API is not available in this browser context.");
      return;
    }
    try {
      await navigator.clipboard.writeText(bundle.envelope);
      setStatusMessage("Signed completion envelope copied to clipboard.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Failed to copy completion envelope");
    }
  }, [bundle]);

  return (
    <div
      className="space-y-4"
      style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}
    >
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="font-display text-2xl" style={{ letterSpacing: "-0.02em" }}>
            Broker Mission Control
          </div>
          <div className="font-mono text-xs" style={{ color: "rgba(154,167,181,0.72)" }}>
            Approval queue, lineage visibility, replay diffs, and signed completion bundles
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <GlassButton onClick={() => void refresh()} disabled={loading || actionBusy !== null}>
            Refresh
          </GlassButton>
          <GlassButton
            onClick={() => void handleReplay()}
            disabled={!selectedCapability || actionBusy !== null}
          >
            Replay Diff
          </GlassButton>
          <GlassButton
            onClick={() => void handleExportBundle()}
            disabled={!selectedCapability || actionBusy !== null}
          >
            Export Bundle
          </GlassButton>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard label="Pending Approvals" value={counts.pendingApprovals} variant="warn" />
        <MetricCard label="Active Capabilities" value={counts.activeCapabilities} variant="allowed" />
        <MetricCard label="Frozen Providers" value={counts.frozenProviders} variant="blocked" />
        <MetricCard label="Delegation Chains" value={counts.delegatedChains} variant="warn" />
        <MetricCard label="Minted Identities" value={counts.mintedIdentities} variant="allowed" />
        <MetricCard label="Suspicion Flags" value={counts.suspiciousArtifacts} variant="blocked" />
      </div>

      {error && (
        <Banner variant="blocked">{error}</Banner>
      )}
      {statusMessage && !error && <Banner variant="allowed">{statusMessage}</Banner>}

      <div className="grid gap-4 xl:grid-cols-[0.92fr_1.48fr]">
        <div className="space-y-4">
          <div className="glass-panel" style={{ minHeight: 320 }}>
            <NoiseGrain />
            <PanelHeader
              title="Intent Preview Queue"
              meta={`${pendingPreviews.length} pending / ${previews.length} total`}
            />
            <div style={{ maxHeight: 380, overflow: "auto", padding: 12 }}>
              {loading ? (
                <HintBlock>Loading broker previews...</HintBlock>
              ) : previews.length === 0 ? (
                <HintBlock>No broker previews have been minted yet.</HintBlock>
              ) : (
                <div className="space-y-3">
                  {previews.map((preview) => {
                    const selected = preview.preview_id === selectedPreviewId;
                    const actionable =
                      preview.approval_required && preview.approval_state === "pending";
                    const resources = preview.resources ?? [];
                    const dataClasses = preview.data_classes ?? [];
                    return (
                      <div
                        key={preview.preview_id}
                        className="rounded-xl"
                        onClick={() => handleSelectPreview(preview.preview_id)}
                        style={{
                          padding: 14,
                          border: selected
                            ? "1px solid rgba(214,177,90,0.35)"
                            : "1px solid rgba(27,34,48,0.8)",
                          background: selected ? "rgba(214,177,90,0.06)" : "rgba(8,10,14,0.9)",
                          cursor: "pointer",
                        }}
                      >
                        <div className="flex flex-wrap items-start justify-between gap-2">
                          <div>
                            <div className="font-mono text-sm">{preview.operation}</div>
                            <div
                              className="mt-1 font-mono text-[11px]"
                              style={{ color: "rgba(154,167,181,0.72)" }}
                            >
                              {preview.preview_id}
                            </div>
                          </div>
                          <div className="flex flex-wrap gap-2">
                            <Stamp variant={riskVariant(preview.risk_level)}>
                              {preview.risk_level}
                            </Stamp>
                            <Stamp variant={approvalVariant(preview.approval_state)}>
                              {preview.approval_state.replace("_", " ")}
                            </Stamp>
                          </div>
                        </div>
                        <div className="mt-2 text-sm" style={{ color: "rgba(230,236,244,0.92)" }}>
                          {preview.summary}
                        </div>
                        <div
                          className="mt-3 flex flex-wrap gap-2 font-mono text-[11px]"
                          style={{ color: "rgba(154,167,181,0.72)" }}
                        >
                          <Tag>{preview.provider}</Tag>
                          <Tag>{preview.egress_host}</Tag>
                          <Tag>{formatCost(preview.estimated_cost_usd_micros)}</Tag>
                          <Tag>{formatRelative(preview.created_at)}</Tag>
                        </div>
                        {(resources.length > 0 || dataClasses.length > 0) && (
                          <div className="mt-3 grid gap-2 md:grid-cols-2">
                            <Stack label="Resources">
                              {resources.length === 0 ? (
                                <span>-</span>
                              ) : (
                                resources.map((resource) => (
                                  <Tag key={`${resource.kind}:${resource.value}`}>
                                    {resource.kind}:{resource.value}
                                  </Tag>
                                ))
                              )}
                            </Stack>
                            <Stack label="Data Classes">
                              {dataClasses.length === 0 ? (
                                <span>-</span>
                              ) : (
                                dataClasses.map((dataClass) => (
                                  <Tag key={dataClass}>{dataClass}</Tag>
                                ))
                              )}
                            </Stack>
                          </div>
                        )}
                        <div className="mt-3 flex flex-wrap items-center justify-between gap-2">
                          <div
                            className="font-mono text-[11px]"
                            style={{ color: "rgba(154,167,181,0.72)" }}
                          >
                            {preview.approver
                              ? `approved by ${preview.approver} ${formatRelative(preview.approved_at)}`
                              : preview.approval_required
                                ? "awaiting operator approval"
                                : "approval not required"}
                          </div>
                          {actionable && (
                            <span onClick={(e) => e.stopPropagation()}>
                              <GlassButton
                                onClick={() => void handleApprovePreview(preview.preview_id)}
                                disabled={actionBusy !== null}
                              >
                                Approve
                              </GlassButton>
                            </span>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          <div className="glass-panel" style={{ minHeight: 380 }}>
            <NoiseGrain />
            <PanelHeader
              title="Capability Wallet"
              meta={`${capabilities.length} live / ${providerSet.length} providers`}
            />
            <div style={{ maxHeight: 460, overflow: "auto" }}>
              {loading ? (
                <HintBlock>Loading broker capabilities...</HintBlock>
              ) : capabilities.length === 0 ? (
                <HintBlock>No broker capabilities are currently tracked.</HintBlock>
              ) : (
                capabilities.map((capability) => {
                  const selected = capability.capability_id === selectedCapabilityId;
                  return (
                    <button
                      key={capability.capability_id}
                      type="button"
                      className="hover-row"
                      onClick={() => handleSelectCapability(capability.capability_id)}
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
                          <div className="font-mono text-sm">{capability.provider}</div>
                          <div
                            className="font-mono text-[11px]"
                            style={{ color: "rgba(154,167,181,0.72)" }}
                          >
                            {capability.capability_id}
                          </div>
                        </div>
                        <Stamp variant={statusVariant(capability.state)}>{capability.state}</Stamp>
                      </div>
                      <div className="mt-2 text-sm" style={{ color: "rgba(154,167,181,0.76)" }}>
                        {capability.url}
                      </div>
                      <div
                        className="mt-2 flex flex-wrap gap-2 font-mono text-[11px]"
                        style={{ color: "rgba(154,167,181,0.7)" }}
                      >
                        <Tag>{capability.execution_count} executions</Tag>
                        <Tag>expires {formatRelative(capability.expires_at)}</Tag>
                        {capability.intent_preview && (
                          <Tag>{capability.intent_preview.approval_state.replace("_", " ")}</Tag>
                        )}
                        {capability.minted_identity && <Tag>{capability.minted_identity.kind}</Tag>}
                        {capability.lineage && <Tag>depth {capability.lineage.depth}</Tag>}
                      </div>
                    </button>
                  );
                })
              )}
            </div>
          </div>
        </div>

        <div className="space-y-4">
          <div className="glass-panel" style={{ padding: 16 }}>
            <NoiseGrain />
            <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
              <div>
                <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
                  Mission Overview
                </div>
                {selectedCapability ? (
                  <div className="mt-2 space-y-1">
                    <div className="font-display text-2xl">{selectedCapability.provider}</div>
                    <div
                      className="font-mono text-xs"
                      style={{ color: "rgba(154,167,181,0.72)" }}
                    >
                      {selectedCapability.capability_id}
                    </div>
                  </div>
                ) : (
                  <HintBlock>Select a capability to inspect mission metadata.</HintBlock>
                )}
              </div>
              {selectedCapability && (
                <div className="flex flex-wrap gap-2">
                  <GlassButton onClick={() => void handleReplay()} disabled={actionBusy !== null}>
                    Replay
                  </GlassButton>
                  <GlassButton
                    onClick={() => void handleExportBundle()}
                    disabled={actionBusy !== null}
                  >
                    Export Bundle
                  </GlassButton>
                </div>
              )}
            </div>

            {selectedCapability && (
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                <DetailItem label="State">
                  <Stamp variant={statusVariant(selectedCapability.state)}>
                    {selectedCapability.state}
                  </Stamp>
                </DetailItem>
                <DetailItem label="Expires">
                  <span className="text-sm">{formatDateTime(selectedCapability.expires_at)}</span>
                </DetailItem>
                <DetailItem label="Policy Hash">
                  <span className="font-mono text-xs">{shortValue(selectedCapability.policy_hash)}</span>
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
                <DetailItem label="Origin">
                  <span className="font-mono text-xs">
                    {selectedCapability.origin_fingerprint ?? "-"}
                  </span>
                </DetailItem>
                <DetailItem label="Suspicion">
                  <span className="text-sm">{selectedCapability.suspicion_reason ?? "-"}</span>
                </DetailItem>
                <div style={{ gridColumn: "1 / -1" }}>
                  <DetailItem label="Request Target">
                    <span className="font-mono text-xs" style={{ color: "rgba(154,167,181,0.82)" }}>
                      {selectedCapability.method} {selectedCapability.url}
                    </span>
                  </DetailItem>
                </div>
              </div>
            )}

            <div className="mt-4 grid gap-4 lg:grid-cols-2">
              <PreviewCard preview={selectedPreview} loading={previewLoading} />
              <IdentityCard identity={missionIdentity} lineage={missionLineage} />
            </div>
          </div>

          <div className="grid gap-4 lg:grid-cols-2">
            <LineageCard lineage={missionLineage} />
            <div className="glass-panel" style={{ padding: 16 }}>
              <NoiseGrain />
              <div className="flex items-center justify-between gap-3">
                <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
                  Replay Diff
                </div>
                <Stamp variant={replayVariant(replay)}>
                  {replay ? (replay.would_allow ? "would allow" : "blocked") : "pending"}
                </Stamp>
              </div>
              {!replay ? (
                <div className="mt-4">
                  <HintBlock>
                    Run replay to compare current policy, preview approval state, and delegated
                    identity context against the selected capability.
                  </HintBlock>
                </div>
              ) : (
                <div className="mt-4 space-y-4">
                  <div className="text-sm">{replay.reason}</div>
                  <div
                    className="flex flex-wrap gap-2 font-mono text-[11px]"
                    style={{ color: "rgba(154,167,181,0.78)" }}
                  >
                    <Tag>policy changed {String(replay.policy_changed)}</Tag>
                    <Tag>approval required {String(replay.approval_required)}</Tag>
                    <Tag>preview approved {String(replay.preview_still_approved ?? true)}</Tag>
                    <Tag>provider frozen {String(replay.provider_frozen)}</Tag>
                    {replay.delegated_subject && <Tag>{replay.delegated_subject}</Tag>}
                    {replay.minted_identity_kind && <Tag>{replay.minted_identity_kind}</Tag>}
                  </div>
                  {replay.diffs?.length ? (
                    <div className="space-y-2">
                      {replay.diffs.map((diff) => (
                        <div
                          key={`${diff.field}:${diff.previous}:${diff.current}`}
                          className="rounded-lg"
                          style={{
                            padding: 10,
                            border: "1px solid rgba(27,34,48,0.8)",
                            background: "rgba(8,10,14,0.9)",
                          }}
                        >
                          <div className="font-mono text-xs">{diff.field}</div>
                          <div
                            className="mt-2 flex flex-wrap gap-2 font-mono text-[11px]"
                            style={{ color: "rgba(154,167,181,0.78)" }}
                          >
                            <Tag>prev {diff.previous}</Tag>
                            <Tag>now {diff.current}</Tag>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <HintBlock>No field-level policy diffs were returned.</HintBlock>
                  )}
                  {replay.notes?.length ? (
                    <div className="space-y-1">
                      {replay.notes.map((note) => (
                        <div
                          key={note}
                          className="font-mono text-[11px]"
                          style={{ color: "rgba(154,167,181,0.78)" }}
                        >
                          {note}
                        </div>
                      ))}
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          </div>

          <div className="glass-panel" style={{ padding: 16 }}>
            <NoiseGrain />
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
                  Completion Bundle
                </div>
                <div className="mt-1 font-mono text-[11px]" style={{ color: "rgba(154,167,181,0.72)" }}>
                  Signed export surface for the selected capability and execution evidence
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <GlassButton
                  onClick={() => void handleExportBundle()}
                  disabled={!selectedCapability || actionBusy !== null}
                >
                  Export JSON
                </GlassButton>
                <GlassButton onClick={() => void handleCopyEnvelope()} disabled={!bundle}>
                  Copy Envelope
                </GlassButton>
              </div>
            </div>
            {!bundle ? (
              <div className="mt-4">
                <HintBlock>
                  Export a bundle to capture the selected capability, signed envelope, and
                  execution trail for audit or handoff.
                </HintBlock>
              </div>
            ) : (
              <div className="mt-4 space-y-4">
                <div className="grid gap-3 md:grid-cols-3">
                  <DetailItem label="Generated">
                    <span className="text-sm">{formatDateTime(bundle.bundle.generated_at)}</span>
                  </DetailItem>
                  <DetailItem label="Capability">
                    <span className="font-mono text-xs">{bundle.bundle.capability.capability_id}</span>
                  </DetailItem>
                  <DetailItem label="Executions">
                    <span className="text-sm">{bundle.bundle.executions.length}</span>
                  </DetailItem>
                </div>
                <div>
                  <div
                    className="font-mono text-[11px]"
                    style={{ color: "rgba(154,167,181,0.72)" }}
                  >
                    Signed Envelope
                  </div>
                  <pre
                    className="mt-2 overflow-auto rounded-lg font-mono text-[11px]"
                    style={{
                      maxHeight: 140,
                      padding: 12,
                      border: "1px solid rgba(27,34,48,0.8)",
                      background: "rgba(8,10,14,0.92)",
                      color: "rgba(222,229,239,0.88)",
                      whiteSpace: "pre-wrap",
                      wordBreak: "break-word",
                    }}
                  >
                    {bundle.envelope}
                  </pre>
                </div>
              </div>
            )}
          </div>

          <div className="glass-panel" style={{ minHeight: 280 }}>
            <NoiseGrain />
            <PanelHeader
              title="Execution Ledger"
              meta={detailLoading ? "refreshing..." : `${executions.length} evidence records`}
            />
            <div style={{ maxHeight: 340, overflow: "auto" }}>
              {!selectedCapabilityId ? (
                <HintBlock>Select a capability to inspect its execution trail.</HintBlock>
              ) : executions.length === 0 ? (
                <HintBlock>No execution evidence has been recorded for this capability yet.</HintBlock>
              ) : (
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr>
                      {["Phase", "Time", "Status", "Outcome", "Mission Tags"].map((label) => (
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
                        <td className="px-4 py-3 text-sm">{execution.outcome ?? "-"}</td>
                        <td className="px-4 py-3">
                          <ExecutionTags execution={execution} />
                        </td>
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

function PreviewCard({
  preview,
  loading,
}: {
  preview: BrokerIntentPreview | null;
  loading: boolean;
}) {
  return (
    <div className="rounded-xl" style={{ padding: 14, border: "1px solid rgba(27,34,48,0.8)" }}>
      <div className="flex items-center justify-between gap-3">
        <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
          Intent Preview
        </div>
        {preview ? (
          <Stamp variant={approvalVariant(preview.approval_state)}>
            {preview.approval_state.replace("_", " ")}
          </Stamp>
        ) : null}
      </div>
      {loading ? (
        <div className="mt-4">
          <HintBlock>Loading preview detail...</HintBlock>
        </div>
      ) : !preview ? (
        <div className="mt-4">
          <HintBlock>No intent preview is attached to the current mission.</HintBlock>
        </div>
      ) : (
        <div className="mt-4 space-y-3">
          <div>
            <div className="font-display text-xl">{preview.operation}</div>
            <div className="mt-1 text-sm" style={{ color: "rgba(154,167,181,0.8)" }}>
              {preview.summary}
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Tag>{preview.provider}</Tag>
            <Tag>{preview.egress_host}</Tag>
            <Tag>{formatCost(preview.estimated_cost_usd_micros)}</Tag>
            <Tag>{preview.risk_level}</Tag>
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <DetailItem label="Created">
              <span className="text-sm">{formatDateTime(preview.created_at)}</span>
            </DetailItem>
            <DetailItem label="Approver">
              <span className="text-sm">{preview.approver ?? "-"}</span>
            </DetailItem>
          </div>
        </div>
      )}
    </div>
  );
}

function IdentityCard({
  identity,
  lineage,
}: {
  identity: BrokerMintedIdentity | null;
  lineage: BrokerDelegationLineage | null;
}) {
  const metadataEntries = Object.entries(identity?.metadata ?? {});
  return (
    <div className="rounded-xl" style={{ padding: 14, border: "1px solid rgba(27,34,48,0.8)" }}>
      <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
        Minted Identity
      </div>
      {!identity ? (
        <div className="mt-4">
          <HintBlock>No minted downstream identity is attached to this mission.</HintBlock>
        </div>
      ) : (
        <div className="mt-4 space-y-3">
          <div className="flex flex-wrap gap-2">
            <Stamp variant="allowed">{identity.kind}</Stamp>
            {lineage?.subject && <Tag>subject {lineage.subject}</Tag>}
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <DetailItem label="Subject">
              <span className="font-mono text-xs">{identity.subject}</span>
            </DetailItem>
            <DetailItem label="Expires">
              <span className="text-sm">{formatDateTime(identity.expires_at)}</span>
            </DetailItem>
          </div>
          <Stack label="Metadata">
            {metadataEntries.length === 0 ? (
              <span className="font-mono text-[11px]" style={{ color: "rgba(154,167,181,0.72)" }}>
                -
              </span>
            ) : (
              metadataEntries.map(([key, value]) => (
                <Tag key={key}>
                  {key}:{value}
                </Tag>
              ))
            )}
          </Stack>
        </div>
      )}
    </div>
  );
}

function LineageCard({ lineage }: { lineage: BrokerDelegationLineage | null }) {
  const chain = lineage?.chain ?? [];
  return (
    <div className="glass-panel" style={{ padding: 16 }}>
      <NoiseGrain />
      <div className="font-mono text-xs uppercase" style={{ letterSpacing: "0.08em" }}>
        Delegation Lineage
      </div>
      {!lineage ? (
        <div className="mt-4">
          <HintBlock>No delegation lineage was recorded for this capability.</HintBlock>
        </div>
      ) : (
        <div className="mt-4 space-y-4">
          <div className="grid gap-3 md:grid-cols-2">
            <DetailItem label="Issuer">
              <span className="font-mono text-xs">{lineage.issuer}</span>
            </DetailItem>
            <DetailItem label="Subject">
              <span className="font-mono text-xs">{lineage.subject}</span>
            </DetailItem>
            <DetailItem label="Depth">
              <span className="text-sm">{lineage.depth}</span>
            </DetailItem>
            <DetailItem label="Purpose">
              <span className="text-sm">{lineage.purpose ?? "-"}</span>
            </DetailItem>
            <DetailItem label="Token JTI">
              <span className="font-mono text-xs">{shortValue(lineage.token_jti)}</span>
            </DetailItem>
            <DetailItem label="Parent JTI">
              <span className="font-mono text-xs">{shortValue(lineage.parent_token_jti)}</span>
            </DetailItem>
          </div>
          <Stack label="Chain">
            {chain.length === 0 ? (
              <span className="font-mono text-[11px]" style={{ color: "rgba(154,167,181,0.72)" }}>
                -
              </span>
            ) : (
              chain.map((entry) => <Tag key={entry}>{entry}</Tag>)
            )}
          </Stack>
        </div>
      )}
    </div>
  );
}

function ExecutionTags({ execution }: { execution: BrokerExecutionEvidence }) {
  return (
    <div className="flex flex-wrap gap-2">
      {execution.preview_id && <Tag>{execution.preview_id}</Tag>}
      {execution.minted_identity && <Tag>{execution.minted_identity.kind}</Tag>}
      {execution.lineage?.subject && <Tag>{execution.lineage.subject}</Tag>}
      {execution.suspicion_reason && <Tag>{execution.suspicion_reason}</Tag>}
      {!execution.preview_id &&
        !execution.minted_identity &&
        !execution.lineage &&
        !execution.suspicion_reason && <span>-</span>}
    </div>
  );
}
