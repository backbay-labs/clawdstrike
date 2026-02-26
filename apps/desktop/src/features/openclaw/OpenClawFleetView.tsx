/**
 * OpenClawFleetView - Gateway WebSocket control plane for nodes, presence, and approvals.
 *
 * This view connects directly to the OpenClaw Gateway WS (no proxy) and exposes:
 * - multi-gateway management (local + tailnet)
 * - node inventory and `system.run` invocations (approval gated)
 * - exec approval inbox
 * - device pairing list
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { clsx } from "clsx";
import { GlassHeader, GlassPanel } from "@backbay/glia/primitives";
import { GlowButton } from "@backbay/glia/primitives";
import { GlowInput } from "@backbay/glia/primitives";
import { Badge } from "@backbay/glia/primitives";
import { useOpenClaw, type ExecApprovalDecision, type ExecApprovalQueueItem, type OpenClawGatewayConfig } from "@/context/OpenClawContext";
import { isTauri, openclawGatewayDiscover, openclawGatewayProbe } from "@/services/tauri";
import { DEFAULT_GATEWAY_URL, normalizeGatewayUrl, originFixHint, parseCommand, selectSystemRunNodes, statusDotClass, timeAgo } from "./openclawFleetUtils";

function GatewayCard({
  gateway,
  isActive,
  status,
  nodes,
  presence,
  approvals,
  onSetActive,
  onConnect,
  onDisconnect,
  onRemove,
}: {
  gateway: OpenClawGatewayConfig;
  isActive: boolean;
  status: string;
  nodes: number;
  presence: number;
  approvals: number;
  onSetActive: () => void;
  onConnect: () => void;
  onDisconnect: () => void;
  onRemove: () => void;
}) {
  return (
    <div className="p-4 rounded-lg border border-sdr-border bg-sdr-bg-secondary">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <div className="text-sm font-semibold text-sdr-text-primary truncate">{gateway.label}</div>
            {isActive ? (
              <Badge variant="secondary">Active</Badge>
            ) : null}
          </div>
          <div className="text-xs text-sdr-text-muted mt-1 truncate">{gateway.gatewayUrl}</div>
          <div className="mt-2 flex items-center gap-2 text-xs text-sdr-text-muted">
            <span className={clsx("w-2 h-2 rounded-full", statusDotClass(status))} />
            <span className="uppercase tracking-wide">{status}</span>
            <span className="opacity-50">·</span>
            <span>{nodes} nodes</span>
            <span className="opacity-50">·</span>
            <span>{presence} presence</span>
            <span className="opacity-50">·</span>
            <span>{approvals} approvals</span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {isActive ? null : (
            <GlowButton onClick={onSetActive} variant="secondary">
              Set Active
            </GlowButton>
          )}
          {status === "connected" ? (
            <GlowButton onClick={onDisconnect} variant="secondary">
              Disconnect
            </GlowButton>
          ) : (
            <GlowButton onClick={onConnect} variant="default">
              Connect
            </GlowButton>
          )}
          <GlowButton onClick={onRemove} variant="secondary">
            Remove
          </GlowButton>
        </div>
      </div>
    </div>
  );
}

/** Ticking countdown hook - returns milliseconds remaining, updated every second. */
function useCountdown(targetMs: number): number {
  const [remaining, setRemaining] = useState(Math.max(0, targetMs - Date.now()));
  useEffect(() => {
    // Sync immediately in case targetMs changed between render and effect
    const initialRemaining = Math.max(0, targetMs - Date.now());
    setRemaining(initialRemaining);
    if (initialRemaining <= 0) {
      return;
    }
    const timer = setInterval(() => {
      const nextRemaining = Math.max(0, targetMs - Date.now());
      setRemaining(nextRemaining);
      if (nextRemaining <= 0) {
        clearInterval(timer);
      }
    }, 1_000);
    return () => clearInterval(timer);
  }, [targetMs]);
  return remaining;
}

function ExecApprovalCard({
  approval,
  busy,
  onResolve,
}: {
  approval: ExecApprovalQueueItem;
  busy: boolean;
  onResolve: (decision: ExecApprovalDecision) => void | Promise<void>;
}) {
  const expiresIn = useCountdown(approval.expiresAtMs);
  const expired = expiresIn <= 0;
  const expiresLabel = !expired ? `expires in ${Math.max(0, Math.floor(expiresIn / 1000))}s` : "expired";

  const [resolveError, setResolveError] = useState<string | null>(null);

  const safeResolve = useCallback(
    async (decision: ExecApprovalDecision) => {
      setResolveError(null);
      try {
        await onResolve(decision);
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        console.error("[ExecApprovalCard] resolve error:", message);
        setResolveError(message);
      }
    },
    [onResolve],
  );

  return (
    <div className={clsx("p-3 rounded border border-sdr-border bg-sdr-bg-tertiary/30", expired && "opacity-50")}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className={clsx("text-xs", expired ? "text-sdr-accent-red" : "text-sdr-text-muted")}>{expiresLabel}</div>
          <div className="mt-1 text-sm font-mono text-sdr-text-primary break-all">{approval.request.command}</div>
          <div className="mt-2 grid grid-cols-1 md:grid-cols-2 gap-x-4 gap-y-1 text-xs text-sdr-text-muted">
            {approval.request.host ? <div>Host: {approval.request.host}</div> : null}
            {approval.request.cwd ? <div>CWD: {approval.request.cwd}</div> : null}
            {approval.request.agentId ? <div>Agent: {approval.request.agentId}</div> : null}
            {approval.request.sessionKey ? <div>Session: {approval.request.sessionKey}</div> : null}
            {approval.request.resolvedPath ? <div>Resolved: {approval.request.resolvedPath}</div> : null}
            {approval.request.security ? <div>Security: {approval.request.security}</div> : null}
            {approval.request.ask ? <div>Ask: {approval.request.ask}</div> : null}
          </div>
          {resolveError ? (
            <div className="mt-2 text-xs text-sdr-accent-red whitespace-pre-wrap">
              Resolution error: {resolveError}
            </div>
          ) : null}
        </div>

        <div className="flex flex-col gap-2 shrink-0">
          <GlowButton onClick={() => void safeResolve("allow-once")} disabled={busy || expired} variant="default">
            Allow once
          </GlowButton>
          <GlowButton onClick={() => void safeResolve("allow-always")} disabled={busy || expired} variant="secondary">
            Always allow
          </GlowButton>
          <GlowButton onClick={() => void safeResolve("deny")} disabled={busy || expired} variant="secondary">
            Deny
          </GlowButton>
        </div>
      </div>
    </div>
  );
}

export function OpenClawFleetView() {
  const oc = useOpenClaw();
  const runtime = oc.runtimeByGatewayId[oc.activeGatewayId];
  const tauri = isTauri();

  const [label, setLabel] = useState(oc.active.label);
  const [gatewayUrl, setGatewayUrl] = useState(oc.active.gatewayUrl);
  const [token, setToken] = useState(oc.active.token);

  useEffect(() => {
    setLabel(oc.active.label);
    setGatewayUrl(oc.active.gatewayUrl);
    setToken(oc.active.token);
  }, [oc.active.gatewayUrl, oc.active.id, oc.active.label, oc.active.token]);

  const status = runtime?.status ?? "disconnected";
  const originHint = originFixHint(runtime?.lastError ?? null);

  const summaryRows = oc.summary.gateways;

  const systemRunNodes = useMemo(() => selectSystemRunNodes(runtime?.nodes ?? []), [runtime?.nodes]);

  const [discoverBusy, setDiscoverBusy] = useState(false);
  const [probeBusy, setProbeBusy] = useState(false);
  const [discoveryError, setDiscoveryError] = useState<string | null>(null);
  const [tailnetHint, setTailnetHint] = useState<string | null>(null);

  const [nodeId, setNodeId] = useState<string>("");
  useEffect(() => {
    if (nodeId && systemRunNodes.some((n) => n.nodeId === nodeId)) return;
    setNodeId(systemRunNodes[0]?.nodeId ?? "");
  }, [nodeId, systemRunNodes]);

  const [cwd, setCwd] = useState("");
  const [timeoutMs, setTimeoutMs] = useState("120000");
  const [command, setCommand] = useState("echo test");
  const [invokeBusy, setInvokeBusy] = useState(false);
  const [invokeError, setInvokeError] = useState<string | null>(null);
  const [invokeResult, setInvokeResult] = useState<unknown>(null);

  const [resolveBusyId, setResolveBusyId] = useState<string | null>(null);
  const [pairingBusy, setPairingBusy] = useState<{ id: string; action: "approve" | "reject" } | null>(null);
  const [pairingError, setPairingError] = useState<string | null>(null);

  async function handleDiscoverGateways() {
    setDiscoveryError(null);
    setDiscoverBusy(true);
    try {
      const result = await openclawGatewayDiscover(2500);
      const beacons = Array.isArray(result.beacons) ? result.beacons : [];
      const existing = new Set(oc.gateways.map((g) => normalizeGatewayUrl(g.gatewayUrl)));

      for (const beacon of beacons) {
        const wsUrl = typeof beacon.wsUrl === "string" ? normalizeGatewayUrl(beacon.wsUrl) : "";
        if (!wsUrl) continue;
        if (existing.has(wsUrl)) continue;
        existing.add(wsUrl);

        const label = (beacon.displayName || beacon.instanceName || "Discovered Gateway").toString();
        oc.addGateway({ label, gatewayUrl: wsUrl, token: oc.active.token });
      }
    } catch (err) {
      setDiscoveryError(err instanceof Error ? err.message : String(err));
    } finally {
      setDiscoverBusy(false);
    }
  }

  async function handleProbeTailnet() {
    setDiscoveryError(null);
    setProbeBusy(true);
    try {
      const result = await openclawGatewayProbe(3500);
      const tailnetUrl =
        typeof result.network?.localTailnetUrl === "string" ? normalizeGatewayUrl(result.network.localTailnetUrl) : null;
      const tailnetIPv4 = result.network?.tailnetIPv4;
      setTailnetHint(tailnetIPv4 ? `tailnet: ${tailnetIPv4}` : null);
      const existing = new Set(oc.gateways.map((g) => normalizeGatewayUrl(g.gatewayUrl)));

      if (typeof tailnetUrl === "string" && tailnetUrl.trim()) {
        if (!existing.has(tailnetUrl)) {
          existing.add(tailnetUrl);
          oc.addGateway({ label: "Local Tailnet Gateway", gatewayUrl: tailnetUrl, token: oc.active.token });
        }
      }

      const beacons = result.discovery?.beacons;
      if (Array.isArray(beacons)) {
        for (const beacon of beacons) {
          const wsUrl = typeof beacon.wsUrl === "string" ? normalizeGatewayUrl(beacon.wsUrl) : "";
          if (!wsUrl) continue;
          if (existing.has(wsUrl)) continue;
          existing.add(wsUrl);
          oc.addGateway({
            label: (beacon.displayName || "Discovered Gateway").toString(),
            gatewayUrl: wsUrl,
            token: oc.active.token,
          });
        }
      }
    } catch (err) {
      setDiscoveryError(err instanceof Error ? err.message : String(err));
    } finally {
      setProbeBusy(false);
    }
  }

  async function handleSave() {
    const normalizedUrl = normalizeGatewayUrl(gatewayUrl);
    oc.updateGateway(oc.active.id, {
      label: label.trim() ? label.trim() : label,
      gatewayUrl: normalizedUrl || (gatewayUrl.trim() ? gatewayUrl.trim() : gatewayUrl),
      token: token.trim() ? token.trim() : token,
    });
  }

  async function handleSaveAndConnect() {
    await handleSave();
    await oc.connectGateway(oc.active.id).catch(() => {});
  }

  async function handleRunSystemRun() {
    setInvokeError(null);
    setInvokeResult(null);

    const parsed = parseCommand(command);
    if (parsed.error) {
      setInvokeError(parsed.error);
      return;
    }
    if (!nodeId) {
      setInvokeError("node required");
      return;
    }

    const t = Number(timeoutMs);
    const timeout = Number.isFinite(t) && t > 0 ? Math.floor(t) : 120000;

    setInvokeBusy(true);
    try {
      const res = await oc.request("node.invoke", {
        nodeId,
        command: "system.run",
        params: {
          command: parsed.argv,
          rawCommand: parsed.rawCommand,
          cwd: cwd.trim() ? cwd.trim() : null,
          timeoutMs: timeout,
          sessionKey: "sdr-desktop",
          runId: `sdr:${Date.now()}`,
        },
        timeoutMs: timeout + 10_000,
        idempotencyKey: `${Date.now()}-${Math.random().toString(16).slice(2)}`,
      }, { timeoutMs: timeout + 15_000 });
      setInvokeResult(res);
    } catch (err) {
      setInvokeError(err instanceof Error ? err.message : String(err));
    } finally {
      setInvokeBusy(false);
    }
  }

  async function handleResolveApproval(approvalId: string, decision: ExecApprovalDecision) {
    setResolveBusyId(approvalId);
    try {
      await oc.resolveExecApproval(approvalId, decision);
    } finally {
      setResolveBusyId(null);
    }
  }

  async function handleApproveDevice(requestId: string) {
    setPairingError(null);
    setPairingBusy({ id: requestId, action: "approve" });
    try {
      await oc.approveDevicePairing(requestId);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error("[OpenClawFleetView] approve device error:", message);
      setPairingError(message);
    } finally {
      setPairingBusy(null);
    }
  }

  async function handleRejectDevice(requestId: string) {
    setPairingError(null);
    setPairingBusy({ id: requestId, action: "reject" });
    try {
      await oc.rejectDevicePairing(requestId);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error("[OpenClawFleetView] reject device error:", message);
      setPairingError(message);
    } finally {
      setPairingBusy(null);
    }
  }

  return (
    <GlassPanel className="h-full overflow-y-auto" variant="flush">
      <GlassHeader className="flex items-start justify-between gap-3 px-6 py-4">
        <div>
          <h1 className="text-lg font-semibold text-sdr-text-primary">OpenClaw Fleet</h1>
          <p className="text-sm text-sdr-text-muted mt-1">
            Gateway WebSocket control plane for nodes, presence, and approvals.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap justify-end">
          <select
            value={oc.activeGatewayId}
            onChange={(e) => oc.setActiveGatewayId(e.target.value)}
            className="px-3 py-2 text-sm rounded border border-sdr-border bg-sdr-bg-tertiary text-sdr-text-primary outline-none min-w-[260px]"
            aria-label="Active gateway"
          >
            {oc.gateways.map((g) => (
              <option key={g.id} value={g.id}>
                {g.label} · {g.gatewayUrl}
              </option>
            ))}
          </select>

          <GlowButton onClick={() => oc.addGateway({ gatewayUrl: DEFAULT_GATEWAY_URL, token: "" })} variant="secondary">
            Add
          </GlowButton>

          <div className="flex items-center gap-2">
            <span className={clsx("w-2.5 h-2.5 rounded-full", statusDotClass(status))} />
            <Badge variant={status === "connected" ? "default" : status === "error" ? "destructive" : "secondary"}>
              {status}
            </Badge>
          </div>

          <GlowButton
            onClick={() => {
              void Promise.all([oc.refreshPresence(), oc.refreshNodes(), oc.refreshDevices(undefined, { quiet: true })]).catch(() => {});
            }}
            variant="secondary"
          >
            Refresh
          </GlowButton>

          {status === "connected" ? (
            <GlowButton onClick={oc.disconnect} variant="secondary">
              Disconnect
            </GlowButton>
          ) : (
            <GlowButton
              onClick={() => {
                void oc.connect().catch(() => {});
              }}
              variant="default"
            >
              Connect
            </GlowButton>
          )}
        </div>
      </GlassHeader>

      <div className="max-w-5xl mx-auto p-6 space-y-6">
        {/* Gateways */}
        <section className="space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-sdr-text-primary">Gateways</div>
              <div className="text-xs text-sdr-text-muted">Manage multiple gateways (local + tailnet) and choose an active control plane.</div>
            </div>
            <div className="flex items-center gap-2">
              <GlowButton
                onClick={() => {
                  void oc.connectAll().catch(() => {});
                }}
                variant="secondary"
              >
                Connect All
              </GlowButton>
              <GlowButton onClick={oc.disconnectAll} variant="secondary">
                Disconnect All
              </GlowButton>
              <GlowButton onClick={handleProbeTailnet} disabled={!tauri || probeBusy} variant="secondary">
                Probe Tailnet
              </GlowButton>
              <GlowButton onClick={handleDiscoverGateways} disabled={!tauri || discoverBusy} variant="secondary">
                Discover
              </GlowButton>
              <Badge variant="secondary">{oc.summary.connected} connected</Badge>
              {tailnetHint ? <Badge variant="secondary">{tailnetHint}</Badge> : null}
            </div>
          </div>

          <div className="space-y-3">
            {summaryRows.map((row) => {
              const gw = oc.gateways.find((g) => g.id === row.id);
              if (!gw) return null;
              return (
                <GatewayCard
                  key={row.id}
                  gateway={gw}
                  isActive={row.id === oc.activeGatewayId}
                  status={row.status}
                  nodes={row.nodes}
                  presence={row.presence}
                  approvals={row.approvals}
                  onSetActive={() => oc.setActiveGatewayId(row.id)}
                  onConnect={() => {
                    void oc.connectGateway(row.id).catch(() => {});
                  }}
                  onDisconnect={() => oc.disconnectGateway(row.id)}
                  onRemove={() => {
                    if (!globalThis.confirm?.(`Remove gateway "${gw.label}"?`)) return;
                    oc.removeGateway(row.id);
                  }}
                />
              );
            })}
          </div>
        </section>

        {!tauri ? (
          <div className="text-xs text-sdr-text-muted">
            Tailnet discovery requires the desktop app (Tauri).
          </div>
        ) : null}
        {discoveryError ? (
          <div className="text-xs text-sdr-accent-red whitespace-pre-wrap">
            Discovery error: {discoveryError}
          </div>
        ) : null}

        {/* Active gateway config */}
        <section className="p-4 rounded-lg border border-sdr-border bg-sdr-bg-secondary space-y-3">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-sdr-text-primary">Active Gateway</div>
              <div className="text-xs text-sdr-text-muted">Device tokens and gateway-scoped tokens are stored locally.</div>
            </div>
            <div className="text-xs text-sdr-text-muted">
              last msg: {timeAgo(runtime?.lastMessageAtMs)}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div>
              <div className="text-xs text-sdr-text-muted uppercase tracking-wide mb-1">Label</div>
              <GlowInput value={label} onChange={(e) => setLabel(e.target.value)} placeholder="Gateway 1" />
            </div>
            <div className="md:col-span-2">
              <div className="text-xs text-sdr-text-muted uppercase tracking-wide mb-1">Gateway WS URL</div>
              <GlowInput value={gatewayUrl} onChange={(e) => setGatewayUrl(e.target.value)} placeholder="ws://127.0.0.1:18789" />
            </div>
          </div>

          <div>
            <div className="text-xs text-sdr-text-muted uppercase tracking-wide mb-1">Token</div>
            <input
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder="(optional if gateway auth disabled)"
              type="password"
              className="w-full px-3 py-2 text-sm rounded border border-sdr-border bg-sdr-bg-tertiary text-sdr-text-primary outline-none"
            />
          </div>

          <div className="flex items-center gap-2">
            <GlowButton onClick={handleSave} variant="secondary">
              Save
            </GlowButton>
            <GlowButton onClick={handleSaveAndConnect} variant="default">
              Save + Connect
            </GlowButton>
          </div>

          {originHint ? (
            <pre className="text-xs text-sdr-text-muted whitespace-pre-wrap p-3 rounded border border-sdr-border bg-sdr-bg-tertiary/30">
              {originHint}
            </pre>
          ) : null}
          {runtime?.lastError ? (
            <div className="text-xs text-sdr-accent-red whitespace-pre-wrap">
              Last error: {runtime.lastError}
            </div>
          ) : null}
        </section>

        {/* Presence + nodes snapshot */}
        <section className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="p-4 rounded-lg border border-sdr-border bg-sdr-bg-secondary">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-semibold text-sdr-text-primary">Presence</div>
                <div className="text-xs text-sdr-text-muted">Best-effort list of connected clients and the gateway itself.</div>
              </div>
              <Badge variant="secondary">{runtime?.presence?.length ?? 0}</Badge>
            </div>
            <div className="mt-3 space-y-2">
              {(runtime?.presence ?? []).slice(0, 12).map((p, idx) => {
                const entry = p && typeof p === "object" ? (p as Record<string, unknown>) : null;
                const knownFields = ["clientId", "displayName", "version", "platform", "mode"] as const;
                const hasKnown = entry && knownFields.some((f) => entry[f] != null);

                if (!hasKnown) {
                  return (
                    <pre
                      key={idx}
                      className="text-xs text-sdr-text-muted whitespace-pre-wrap p-2 rounded border border-sdr-border bg-sdr-bg-tertiary/30 overflow-x-auto"
                    >
                      {JSON.stringify(p, null, 2)}
                    </pre>
                  );
                }

                return (
                  <div
                    key={idx}
                    className="p-2 rounded border border-sdr-border bg-sdr-bg-tertiary/30 text-xs text-sdr-text-muted"
                  >
                    <ul className="space-y-0.5">
                      {knownFields.map((field) =>
                        entry![field] != null ? (
                          <li key={field}>
                            <span className="font-medium text-sdr-text-secondary">{field}:</span>{" "}
                            {String(entry![field])}
                          </li>
                        ) : null,
                      )}
                    </ul>
                  </div>
                );
              })}
              {(runtime?.presence ?? []).length > 12 && (
                <p className="text-xs text-sdr-text-muted mt-1">and {(runtime?.presence ?? []).length - 12} more</p>
              )}
              {(runtime?.presence ?? []).length === 0 ? (
                <div className="text-sm text-sdr-text-muted mt-2">No presence entries yet.</div>
              ) : null}
            </div>
          </div>

          <div className="p-4 rounded-lg border border-sdr-border bg-sdr-bg-secondary">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-semibold text-sdr-text-primary">Nodes</div>
                <div className="text-xs text-sdr-text-muted">Paired and currently-connected nodes (via `node.list`).</div>
              </div>
              <Badge variant="secondary">{runtime?.nodes?.length ?? 0}</Badge>
            </div>
            <div className="mt-3 space-y-2">
              {(runtime?.nodes ?? []).slice(0, 12).map((n, idx) => (
                <div key={`${n.nodeId ?? "node"}-${idx}`} className="p-3 rounded border border-sdr-border bg-sdr-bg-tertiary/30">
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="text-sm font-medium text-sdr-text-primary truncate">
                        {n.displayName?.trim() ? n.displayName.trim() : n.nodeId ?? "node"}
                      </div>
                      <div className="text-xs text-sdr-text-muted mt-1 truncate">
                        {n.nodeId ? `${n.nodeId.slice(0, 10)}…${n.nodeId.slice(-6)}` : "missing nodeId"}{" "}
                        {n.platform ? `· ${n.platform}` : ""} {n.version ? `· ${n.version}` : ""}
                      </div>
                      <div className="mt-2 flex items-center gap-2 text-xs text-sdr-text-muted">
                        <span className={clsx("px-2 py-0.5 rounded", n.connected ? "bg-sdr-accent-green/10 text-sdr-accent-green" : "bg-sdr-bg-secondary")}>
                          {n.connected ? "connected" : "disconnected"}
                        </span>
                        <span className={clsx("px-2 py-0.5 rounded", n.paired ? "bg-sdr-accent-blue/10 text-sdr-accent-blue" : "bg-sdr-bg-secondary")}>
                          {n.paired ? "paired" : "unpaired"}
                        </span>
                        {Array.isArray(n.commands) ? (
                          <span className="px-2 py-0.5 rounded bg-sdr-bg-secondary">{n.commands.length} cmds</span>
                        ) : null}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
              {(runtime?.nodes ?? []).length > 12 && (
                <p className="text-xs text-sdr-text-muted mt-1">and {(runtime?.nodes ?? []).length - 12} more</p>
              )}
              {(runtime?.nodes ?? []).length === 0 ? (
                <div className="text-sm text-sdr-text-muted mt-2">No nodes yet. Install a node host and pair it.</div>
              ) : null}
            </div>
          </div>
        </section>

        {/* Exec approvals */}
        <section className="p-4 rounded-lg border border-sdr-border bg-sdr-bg-secondary">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-sdr-text-primary">Exec Approvals</div>
              <div className="text-xs text-sdr-text-muted">Pending approvals emitted as `exec.approval.requested`.</div>
            </div>
            <Badge variant={(runtime?.execApprovalQueue?.length ?? 0) > 0 ? "secondary" : "default"}>
              {runtime?.execApprovalQueue?.length ?? 0} pending
            </Badge>
          </div>
          <div className="mt-3 space-y-2">
            {(runtime?.execApprovalQueue ?? []).slice(0, 20).map((a) => (
              <ExecApprovalCard
                key={a.id}
                approval={a}
                busy={resolveBusyId === a.id}
                onResolve={(decision) => handleResolveApproval(a.id, decision)}
              />
            ))}
            {(runtime?.execApprovalQueue ?? []).length > 20 && (
              <p className="text-xs text-sdr-text-muted mt-1">showing 20 of {(runtime?.execApprovalQueue ?? []).length}</p>
            )}
            {(runtime?.execApprovalQueue ?? []).length === 0 ? (
              <div className="text-sm text-sdr-text-muted mt-2">No pending approvals.</div>
            ) : null}
          </div>
        </section>

        {/* Node invoke */}
        <section className="p-4 rounded-lg border border-sdr-border bg-sdr-bg-secondary">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-sdr-text-primary">Node Invoke</div>
              <div className="text-xs text-sdr-text-muted">Run node commands like `system.run` (approval-gated).</div>
            </div>
            <Badge variant={systemRunNodes.length > 0 ? "secondary" : "default"}>
              {systemRunNodes.length} system.run nodes
            </Badge>
          </div>

          {status !== "connected" ? (
            <div className="mt-4 text-sm text-sdr-text-muted">Connect to a gateway to invoke node commands.</div>
          ) : systemRunNodes.length === 0 ? (
            <div className="mt-4 text-sm text-sdr-text-muted whitespace-pre-wrap">
              No nodes with `system.run` available.
              {"\n"}Try:
              {"\n"}openclaw node install
              {"\n"}openclaw node restart
            </div>
          ) : (
            <div className="mt-4 space-y-3">
              <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
                <div>
                  <div className="text-xs text-sdr-text-muted uppercase tracking-wide mb-1">Node</div>
                  <select
                    value={nodeId}
                    onChange={(e) => setNodeId(e.target.value)}
                    className="w-full px-3 py-2 text-sm rounded border border-sdr-border bg-sdr-bg-tertiary text-sdr-text-primary outline-none"
                  >
                    {systemRunNodes.map((n) => (
                      <option key={n.nodeId} value={n.nodeId}>
                        {(n.displayName?.trim() ? `${n.displayName.trim()} · ` : "") + (n.nodeId ?? "")}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <div className="text-xs text-sdr-text-muted uppercase tracking-wide mb-1">CWD (optional)</div>
                  <GlowInput value={cwd} onChange={(e) => setCwd(e.target.value)} placeholder="/Users/connor" />
                </div>
                <div>
                  <div className="text-xs text-sdr-text-muted uppercase tracking-wide mb-1">Timeout (ms)</div>
                  <GlowInput value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)} placeholder="120000" />
                </div>
              </div>

              <div>
                <div className="text-xs text-sdr-text-muted uppercase tracking-wide mb-1">Command</div>
                <GlowInput value={command} onChange={(e) => setCommand(e.target.value)} placeholder={'ls -la   (or JSON: ["ls","-la"])'} />
                <div className="mt-2 text-xs text-sdr-text-muted whitespace-pre-wrap">Tip: For quoting/escaping, use JSON argv form.</div>
              </div>

              <div className="flex items-center gap-2">
                <GlowButton onClick={handleRunSystemRun} variant="default" disabled={invokeBusy}>
                  {invokeBusy ? "Running..." : "Run system.run"}
                </GlowButton>
                <GlowButton onClick={() => { setInvokeError(null); setInvokeResult(null); }} variant="secondary" disabled={invokeBusy}>
                  Clear
                </GlowButton>
              </div>

              {invokeError ? (
                <div className="p-3 rounded border border-sdr-accent-red/30 bg-sdr-accent-red/10 text-sm text-sdr-accent-red whitespace-pre-wrap">
                  {invokeError}
                </div>
              ) : null}
              {invokeResult ? (
                <pre className="p-3 rounded border border-sdr-border bg-sdr-bg-tertiary/30 text-xs text-sdr-text-secondary overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(invokeResult, null, 2)}
                </pre>
              ) : null}
            </div>
          )}
        </section>

        {/* Device pairing */}
        <section className="p-4 rounded-lg border border-sdr-border bg-sdr-bg-secondary">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-semibold text-sdr-text-primary">Device Pairing</div>
              <div className="text-xs text-sdr-text-muted">Pending device pairing requests and issued tokens.</div>
            </div>
            <div className="flex items-center gap-2">
              <Badge variant={(runtime?.devices?.pending?.length ?? 0) > 0 ? "secondary" : "default"}>
                {runtime?.devices?.pending?.length ?? 0} pending
              </Badge>
              <Badge variant="secondary">{runtime?.devices?.paired?.length ?? 0} paired</Badge>
            </div>
          </div>

          {pairingError ? (
            <div className="mt-2 text-xs text-sdr-accent-red whitespace-pre-wrap">
              Pairing error: {pairingError}
            </div>
          ) : null}
          <div className="mt-3 space-y-2">
            {(runtime?.devices?.pending ?? []).slice(0, 20).map((d) => (
              <div key={d.requestId} className="p-3 rounded border border-sdr-border bg-sdr-bg-tertiary/30 flex items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="text-sm font-medium text-sdr-text-primary truncate">{d.displayName?.trim() || d.deviceId}</div>
                  <div className="text-xs text-sdr-text-muted mt-1 truncate">
                    {d.deviceId}
                    {d.remoteIp ? ` · ${d.remoteIp}` : ""}
                    {d.role ? ` · role: ${d.role}` : ""}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <GlowButton onClick={() => void handleApproveDevice(d.requestId)} disabled={pairingBusy?.id === d.requestId} variant="default">
                    {pairingBusy?.id === d.requestId && pairingBusy.action === "approve" ? "Approving..." : "Approve"}
                  </GlowButton>
                  <GlowButton onClick={() => void handleRejectDevice(d.requestId)} disabled={pairingBusy?.id === d.requestId} variant="secondary">
                    {pairingBusy?.id === d.requestId && pairingBusy.action === "reject" ? "Rejecting..." : "Reject"}
                  </GlowButton>
                </div>
              </div>
            ))}
            {(runtime?.devices?.pending ?? []).length === 0 ? (
              <div className="text-sm text-sdr-text-muted mt-2">No pending pairing requests.</div>
            ) : null}
          </div>
        </section>
      </div>
    </GlassPanel>
  );
}
