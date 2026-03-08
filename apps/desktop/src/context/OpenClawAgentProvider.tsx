import * as React from "react";
import {
  type AgentGatewayListResponse,
  type AgentGatewayRuntime,
  AgentOpenClawClient,
} from "@/services/agentOpenClawClient";
import type { GatewayConnectionStatus } from "@/services/openclaw/gatewayClient";
import type { GatewayEventFrame } from "@/services/openclaw/gatewayProtocol";
import {
  applyGatewayEventFrame,
  type ExecApprovalDecision,
  type OpenClawContextValue,
  type OpenClawDevicePairingSnapshot,
  type OpenClawGatewayConfig,
  type OpenClawGatewayRuntime,
  type OpenClawNode,
} from "./OpenClawDirectFallback";

const STORAGE_KEY = "sdr:openclaw:gateways";
const STORAGE_ACTIVE_KEY = "sdr:openclaw:activeGatewayId";

const OpenClawContext = React.createContext<OpenClawContextValue | null>(null);

function emptyRuntime(): OpenClawGatewayRuntime {
  return {
    status: "disconnected",
    lastError: null,
    connectedAtMs: null,
    lastMessageAtMs: null,
    presence: [],
    nodes: [],
    devices: null,
    execApprovalQueue: [],
  };
}

function runtimeFromAgent(runtime: AgentGatewayRuntime): OpenClawGatewayRuntime {
  return {
    status: runtime.status as GatewayConnectionStatus,
    lastError: runtime.last_error ?? null,
    connectedAtMs: runtime.connected_at_ms ?? null,
    lastMessageAtMs: runtime.last_message_at_ms ?? null,
    presence: Array.isArray(runtime.presence) ? runtime.presence : [],
    nodes: Array.isArray(runtime.nodes) ? (runtime.nodes as OpenClawNode[]) : [],
    devices: (runtime.devices as OpenClawDevicePairingSnapshot | null) ?? null,
    execApprovalQueue: Array.isArray(runtime.exec_approval_queue)
      ? (runtime.exec_approval_queue as OpenClawGatewayRuntime["execApprovalQueue"])
      : [],
  };
}

function normalizeGatewayList(list: AgentGatewayListResponse): {
  gateways: OpenClawGatewayConfig[];
  activeGatewayId: string;
  runtimeByGatewayId: Record<string, OpenClawGatewayRuntime>;
} {
  const gateways: OpenClawGatewayConfig[] = list.gateways.map((gateway) => ({
    id: gateway.id,
    label: gateway.label,
    gatewayUrl: gateway.gateway_url,
    // Secrets are agent-owned now; keep UI field empty unless user enters a replacement.
    token: "",
    deviceToken: undefined,
  }));

  const runtimeByGatewayId: Record<string, OpenClawGatewayRuntime> = {};
  for (const gateway of list.gateways) {
    runtimeByGatewayId[gateway.id] = runtimeFromAgent(gateway.runtime);
  }

  const firstGatewayId = gateways[0]?.id ?? "";
  const activeGatewayId =
    (list.active_gateway_id && gateways.some((gateway) => gateway.id === list.active_gateway_id)
      ? list.active_gateway_id
      : firstGatewayId) ?? "";

  return { gateways, activeGatewayId, runtimeByGatewayId };
}

function loadLegacyLocalStorageGateways(): {
  gateways: Array<{
    id: string;
    label: string;
    gatewayUrl: string;
    token?: string;
    deviceToken?: string;
  }>;
  activeGatewayId: string | null;
} {
  try {
    const rawGateways = localStorage.getItem(STORAGE_KEY);
    if (!rawGateways) {
      return { gateways: [], activeGatewayId: null };
    }

    const parsed = JSON.parse(rawGateways);
    const normalized = Array.isArray(parsed)
      ? parsed
          .filter((entry) => entry && typeof entry === "object")
          .map((entry) => {
            const value = entry as Record<string, unknown>;
            return {
              id: String(value.id ?? ""),
              label: String(value.label ?? "Gateway"),
              gatewayUrl: String(value.gatewayUrl ?? ""),
              token: typeof value.token === "string" ? value.token : undefined,
              deviceToken: typeof value.deviceToken === "string" ? value.deviceToken : undefined,
            };
          })
          .filter((entry) => entry.id && entry.gatewayUrl)
      : [];

    const activeGatewayIdRaw = localStorage.getItem(STORAGE_ACTIVE_KEY);
    const activeGatewayId =
      typeof activeGatewayIdRaw === "string" && activeGatewayIdRaw.trim()
        ? activeGatewayIdRaw
        : null;
    return { gateways: normalized, activeGatewayId };
  } catch {
    return { gateways: [], activeGatewayId: null };
  }
}

function scrubLegacyLocalStorageSecrets() {
  try {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(STORAGE_ACTIVE_KEY);
  } catch {
    // ignore cleanup errors
  }
}

export function OpenClawAgentProvider({ children }: { children: React.ReactNode }) {
  const [gateways, setGateways] = React.useState<OpenClawGatewayConfig[]>([]);
  const [activeGatewayId, setActiveGatewayIdState] = React.useState("");
  const [runtimeByGatewayId, setRuntimeByGatewayId] = React.useState<
    Record<string, OpenClawGatewayRuntime>
  >({});

  const clientRef = React.useRef<AgentOpenClawClient | null>(null);
  const unsubscribeEventsRef = React.useRef<(() => void) | null>(null);
  const autoConnectAttemptAtRef = React.useRef<Record<string, number>>({});
  const autoConnectHoldUntilRef = React.useRef<Record<string, number>>({});
  const autoConnectInFlightRef = React.useRef<Record<string, boolean>>({});
  const warmupTriggeredRef = React.useRef<Record<string, boolean>>({});

  const syncFromAgent = React.useCallback(async () => {
    const client = clientRef.current;
    if (!client) return;

    const list = await client.listGateways();
    if (list.secret_store_mode === "memory_fallback") {
      console.warn("OpenClaw secret store keyring unavailable; using memory-only session secrets.");
    }

    let normalized = normalizeGatewayList(list);
    if (normalized.gateways.length === 0) {
      try {
        await client.createGateway({
          label: "Local Gateway",
          gatewayUrl: "ws://openclaw.localhost:18789",
        });
      } catch {
        try {
          await client.createGateway({
            label: "Local Gateway",
            gatewayUrl: "ws://127.0.0.1:18789",
          });
        } catch {
          // no-op
        }
      }
      normalized = normalizeGatewayList(await client.listGateways());
    }
    setGateways(normalized.gateways);
    setActiveGatewayIdState(normalized.activeGatewayId);
    setRuntimeByGatewayId(normalized.runtimeByGatewayId);
  }, []);

  React.useEffect(() => {
    let cancelled = false;

    void (async () => {
      try {
        const client = await AgentOpenClawClient.create();
        if (cancelled) return;
        clientRef.current = client;

        // One-time migration from legacy renderer storage -> agent secure storage.
        const legacy = loadLegacyLocalStorageGateways();
        if (legacy.gateways.length > 0) {
          try {
            await client.importDesktopGateways({
              activeGatewayId: legacy.activeGatewayId,
              gateways: legacy.gateways,
            });
            scrubLegacyLocalStorageSecrets();
          } catch (err) {
            console.warn("OpenClaw legacy migration failed:", err);
          }
        }

        await syncFromAgent();

        unsubscribeEventsRef.current = client.subscribeEvents(
          (event) => {
            if (event.type === "status") {
              setRuntimeByGatewayId((prev) => ({
                ...prev,
                [event.gateway_id]: runtimeFromAgent(event.runtime),
              }));
              return;
            }

            if (event.type === "gateway_event") {
              setRuntimeByGatewayId((prev) => {
                const current = prev[event.gateway_id] ?? emptyRuntime();
                const updated = applyGatewayEventFrame(current, event.frame as GatewayEventFrame);
                if (updated === current) return prev;
                return { ...prev, [event.gateway_id]: updated };
              });
            }
          },
          () => {
            // Background sync can restore state after SSE interruptions.
            void syncFromAgent().catch(() => {});
          },
        );
      } catch (err) {
        console.error("Failed to initialize OpenClaw agent client:", err);
      }
    })();

    return () => {
      cancelled = true;
      unsubscribeEventsRef.current?.();
      unsubscribeEventsRef.current = null;
    };
  }, [syncFromAgent]);

  const active = React.useMemo(() => {
    return (
      gateways.find((gateway) => gateway.id === activeGatewayId) ??
      gateways[0] ?? {
        id: "",
        label: "Gateway",
        gatewayUrl: "",
        token: "",
      }
    );
  }, [activeGatewayId, gateways]);

  const setActiveGatewayId = React.useCallback((id: string) => {
    setActiveGatewayIdState(id);
    const client = clientRef.current;
    if (!client) return;
    void client.updateActiveGateway(id || null).catch(() => {});
  }, []);

  const addGateway = React.useCallback(
    (partial?: Partial<Pick<OpenClawGatewayConfig, "label" | "gatewayUrl" | "token">>) => {
      const client = clientRef.current;
      if (!client) return;

      const label = partial?.label?.trim() ? partial.label.trim() : "Gateway";
      const gatewayUrl = partial?.gatewayUrl?.trim()
        ? partial.gatewayUrl.trim()
        : "ws://127.0.0.1:18789";
      const token = partial?.token?.trim() ? partial.token.trim() : undefined;

      void client
        .createGateway({ label, gatewayUrl, token })
        .then(() => syncFromAgent())
        .catch(() => {});
    },
    [syncFromAgent],
  );

  const updateGateway = React.useCallback(
    (id: string, patch: Partial<Omit<OpenClawGatewayConfig, "id">>) => {
      const client = clientRef.current;
      if (!client) return;

      const nextPatch: {
        label?: string;
        gatewayUrl?: string;
        token?: string;
        deviceToken?: string;
      } = {};

      if (typeof patch.label === "string") nextPatch.label = patch.label;
      if (typeof patch.gatewayUrl === "string") nextPatch.gatewayUrl = patch.gatewayUrl;

      // Agent-backed secrets are write-only from UI. Ignore blank placeholders so we do not
      // accidentally clear stored tokens when a user edits non-secret gateway fields.
      if (typeof patch.token === "string" && patch.token.trim().length > 0) {
        nextPatch.token = patch.token.trim();
      }
      if (typeof patch.deviceToken === "string" && patch.deviceToken.trim().length > 0) {
        nextPatch.deviceToken = patch.deviceToken.trim();
      }

      void client
        .patchGateway(id, nextPatch)
        .then(() => syncFromAgent())
        .catch(() => {});
    },
    [syncFromAgent],
  );

  const removeGateway = React.useCallback(
    (id: string) => {
      const client = clientRef.current;
      if (!client) return;
      void client
        .deleteGateway(id)
        .then(() => syncFromAgent())
        .catch(() => {});
    },
    [syncFromAgent],
  );

  const connectGateway = React.useCallback(
    async (id: string) => {
      const client = clientRef.current;
      if (!client) throw new Error("OpenClaw agent client unavailable");
      await client.connectGateway(id);
      await syncFromAgent();
    },
    [syncFromAgent],
  );

  const disconnectGateway = React.useCallback(
    (id: string) => {
      const client = clientRef.current;
      if (!client) return;
      autoConnectHoldUntilRef.current[id] = Date.now() + 60_000;
      warmupTriggeredRef.current[id] = false;
      void client
        .disconnectGateway(id)
        .then(() => syncFromAgent())
        .catch(() => {});
    },
    [syncFromAgent],
  );

  const connect = React.useCallback(async () => {
    if (!active.id) throw new Error("No active gateway selected");
    await connectGateway(active.id);
  }, [active.id, connectGateway]);

  const disconnect = React.useCallback(() => {
    if (!active.id) return;
    autoConnectHoldUntilRef.current[active.id] = Date.now() + 60_000;
    warmupTriggeredRef.current[active.id] = false;
    disconnectGateway(active.id);
  }, [active.id, disconnectGateway]);

  const connectAll = React.useCallback(async () => {
    const client = clientRef.current;
    if (!client) throw new Error("OpenClaw agent client unavailable");
    await Promise.allSettled(gateways.map((gateway) => client.connectGateway(gateway.id)));
    await syncFromAgent();
  }, [gateways, syncFromAgent]);

  const disconnectAll = React.useCallback(() => {
    const client = clientRef.current;
    if (!client) return;
    const holdUntil = Date.now() + 60_000;
    for (const gateway of gateways) {
      autoConnectHoldUntilRef.current[gateway.id] = holdUntil;
      warmupTriggeredRef.current[gateway.id] = false;
    }

    void Promise.allSettled(gateways.map((gateway) => client.disconnectGateway(gateway.id)))
      .then(() => syncFromAgent())
      .catch(() => {});
  }, [gateways, syncFromAgent]);

  const request = React.useCallback(
    async <TPayload,>(method: string, params?: unknown, opts?: { timeoutMs?: number }) => {
      const client = clientRef.current;
      if (!client) throw new Error("OpenClaw agent client unavailable");
      if (!active.id) throw new Error("No active gateway selected");
      return client.relayRequest<TPayload>({
        gatewayId: active.id,
        method,
        params,
        timeoutMs: opts?.timeoutMs,
      });
    },
    [active.id],
  );

  const requestForGateway = React.useCallback(
    async <TPayload,>(
      gatewayId: string,
      method: string,
      params?: unknown,
      opts?: { timeoutMs?: number },
    ) => {
      const client = clientRef.current;
      if (!client) throw new Error("OpenClaw agent client unavailable");
      return client.relayRequest<TPayload>({
        gatewayId,
        method,
        params,
        timeoutMs: opts?.timeoutMs,
      });
    },
    [],
  );

  const refreshPresence = React.useCallback(
    async (gatewayId = active.id) => {
      const presence = await requestForGateway<unknown[]>(gatewayId, "system-presence", undefined, {
        timeoutMs: 8_000,
      });
      setRuntimeByGatewayId((prev) => ({
        ...prev,
        [gatewayId]: {
          ...(prev[gatewayId] ?? emptyRuntime()),
          presence: Array.isArray(presence) ? presence : [],
        },
      }));
    },
    [active.id, requestForGateway],
  );

  const refreshNodes = React.useCallback(
    async (gatewayId = active.id) => {
      const result = await requestForGateway<{ nodes?: OpenClawNode[] }>(
        gatewayId,
        "node.list",
        undefined,
        { timeoutMs: 10_000 },
      );
      const nodes = Array.isArray(result?.nodes) ? result.nodes : [];
      setRuntimeByGatewayId((prev) => ({
        ...prev,
        [gatewayId]: {
          ...(prev[gatewayId] ?? emptyRuntime()),
          nodes,
        },
      }));
    },
    [active.id, requestForGateway],
  );

  const refreshDevices = React.useCallback(
    async (gatewayId = active.id, opts?: { quiet?: boolean }) => {
      try {
        const snapshot = await requestForGateway<OpenClawDevicePairingSnapshot>(
          gatewayId,
          "device.pair.list",
          undefined,
          { timeoutMs: 10_000 },
        );
        setRuntimeByGatewayId((prev) => ({
          ...prev,
          [gatewayId]: {
            ...(prev[gatewayId] ?? emptyRuntime()),
            devices: snapshot ?? null,
          },
        }));
      } catch (err) {
        if (!opts?.quiet) throw err;
      }
    },
    [active.id, requestForGateway],
  );

  const resolveExecApproval = React.useCallback(
    async (approvalId: string, decision: ExecApprovalDecision, gatewayId = active.id) => {
      await requestForGateway(
        gatewayId,
        "exec.approval.resolve",
        { id: approvalId, decision },
        { timeoutMs: 10_000 },
      );
      setRuntimeByGatewayId((prev) => {
        const current = prev[gatewayId] ?? emptyRuntime();
        return {
          ...prev,
          [gatewayId]: {
            ...current,
            execApprovalQueue: current.execApprovalQueue.filter((item) => item.id !== approvalId),
          },
        };
      });
    },
    [active.id, requestForGateway],
  );

  const approveDevicePairing = React.useCallback(
    async (requestId: string, gatewayId = active.id) => {
      await requestForGateway(
        gatewayId,
        "device.pair.approve",
        { requestId },
        { timeoutMs: 12_000 },
      );
      await refreshDevices(gatewayId, { quiet: true });
    },
    [active.id, refreshDevices, requestForGateway],
  );

  const rejectDevicePairing = React.useCallback(
    async (requestId: string, gatewayId = active.id) => {
      await requestForGateway(
        gatewayId,
        "device.pair.reject",
        { requestId },
        { timeoutMs: 12_000 },
      );
      await refreshDevices(gatewayId, { quiet: true });
    },
    [active.id, refreshDevices, requestForGateway],
  );

  const summary = React.useMemo(() => {
    const rows = gateways.map((gateway) => {
      const runtime = runtimeByGatewayId[gateway.id] ?? emptyRuntime();
      return {
        id: gateway.id,
        label: gateway.label,
        gatewayUrl: gateway.gatewayUrl,
        status: runtime.status,
        nodes: runtime.nodes.length,
        presence: runtime.presence.length,
        approvals: runtime.execApprovalQueue.length,
      };
    });
    return {
      gateways: rows,
      connected: rows.filter((row) => row.status === "connected").length,
    };
  }, [gateways, runtimeByGatewayId]);

  React.useEffect(() => {
    if (!active.id) return;
    const runtime = runtimeByGatewayId[active.id] ?? emptyRuntime();
    if (runtime.status === "connected" || runtime.status === "connecting") return;

    // Guard against re-entry: connectGateway calls syncFromAgent which updates
    // runtimeByGatewayId which re-triggers this effect. Without this guard a
    // fast-failing connection can cause a tight retry loop.
    if (autoConnectInFlightRef.current[active.id]) return;

    const now = Date.now();
    const holdUntil = autoConnectHoldUntilRef.current[active.id] ?? 0;
    if (now < holdUntil) return;

    const lastAttempt = autoConnectAttemptAtRef.current[active.id] ?? 0;
    const retryCooldownMs = runtime.status === "error" ? 6_000 : 2_500;
    if (now - lastAttempt < retryCooldownMs) return;

    autoConnectAttemptAtRef.current[active.id] = now;
    autoConnectInFlightRef.current[active.id] = true;
    void connectGateway(active.id)
      .catch(() => {})
      .finally(() => {
        autoConnectInFlightRef.current[active.id] = false;
      });
  }, [active.id, connectGateway, runtimeByGatewayId]);

  React.useEffect(() => {
    if (!active.id) return;
    const runtime = runtimeByGatewayId[active.id] ?? emptyRuntime();
    if (runtime.status !== "connected") {
      warmupTriggeredRef.current[active.id] = false;
      return;
    }
    if (warmupTriggeredRef.current[active.id]) return;
    warmupTriggeredRef.current[active.id] = true;
    void Promise.allSettled([
      refreshNodes(active.id),
      refreshPresence(active.id),
      refreshDevices(active.id, { quiet: true }),
    ]);
  }, [active.id, refreshDevices, refreshNodes, refreshPresence, runtimeByGatewayId]);

  const value: OpenClawContextValue = {
    gateways,
    activeGatewayId,
    active,
    runtimeByGatewayId,
    summary,
    addGateway,
    updateGateway,
    removeGateway,
    setActiveGatewayId,
    connect,
    disconnect,
    connectGateway,
    disconnectGateway,
    connectAll,
    disconnectAll,
    request,
    refreshPresence,
    refreshNodes,
    refreshDevices,
    resolveExecApproval,
    approveDevicePairing,
    rejectDevicePairing,
  };

  return <OpenClawContext.Provider value={value}>{children}</OpenClawContext.Provider>;
}

export function useOpenClawAgent(): OpenClawContextValue {
  const context = React.useContext(OpenClawContext);
  if (!context) throw new Error("useOpenClawAgent must be used within OpenClawAgentProvider");
  return context;
}
