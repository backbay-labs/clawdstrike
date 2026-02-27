import * as React from "react";
import type { GatewayEventFrame } from "@/services/openclaw/gatewayProtocol";
import { OpenClawGatewayClient, type GatewayConnectionStatus } from "@/services/openclaw/gatewayClient";
import { DEFAULT_GATEWAY_URL } from "@/features/openclaw/openclawFleetUtils";

export type OpenClawGatewayConfig = {
  id: string;
  label: string;
  gatewayUrl: string;
  token: string;
  deviceToken?: string;
};

export type OpenClawNode = {
  nodeId?: string;
  displayName?: string;
  platform?: string;
  version?: string;
  caps?: unknown;
  commands?: unknown;
  connectedAtMs?: number;
  paired?: boolean;
  connected?: boolean;
};

export type OpenClawDevicePairingSnapshot = {
  pending: Array<{
    requestId: string;
    deviceId: string;
    displayName?: string;
    role?: string;
    remoteIp?: string;
  }>;
  paired: Array<{
    deviceId: string;
    role?: string;
    roles?: string[];
    scopes?: string[];
    createdAtMs?: number;
    approvedAtMs?: number;
    tokens?: Array<{ role?: string; scopes?: string[]; createdAtMs?: number }>;
  }>;
};

export type ExecApprovalDecision = "allow-once" | "allow-always" | "deny";

export type ExecApprovalQueueItem = {
  id: string;
  expiresAtMs: number;
  request: {
    command: string;
    ask?: string | null;
    host?: string | null;
    cwd?: string | null;
    agentId?: string | null;
    sessionKey?: string | null;
    resolvedPath?: string | null;
    security?: string | null;
  };
};

export type OpenClawGatewayRuntime = {
  status: GatewayConnectionStatus;
  lastError: string | null;
  connectedAtMs: number | null;
  lastMessageAtMs: number | null;
  presence: unknown[];
  nodes: OpenClawNode[];
  devices: OpenClawDevicePairingSnapshot | null;
  execApprovalQueue: ExecApprovalQueueItem[];
};

export type OpenClawContextValue = {
  gateways: OpenClawGatewayConfig[];
  activeGatewayId: string;
  active: OpenClawGatewayConfig;
  runtimeByGatewayId: Record<string, OpenClawGatewayRuntime>;
  summary: {
    gateways: Array<{
      id: string;
      label: string;
      gatewayUrl: string;
      status: GatewayConnectionStatus;
      nodes: number;
      presence: number;
      approvals: number;
    }>;
    connected: number;
  };
  addGateway: (partial?: Partial<Pick<OpenClawGatewayConfig, "label" | "gatewayUrl" | "token">>) => void;
  updateGateway: (id: string, patch: Partial<Omit<OpenClawGatewayConfig, "id">>) => void;
  removeGateway: (id: string) => void;
  setActiveGatewayId: (id: string) => void;
  connect: () => Promise<void>;
  disconnect: () => void;
  connectGateway: (id: string) => Promise<void>;
  disconnectGateway: (id: string) => void;
  connectAll: () => Promise<void>;
  disconnectAll: () => void;
  request: <TPayload = unknown>(method: string, params?: unknown, opts?: { timeoutMs?: number }) => Promise<TPayload>;
  refreshPresence: (gatewayId?: string) => Promise<void>;
  refreshNodes: (gatewayId?: string) => Promise<void>;
  refreshDevices: (gatewayId?: string, opts?: { quiet?: boolean }) => Promise<void>;
  resolveExecApproval: (approvalId: string, decision: ExecApprovalDecision, gatewayId?: string) => Promise<void>;
  approveDevicePairing: (requestId: string, gatewayId?: string) => Promise<void>;
  rejectDevicePairing: (requestId: string, gatewayId?: string) => Promise<void>;
};

const OpenClawContext = React.createContext<OpenClawContextValue | null>(null);

const STORAGE_KEY = "sdr:openclaw:gateways";
const STORAGE_ACTIVE_KEY = "sdr:openclaw:activeGatewayId";

function defaultGateway(): OpenClawGatewayConfig {
  return {
    id: `gw:${Date.now()}-${Math.random().toString(16).slice(2)}`,
    label: "Local Gateway",
    gatewayUrl: DEFAULT_GATEWAY_URL,
    token: "",
  };
}

function loadGateways(): OpenClawGatewayConfig[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [defaultGateway()];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed) || parsed.length === 0) return [defaultGateway()];
    return parsed
      .map((v) => (typeof v === "object" && v ? (v as Partial<OpenClawGatewayConfig>) : null))
      .filter(Boolean)
      .map((v) => ({
        id: String(v!.id ?? defaultGateway().id),
        label: String(v!.label ?? "Gateway"),
        gatewayUrl: String(v!.gatewayUrl ?? DEFAULT_GATEWAY_URL),
        token: String(v!.token ?? ""),
        deviceToken: typeof v!.deviceToken === "string" ? v!.deviceToken : undefined,
      }));
  } catch {
    return [defaultGateway()];
  }
}

function saveGateways(gateways: OpenClawGatewayConfig[]) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(gateways));
  } catch {
    // ignore
  }
}

function loadActiveGatewayId(gateways: OpenClawGatewayConfig[]): string {
  const first = gateways[0]?.id;
  if (!first) return "";
  try {
    const raw = localStorage.getItem(STORAGE_ACTIVE_KEY);
    if (raw && gateways.some((g) => g.id === raw)) return raw;
  } catch {
    // ignore
  }
  return first;
}

function saveActiveGatewayId(id: string) {
  try {
    localStorage.setItem(STORAGE_ACTIVE_KEY, id);
  } catch {
    // ignore
  }
}

function createEmptyRuntime(): OpenClawGatewayRuntime {
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

export function applyGatewayEventFrame(
  current: OpenClawGatewayRuntime,
  frame: GatewayEventFrame
): OpenClawGatewayRuntime {
  // Presence updates may be deltas; for now keep the last payload on a best-effort basis.
  if (frame.event === "presence") {
    const payload = frame.payload;
    const list = Array.isArray(payload) ? payload : [];
    return { ...current, presence: list };
  }

  if (frame.event === "exec.approval.requested") {
    const payload = frame.payload as Partial<ExecApprovalQueueItem> | undefined;
    if (!payload?.id || !payload.request?.command || typeof payload.expiresAtMs !== "number") return current;

    const deduped = current.execApprovalQueue.filter((a) => a.id !== payload.id);
    return {
      ...current,
      execApprovalQueue: [{ ...(payload as ExecApprovalQueueItem) }, ...deduped].slice(0, 100),
    };
  }

  if (frame.event === "exec.approval.resolved" || frame.event === "exec.approval.rejected") {
    const approvalId = typeof (frame.payload as Record<string, unknown>)?.approvalId === "string"
      ? (frame.payload as Record<string, unknown>).approvalId as string
      : typeof (frame.payload as Record<string, unknown>)?.id === "string"
        ? (frame.payload as Record<string, unknown>).id as string
        : null;
    if (approvalId && current.execApprovalQueue) {
      return {
        ...current,
        execApprovalQueue: current.execApprovalQueue.filter((a) => a.id !== approvalId),
      };
    }
    return current;
  }

  if (frame.event === "node.connected" || frame.event === "node.updated") {
    const payload = frame.payload;
    if (payload && typeof payload === "object") {
      const raw = payload as Record<string, unknown>;
      const nodeId = typeof raw.nodeId === "string" ? raw.nodeId : typeof raw.id === "string" ? raw.id : undefined;
      if (nodeId) {
        const node: OpenClawNode = { ...(raw as OpenClawNode), nodeId };
        const nodes = [...(current.nodes ?? [])];
        const idx = nodes.findIndex((n) => n.nodeId === nodeId);
        if (idx >= 0) {
          nodes[idx] = node;
        } else {
          nodes.push(node);
        }
        return { ...current, nodes };
      }
    }
  }

  if (frame.event === "node.disconnected") {
    const payload = frame.payload;
    if (payload && typeof payload === "object") {
      const raw = payload as Record<string, unknown>;
      const nodeId = typeof raw.nodeId === "string" ? raw.nodeId : typeof raw.id === "string" ? raw.id : undefined;
      if (nodeId) {
        const nodes = (current.nodes ?? []).filter((n) => n.nodeId !== nodeId);
        return { ...current, nodes };
      }
    }
  }

  return current;
}

export function OpenClawProvider({ children }: { children: React.ReactNode }) {
  const initialGatewaysRef = React.useRef<OpenClawGatewayConfig[] | null>(null);
  if (initialGatewaysRef.current === null) initialGatewaysRef.current = loadGateways();
  const initialGateways = initialGatewaysRef.current;

  const [gateways, setGateways] = React.useState<OpenClawGatewayConfig[]>(initialGateways);
  const gatewaysRef = React.useRef<OpenClawGatewayConfig[]>(initialGateways);
  const [activeGatewayId, setActiveGatewayIdState] = React.useState(() => loadActiveGatewayId(initialGateways));
  const [runtimeByGatewayId, setRuntimeByGatewayId] = React.useState<Record<string, OpenClawGatewayRuntime>>(() => {
    const initial: Record<string, OpenClawGatewayRuntime> = {};
    for (const g of initialGateways) initial[g.id] = createEmptyRuntime();
    return initial;
  });

  const clientsRef = React.useRef<Record<string, OpenClawGatewayClient>>({});
  const lastStatusByGatewayIdRef = React.useRef<Record<string, GatewayConnectionStatus>>({});

  React.useEffect(() => {
    return () => {
      for (const client of Object.values(clientsRef.current)) client.disconnect();
      clientsRef.current = {};
    };
  }, []);

  React.useEffect(() => {
    gatewaysRef.current = gateways;
    saveGateways(gateways);
    setRuntimeByGatewayId((prev) => {
      const next: Record<string, OpenClawGatewayRuntime> = { ...prev };
      for (const g of gateways) next[g.id] ??= createEmptyRuntime();
      for (const id of Object.keys(next)) {
        if (!gateways.some((g) => g.id === id)) delete next[id];
      }
      return next;
    });

    if (!gateways.some((g) => g.id === activeGatewayId)) {
      const nextActive = gateways[0]?.id ?? "";
      setActiveGatewayIdState(nextActive);
      saveActiveGatewayId(nextActive);
    }
  }, [activeGatewayId, gateways]);

  const active = React.useMemo(() => {
    return gateways.find((g) => g.id === activeGatewayId) ?? gateways[0] ?? defaultGateway();
  }, [activeGatewayId, gateways]);

  const setActiveGatewayId = React.useCallback((id: string) => {
    setActiveGatewayIdState(id);
    saveActiveGatewayId(id);
  }, []);

  const addGateway = React.useCallback(
    (partial?: Partial<Pick<OpenClawGatewayConfig, "label" | "gatewayUrl" | "token">>) => {
      setGateways((prev) => {
        const base = defaultGateway();
        const next: OpenClawGatewayConfig = {
          ...base,
          label: partial?.label?.trim() ? partial.label.trim() : base.label,
          gatewayUrl: partial?.gatewayUrl?.trim() ? partial.gatewayUrl.trim() : base.gatewayUrl,
          token: typeof partial?.token === "string" ? partial.token : base.token,
        };
        const updated = [...prev, next];
        gatewaysRef.current = updated;
        return updated;
      });
    },
    []
  );

  const updateGateway = React.useCallback((id: string, patch: Partial<Omit<OpenClawGatewayConfig, "id">>) => {
    setGateways((prev) => {
      const updated = prev.map((g) => {
        if (g.id !== id) return g;
        return {
          ...g,
          ...patch,
          label: typeof patch.label === "string" ? patch.label : g.label,
          gatewayUrl: typeof patch.gatewayUrl === "string" ? patch.gatewayUrl : g.gatewayUrl,
          token: typeof patch.token === "string" ? patch.token : g.token,
        };
      });
      gatewaysRef.current = updated;
      return updated;
    });
  }, []);

  const removeGateway = React.useCallback((id: string) => {
    disconnectGatewayInternal(id, clientsRef, setRuntimeByGatewayId);
    setGateways((prev) => {
      const updated = prev.filter((g) => g.id !== id);
      gatewaysRef.current = updated;
      return updated;
    });
  }, []);

  const request = React.useCallback(
    async <TPayload,>(method: string, params?: unknown, opts?: { timeoutMs?: number }) => {
      const client = clientsRef.current[active.id];
      if (!client) throw new Error("Not connected");
      return client.request<TPayload>(method, params, opts);
    },
    [active.id]
  );

  const requestForGateway = React.useCallback(
    async <TPayload,>(gatewayId: string, method: string, params?: unknown, opts?: { timeoutMs?: number }) => {
      const client = clientsRef.current[gatewayId];
      if (!client) throw new Error("Not connected");
      return client.request<TPayload>(method, params, opts);
    },
    []
  );

  const refreshPresence = React.useCallback(
    async (gatewayId = active.id) => {
      const presence = await requestForGateway<unknown[]>(gatewayId, "system-presence", undefined, { timeoutMs: 8_000 });
      setRuntimeByGatewayId((prev) => ({
        ...prev,
        [gatewayId]: { ...(prev[gatewayId] ?? createEmptyRuntime()), presence: Array.isArray(presence) ? presence : [] },
      }));
    },
    [active.id, requestForGateway]
  );

  const refreshNodes = React.useCallback(
    async (gatewayId = active.id) => {
      const result = await requestForGateway<{ nodes?: OpenClawNode[] }>(gatewayId, "node.list", undefined, { timeoutMs: 10_000 });
      const nodes = Array.isArray(result?.nodes) ? result.nodes : [];
      setRuntimeByGatewayId((prev) => ({
        ...prev,
        [gatewayId]: { ...(prev[gatewayId] ?? createEmptyRuntime()), nodes },
      }));
    },
    [active.id, requestForGateway]
  );

  const refreshDevices = React.useCallback(
    async (gatewayId = active.id, opts?: { quiet?: boolean }) => {
      try {
        const snapshot = await requestForGateway<OpenClawDevicePairingSnapshot>(gatewayId, "device.pair.list", undefined, { timeoutMs: 10_000 });
        setRuntimeByGatewayId((prev) => ({
          ...prev,
          [gatewayId]: { ...(prev[gatewayId] ?? createEmptyRuntime()), devices: snapshot ?? null },
        }));
      } catch (err) {
        if (!opts?.quiet) throw err;
      }
    },
    [active.id, requestForGateway]
  );

  const connectGateway = React.useCallback(
    async (id: string) => {
      const gw = gatewaysRef.current.find((g) => g.id === id);
      if (!gw) return;

      const existing = clientsRef.current[id];
      if (existing) existing.disconnect();

      const client = new OpenClawGatewayClient(gw.gatewayUrl, {
        token: gw.token,
        deviceToken: gw.deviceToken,
        instanceId: `sdr:${id}`,
        autoReconnect: true,
        reconnectOnCleanClose: true,
        reconnect: { maxAttempts: 20, initialDelayMs: 400, maxDelayMs: 12_000, backoffFactor: 1.6, jitterRatio: 0.15 },
      });
      clientsRef.current[id] = client;

      client.onStatus((snap) => {
        const previousStatus = lastStatusByGatewayIdRef.current[id];
        lastStatusByGatewayIdRef.current[id] = snap.status;

        setRuntimeByGatewayId((prev) => ({
          ...prev,
          [id]: {
            ...(prev[id] ?? createEmptyRuntime()),
            status: snap.status,
            lastError: snap.lastError,
            connectedAtMs: snap.connectedAtMs,
            lastMessageAtMs: snap.lastMessageAtMs,
          },
        }));

        if (snap.status === "connected" && previousStatus !== "connected") {
          void Promise.all([refreshPresence(id), refreshNodes(id), refreshDevices(id, { quiet: true })]).catch(() => {});
        }
      });

      client.onEvent((evt) => handleGatewayEvent(id, evt, setRuntimeByGatewayId));

      try {
        await client.connect();
      } catch (err) {
        // Do NOT call disconnectGatewayInternal here — that invokes
        // client.disconnect() which sets manualDisconnect = true and
        // permanently kills auto-reconnect.  Instead, mark as disconnected
        // and rethrow so the caller can decide whether to retry.
        const message = err instanceof Error ? err.message : String(err);
        console.warn(`[OpenClaw] initial connect failed for gateway ${id}: ${message}`);
        setRuntimeByGatewayId((prev) => ({
          ...prev,
          [id]: {
            ...(prev[id] ?? createEmptyRuntime()),
            status: "disconnected",
            lastError: message,
          },
        }));
        throw err;
      }
    },
    [refreshDevices, refreshNodes, refreshPresence]
  );

  const connect = React.useCallback(async () => connectGateway(active.id), [active.id, connectGateway]);

  const disconnectGateway = React.useCallback((id: string) => {
    disconnectGatewayInternal(id, clientsRef, setRuntimeByGatewayId);
  }, []);

  const disconnect = React.useCallback(() => disconnectGateway(active.id), [active.id, disconnectGateway]);

  const connectAll = React.useCallback(async () => {
    const current = gatewaysRef.current;
    await Promise.allSettled(current.map((g) => connectGateway(g.id)));
  }, [connectGateway]);

  const disconnectAll = React.useCallback(() => {
    for (const g of gatewaysRef.current) disconnectGatewayInternal(g.id, clientsRef, setRuntimeByGatewayId);
  }, []);

  const resolveExecApproval = React.useCallback(
    async (approvalId: string, decision: ExecApprovalDecision, gatewayId = active.id) => {
      await requestForGateway(gatewayId, "exec.approval.resolve", { id: approvalId, decision }, { timeoutMs: 10_000 });
      setRuntimeByGatewayId((prev) => {
        const current = prev[gatewayId] ?? createEmptyRuntime();
        return {
          ...prev,
          [gatewayId]: {
            ...current,
            execApprovalQueue: current.execApprovalQueue.filter((a) => a.id !== approvalId),
          },
        };
      });
    },
    [active.id, requestForGateway]
  );

  const approveDevicePairing = React.useCallback(
    async (requestId: string, gatewayId = active.id) => {
      await requestForGateway(gatewayId, "device.pair.approve", { requestId }, { timeoutMs: 12_000 });
      await refreshDevices(gatewayId, { quiet: true });
    },
    [active.id, refreshDevices, requestForGateway]
  );

  const rejectDevicePairing = React.useCallback(
    async (requestId: string, gatewayId = active.id) => {
      await requestForGateway(gatewayId, "device.pair.reject", { requestId }, { timeoutMs: 12_000 });
      await refreshDevices(gatewayId, { quiet: true });
    },
    [active.id, refreshDevices, requestForGateway]
  );

  const summary = React.useMemo(() => {
    const rows = gateways.map((g) => {
      const rt = runtimeByGatewayId[g.id] ?? createEmptyRuntime();
      return {
        id: g.id,
        label: g.label,
        gatewayUrl: g.gatewayUrl,
        status: rt.status,
        nodes: rt.nodes.length,
        presence: rt.presence.length,
        approvals: rt.execApprovalQueue.length,
      };
    });
    return { gateways: rows, connected: rows.filter((r) => r.status === "connected").length };
  }, [gateways, runtimeByGatewayId]);

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

function disconnectGatewayInternal(
  gatewayId: string,
  clientsRef: React.RefObject<Record<string, OpenClawGatewayClient>>,
  setRuntime: React.Dispatch<React.SetStateAction<Record<string, OpenClawGatewayRuntime>>>
) {
  const client = clientsRef.current[gatewayId];
  if (client) client.disconnect();
  delete clientsRef.current[gatewayId];
  setRuntime((prev) => ({
    ...prev,
    [gatewayId]: { ...(prev[gatewayId] ?? createEmptyRuntime()), status: "disconnected" },
  }));
}

function handleGatewayEvent(
  gatewayId: string,
  frame: GatewayEventFrame,
  setRuntime: React.Dispatch<React.SetStateAction<Record<string, OpenClawGatewayRuntime>>>
) {
  setRuntime((prev) => {
    const current = prev[gatewayId] ?? createEmptyRuntime();
    const next = applyGatewayEventFrame(current, frame);
    if (next === current) return prev;
    return { ...prev, [gatewayId]: next };
  });
}

export function useOpenClaw(): OpenClawContextValue {
  const ctx = React.useContext(OpenClawContext);
  if (!ctx) throw new Error("useOpenClaw must be used within OpenClawProvider");
  return ctx;
}
