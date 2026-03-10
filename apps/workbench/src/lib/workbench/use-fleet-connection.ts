// ---------------------------------------------------------------------------
// Fleet Connection Hook & React Context
// ---------------------------------------------------------------------------
import {
  createContext,
  useContext,
  useState,
  useCallback,
  useEffect,
  useRef,
  type ReactNode,
} from "react";
import { createElement } from "react";
import type { FleetConnection, HealthResponse, AgentInfo } from "./fleet-client";
import {
  testConnection as apiTestConnection,
  fetchAgentCount as apiFetchAgentCount,
  fetchAgentList as apiFetchAgentList,
  fetchRemotePolicy as apiFetchRemotePolicy,
  loadSavedConnection,
  loadSavedConnectionAsync,
  saveConnectionConfig,
  clearConnectionConfig,
  validateFleetUrl,
} from "./fleet-client";

// ---- Types ----

export interface RemotePolicyInfo {
  name?: string;
  version?: string;
  policyHash?: string;
  yaml: string;
}

export interface FleetConnectionState {
  connection: FleetConnection;
  isConnecting: boolean;
  error: string | null;
  agents: AgentInfo[];
  remotePolicyInfo: RemotePolicyInfo | null;
}

export interface FleetConnectionActions {
  /** Attempt to connect with the given credentials. */
  connect: (hushdUrl: string, controlApiUrl: string, apiKey: string, controlApiToken?: string) => Promise<boolean>;
  /** Disconnect and clear saved credentials. */
  disconnect: () => void;
  /** Test connection without saving (for the "Test" button). */
  testConnection: (hushdUrl: string, apiKey: string) => Promise<HealthResponse>;
  /** Force refresh agent list. */
  refreshAgents: () => Promise<void>;
  /** Force refresh remote policy info. */
  refreshRemotePolicy: () => Promise<void>;
}

export type FleetConnectionHook = FleetConnectionState & FleetConnectionActions;

// ---- Context ----

const FleetContext = createContext<FleetConnectionHook | null>(null);

export function useFleetConnection(): FleetConnectionHook {
  const ctx = useContext(FleetContext);
  if (!ctx) throw new Error("useFleetConnection must be used within FleetConnectionProvider");
  return ctx;
}

// ---- Constants ----

const HEALTH_POLL_MS = 30_000;
const AGENT_POLL_MS = 60_000;

function assertValidFleetUrl(url: string, fieldName: string) {
  const validation = validateFleetUrl(url);
  if (!validation.valid) {
    throw new Error(`Invalid ${fieldName}: ${validation.reason}`);
  }
}

// ---- Default connection ----

function defaultConnection(): FleetConnection {
  const saved = loadSavedConnection();
  return {
    hushdUrl: saved.hushdUrl ?? "",
    controlApiUrl: saved.controlApiUrl ?? "",
    apiKey: saved.apiKey ?? "",
    controlApiToken: saved.controlApiToken ?? "",
    connected: false,
    hushdHealth: null,
    agentCount: 0,
  };
}

// ---- Provider ----

export function FleetConnectionProvider({ children }: { children: ReactNode }) {
  const [connection, setConnection] = useState<FleetConnection>(defaultConnection);
  const [isConnecting, setIsConnecting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [remotePolicyInfo, setRemotePolicyInfo] = useState<RemotePolicyInfo | null>(null);

  const healthTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const agentTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Finding L8: Use a ref to hold the current connection state so interval
  // callbacks always read the latest value instead of a stale closure capture.
  const connectionRef = useRef(connection);
  useEffect(() => {
    connectionRef.current = connection;
  }, [connection]);

  // ---- Internal: poll health ----
  const pollHealth = useCallback(async (conn: FleetConnection) => {
    if (!conn.connected || !conn.hushdUrl) return;
    try {
      const health = await apiTestConnection(conn.hushdUrl, conn.apiKey);
      setConnection((prev) => ({
        ...prev,
        hushdHealth: health,
        connected: true,
      }));
      setError(null);
    } catch (err) {
      setConnection((prev) => ({ ...prev, connected: false, hushdHealth: null }));
      setError(err instanceof Error ? err.message : "Connection lost");
    }
  }, []);

  // ---- Internal: poll agents ----
  const pollAgents = useCallback(async (conn: FleetConnection) => {
    if (!conn.connected || !conn.hushdUrl) return;
    try {
      const list = await apiFetchAgentList(conn);
      setAgents(list);
      setConnection((prev) => ({ ...prev, agentCount: list.length }));
    } catch {
      // silently continue — stale data is better than no data
    }
  }, []);

  // ---- Internal: fetch remote policy ----
  const fetchRemoteInfo = useCallback(async (conn: FleetConnection) => {
    if (!conn.connected || !conn.hushdUrl) return;
    try {
      const info = await apiFetchRemotePolicy(conn);
      setRemotePolicyInfo(info);
    } catch {
      // not critical
    }
  }, []);

  // ---- Start / stop polling ----
  const startPolling = useCallback(
    (conn: FleetConnection) => {
      stopPolling();

      // Initial fetches
      pollHealth(conn);
      pollAgents(conn);
      fetchRemoteInfo(conn);

      // Finding L8: Read from connectionRef inside interval callbacks to avoid
      // stale closure captures of the initial `conn` value.
      healthTimerRef.current = setInterval(() => pollHealth(connectionRef.current), HEALTH_POLL_MS);
      agentTimerRef.current = setInterval(() => pollAgents(connectionRef.current), AGENT_POLL_MS);
    },
    [pollHealth, pollAgents, fetchRemoteInfo],
  );

  const stopPolling = useCallback(() => {
    if (healthTimerRef.current) {
      clearInterval(healthTimerRef.current);
      healthTimerRef.current = null;
    }
    if (agentTimerRef.current) {
      clearInterval(agentTimerRef.current);
      agentTimerRef.current = null;
    }
  }, []);

  // Cleanup on unmount
  useEffect(() => stopPolling, [stopPolling]);

  // ---- Auto-reconnect if saved credentials exist ----
  // Uses the async secureStore loader (Stronghold on desktop) with a
  // synchronous localStorage fallback for initial render.
  // Finding M19: Use isMounted flag and reconnect lock to prevent races.
  const reconnectLockRef = useRef(false);

  useEffect(() => {
    let isMounted = true;

    async function attemptReconnect() {
      // Prevent concurrent reconnection attempts (Finding M19)
      if (reconnectLockRef.current) return;
      reconnectLockRef.current = true;

      try {
        // Try secureStore first (Stronghold on desktop), then localStorage.
        const saved = await loadSavedConnectionAsync();
        if (!isMounted) return;
        if (!saved.hushdUrl) return;

        const conn: FleetConnection = {
          hushdUrl: saved.hushdUrl ?? "",
          controlApiUrl: saved.controlApiUrl ?? "",
          apiKey: saved.apiKey ?? "",
          controlApiToken: saved.controlApiToken ?? "",
          connected: false,
          hushdHealth: null,
          agentCount: 0,
        };

        try {
          const health = await apiTestConnection(conn.hushdUrl, conn.apiKey);
          if (!isMounted) return;
          const connected: FleetConnection = { ...conn, connected: true, hushdHealth: health };
          setConnection(connected);
          startPolling(connected);
        } catch {
          if (!isMounted) return;
          // Saved creds are stale — show as disconnected but keep the URLs
          setConnection(conn);
        }
      } finally {
        reconnectLockRef.current = false;
      }
    }

    attemptReconnect();
    return () => { isMounted = false; };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ---- Public actions ----

  const connect = useCallback(
    async (hushdUrl: string, controlApiUrl: string, apiKey: string, controlApiToken?: string): Promise<boolean> => {
      setIsConnecting(true);
      setError(null);

      try {
        assertValidFleetUrl(hushdUrl, "hushd URL");
        if (controlApiUrl) {
          assertValidFleetUrl(controlApiUrl, "control API URL");
        }
        const health = await apiTestConnection(hushdUrl, apiKey);
        const conn: FleetConnection = {
          hushdUrl,
          controlApiUrl,
          apiKey,
          controlApiToken: controlApiToken ?? "",
          connected: true,
          hushdHealth: health,
          agentCount: 0,
        };

        await saveConnectionConfig({ hushdUrl, controlApiUrl, apiKey, controlApiToken: controlApiToken ?? "" });
        setConnection(conn);
        startPolling(conn);
        setIsConnecting(false);
        return true;
      } catch (err) {
        setError(err instanceof Error ? err.message : "Connection failed");
        setIsConnecting(false);
        return false;
      }
    },
    [startPolling],
  );

  const disconnect = useCallback(() => {
    stopPolling();
    clearConnectionConfig();
    setConnection({
      hushdUrl: "",
      controlApiUrl: "",
      apiKey: "",
      controlApiToken: "",
      connected: false,
      hushdHealth: null,
      agentCount: 0,
    });
    setAgents([]);
    setRemotePolicyInfo(null);
    setError(null);
  }, [stopPolling]);

  const testConn = useCallback(
    async (hushdUrl: string, apiKey: string): Promise<HealthResponse> => {
      return apiTestConnection(hushdUrl, apiKey);
    },
    [],
  );

  const refreshAgents = useCallback(async () => {
    await pollAgents(connection);
  }, [pollAgents, connection]);

  const refreshRemotePolicy = useCallback(async () => {
    await fetchRemoteInfo(connection);
  }, [fetchRemoteInfo, connection]);

  const value: FleetConnectionHook = {
    connection,
    isConnecting,
    error,
    agents,
    remotePolicyInfo,
    connect,
    disconnect,
    testConnection: testConn,
    refreshAgents,
    refreshRemotePolicy,
  };

  return createElement(FleetContext.Provider, { value }, children);
}
