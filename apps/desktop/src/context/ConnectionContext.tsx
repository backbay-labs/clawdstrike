/**
 * ConnectionContext - Hushd daemon connection state management
 */
import { createContext, useContext, useCallback, useState, useEffect, type ReactNode } from "react";

export type ConnectionMode = "local" | "remote" | "embedded";
export type ConnectionStatus = "disconnected" | "connecting" | "connected" | "error";

export interface DaemonInfo {
  version: string;
  policy_hash?: string;
  policy_name?: string;
  uptime_secs?: number;
}

export interface ConnectionState {
  mode: ConnectionMode;
  daemonUrl: string;
  status: ConnectionStatus;
  info?: DaemonInfo;
  error?: string;
  lastConnected?: number;
}

interface ConnectionContextValue extends ConnectionState {
  setDaemonUrl: (url: string) => void;
  setMode: (mode: ConnectionMode) => void;
  connect: () => Promise<void>;
  disconnect: () => void;
  testConnection: (url?: string) => Promise<DaemonInfo>;
}

const ConnectionContext = createContext<ConnectionContextValue | null>(null);

const STORAGE_KEY = "sdr:connection";
const DEFAULT_URL = "http://localhost:8765";

interface StoredConnection {
  mode: ConnectionMode;
  daemonUrl: string;
}

function loadStoredConnection(): StoredConnection {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const data = JSON.parse(raw);
      return {
        mode: data.mode ?? "local",
        daemonUrl: data.daemonUrl ?? DEFAULT_URL,
      };
    }
  } catch {
    // Ignore
  }
  return { mode: "local", daemonUrl: DEFAULT_URL };
}

function saveConnection(data: StoredConnection): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    // Ignore
  }
}

export function ConnectionProvider({ children }: { children: ReactNode }) {
  const stored = loadStoredConnection();

  const [state, setState] = useState<ConnectionState>({
    mode: stored.mode,
    daemonUrl: stored.daemonUrl,
    status: "disconnected",
  });

  const setDaemonUrl = useCallback((url: string) => {
    setState((s) => ({ ...s, daemonUrl: url, status: "disconnected", error: undefined }));
    saveConnection({ mode: state.mode, daemonUrl: url });
  }, [state.mode]);

  const setMode = useCallback((mode: ConnectionMode) => {
    setState((s) => ({ ...s, mode, status: "disconnected", error: undefined }));
    saveConnection({ mode, daemonUrl: state.daemonUrl });
  }, [state.daemonUrl]);

  const testConnection = useCallback(async (url?: string): Promise<DaemonInfo> => {
    const targetUrl = url ?? state.daemonUrl;
    const response = await fetch(`${targetUrl}/health`);
    if (!response.ok) {
      throw new Error(`Connection failed: ${response.status}`);
    }
    const data = await response.json();
    return {
      version: data.version ?? "unknown",
      policy_hash: data.policy_hash,
      policy_name: data.policy_name,
      uptime_secs: data.uptime_secs,
    };
  }, [state.daemonUrl]);

  const connect = useCallback(async () => {
    setState((s) => ({ ...s, status: "connecting", error: undefined }));
    try {
      const info = await testConnection();
      setState((s) => ({
        ...s,
        status: "connected",
        info,
        lastConnected: Date.now(),
        error: undefined,
      }));
    } catch (e) {
      const message = e instanceof Error ? e.message : "Connection failed";
      setState((s) => ({ ...s, status: "error", error: message }));
      throw e;
    }
  }, [testConnection]);

  const disconnect = useCallback(() => {
    setState((s) => ({ ...s, status: "disconnected", info: undefined, error: undefined }));
  }, []);

  // Auto-connect on mount
  useEffect(() => {
    connect().catch(() => {
      // Silent fail on auto-connect
    });
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Periodic health check
  useEffect(() => {
    if (state.status !== "connected") return;

    const interval = setInterval(async () => {
      try {
        const info = await testConnection();
        setState((s) => ({ ...s, info }));
      } catch {
        setState((s) => ({ ...s, status: "error", error: "Connection lost" }));
      }
    }, 30000); // 30 second health check

    return () => clearInterval(interval);
  }, [state.status, testConnection]);

  const value: ConnectionContextValue = {
    ...state,
    setDaemonUrl,
    setMode,
    connect,
    disconnect,
    testConnection,
  };

  return <ConnectionContext.Provider value={value}>{children}</ConnectionContext.Provider>;
}

export function useConnection(): ConnectionContextValue {
  const context = useContext(ConnectionContext);
  if (!context) {
    throw new Error("useConnection must be used within ConnectionProvider");
  }
  return context;
}

export function useConnectionStatus(): ConnectionStatus {
  return useConnection().status;
}

export function useDaemonInfo(): DaemonInfo | undefined {
  return useConnection().info;
}
