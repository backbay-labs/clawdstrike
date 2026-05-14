// Fleet Connection — Zustand + immer store for hushd fleet connectivity.
//
// Migrated from React Context + useState. Preserves credential separation
// (credentials are kept in a closure, never exposed in the store state),
// health polling, agent polling, SSE streaming, and auto-reconnect behavior.
import { useLayoutEffect, type ReactElement, type ReactNode } from "react";
import { create } from "zustand";
import { immer } from "zustand/middleware/immer";
import { createSelectors } from "@/lib/create-selectors";
import type {
  FleetConnection,
  FleetConnectionInfo,
  HealthResponse,
  AgentInfo,
} from "@/features/fleet/fleet-client";
import {
  testConnection as apiTestConnection,
  fetchAgentList as apiFetchAgentList,
  fetchRemotePolicy as apiFetchRemotePolicy,
  loadSavedConnection,
  loadSavedConnectionAsync,
  saveConnectionConfig,
  clearConnectionConfig,
  validateFleetUrl,
  redactFleetConnection,
} from "@/features/fleet/fleet-client";
import { secureStore } from "@/features/settings/secure-store";
import { FleetEventStream, type FleetSSEState } from "@/features/fleet/fleet-event-stream";
import { reduceFleetEvent } from "@/features/fleet/fleet-event-reducer";
import type { CheckEventData } from "@/features/fleet/fleet-event-reducer";
import { useSignalStore } from "@/features/findings/stores/signal-store";
import type { Signal } from "@/lib/workbench/signal-pipeline";

// ---- Types ----

export interface RemotePolicyInfo {
  name?: string;
  version?: string;
  policyHash?: string;
  yaml: string;
}

export interface FleetConnectionState {
  /**
   * Credential-free connection info. Credentials are NOT included here — use
   * `getCredentials()` to obtain them when needed for API calls.
   */
  connection: FleetConnectionInfo;
  isConnecting: boolean;
  error: string | null;
  /** Warning surfaced after 3+ consecutive poll failures. */
  pollError: string | null;
  /** True when credentials are stored in browser session only (not Stronghold). */
  secureStorageWarning: boolean;
  agents: AgentInfo[];
  remotePolicyInfo: RemotePolicyInfo | null;
  /** SSE connection state: idle before first connect, then tracks lifecycle. */
  sseState: FleetSSEState;
}

export interface FleetCredentials {
  apiKey: string;
  controlApiToken: string;
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
  /**
   * Retrieve credentials from the internal store. Credentials are never
   * included in the `connection` state object; call this method when you
   * need them for an API call.
   */
  getCredentials: () => FleetCredentials;
  /**
   * Build a full FleetConnection (with credentials) for passing to fleet-client
   * API functions. This merges the credential-free connection info with the
   * stored credentials.
   */
  getAuthenticatedConnection: () => FleetConnection;
}

export type FleetConnectionHook = FleetConnectionState & FleetConnectionActions;

// ---- Constants ----

const HEALTH_POLL_MS = 30_000;
export const AGENT_POLL_MS = 60_000;
let lastFleetConnectionSnapshot = readFleetConnectionSnapshot();

function normalizeFleetUrl(url: string): string {
  return url.trim().replace(/\/+$/, "");
}

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

function readFleetConnectionSnapshot(): string {
  try {
    return JSON.stringify(loadSavedConnection());
  } catch {
    return "";
  }
}

// ---------------------------------------------------------------------------
// Fleet check event -> Signal bridge (INTEL-01)
// ---------------------------------------------------------------------------

function checkEventToSignal(check: CheckEventData): Signal {
  const verdict = check.verdict?.toLowerCase();
  const severity = verdict === "deny" ? "high" : verdict === "warn" ? "medium" : "low";
  return {
    id: crypto.randomUUID(),
    type: "policy_violation",
    source: {
      sentinelId: null,
      guardId: check.guard ?? null,
      externalFeed: null,
      provenance: "guard_evaluation",
    },
    timestamp: Date.now(),
    severity,
    confidence: 0.8,
    data: {
      kind: "fleet_check",
      summary: `${check.action_type} on ${check.target}: ${check.verdict}`,
      actionType: check.action_type as any,
      verdict: verdict === "deny" ? "deny" : verdict === "warn" ? "warn" : undefined,
      target: check.target,
    },
    context: {
      agentId: check.agent_id ?? "unknown",
      agentName: check.agent_id ?? "unknown",
      sessionId: check.session_id ?? "unknown",
      flags: check.guard ? [{ type: "guard", reason: check.guard }] : [],
    },
    relatedSignals: [],
    ttl: null,
    findingId: null,
  };
}

// ---------------------------------------------------------------------------
// Credential closure — keeps apiKey + controlApiToken out of the Zustand
// state tree so they are never serialized / exposed via selectors.
// ---------------------------------------------------------------------------

let _credentials: FleetCredentials = { apiKey: "", controlApiToken: "" };

function setCredentials(apiKey: string, controlApiToken: string) {
  _credentials = { apiKey, controlApiToken };
}

function getCredentials(): FleetCredentials {
  return { ..._credentials };
}

/** Build a full FleetConnection from the store state + credential closure. */
function buildAuthenticatedConnection(info: FleetConnectionInfo): FleetConnection {
  return {
    ...info,
    apiKey: _credentials.apiKey,
    controlApiToken: _credentials.controlApiToken,
  };
}

// ---------------------------------------------------------------------------
// Polling machinery
// ---------------------------------------------------------------------------

let healthTimer: ReturnType<typeof setInterval> | null = null;
let agentTimer: ReturnType<typeof setInterval> | null = null;
let consecutivePollFailures = 0;
let fleetEventStream: FleetEventStream | null = null;

function stopPolling(): void {
  if (healthTimer) {
    clearInterval(healthTimer);
    healthTimer = null;
  }
  if (agentTimer) {
    clearInterval(agentTimer);
    agentTimer = null;
  }
  if (fleetEventStream) {
    fleetEventStream.disconnect();
    fleetEventStream = null;
  }
}

function syncFleetConnectionStoreWithStorage(): void {
  const snapshot = readFleetConnectionSnapshot();
  if (snapshot === lastFleetConnectionSnapshot) {
    return;
  }

  const saved = loadSavedConnection();
  stopPolling();
  consecutivePollFailures = 0;
  setCredentials(saved.apiKey ?? "", saved.controlApiToken ?? "");
  lastFleetConnectionSnapshot = snapshot;
  useFleetConnectionStoreBase.setState({
    connection: {
      hushdUrl: saved.hushdUrl ?? "",
      controlApiUrl: saved.controlApiUrl ?? "",
      connected: false,
      hushdHealth: null,
      agentCount: 0,
    },
    isConnecting: false,
    error: null,
    pollError: null,
    secureStorageWarning: false,
    agents: [],
    remotePolicyInfo: null,
    sseState: "idle",
  });
}

// ---------------------------------------------------------------------------
// Zustand store
// ---------------------------------------------------------------------------

export interface FleetStoreState extends FleetConnectionState {
  actions: FleetConnectionActions;
}

const useFleetConnectionStoreBase = create<FleetStoreState>()(
  immer((set, get) => {
    const initial = defaultConnection();

    // Seed credential closure from initial (synchronous) load
    setCredentials(initial.apiKey, initial.controlApiToken);

    // ---- Internal polling helpers ----

    function pollHealth(): void {
      const conn = buildAuthenticatedConnection(get().connection);
      if (!conn.connected || !conn.hushdUrl) return;
      apiTestConnection(conn.hushdUrl, conn.apiKey)
        .then((health) => {
          set((state) => {
            state.connection.hushdHealth = health as any;
            state.connection.connected = true;
          });
          set((state) => {
            state.error = null;
          });
        })
        .catch((err) => {
          set((state) => {
            state.connection.connected = false;
            state.connection.hushdHealth = null;
            state.error = err instanceof Error ? err.message : "Connection lost";
          });
        });
    }

    function pollAgents(): void {
      const conn = buildAuthenticatedConnection(get().connection);
      if (!conn.connected || !conn.hushdUrl) return;
      const remotePolicyVersion =
        get().remotePolicyInfo?.policyHash ?? get().remotePolicyInfo?.version;
      apiFetchAgentList(
        conn,
        remotePolicyVersion ? { expectedPolicyVersion: remotePolicyVersion } : undefined,
      )
        .then((list) => {
          set((state) => {
            state.agents = list as any;
            state.connection.agentCount = list.length;
          });
          consecutivePollFailures = 0;
          set((state) => {
            state.pollError = null;
          });
        })
        .catch((err) => {
          const message = err instanceof Error ? err.message : String(err);

          // Auth failures are non-transient — surface immediately
          if (/\b(401|403)\b/.test(message) || /unauthorized|forbidden/i.test(message)) {
            set((state) => {
              state.connection.connected = false;
              state.error = `Authentication failed: ${message}`;
              state.pollError = `Authentication failed: ${message}`;
            });
            consecutivePollFailures = 0;
            return;
          }

          // Track consecutive failures for transient errors
          consecutivePollFailures += 1;
          if (consecutivePollFailures >= 3) {
            set((state) => {
              state.pollError = `Agent polling failing repeatedly: ${message}`;
            });
            console.warn(
              `[fleet-connection] pollAgents: ${consecutivePollFailures} consecutive failures — ${message}`,
            );
          }
          // First 1-2 failures: silently continue (stale data is better than no data)
        });
    }

    function fetchRemoteInfo(): void {
      const conn = buildAuthenticatedConnection(get().connection);
      if (!conn.connected || !conn.hushdUrl) return;
      apiFetchRemotePolicy(conn)
        .then((info) => {
          set((state) => {
            state.remotePolicyInfo = info as any;
          });
        })
        .catch(() => {
          // not critical
        });
    }

    function startPolling(conn: FleetConnection): void {
      stopPolling();

      // Seed credential closure with the connected credentials
      setCredentials(conn.apiKey, conn.controlApiToken);

      // Initial fetches
      pollHealth();
      pollAgents();
      fetchRemoteInfo();

      healthTimer = setInterval(pollHealth, HEALTH_POLL_MS);
      agentTimer = setInterval(pollAgents, AGENT_POLL_MS);

      // Start SSE stream for real-time agent updates (additive to polling)
      fleetEventStream = new FleetEventStream({
        hushdUrl: conn.hushdUrl,
        getApiKey: () => _credentials.apiKey,
        onEvent: (event) => {
          const currentAgents = get().agents;
          const result = reduceFleetEvent(currentAgents, event);
          set((state) => {
            state.agents = result.agents as any;
            state.connection.agentCount = result.agents.length;
          });
          // Bridge check events to signal pipeline (INTEL-01)
          if (event.type === "check" && event.data) {
            const signal = checkEventToSignal(event.data as CheckEventData);
            useSignalStore.getState().actions.ingestSignal(signal);
          }
          if (result.refreshPolicy) {
            fetchRemoteInfo();
          }
        },
        onStateChange: (sseState) => {
          set((state) => {
            state.sseState = sseState;
          });
        },
        onReconnect: () => pollAgents(),
      });
      fleetEventStream.connect();
    }

    // ---- Auto-reconnect ----
    // Runs once at store creation time (replaces the useEffect in the old provider).
    let reconnectLock = false;

    function attemptReconnect(): void {
      if (reconnectLock) return;
      reconnectLock = true;

      loadSavedConnectionAsync()
        .then(async (saved) => {
          if (!saved.hushdUrl) {
            reconnectLock = false;
            return;
          }

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
            const connected: FleetConnection = { ...conn, connected: true, hushdHealth: health };
            setCredentials(conn.apiKey, conn.controlApiToken);
            set((state) => {
              state.connection = redactFleetConnection(connected) as any;
            });
            startPolling(connected);

            // Check secure storage backend on auto-reconnect
            secureStore
              .isSecure()
              .then((secure) => {
                set((state) => {
                  state.secureStorageWarning = !secure;
                });
              })
              .catch(() => {
                set((state) => {
                  state.secureStorageWarning = true;
                });
              });
          } catch {
            // Saved creds are stale — show as disconnected but keep the URLs
            setCredentials(conn.apiKey, conn.controlApiToken);
            set((state) => {
              state.connection = redactFleetConnection(conn) as any;
            });
          }

          reconnectLock = false;
        })
        .catch(() => {
          reconnectLock = false;
        });
    }

    // Kick off auto-reconnect (equivalent to the useEffect([], ...) in the old provider)
    setTimeout(attemptReconnect, 0);

    return {
      connection: redactFleetConnection(initial),
      isConnecting: false,
      error: null,
      pollError: null,
      secureStorageWarning: false,
      agents: [],
      remotePolicyInfo: null,
      sseState: "idle" as FleetSSEState,

      actions: {
        connect: async (
          hushdUrl: string,
          controlApiUrl: string,
          apiKey: string,
          controlApiToken?: string,
        ): Promise<boolean> => {
          set((state) => {
            state.isConnecting = true;
            state.error = null;
          });

          try {
            const normalizedHushdUrl = normalizeFleetUrl(hushdUrl);
            const normalizedControlApiUrl = normalizeFleetUrl(controlApiUrl);

            assertValidFleetUrl(normalizedHushdUrl, "hushd URL");
            if (normalizedControlApiUrl) {
              assertValidFleetUrl(normalizedControlApiUrl, "control API URL");
            }

            const health = await apiTestConnection(normalizedHushdUrl, apiKey);
            const conn: FleetConnection = {
              hushdUrl: normalizedHushdUrl,
              controlApiUrl: normalizedControlApiUrl,
              apiKey,
              controlApiToken: controlApiToken ?? "",
              connected: true,
              hushdHealth: health,
              agentCount: 0,
            };

            await saveConnectionConfig({
              hushdUrl: normalizedHushdUrl,
              controlApiUrl: normalizedControlApiUrl,
              apiKey,
              controlApiToken: controlApiToken ?? "",
            });
            lastFleetConnectionSnapshot = readFleetConnectionSnapshot();

            setCredentials(apiKey, controlApiToken ?? "");
            set((state) => {
              state.connection = redactFleetConnection(conn) as any;
              state.isConnecting = false;
            });
            startPolling(conn);

            // Check if credentials are stored securely (Stronghold) or in browser session
            secureStore
              .isSecure()
              .then((secure) => {
                set((state) => {
                  state.secureStorageWarning = !secure;
                });
              })
              .catch(() => {
                set((state) => {
                  state.secureStorageWarning = true;
                });
              });

            return true;
          } catch (err) {
            set((state) => {
              state.error = err instanceof Error ? err.message : "Connection failed";
              state.isConnecting = false;
            });
            return false;
          }
        },

        disconnect: () => {
          stopPolling();
          clearConnectionConfig();
          lastFleetConnectionSnapshot = readFleetConnectionSnapshot();
          setCredentials("", "");
          set((state) => {
            state.connection = {
              hushdUrl: "",
              controlApiUrl: "",
              connected: false,
              hushdHealth: null,
              agentCount: 0,
            };
            state.agents = [];
            state.remotePolicyInfo = null;
            state.error = null;
            state.sseState = "idle";
          });
        },

        testConnection: async (hushdUrl: string, apiKey: string): Promise<HealthResponse> => {
          return apiTestConnection(hushdUrl, apiKey);
        },

        refreshAgents: async () => {
          pollAgents();
        },

        refreshRemotePolicy: async () => {
          fetchRemoteInfo();
        },

        getCredentials: (): FleetCredentials => {
          return getCredentials();
        },

        getAuthenticatedConnection: (): FleetConnection => {
          return buildAuthenticatedConnection(get().connection);
        },
      },
    };
  }),
);

export const useFleetConnectionStore = createSelectors(useFleetConnectionStoreBase);

// ---------------------------------------------------------------------------
// Backward-compatible hook — same shape the old Context-based hook returned
// ---------------------------------------------------------------------------

/** @deprecated Use useFleetConnectionStore directly */
export function useFleetConnection(): FleetConnectionHook {
  useLayoutEffect(() => {
    syncFleetConnectionStoreWithStorage();
  }, []);

  const connection = useFleetConnectionStore((s) => s.connection);
  const isConnecting = useFleetConnectionStore((s) => s.isConnecting);
  const error = useFleetConnectionStore((s) => s.error);
  const pollError = useFleetConnectionStore((s) => s.pollError);
  const secureStorageWarning = useFleetConnectionStore((s) => s.secureStorageWarning);
  const agents = useFleetConnectionStore((s) => s.agents);
  const remotePolicyInfo = useFleetConnectionStore((s) => s.remotePolicyInfo);
  const sseState = useFleetConnectionStore((s) => s.sseState);
  const actions = useFleetConnectionStore((s) => s.actions);

  return {
    connection,
    isConnecting,
    error,
    pollError,
    secureStorageWarning,
    agents,
    remotePolicyInfo,
    sseState,
    connect: actions.connect,
    disconnect: actions.disconnect,
    testConnection: actions.testConnection,
    refreshAgents: actions.refreshAgents,
    refreshRemotePolicy: actions.refreshRemotePolicy,
    getCredentials: actions.getCredentials,
    getAuthenticatedConnection: actions.getAuthenticatedConnection,
  };
}

/**
 * @deprecated Provider is no longer needed — FleetConnection is now a Zustand store.
 * Kept as a pass-through wrapper for backward compatibility.
 */
export function FleetConnectionProvider({ children }: { children: ReactNode }) {
  useLayoutEffect(() => {
    syncFleetConnectionStoreWithStorage();
  }, []);

  return children as ReactElement;
}
