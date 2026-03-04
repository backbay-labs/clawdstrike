import { useCallback, useEffect, useRef, useState } from "react";

export interface SSEEvent {
  _id: number;
  event_type: string;
  action_type?: string;
  target?: string;
  allowed?: boolean;
  guard?: string;
  policy_hash?: string;
  session_id?: string;
  endpoint_agent_id?: string;
  agent_id?: string;
  runtime_agent_id?: string;
  runtime_agent_kind?: string;
  timestamp: string;
}

export type SSEConnectionStatus =
  | "connecting"
  | "connected"
  | "disconnected"
  | "unauthorized"
  | "network_error";

export const SSE_CONFIG_CHANGED_EVENT = "clawdstrike:sse-config-changed";

export function notifySSEConfigChanged() {
  window.dispatchEvent(new Event(SSE_CONFIG_CHANGED_EVENT));
}

interface UseSSEResult {
  events: SSEEvent[];
  connected: boolean;
  status: SSEConnectionStatus;
  error: string | null;
  reconnect: () => void;
  paused: boolean;
  setPaused: (paused: boolean) => void;
  maxEvents: number;
  setMaxEvents: (max: number) => void;
  droppedEvents: number;
  clearEvents: () => void;
}

interface UseSSEOptions {
  initialMaxEvents?: number;
}

const DEFAULT_MAX_EVENTS = 500;
const MIN_MAX_EVENTS = 1;
const MAX_MAX_EVENTS = 10_000;

export function useSSE(url: string, options?: UseSSEOptions): UseSSEResult {
  const nextEventIdRef = useRef(1);
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const [connected, setConnected] = useState(false);
  const [status, setStatus] = useState<SSEConnectionStatus>("connecting");
  const [error, setError] = useState<string | null>(null);
  const [paused, setPausedState] = useState(false);
  const [maxEvents, setMaxEventsState] = useState(
    Math.min(
      MAX_MAX_EVENTS,
      Math.max(MIN_MAX_EVENTS, options?.initialMaxEvents ?? DEFAULT_MAX_EVENTS),
    ),
  );
  const [droppedEvents, setDroppedEvents] = useState(0);
  const [reconnectNonce, setReconnectNonce] = useState(0);
  const sourceRef = useRef<EventSource | null>(null);
  const pausedRef = useRef(paused);
  const maxEventsRef = useRef(maxEvents);

  useEffect(() => {
    pausedRef.current = paused;
  }, [paused]);

  useEffect(() => {
    maxEventsRef.current = maxEvents;
    setEvents((prev) => prev.slice(0, maxEvents));
  }, [maxEvents]);

  const setMaxEvents = useCallback((value: number) => {
    setMaxEventsState(
      Math.min(MAX_MAX_EVENTS, Math.max(MIN_MAX_EVENTS, Math.floor(value || DEFAULT_MAX_EVENTS))),
    );
  }, []);

  const clearEvents = useCallback(() => {
    setEvents([]);
    setDroppedEvents(0);
  }, []);

  const setPaused = useCallback((value: boolean) => {
    pausedRef.current = value;
    setPausedState(value);
  }, []);

  const pushEvent = useCallback((event: SSEEvent) => {
    if (pausedRef.current) {
      setDroppedEvents((prev) => prev + 1);
      return;
    }
    setEvents((prev) => {
      const next = [event, ...prev];
      const cap = maxEventsRef.current;
      if (next.length <= cap) {
        return next;
      }
      setDroppedEvents((dropped) => dropped + (next.length - cap));
      return next.slice(0, cap);
    });
  }, []);

  const reconnect = useCallback(() => {
    setReconnectNonce((prev) => prev + 1);
  }, []);

  useEffect(() => {
    const onStorage = (event: StorageEvent) => {
      if (!event.key || event.key === "hushd_url" || event.key === "hushd_api_key") {
        reconnect();
      }
    };
    const onConfigChanged = () => reconnect();

    window.addEventListener("storage", onStorage);
    window.addEventListener(SSE_CONFIG_CHANGED_EVENT, onConfigChanged);

    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener(SSE_CONFIG_CHANGED_EVENT, onConfigChanged);
    };
  }, [reconnect]);

  useEffect(() => {
    const apiBase = localStorage.getItem("hushd_url") || "";
    const fullUrl = `${apiBase}${url}`;
    setConnected(false);
    setStatus("connecting");
    setError(null);

    // EventSource doesn't support custom headers, so for authenticated
    // hushd deployments we use a fetch-based approach.
    const apiKey = localStorage.getItem("hushd_api_key");
    const useHeaderAuth = Boolean(apiBase) && Boolean(apiKey);
    let source: EventSource;
    if (useHeaderAuth) {
      // Use fetch + ReadableStream to send Authorization header.
      // Wrap in a connect() function so we can reconnect on EOF.
      let ctrl = new AbortController();
      let cancelled = false;
      const reconnectDelayMs = 3000;
      let reconnectTimer: number | null = null;

      const clearReconnectTimer = () => {
        if (reconnectTimer != null) {
          window.clearTimeout(reconnectTimer);
          reconnectTimer = null;
        }
      };

      const scheduleReconnect = (nextStatus: SSEConnectionStatus, nextError: string) => {
        setConnected(false);
        setStatus(nextStatus);
        setError(nextError);
        if (!cancelled) {
          clearReconnectTimer();
          reconnectTimer = window.setTimeout(connect, reconnectDelayMs);
        }
      };

      function connect() {
        if (cancelled) return;
        clearReconnectTimer();
        setStatus("connecting");
        setError(null);
        ctrl = new AbortController();
        fetch(fullUrl, {
          headers: { Authorization: `Bearer ${apiKey}` },
          signal: ctrl.signal,
        })
          .then((res) => {
            if (!res.ok || !res.body) {
              if (res.status === 401 || res.status === 403) {
                setConnected(false);
                setStatus("unauthorized");
                setError(`Unauthorized (${res.status})`);
                return;
              }
              scheduleReconnect("network_error", `SSE request failed (${res.status})`);
              return;
            }
            setConnected(true);
            setStatus("connected");
            setError(null);
            const reader = res.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";
            let currentEvent = "";
            let dataLines: string[] = [];

            const pump = async (): Promise<void> => {
              try {
                while (!cancelled) {
                  const { done, value } = await reader.read();
                  if (done) {
                    scheduleReconnect("disconnected", "SSE stream closed; reconnecting");
                    return;
                  }
                  buffer += decoder.decode(value, { stream: true });
                  const lines = buffer.split("\n");
                  buffer = lines.pop() ?? "";
                  for (const rawLine of lines) {
                    const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
                    if (line.startsWith("event:")) {
                      currentEvent = line.slice(6).trim();
                    } else if (line.startsWith("data:")) {
                      // SSE allows multiple data lines per event; they are joined with "\n"
                      // and dispatched when a blank line terminates the event block.
                      dataLines.push(line.slice(5).trimStart());
                    } else if (line.startsWith(":")) {
                      // SSE comment line; ignore.
                    } else if (line.trim() === "") {
                      if (dataLines.length > 0) {
                        const raw = dataLines.join("\n");
                        try {
                          const data = JSON.parse(raw);
                          if (data !== "ping" && raw !== "ping") {
                            const eventType = currentEvent || "message";
                            const endpointAgentId =
                              data.endpoint_agent_id ?? data.agent_id;
                            const event: SSEEvent = {
                              _id: nextEventIdRef.current++,
                              ...data,
                              endpoint_agent_id: endpointAgentId,
                              agent_id: endpointAgentId,
                              event_type: eventType,
                              timestamp: data.timestamp ?? new Date().toISOString(),
                            };
                            pushEvent(event);
                          }
                        } catch (err) {
                          console.debug("[SSE] skipping malformed payload:", err);
                        }
                      }
                      dataLines = [];
                      currentEvent = "";
                    }
                  }
                }
              } catch (err) {
                console.warn("[SSE] read error, will reconnect:", err);
                // read errors (network drop/hushd restart/abort mid-read) should reconnect
                if (!cancelled && !ctrl.signal.aborted) {
                  scheduleReconnect("network_error", "SSE stream read failed; reconnecting");
                }
              } finally {
                try {
                  reader.releaseLock();
                } catch (err) {
                  console.debug("[SSE] lock release error:", err);
                }
              }
            };

            void pump();
          })
          .catch(() => {
            if (!cancelled && !ctrl.signal.aborted) {
              scheduleReconnect("network_error", "SSE connection failed; reconnecting");
            }
          });
      }
      connect();

      return () => {
        cancelled = true;
        clearReconnectTimer();
        ctrl.abort();
      };
    }

    source = new EventSource(fullUrl);
    sourceRef.current = source;

    source.onopen = () => {
      setConnected(true);
      setStatus("connected");
      setError(null);
    };
    source.onerror = () => {
      setConnected(false);
      setStatus("network_error");
      setError("SSE transport error");
    };

    function handleEvent(eventType: string) {
      return (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data);
          const endpointAgentId = data.endpoint_agent_id ?? data.agent_id;
          const event: SSEEvent = {
            _id: nextEventIdRef.current++,
            ...data,
            endpoint_agent_id: endpointAgentId,
            agent_id: endpointAgentId,
            event_type: eventType,
            timestamp: data.timestamp ?? new Date().toISOString(),
          };
          pushEvent(event);
        } catch (err) {
          console.debug("[SSE] skipping malformed event:", err);
        }
      };
    }

    source.addEventListener("check", handleEvent("check"));
    source.addEventListener("violation", handleEvent("violation"));
    source.addEventListener("policy_updated", handleEvent("policy_updated"));
    source.addEventListener(
      "session_posture_transition",
      handleEvent("session_posture_transition"),
    );

    // Also handle unnamed messages
    source.onmessage = (e) => {
      try {
        const data = JSON.parse(e.data);
        if (data === "ping" || e.data === "ping") return;
        const endpointAgentId = data.endpoint_agent_id ?? data.agent_id;
        const event: SSEEvent = {
          _id: nextEventIdRef.current++,
          ...data,
          endpoint_agent_id: endpointAgentId,
          agent_id: endpointAgentId,
          event_type: "message",
          timestamp: data.timestamp ?? new Date().toISOString(),
        };
        pushEvent(event);
      } catch (err) {
        console.debug("[SSE] event parse error:", err);
      }
    };

    return () => {
      source.close();
      sourceRef.current = null;
    };
  }, [url, reconnectNonce, pushEvent]);

  return {
    events,
    connected,
    status,
    error,
    reconnect,
    paused,
    setPaused,
    maxEvents,
    setMaxEvents,
    droppedEvents,
    clearEvents,
  };
}
