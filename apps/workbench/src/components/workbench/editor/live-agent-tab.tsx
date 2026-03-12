import { useState, useCallback, useRef, useMemo, useEffect } from "react";
import { useWorkbench } from "@/lib/workbench/multi-policy-store";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { useToast } from "@/components/ui/toast";
import { policyToYaml } from "@/lib/workbench/yaml-utils";
import { isDesktop, savePolicyFile } from "@/lib/tauri-bridge";
import { cn } from "@/lib/utils";
import {
  IconPlayerPlay,
  IconPlayerStop,
  IconCopy,
  IconCheck,
  IconDownload,
  IconPlugConnected,
  IconPlugConnectedX,
  IconTerminal2,
  IconServer,
  IconInfoCircle,
  IconTrash,
  IconRefresh,
} from "@tabler/icons-react";
import type { HushdEvent as BaseHushdEvent } from "@/lib/workbench/hushd-event-simulator";

/** Extend HushdEvent with source tracking so the UI can distinguish live vs simulated */
interface HushdEvent extends Omit<BaseHushdEvent, "verdict"> {
  verdict: "ALLOW" | "DENY" | "WARN" | "INFO";
  /** The raw event_id from the daemon SSE stream */
  sourceEventId?: string;
  /** The SSE event type that carried this event (e.g. "check", "violation") */
  sseEventType?: string;
}

// ---------------------------------------------------------------------------
// Script Runner sub-panel
// ---------------------------------------------------------------------------

const EXAMPLE_SCRIPT = `"""
Example test script using the clawdstrike.testing module.

Run against your policy to validate guard behavior across scenarios.
"""
from clawdstrike import Clawdstrike
from clawdstrike.testing import ScenarioRunner, ScenarioSuite

# Point to the exported policy file
runner = ScenarioRunner("policy.yaml")

# Define inline scenarios
r1 = runner.check("SSH key blocked", "file_access", "~/.ssh/id_rsa", expect="deny")
r2 = runner.check("Temp write allowed", "file_write", "/tmp/out.json", expect="allow")
r3 = runner.check("Dangerous rm blocked", "shell_command", "rm -rf /", expect="deny")
r4 = runner.check("API egress allowed", "network_egress", "api.openai.com", expect="allow")

# Or load from a YAML suite file
suite = ScenarioSuite.from_yaml_file("tests/policy-tests.yaml")
report = runner.run(suite)
report.print_summary()

# Exit with non-zero if any test failed
import sys
sys.exit(0 if report.all_passed else 1)
`;

function ScriptRunnerPanel() {
  const { state } = useWorkbench();
  const { toast } = useToast();
  const [copied, setCopied] = useState(false);
  const [saving, setSaving] = useState(false);

  const policyYaml = useMemo(
    () => policyToYaml(state.activePolicy),
    [state.activePolicy],
  );

  const command = `python -m clawdstrike.testing run --policy policy.yaml --suite tests/policy-tests.yaml`;

  const copyCommand = useCallback(() => {
    void navigator.clipboard.writeText(command);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [command]);

  const handleSavePolicy = useCallback(async () => {
    setSaving(true);
    try {
      if (isDesktop()) {
        const path = await savePolicyFile(policyYaml);
        if (path) {
          toast({
            type: "success",
            title: "Policy exported",
            description: `Saved to ${path}`,
          });
        }
      } else {
        // Web fallback: download as file
        const blob = new Blob([policyYaml], { type: "text/yaml" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${state.activePolicy.name || "policy"}.yaml`;
        a.click();
        URL.revokeObjectURL(url);
        toast({
          type: "success",
          title: "Policy downloaded",
          description: "Check your downloads folder",
        });
      }
    } catch (err) {
      toast({
        type: "error",
        title: "Export failed",
        description: String(err),
      });
    } finally {
      setSaving(false);
    }
  }, [policyYaml, state.activePolicy.name, toast]);

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <IconTerminal2 size={12} stroke={1.5} className="text-[#d4a84b]" />
        <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
          Script Runner
        </span>
        <div className="flex-1" />
        <button
          onClick={handleSavePolicy}
          disabled={saving}
          className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-[#2d3240] rounded transition-colors disabled:opacity-50"
        >
          <IconDownload size={10} stroke={1.5} />
          {saving ? "Saving..." : "Save policy to file"}
        </button>
      </div>

      {/* Command bar */}
      <div className="px-3 py-2 border-b border-[#2d3240] bg-[#0b0d13]/80">
        <div className="flex items-center gap-1.5 text-[9px] font-mono text-[#6f7f9a] mb-1">
          <IconInfoCircle size={10} stroke={1.5} />
          Run this command after exporting your policy:
        </div>
        <div className="flex items-center gap-2">
          <code className="flex-1 bg-[#0a0a0a] text-[#3dbf84] text-[10px] font-mono px-2 py-1.5 rounded border border-[#2d3240] overflow-x-auto whitespace-nowrap">
            $ {command}
          </code>
          <button
            onClick={copyCommand}
            className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#6f7f9a] hover:text-[#d4a84b] border border-[#2d3240] rounded transition-colors shrink-0"
          >
            {copied ? (
              <>
                <IconCheck size={10} stroke={1.5} />
                Copied
              </>
            ) : (
              <>
                <IconCopy size={10} stroke={1.5} />
                Copy
              </>
            )}
          </button>
        </div>
      </div>

      {/* Example script (read-only code viewer) */}
      <div className="flex-1 overflow-auto">
        <pre className="p-3 text-[11px] font-mono text-[#ece7dc]/90 leading-relaxed whitespace-pre">
          {EXAMPLE_SCRIPT}
        </pre>
      </div>

      {/* Mock terminal output */}
      <div className="shrink-0 border-t border-[#2d3240]">
        <div className="flex items-center gap-1.5 px-3 py-1 bg-[#0b0d13] border-b border-[#2d3240]">
          <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
            Terminal Output
          </span>
          <span className="text-[8px] font-mono text-[#6f7f9a]/40 ml-auto">
            preview
          </span>
        </div>
        <div
          className="px-3 py-2 font-mono text-[10px] leading-relaxed overflow-auto"
          style={{
            backgroundColor: "#0a0a0a",
            maxHeight: "140px",
          }}
        >
          <div className="text-[#6f7f9a]/60">$ python -m clawdstrike.testing run --policy policy.yaml</div>
          <div className="text-[#6f7f9a]/40 mt-1">Running 6 scenarios against &quot;{state.activePolicy.name || "policy"}&quot;...</div>
          <div className="mt-1">
            <span className="text-[#3dbf84]">PASS</span>
            <span className="text-[#6f7f9a]/60"> SSH key blocked</span>
            <span className="text-[#6f7f9a]/30"> ............ deny (forbidden_path) 2ms</span>
          </div>
          <div>
            <span className="text-[#3dbf84]">PASS</span>
            <span className="text-[#6f7f9a]/60"> Temp write allowed</span>
            <span className="text-[#6f7f9a]/30"> ...... allow 1ms</span>
          </div>
          <div>
            <span className="text-[#3dbf84]">PASS</span>
            <span className="text-[#6f7f9a]/60"> Dangerous rm blocked</span>
            <span className="text-[#6f7f9a]/30"> .... deny (shell_command) 1ms</span>
          </div>
          <div>
            <span className="text-[#3dbf84]">PASS</span>
            <span className="text-[#6f7f9a]/60"> API egress allowed</span>
            <span className="text-[#6f7f9a]/30"> ..... allow 1ms</span>
          </div>
          <div>
            <span className="text-[#c45c5c]">FAIL</span>
            <span className="text-[#6f7f9a]/60"> Block unknown domain</span>
            <span className="text-[#6f7f9a]/30"> ... expected deny, got allow 1ms</span>
          </div>
          <div>
            <span className="text-[#3dbf84]">PASS</span>
            <span className="text-[#6f7f9a]/60"> Detect jailbreak</span>
            <span className="text-[#6f7f9a]/30"> ........ deny (jailbreak) 3ms</span>
          </div>
          <div className="mt-1 text-[#6f7f9a]/40">
            ----------------------------------------
          </div>
          <div className="text-[#6f7f9a]/60">
            Results: <span className="text-[#3dbf84]">5 passed</span>, <span className="text-[#c45c5c]">1 failed</span>, 6 total (9ms)
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// hushd Monitor sub-panel
// ---------------------------------------------------------------------------

type VerdictFilter = "ALL" | HushdEvent["verdict"];

const MAX_EVENTS = 200;

function verdictColor(v: HushdEvent["verdict"]): string {
  if (v === "ALLOW") return "#3dbf84";
  if (v === "DENY") return "#c45c5c";
  if (v === "WARN") return "#d4a84b";
  return "#6f7f9a";
}

function formatTimestamp(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-US", { hour12: false, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/**
 * Parse an SSE event from the hushd `/api/v1/events` stream into an HushdEvent.
 *
 * hushd check/violation events have this shape:
 *   { event_id, timestamp, action_type, target, allowed: bool, guard, severity,
 *     message, policy_hash, session_id, endpoint_agent_id, agent_id,
 *     runtime_agent_id, runtime_agent_kind }
 */
export function parseHushdSseEvent(
  data: Record<string, unknown>,
  sseEventType?: string,
): HushdEvent | null {
  // hushd sends `allowed: bool` + `severity: string`.
  // WARN = allowed:true + severity:"warning"
  // ALLOW = allowed:true + severity:"info"
  // DENY = allowed:false (any severity)
  let verdict: HushdEvent["verdict"];
  if (typeof data.allowed === "boolean") {
    if (!data.allowed) {
      verdict = "DENY";
    } else {
      const severity = String(data.severity ?? "info").toLowerCase();
      verdict = severity === "warning" ? "WARN" : "ALLOW";
    }
  } else {
    const rawDecision = data.decision ?? data.verdict;
    if (rawDecision == null) {
      verdict = "INFO";
    } else {
      const decision = String(rawDecision).toLowerCase();
      if (decision === "allowed" || decision === "allow") verdict = "ALLOW";
      else if (decision === "warn" || decision === "warning") verdict = "WARN";
      else if (decision === "deny" || decision === "denied" || decision === "block") verdict = "DENY";
      else verdict = "INFO";
    }
  }

  const rawEventId = data.event_id ?? data.id;

  return {
    id: String(rawEventId ?? `sse-${Date.now()}-${Math.random()}`),
    timestamp: String(data.timestamp ?? new Date().toISOString()),
    verdict,
    guard: String(data.guard ?? sseEventType ?? "system"),
    action: String(data.action_type ?? sseEventType ?? "event"),
    target: String(data.target ?? data.message ?? data.policy_hash ?? ""),
    agent: String(data.endpoint_agent_id ?? data.agent_id ?? data.runtime_agent_id ?? "remote"),
    durationMs: typeof data.duration_ms === "number" ? data.duration_ms : 0,
    sourceEventId: rawEventId ? String(rawEventId) : undefined,
    sseEventType: sseEventType ?? undefined,
  };
}

/**
 * Resolve the user-entered endpoint to a URL the browser can actually reach.
 *
 * In dev mode, Vite proxies `/_proxy/hushd` → localhost:9876 and
 * `/_proxy/control` → localhost:8080 to avoid CORS.  When the user enters
 * a localhost/127.0.0.1 URL we route through the matching Vite proxy so
 * the browser never makes a cross-origin request.
 *
 * In production (Tauri desktop) the app is served from the same origin or
 * has relaxed security, so we use the URL directly.
 */
export function resolveProxyBase(raw: string, isDev = import.meta.env.DEV): string {
  const cleaned = raw.replace(/\/+$/, "");

  // Only proxy in dev (Vite dev server)
  if (!isDev) return cleaned;

  try {
    const u = new URL(cleaned);
    const isLocal =
      u.hostname === "localhost" ||
      u.hostname === "127.0.0.1" ||
      u.hostname === "::1" ||
      u.hostname === "[::1]";
    if (!isLocal) return cleaned;

    if (u.port === "9876") return "/_proxy/hushd";
    if (u.port === "8080") return "/_proxy/control";
    // Non-standard local port — pass through directly (may hit CORS in dev)
    return cleaned;
  } catch {
    return cleaned;
  }
}

function normalizeMonitorEndpoint(raw: string): string {
  return raw.trim().replace(/\/+$/, "");
}

export function endpointsShareAuthScope(endpoint: string, hushdUrl: string): boolean {
  try {
    const left = new URL(normalizeMonitorEndpoint(endpoint));
    const right = new URL(normalizeMonitorEndpoint(hushdUrl));
    return left.origin === right.origin;
  } catch {
    return false;
  }
}

export function buildHushdAuthHeaders(
  endpoint: string,
  hushdUrl: string,
  apiKey: string,
): Record<string, string> {
  const trimmed = apiKey.trim();
  if (!trimmed || !hushdUrl.trim() || !endpointsShareAuthScope(endpoint, hushdUrl)) {
    return {};
  }
  return { Authorization: `Bearer ${trimmed}` };
}

export function describeHushdAuthScopeMismatch(
  endpoint: string,
  hushdUrl: string,
  apiKey: string,
): string | null {
  const trimmedApiKey = apiKey.trim();
  const normalizedHushdUrl = normalizeMonitorEndpoint(hushdUrl);
  if (!trimmedApiKey || !normalizedHushdUrl) {
    return null;
  }
  if (endpointsShareAuthScope(endpoint, normalizedHushdUrl)) {
    return null;
  }
  return `Saved hushd credentials are only sent to the configured hushd URL (${normalizedHushdUrl}). Use that exact URL here or reconnect this endpoint in Settings.`;
}

export interface ParsedSseMessage {
  eventType: string;
  data: string;
}

export function consumeSseMessages(buffer: string): {
  messages: ParsedSseMessage[];
  remainder: string;
} {
  const normalized = buffer.replace(/\r\n/g, "\n");
  const blocks = normalized.split("\n\n");
  const remainder = blocks.pop() ?? "";
  const messages: ParsedSseMessage[] = [];

  for (const block of blocks) {
    if (!block.trim()) continue;
    let eventType = "message";
    const dataLines: string[] = [];

    for (const rawLine of block.split("\n")) {
      const line = rawLine.endsWith("\r") ? rawLine.slice(0, -1) : rawLine;
      if (line.startsWith(":")) continue;
      if (line.startsWith("event:")) {
        eventType = line.slice(6).trim() || "message";
      } else if (line.startsWith("data:")) {
        dataLines.push(line.slice(5).trimStart());
      }
    }

    if (dataLines.length > 0) {
      messages.push({ eventType, data: dataLines.join("\n") });
    }
  }

  return { messages, remainder };
}

function HushdMonitorPanel() {
  const { connection } = useFleetConnection();
  const { toast } = useToast();
  const [endpoint, setEndpoint] = useState(connection.hushdUrl || "http://127.0.0.1:8080");
  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [connectionError, setConnectionError] = useState<string | null>(null);
  const [events, setEvents] = useState<HushdEvent[]>([]);
  const [verdictFilter, setVerdictFilter] = useState<VerdictFilter>("ALL");
  const eventSourceRef = useRef<EventSource | null>(null);
  const streamAbortRef = useRef<AbortController | null>(null);
  /** Track named-event listener refs so they can be removed before close */
  const listenersRef = useRef<Map<string, EventListener>>(new Map());
  /** Track reconnection attempts for exponential backoff (max 5) */
  const reconnectAttemptsRef = useRef(0);
  /** Timer ID for reconnection delay */
  const reconnectTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  /** Timer ID for CONNECTING-state stall detection */
  const connectingStallTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const MAX_RECONNECT_ATTEMPTS = 5;

  useEffect(() => {
    if (!connection.hushdUrl) return;
    setEndpoint((current) =>
      current === "http://127.0.0.1:8080" || current.trim() === ""
        ? connection.hushdUrl
        : current,
    );
  }, [connection.hushdUrl]);

  useEffect(() => {
    if (!connection.hushdUrl) return;
    if (endpoint === "http://127.0.0.1:8080") {
      setEndpoint(connection.hushdUrl);
    }
  }, [connection.hushdUrl, endpoint]);

  // --- SSE streaming ---
  // hushd emits *named* SSE events ("check", "violation", "policy_reload"),
  // NOT unnamed data-only messages.  EventSource.onmessage only fires for
  // unnamed events, so we must use addEventListener for each event type.

  /** Remove all named-event listeners from the EventSource and clear the map */
  const removeListeners = useCallback(() => {
    const es = eventSourceRef.current;
    if (es) {
      for (const [eventType, handler] of listenersRef.current.entries()) {
        es.removeEventListener(eventType, handler);
      }
    }
    listenersRef.current.clear();
  }, []);

  /** Clear any pending reconnection / stall timers */
  const clearReconnectTimers = useCallback(() => {
    if (reconnectTimerRef.current !== null) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
    if (connectingStallTimerRef.current !== null) {
      clearTimeout(connectingStallTimerRef.current);
      connectingStallTimerRef.current = null;
    }
  }, []);

  const stopSse = useCallback(() => {
    clearReconnectTimers();
    removeListeners();
    if (eventSourceRef.current) {
      eventSourceRef.current.close();
      eventSourceRef.current = null;
    }
    if (streamAbortRef.current) {
      streamAbortRef.current.abort();
      streamAbortRef.current = null;
    }
    reconnectAttemptsRef.current = 0;
    setReconnecting(false);
  }, [clearReconnectTimers, removeListeners]);

  /** Attempt an SSE reconnection with exponential backoff */
  const scheduleReconnect = useCallback(
    (proxyBase: string, startSseFn: (base: string) => void) => {
      const attempt = reconnectAttemptsRef.current;
      if (attempt >= MAX_RECONNECT_ATTEMPTS) {
        // Give up — too many failures
        stopSse();
        setConnected(false);
        setReconnecting(false);
        setConnectionError(
          `Lost connection after ${MAX_RECONNECT_ATTEMPTS} reconnect attempts. Click Connect to try again.`,
        );
        toast({
          type: "error",
          title: "Reconnection failed",
          description: `Could not reconnect after ${MAX_RECONNECT_ATTEMPTS} attempts.`,
        });
        return;
      }

      const delayMs = Math.min(1000 * 2 ** attempt, 16_000); // 1s, 2s, 4s, 8s, 16s
      reconnectAttemptsRef.current = attempt + 1;
      setReconnecting(true);
      setConnected(false);

      reconnectTimerRef.current = setTimeout(() => {
        reconnectTimerRef.current = null;
        startSseFn(proxyBase);
      }, delayMs);
    },
    [stopSse, toast],
  );

  const startSse = useCallback(
    (proxyBase: string) => {
      const authScopeMismatch = describeHushdAuthScopeMismatch(
        endpoint,
        connection.hushdUrl,
        connection.apiKey,
      );
      if (authScopeMismatch) {
        setConnected(false);
        setReconnecting(false);
        setConnectionError(authScopeMismatch);
        return;
      }

      const authHeaders = buildHushdAuthHeaders(endpoint, connection.hushdUrl, connection.apiKey);

      // Clean up any prior EventSource before opening a new one
      removeListeners();
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
      }
      if (streamAbortRef.current) {
        streamAbortRef.current.abort();
        streamAbortRef.current = null;
      }

      const url = `${proxyBase}/api/v1/events`;
      if (Object.keys(authHeaders).length > 0) {
        const controller = new AbortController();
        streamAbortRef.current = controller;

        void (async () => {
          try {
            const response = await fetch(url, {
              headers: {
                Accept: "text/event-stream",
                ...authHeaders,
              },
              signal: controller.signal,
            });

            if (connectingStallTimerRef.current !== null) {
              clearTimeout(connectingStallTimerRef.current);
              connectingStallTimerRef.current = null;
            }

            if (!response.ok || !response.body) {
              setConnected(false);
              setReconnecting(false);
              if (response.status === 401 || response.status === 403) {
                setConnectionError(
                  "Unauthorized — update your fleet API token or connect this endpoint in Settings before streaming hushd events.",
                );
                return;
              }
              setConnectionError(`SSE request failed (${response.status}). Reconnecting...`);
              scheduleReconnect(proxyBase, startSse);
              return;
            }

            reconnectAttemptsRef.current = 0;
            setConnected(true);
            setReconnecting(false);
            setConnectionError(null);

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";

            try {
              while (!controller.signal.aborted) {
                const { done, value } = await reader.read();
                if (done) {
                  break;
                }
                buffer += decoder.decode(value, { stream: true });
                const parsed = consumeSseMessages(buffer);
                buffer = parsed.remainder;

                for (const message of parsed.messages) {
                  if (message.data === "ping") continue;
                  try {
                    const data = JSON.parse(message.data) as Record<string, unknown>;
                    const evt = parseHushdSseEvent(data, message.eventType);
                    if (!evt) continue;
                    reconnectAttemptsRef.current = 0;
                    setEvents((prev) => [evt, ...prev].slice(0, MAX_EVENTS));
                  } catch {
                    // Skip malformed payloads without tearing down the stream.
                  }
                }
              }
            } finally {
              reader.releaseLock();
            }

            if (!controller.signal.aborted) {
              setConnected(false);
              setConnectionError("SSE stream closed. Attempting to reconnect...");
              scheduleReconnect(proxyBase, startSse);
            }
          } catch (error) {
            if (controller.signal.aborted) {
              return;
            }
            const message = error instanceof Error ? error.message : String(error);
            setConnected(false);
            setConnectionError(`SSE connection failed: ${message}`);
            scheduleReconnect(proxyBase, startSse);
          }
        })();

        return;
      }

      const es = new EventSource(url);
      eventSourceRef.current = es;

      const makeHandler = (eventType: string) => (e: Event) => {
        const me = e as MessageEvent;
        try {
          const data = JSON.parse(me.data) as Record<string, unknown>;
          const evt = parseHushdSseEvent(data, eventType);
          if (evt) {
            reconnectAttemptsRef.current = 0;
            setReconnecting(false);
            setConnected(true);
            setConnectionError(null);
            setEvents((prev) => [evt, ...prev].slice(0, MAX_EVENTS));
          }
        } catch {
          // Skip unparseable events
        }
      };

      const eventTypes = [
        "check",
        "violation",
        "policy_reload",
        "session_start",
        "session_end",
      ];
      for (const et of eventTypes) {
        const handler = makeHandler(et);
        listenersRef.current.set(et, handler);
        es.addEventListener(et, handler);
      }

      es.onopen = () => {
        if (connectingStallTimerRef.current !== null) {
          clearTimeout(connectingStallTimerRef.current);
          connectingStallTimerRef.current = null;
        }
        setConnected(true);
        setReconnecting(false);
        setConnectionError(null);
      };

      es.onerror = () => {
        if (connectingStallTimerRef.current !== null) {
          clearTimeout(connectingStallTimerRef.current);
          connectingStallTimerRef.current = null;
        }

        if (es.readyState === EventSource.CLOSED) {
          removeListeners();
          es.close();
          eventSourceRef.current = null;
          setConnected(false);
          setConnectionError("SSE stream closed. Attempting to reconnect...");
          scheduleReconnect(proxyBase, startSse);
        } else if (es.readyState === EventSource.CONNECTING) {
          setConnected(false);
          setReconnecting(true);
          setConnectionError("Connection interrupted. Reconnecting...");
          connectingStallTimerRef.current = setTimeout(() => {
            connectingStallTimerRef.current = null;
            if (
              eventSourceRef.current &&
              eventSourceRef.current.readyState === EventSource.CONNECTING
            ) {
              removeListeners();
              eventSourceRef.current.close();
              eventSourceRef.current = null;
              scheduleReconnect(proxyBase, startSse);
            }
          }, 10_000);
        }
      };
    },
    [connection.apiKey, connection.hushdUrl, endpoint, removeListeners, scheduleReconnect],
  );

  // --- Connect: probe /health first, then open SSE ---
  const handleConnect = useCallback(async () => {
    setConnecting(true);
    setConnectionError(null);
    const proxyBase = resolveProxyBase(endpoint);
    const authScopeMismatch = describeHushdAuthScopeMismatch(
      endpoint,
      connection.hushdUrl,
      connection.apiKey,
    );
    if (authScopeMismatch) {
      setConnecting(false);
      setConnectionError(authScopeMismatch);
      toast({
        type: "error",
        title: "Auth scope mismatch",
        description:
          "Saved hushd credentials are only sent to the configured hushd URL. Use that exact URL here or reconnect this endpoint in Settings.",
      });
      return;
    }

    const authHeaders = buildHushdAuthHeaders(endpoint, connection.hushdUrl, connection.apiKey);

    try {
      const resp = await fetch(`${proxyBase}/health`, {
        headers: authHeaders,
        signal: AbortSignal.timeout(3000),
      });
      if (!resp.ok) {
        const body = await resp.text().catch(() => "");
        throw new Error(`Health check returned ${resp.status}${body ? `: ${body}` : ""}`);
      }

      // Daemon is live — open SSE stream
      setConnecting(false);
      setConnected(true);
      startSse(proxyBase);
      toast({ type: "success", title: "Connected", description: `Streaming events from ${endpoint}` });
    } catch (err) {
      setConnecting(false);
      const msg = err instanceof Error ? err.message : String(err);
      const isUnauthorized = msg.includes("401") || msg.includes("403");
      const isNetwork = msg.includes("fetch") || msg.includes("network") || msg.includes("abort") || msg.includes("Failed");
      setConnectionError(
        isUnauthorized
          ? "Unauthorized — update your fleet API token in Settings before opening Live Monitor."
          : isNetwork
          ? `Cannot reach ${endpoint} — is the daemon running? Start it with: clawdstrike daemon start --port 8080`
          : `Connection failed: ${msg}`,
      );
      toast({
        type: "error",
        title: "Connection failed",
        description: isUnauthorized
          ? "Authenticated hushd endpoints require a valid API token from Settings."
          : isNetwork
          ? "Daemon unreachable. Make sure hushd is running."
          : msg,
      });
    }
  }, [connection.apiKey, endpoint, startSse, toast]);

  const handleDisconnect = useCallback(() => {
    stopSse();
    setConnected(false);
    setReconnecting(false);
    setConnectionError(null);
  }, [stopSse]);

  const handleClear = useCallback(() => {
    setEvents([]);
  }, []);

  // Cleanup on unmount — stop SSE and clear all timers
  useEffect(() => {
    return () => {
      stopSse();
    };
  }, [stopSse]);  // stopSse already clears timers and listeners

  const filteredEvents = useMemo(
    () => verdictFilter === "ALL" ? events : events.filter((e) => e.verdict === verdictFilter),
    [events, verdictFilter],
  );

  const FILTER_OPTIONS: VerdictFilter[] = ["ALL", "DENY", "ALLOW", "WARN", "INFO"];

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <IconServer size={12} stroke={1.5} className="text-[#d4a84b]" />
        <span className="text-[9px] font-mono text-[#6f7f9a] uppercase tracking-wider">
          hushd Monitor
        </span>
        <div className="flex-1" />
        {/* Connection status */}
        <span className="inline-flex items-center gap-1 text-[9px] font-mono">
          {connecting ? (
            <>
              <span className="relative flex h-2 w-2">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-[#d4a84b] opacity-75" />
                <span className="relative inline-flex rounded-full h-2 w-2 bg-[#d4a84b]" />
              </span>
              <span className="text-[#d4a84b]">Connecting...</span>
            </>
          ) : reconnecting ? (
            <>
              <IconRefresh size={10} stroke={1.5} className="text-[#d4a84b] animate-spin" />
              <span className="text-[#d4a84b]">Reconnecting...</span>
              <span className="px-1 py-0.5 rounded text-[8px] font-mono bg-[#d4a84b]/15 text-[#d4a84b]">
                {reconnectAttemptsRef.current}/{MAX_RECONNECT_ATTEMPTS}
              </span>
            </>
          ) : connected ? (
            <>
              <IconPlugConnected size={10} stroke={1.5} className="text-[#3dbf84]" />
              <span className="text-[#3dbf84]">Connected</span>
              <span className="px-1 py-0.5 rounded text-[8px] font-mono bg-[#3dbf84]/15 text-[#3dbf84]">
                LIVE
              </span>
            </>
          ) : (
            <>
              <IconPlugConnectedX size={10} stroke={1.5} className="text-[#6f7f9a]/50" />
              <span className="text-[#6f7f9a]/50">Disconnected</span>
            </>
          )}
        </span>
      </div>

      {/* Connection controls */}
      <div className="px-3 py-2 border-b border-[#2d3240] bg-[#0b0d13]/80">
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            disabled={connected || connecting || reconnecting}
            className="flex-1 bg-[#131721] text-[#ece7dc] border border-[#2d3240] rounded px-2 py-1 text-[10px] font-mono placeholder:text-[#6f7f9a]/40 disabled:opacity-50"
            placeholder="http://localhost:8080"
          />
          {connected || reconnecting ? (
            <button
              onClick={handleDisconnect}
              className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#c45c5c] border border-[#c45c5c]/30 rounded hover:bg-[#c45c5c]/10 transition-colors"
            >
              <IconPlayerStop size={10} stroke={1.5} />
              Disconnect
            </button>
          ) : (
            <button
              onClick={handleConnect}
              disabled={connecting}
              className="inline-flex items-center gap-1 px-2 py-1 text-[9px] font-mono text-[#d4a84b] border border-[#d4a84b]/30 rounded hover:bg-[#d4a84b]/10 transition-colors disabled:opacity-50"
            >
              <IconPlayerPlay size={10} stroke={1.5} />
              {connecting ? "Connecting..." : "Connect"}
            </button>
          )}
        </div>
        <p className="mt-1.5 text-[8px] font-mono text-[#6f7f9a]/50">
          {connection.apiKey.trim()
            ? "Uses the configured hushd API key from Settings for health checks and authenticated event streaming."
            : "No hushd API key configured. Authenticated hushd deployments will reject the live stream until you add one in Settings."}
        </p>
      </div>

      {/* Connection error banner */}
      {connectionError && !connected && (
        <div className="px-3 py-2 border-b border-[#c45c5c]/20 bg-[#c45c5c]/5">
          <p className="text-[10px] font-mono text-[#c45c5c]">{connectionError}</p>
        </div>
      )}

      {/* Verdict filter + event count */}
      <div className="flex items-center gap-2 px-3 py-1.5 border-b border-[#2d3240] bg-[#0b0d13]/60 shrink-0">
        <div className="flex items-center gap-0.5">
          {FILTER_OPTIONS.map((f) => (
            <button
              key={f}
              onClick={() => setVerdictFilter(f)}
              className={cn(
                "px-1.5 py-0.5 text-[9px] font-mono rounded transition-colors",
                verdictFilter === f
                  ? f === "ALL"
                    ? "bg-[#2d3240] text-[#ece7dc]"
                    : f === "DENY"
                      ? "bg-[#c45c5c]/20 text-[#c45c5c]"
                    : f === "ALLOW"
                        ? "bg-[#3dbf84]/20 text-[#3dbf84]"
                        : f === "WARN"
                          ? "bg-[#d4a84b]/20 text-[#d4a84b]"
                          : "bg-[#6f7f9a]/20 text-[#6f7f9a]"
                  : "text-[#6f7f9a]/60 hover:text-[#ece7dc]",
              )}
            >
              {f}
            </button>
          ))}
        </div>
        <div className="flex-1" />
        <span className="text-[8px] font-mono text-[#6f7f9a]/40">
          {filteredEvents.length} / {events.length} events
        </span>
        <button
          onClick={handleClear}
          disabled={events.length === 0}
          className="inline-flex items-center gap-1 px-1.5 py-0.5 text-[9px] font-mono text-[#6f7f9a]/60 hover:text-[#ece7dc] transition-colors disabled:opacity-30"
        >
          <IconTrash size={10} stroke={1.5} />
          Clear
        </button>
      </div>

      {/* Event feed */}
      <div className="flex-1 overflow-auto" style={{ backgroundColor: "#0a0a0a" }}>
        <div className="px-3 py-2">
          {filteredEvents.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-[#6f7f9a] text-xs font-mono gap-2">
              {connected
                ? <span>Waiting for events...</span>
                : reconnecting
                  ? <span>Reconnecting to daemon...</span>
                  : <span>Connect to a hushd instance to see live events</span>}
            </div>
          )}
          {filteredEvents.map((evt) => (
            <div
              key={evt.id}
              className="flex items-center gap-2 py-0.5 font-mono text-[10px] leading-relaxed group"
            >
              <span className="text-[#6f7f9a]/40 shrink-0">
                [{formatTimestamp(evt.timestamp)}]
              </span>
              {/* SSE event type badge — proves this came from the daemon */}
              {evt.sseEventType && (
                <span className={cn(
                  "shrink-0 px-1 py-px rounded text-[7px] uppercase tracking-wider",
                  evt.sseEventType === "violation"
                    ? "bg-[#c45c5c]/15 text-[#c45c5c]/70"
                    : evt.sseEventType === "check"
                      ? "bg-[#3dbf84]/15 text-[#3dbf84]/70"
                      : "bg-[#d4a84b]/15 text-[#d4a84b]/70",
                )}>
                  {evt.sseEventType}
                </span>
              )}
              <span
                className="w-10 text-center font-bold shrink-0"
                style={{ color: verdictColor(evt.verdict) }}
              >
                {evt.verdict}
              </span>
              <span className="text-[#6f7f9a]/60 w-32 truncate shrink-0">
                {evt.guard}
              </span>
              <span className="text-[#ece7dc]/70 flex-1 truncate">
                {evt.target}
              </span>
              <span className="text-[#6f7f9a]/30 shrink-0">
                {evt.agent}
              </span>
              {/* Show daemon event_id on hover */}
              {evt.sourceEventId && (
                <span className="text-[#6f7f9a]/20 shrink-0 text-[8px] hidden group-hover:inline truncate max-w-[120px]" title={evt.sourceEventId}>
                  {evt.sourceEventId.length > 12
                    ? `${evt.sourceEventId.slice(0, 8)}…`
                    : evt.sourceEventId}
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Footer info */}
      <div className="shrink-0 px-3 py-2 border-t border-[#2d3240] bg-[#0b0d13]">
        <p className="text-[8px] font-mono text-[#6f7f9a]/40">
          {connected ? (
            <>
              <span className="inline-flex items-center gap-1">
                <span className="h-1.5 w-1.5 rounded-full bg-[#3dbf84] animate-pulse" />
                Live SSE stream:
              </span>{" "}
              <code className="text-[#3dbf84]/60">{endpoint}/api/v1/events</code>
              <span className="ml-2 text-[#6f7f9a]/25">
                Hover events to see daemon event IDs
              </span>
            </>
          ) : reconnecting ? (
            <>
              <span className="inline-flex items-center gap-1">
                <IconRefresh size={8} stroke={1.5} className="text-[#d4a84b] animate-spin" />
                Reconnecting to
              </span>{" "}
              <code className="text-[#d4a84b]/60">{endpoint}/api/v1/events</code>
              <span className="ml-2 text-[#6f7f9a]/25">
                Attempt {reconnectAttemptsRef.current} of {MAX_RECONNECT_ATTEMPTS}
              </span>
            </>
          ) : (
            <>
              Start daemon: <code className="text-[#d4a84b]/60">clawdstrike daemon start --port 8080</code>
            </>
          )}
        </p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Live Agent Tab
// ---------------------------------------------------------------------------

type LiveSubTab = "script" | "hushd";

export function LiveAgentTab() {
  const [activeSubTab, setActiveSubTab] = useState<LiveSubTab>("script");

  return (
    <div className="h-full flex flex-col bg-[#05060a]">
      {/* Sub-tab bar */}
      <div className="flex items-center border-b border-[#2d3240] bg-[#0b0d13] shrink-0">
        <button
          onClick={() => setActiveSubTab("script")}
          className={cn(
            "flex items-center gap-1.5 px-3 py-2 text-[10px] font-mono transition-colors border-b-2 -mb-px",
            activeSubTab === "script"
              ? "text-[#d4a84b] border-[#d4a84b]"
              : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:border-[#2d3240]",
          )}
        >
          <IconTerminal2 size={12} stroke={1.5} />
          Script Runner
        </button>
        <button
          onClick={() => setActiveSubTab("hushd")}
          className={cn(
            "flex items-center gap-1.5 px-3 py-2 text-[10px] font-mono transition-colors border-b-2 -mb-px",
            activeSubTab === "hushd"
              ? "text-[#d4a84b] border-[#d4a84b]"
              : "text-[#6f7f9a] border-transparent hover:text-[#ece7dc] hover:border-[#2d3240]",
          )}
        >
          <IconServer size={12} stroke={1.5} />
          hushd Monitor
        </button>
      </div>

      {/* Sub-tab content */}
      <div className="flex-1 min-h-0">
        {activeSubTab === "script" && <ScriptRunnerPanel />}
        {activeSubTab === "hushd" && <HushdMonitorPanel />}
      </div>
    </div>
  );
}
