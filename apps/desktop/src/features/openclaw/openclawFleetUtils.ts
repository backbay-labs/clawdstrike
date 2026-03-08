export const DEFAULT_GATEWAY_URL = "ws://127.0.0.1:18789";

export type ParsedCommand = { argv: string[]; rawCommand: string | null; error: string | null };

export function parseCommand(raw: string): ParsedCommand {
  const trimmed = raw.trim();
  if (!trimmed) return { argv: [], rawCommand: null, error: "command required" };

  if (trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (!Array.isArray(parsed) || parsed.length === 0) {
        return { argv: [], rawCommand: null, error: "JSON argv must be a non-empty array" };
      }
      const argv = parsed
        .map((v) => String(v))
        .map((v) => v.trim())
        .filter(Boolean);
      if (argv.length === 0)
        return { argv: [], rawCommand: null, error: "JSON argv contained only empty items" };
      return { argv, rawCommand: null, error: null };
    } catch (err) {
      return {
        argv: [],
        rawCommand: null,
        error: err instanceof Error ? err.message : "invalid JSON argv",
      };
    }
  }

  return { argv: trimmed.split(/\s+/g).filter(Boolean), rawCommand: trimmed, error: null };
}

export function statusDotClass(status: string) {
  switch (status) {
    case "connected":
      return "bg-sdr-accent-green";
    case "connecting":
      return "bg-sdr-accent-amber animate-pulse";
    case "error":
      return "bg-sdr-accent-red";
    default:
      return "bg-sdr-text-muted";
  }
}

export function timeAgo(ts: number | null | undefined) {
  if (!ts) return "n/a";
  const delta = Date.now() - ts;
  if (delta < 0) return "just now";
  const seconds = Math.floor(delta / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export function originFixHint(lastError: string | null): string | null {
  if (!lastError) return null;
  const msg = lastError.toLowerCase();
  if (!msg.includes("origin") || !msg.includes("allowed")) return null;
  const currentOrigin =
    typeof window !== "undefined" ? window.location.origin : "http://localhost:1420";
  const origins = [currentOrigin];
  if (!origins.includes("tauri://localhost")) {
    origins.push("tauri://localhost");
  }
  return [
    "OpenClaw rejected this app origin.",
    "Fix: allow Huntronomer origins then restart the gateway:",
    `openclaw config set --json gateway.controlUi.allowedOrigins '${JSON.stringify(origins)}'`,
    "openclaw gateway restart",
  ].join("\n");
}

export function normalizeGatewayUrl(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return "";
  const lowered = trimmed.toLowerCase();
  const withScheme =
    lowered.startsWith("ws://") || lowered.startsWith("wss://")
      ? trimmed
      : lowered.startsWith("http://")
        ? `ws://${trimmed.slice("http://".length)}`
        : lowered.startsWith("https://")
          ? `wss://${trimmed.slice("https://".length)}`
          : /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
            ? trimmed
            : `ws://${trimmed}`;
  return withScheme.replace(/\/+$/, "");
}

export function selectSystemRunNodes<
  TNode extends { nodeId?: string; commands?: unknown; connected?: boolean },
>(nodes: TNode[]): TNode[] {
  return nodes.filter((n) => {
    const cmds = Array.isArray(n.commands) ? n.commands : [];
    return !!n.nodeId && !!n.connected && cmds.some((c) => String(c) === "system.run");
  });
}
