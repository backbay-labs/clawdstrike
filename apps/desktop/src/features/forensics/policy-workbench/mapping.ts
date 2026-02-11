export type PolicyTestEventType =
  | "file_read"
  | "file_write"
  | "command_exec"
  | "network_egress"
  | "tool_call"
  | "patch_apply"
  | "secret_access";

export interface PolicyTestForm {
  eventType: PolicyTestEventType;
  target: string;
  content?: string;
  extra?: string;
  sessionId?: string;
  agentId?: string;
}

export const POLICY_TEST_EVENT_TYPES: PolicyTestEventType[] = [
  "file_read",
  "file_write",
  "command_exec",
  "network_egress",
  "tool_call",
  "patch_apply",
  "secret_access",
];

const POLICY_TEST_TARGET_PLACEHOLDERS: Record<PolicyTestEventType, string> = {
  file_read: "/workspace/file.txt",
  file_write: "/workspace/file.txt",
  command_exec: "git status --short",
  network_egress: "https://api.openai.com/v1/models",
  tool_call: "mcp__fs__read_file",
  patch_apply: "/workspace/src/main.ts",
  secret_access: "OPENAI_API_KEY",
};

export function getPolicyTestTargetPlaceholder(eventType: PolicyTestEventType): string {
  return POLICY_TEST_TARGET_PLACEHOLDERS[eventType] ?? "target";
}

function splitCommandline(commandline: string): { command: string; args: string[] } {
  const tokens = commandline
    .trim()
    .split(/\s+/)
    .filter(Boolean);
  if (tokens.length === 0) {
    throw new Error("command_exec target cannot be empty");
  }
  return { command: tokens[0], args: tokens.slice(1) };
}

function normalizeNetworkHost(host: string): string {
  if (host.startsWith("[") && host.endsWith("]")) {
    return host.slice(1, -1);
  }
  return host;
}

function parseNetworkTarget(target: string): { host: string; port: number; url?: string } {
  const trimmed = target.trim();
  if (!trimmed) throw new Error("network_egress target cannot be empty");

  if (trimmed.includes("://")) {
    const parsed = new URL(trimmed);
    const port =
      parsed.port.length > 0
        ? Number(parsed.port)
        : parsed.protocol === "http:"
          ? 80
          : 443;
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      throw new Error("network_egress target has invalid port");
    }
    return { host: normalizeNetworkHost(parsed.hostname), port, url: trimmed };
  }

  if (trimmed.startsWith("[") && trimmed.includes("]:")) {
    const end = trimmed.indexOf("]:");
    const host = trimmed.slice(1, end);
    const port = Number(trimmed.slice(end + 2));
    if (!host) throw new Error("network_egress target has empty host");
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      throw new Error("network_egress target has invalid port");
    }
    return { host, port };
  }

  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    const host = trimmed.slice(1, -1);
    if (!host) throw new Error("network_egress target has empty host");
    return { host, port: 443 };
  }

  const colonCount = (trimmed.match(/:/g) ?? []).length;
  if (colonCount > 1) {
    return { host: trimmed, port: 443 };
  }

  const idx = trimmed.lastIndexOf(":");
  if (idx > 0 && idx < trimmed.length - 1 && /^\d+$/.test(trimmed.slice(idx + 1))) {
    const host = trimmed.slice(0, idx);
    const port = Number(trimmed.slice(idx + 1));
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
      throw new Error("network_egress target has invalid port");
    }
    return { host, port };
  }

  return { host: trimmed, port: 443 };
}

function safeJsonObject(input?: string): Record<string, unknown> {
  if (!input?.trim()) return {};
  const parsed = JSON.parse(input);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("extra must be a JSON object");
  }
  return parsed as Record<string, unknown>;
}

export function buildPolicyTestEvent(
  form: PolicyTestForm,
  options?: { eventId?: string; timestamp?: string }
): Record<string, unknown> {
  const eventId = options?.eventId ?? `evt-${Date.now()}`;
  const timestamp = options?.timestamp ?? new Date().toISOString();

  const event: Record<string, unknown> = {
    eventId,
    eventType: form.eventType,
    timestamp,
    data: {},
    metadata: {},
  };

  if (form.sessionId?.trim()) event.sessionId = form.sessionId.trim();
  if (form.agentId?.trim()) (event.metadata as Record<string, unknown>).agentId = form.agentId.trim();

  switch (form.eventType) {
    case "file_read":
      if (!form.target.trim()) throw new Error("file_read target cannot be empty");
      event.data = { type: "file", path: form.target.trim(), operation: "read" };
      break;
    case "file_write":
      if (!form.target.trim()) throw new Error("file_write target cannot be empty");
      event.data = {
        type: "file",
        path: form.target.trim(),
        operation: "write",
        content: form.content ?? "",
      };
      break;
    case "command_exec": {
      const { command, args } = splitCommandline(form.target);
      event.data = { type: "command", command, args };
      break;
    }
    case "network_egress": {
      const { host, port, url } = parseNetworkTarget(form.target);
      event.data = {
        type: "network",
        host,
        port,
        ...(url ? { url } : {}),
      };
      break;
    }
    case "tool_call":
      if (!form.target.trim()) throw new Error("tool_call target cannot be empty");
      event.data = {
        type: "tool",
        toolName: form.target.trim(),
        parameters: safeJsonObject(form.extra),
      };
      break;
    case "patch_apply":
      if (!form.target.trim()) throw new Error("patch_apply target cannot be empty");
      event.data = {
        type: "patch",
        filePath: form.target.trim(),
        patchContent: form.content ?? "",
      };
      break;
    case "secret_access":
      if (!form.target.trim()) throw new Error("secret_access target cannot be empty");
      event.data = {
        type: "secret",
        secretName: form.target.trim(),
        scope: form.extra?.trim() || "runtime",
      };
      break;
    default:
      throw new Error(`unsupported event type: ${String(form.eventType)}`);
  }

  return event;
}
