import type { PolicyEngine } from '../policy/engine.js';

export function extractPath(params: Record<string, unknown>): string | undefined {
  const pathKeys = ['path', 'file', 'file_path', 'filepath', 'filename', 'target'];
  for (const key of pathKeys) {
    const value = params[key];
    if (typeof value === 'string') {
      return value;
    }
  }

  // Best-effort extraction from a command string (e.g., "cat /path/to/file").
  const cmdLine = typeof params.command === 'string' ? params.command : typeof params.cmd === 'string' ? params.cmd : undefined;
  if (cmdLine) {
    const match = cmdLine.match(/(?:cat|head|tail|less|more|vim|nano|read)\s+([^\s|><]+)/);
    if (match) return match[1];
  }

  return undefined;
}

function formatHostPort(hostRaw: string, port: number): string {
  const trimmed = hostRaw.trim();
  if (!trimmed) return '';

  // If the host already looks like `host:port`, prefer leaving it as-is to avoid
  // producing invalid forms like `[example.com:8080]:443`.
  const unbracketed = trimmed.replace(/^\[|\]$/g, '');
  const colonCount = (unbracketed.match(/:/g) ?? []).length;
  if (colonCount === 1 && !trimmed.startsWith('[')) {
    return trimmed;
  }

  return colonCount >= 2 ? `[${unbracketed}]:${port}` : `${unbracketed}:${port}`;
}

export function extractNetworkTarget(params: Record<string, unknown>): string | undefined {
  const url = typeof params.url === 'string' ? params.url
    : typeof params.endpoint === 'string' ? params.endpoint
    : typeof params.href === 'string' ? params.href
    : undefined;

  if (url) {
    try {
      const parsed = new URL(url);
      const host = parsed.hostname;
      if (host) {
        const port = parsed.port
          ? parseInt(parsed.port, 10)
          : parsed.protocol === 'https:' ? 443 : parsed.protocol === 'http:' ? 80 : undefined;
        if (typeof port === 'number' && Number.isFinite(port)) {
          return formatHostPort(host, port);
        }
        return host;
      }
    } catch {
      // Not a valid URL; fall through to host/port keys.
    }
  }

  const host = typeof params.host === 'string' ? params.host
    : typeof params.hostname === 'string' ? params.hostname
    : undefined;
  if (!host || !host.trim()) return undefined;

  const portRaw = params.port;
  const port = typeof portRaw === 'number' ? portRaw : typeof portRaw === 'string' ? parseInt(portRaw, 10) : undefined;
  if (typeof port === 'number' && Number.isFinite(port)) {
    return formatHostPort(host, port);
  }
  return host.trim();
}

export function normalizeApprovalResource(policyEngine: PolicyEngine, toolName: string, params: Record<string, unknown>): string {
  const raw = extractPath(params)
    ?? extractNetworkTarget(params)
    ?? (typeof params.command === 'string' ? params.command : typeof params.cmd === 'string' ? params.cmd : undefined)
    ?? toolName;
  const redacted = policyEngine.redactSecrets(raw).trim();

  const maxChars = 1024;
  if (redacted.length <= maxChars) return redacted;
  return redacted.slice(0, maxChars) + '...[truncated]';
}
