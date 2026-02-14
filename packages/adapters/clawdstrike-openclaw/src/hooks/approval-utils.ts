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

export function normalizeApprovalResource(policyEngine: PolicyEngine, toolName: string, params: Record<string, unknown>): string {
  const raw = extractPath(params)
    ?? (typeof params.command === 'string' ? params.command : typeof params.cmd === 'string' ? params.cmd : undefined)
    ?? toolName;
  const redacted = policyEngine.redactSecrets(raw).trim();

  const maxChars = 1024;
  if (redacted.length <= maxChars) return redacted;
  return redacted.slice(0, maxChars) + '...[truncated]';
}

