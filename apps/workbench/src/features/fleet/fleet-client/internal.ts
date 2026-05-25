// Internal helpers shared across the fleet-client sub-modules.
// Not part of the public surface of @/features/fleet/fleet-client — consumers
// should keep importing from the barrel.

import { validateFleetUrl } from "@/features/fleet/fleet-url-policy";
import { httpFetch } from "@/lib/workbench/http-transport";
import type { FleetConnection } from "./types";

export const DEV = import.meta.env.DEV;

export function normalizeFleetUrlInput(url: string): string {
  return url.trim();
}

export function normalizedValidatedFleetUrl(url: string, fieldName: string): string {
  const normalized = stripTrailingSlash(normalizeFleetUrlInput(url));
  const validation = validateFleetUrl(normalized);
  if (!validation.valid) {
    throw new Error(`Invalid ${fieldName}: ${validation.reason}`);
  }
  return normalized;
}

export function sanitizeStoredFleetUrl(url: string | null | undefined, fieldName: string): string {
  if (!url) return "";
  try {
    return normalizedValidatedFleetUrl(url, fieldName);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`[fleet-client] ignoring invalid ${fieldName} from storage: ${message}`);
    return "";
  }
}

export function proxyUrl(absoluteUrl: string, kind: "hushd" | "control"): string {
  const normalizedUrl = normalizeFleetUrlInput(absoluteUrl);
  if (!DEV) return normalizedUrl;

  // Validate URL before proxy rewrite (Finding 3)
  const validation = validateFleetUrl(normalizedUrl);
  if (!validation.valid) {
    throw new Error(`[fleet-client] Invalid fleet URL: ${validation.reason}`);
  }

  try {
    const u = new URL(normalizedUrl);
    return `/_proxy/${kind}${u.pathname}${u.search}`;
  } catch {
    // Don't log the raw URL to avoid credential leakage (Finding M3)
    console.warn("[fleet-client] Invalid URL format for proxy rewrite");
    return normalizedUrl;
  }
}

export function hushdHeaders(apiKey: string): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  if (apiKey) h["Authorization"] = `Bearer ${apiKey}`;
  return h;
}

export function isJwtLikeToken(token: string): boolean {
  const parts = token.split(".");
  return (
    parts.length === 3 &&
    parts.every((part) => part.length > 0 && /^[A-Za-z0-9_-]+$/.test(part))
  );
}

export function controlHeaders(conn: FleetConnection): Record<string, string> {
  const h: Record<string, string> = { "Content-Type": "application/json" };
  const token = conn.controlApiToken || conn.apiKey;
  if (token) {
    if (isJwtLikeToken(token)) {
      h["Authorization"] = `Bearer ${token}`;
    } else {
      h["x-api-key"] = token;
    }
  }
  return h;
}

export const MAX_RESPONSE_BYTES = 10_485_760;
export const MAX_ERROR_RESPONSE_BYTES = 2_048;

export function redactSecrets(text: string): string {
  return text
    .replace(/Bearer\s+[^\s]+/gi, "Bearer [REDACTED]")
    .replace(/x-api-key[:\s]+[^\s,;}]+/gi, "x-api-key: [REDACTED]");
}

export async function readResponseTextWithLimit(res: Response, maxBytes: number, signal?: AbortSignal | null): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) {
    const body = await res.arrayBuffer();
    if (body.byteLength > maxBytes) {
      throw new Error(`Response too large (${body.byteLength} bytes exceeds ${maxBytes} limit)`);
    }
    return new TextDecoder().decode(body);
  }

  const decoder = new TextDecoder();
  let total = 0;
  let text = "";

  try {
    while (true) {
      // Check the abort signal before each read to enforce the total request deadline
      if (signal?.aborted) {
        await reader.cancel().catch(() => {});
        throw new DOMException("The operation was aborted.", "AbortError");
      }
      const { done, value } = await reader.read();
      if (done) break;
      if (!value) continue;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new Error(`Response too large (${total} bytes exceeds ${maxBytes} limit)`);
      }
      text += decoder.decode(value, { stream: true });
    }
  } catch (err) {
    // If the signal was aborted mid-read, ensure the reader is cancelled
    if (signal?.aborted) {
      await reader.cancel().catch(() => {});
      throw new DOMException("The operation was aborted.", "AbortError");
    }
    throw err;
  }

  text += decoder.decode();
  return text;
}

export async function jsonFetch<T>(url: string, init?: RequestInit): Promise<T> {
  // Finding M3: block redirects so Bearer tokens / API keys are never
  // forwarded to a different host via an HTTP 3xx redirect.
  const signal = init?.signal ?? AbortSignal.timeout(10_000);
  const res = await httpFetch(url, { ...init, redirect: "error", signal });
  if (!res.ok) {
    const body = await readResponseTextWithLimit(res, MAX_ERROR_RESPONSE_BYTES, signal).catch(() => "");
    // Finding M3: truncate error body and strip secrets
    const sanitized = redactSecrets(body.slice(0, 200));
    throw new Error(sanitized || `HTTP ${res.status}`);
  }

  // Finding L9: check Content-Length before parsing
  const contentLength = res.headers.get("Content-Length");
  if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_BYTES) {
    throw new Error(`Response too large (${contentLength} bytes exceeds ${MAX_RESPONSE_BYTES} limit)`);
  }
  const bodyText = await readResponseTextWithLimit(res, MAX_RESPONSE_BYTES, signal);
  try {
    return JSON.parse(bodyText) as T;
  } catch (error) {
    const message = error instanceof Error ? error.message : "Invalid JSON";
    throw new Error(`Invalid JSON response: ${message}`);
  }
}

export function stripTrailingSlash(url: string): string {
  return url.replace(/\/+$/, "");
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

export function readString(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

export function readStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}

export function readNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

export function readBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

export function preferredUrl(conn: FleetConnection): { url: string; kind: "control" | "hushd" } {
  if (conn.controlApiUrl) {
    return {
      url: normalizedValidatedFleetUrl(conn.controlApiUrl, "control API URL"),
      kind: "control",
    };
  }
  return { url: normalizedValidatedFleetUrl(conn.hushdUrl, "hushd URL"), kind: "hushd" };
}

export function preferredControlUrl(conn: FleetConnection): string | null {
  if (!conn.controlApiUrl.trim()) return null;
  return normalizedValidatedFleetUrl(conn.controlApiUrl, "control API URL");
}
