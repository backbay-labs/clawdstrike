/**
 * @clawdstrike/openclaw - Shared Tool Classification
 *
 * Canonical token-based classification logic shared between the tool-preflight
 * and tool-guard hooks.  This module is self-contained — it only depends on
 * the EventType type from the package's own types module.
 */

import type { EventType } from "./types.js";

// ── Token Sets ───────────────────────────────────────────────────────

/** Read-only tokens: if ANY token matches and no destructive token is present, tool is read-only */
export const READ_ONLY_TOKENS = new Set([
  "read",
  "list",
  "get",
  "search",
  "view",
  "show",
  "find",
  "describe",
  "info",
  "status",
  "check",
  "ls",
  "cat",
  "head",
  "tail",
  "which",
  "echo",
  "pwd",
  "env",
  "whoami",
  "hostname",
  "uname",
  "date",
  "glob",
  "grep",
]);

/** Destructive tokens: if ANY token matches, tool is destructive */
export const DESTRUCTIVE_TOKENS = new Set([
  "write",
  "delete",
  "remove",
  "rm",
  "kill",
  "exec",
  "run",
  "install",
  "uninstall",
  "create",
  "update",
  "modify",
  "patch",
  "put",
  "post",
  "move",
  "mv",
  "rename",
  "chmod",
  "chown",
  "drop",
  "truncate",
  "edit",
  "command",
  "bash",
  "save",
  "overwrite",
  "unlink",
  "terminal",
  "append",
  "replace",
  "deploy",
  "push",
  "send",
  "publish",
  "upload",
]);

/** Destructive token-to-event-type mapping for specific policy routing */
export const DESTRUCTIVE_EVENT_MAP: ReadonlyArray<{ tokens: Set<string>; eventType: EventType }> = [
  {
    tokens: new Set(["write", "edit", "create", "save", "overwrite", "append", "replace"]),
    eventType: "file_write",
  },
  { tokens: new Set(["delete", "remove", "unlink", "rm"]), eventType: "file_write" },
  {
    tokens: new Set(["shell", "bash", "exec", "command", "terminal", "run"]),
    eventType: "command_exec",
  },
  { tokens: new Set(["patch", "diff"]), eventType: "patch_apply" },
];

/** Network tokens for egress classification */
export const NETWORK_TOKENS = new Set([
  "fetch",
  "http",
  "web",
  "curl",
  "request",
  "api",
  "download",
  "socket",
  "connect",
]);

// ── Tokenizer ────────────────────────────────────────────────────────

/**
 * Tokenize a tool name by splitting on common delimiters and camel-case boundaries.
 */
export function tokenize(toolName: string): string[] {
  return (
    toolName
      // Split `fooBar` -> `foo Bar`, `HTTPFetch` -> `HTTP Fetch`
      .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
      .replace(/([A-Z])([A-Z][a-z])/g, "$1 $2")
      .toLowerCase()
      .split(/[_\-/\s.]+/)
      .filter(Boolean)
  );
}

// ── Classification ───────────────────────────────────────────────────

export type ToolClassification = "read_only" | "destructive" | "unknown";

/**
 * Classify a tool based on its name tokens.
 * - If ANY token is destructive -> destructive
 * - If ANY token is read-only and NO token is destructive -> read-only
 * - Otherwise -> unknown (treated as potentially destructive)
 */
export function classifyTool(tokens: string[]): ToolClassification {
  let hasReadOnly = false;
  let hasDestructive = false;

  for (const token of tokens) {
    if (DESTRUCTIVE_TOKENS.has(token)) {
      hasDestructive = true;
    }
    if (READ_ONLY_TOKENS.has(token)) {
      hasReadOnly = true;
    }
  }

  if (hasDestructive) return "destructive";
  if (hasReadOnly) return "read_only";
  return "unknown";
}

// ── Event Type Inference (name-only) ─────────────────────────────────

/**
 * Infer the policy event type from a tool name using only token-based
 * classification.  Returns null when no confident classification can be
 * made (callers may then fall back to parameter-based heuristics).
 *
 * This is the canonical, shared implementation used by both the
 * tool-preflight and tool-guard hooks.
 */
export function inferEventTypeFromName(toolName: string): EventType | null {
  const tokens = tokenize(toolName);
  const classification = classifyTool(tokens);

  if (classification === "read_only") {
    // Read-only tools may still perform network egress (e.g. web_search, http_get).
    if (tokens.some((t) => NETWORK_TOKENS.has(t))) {
      return "network_egress";
    }
    return "file_read";
  }

  // Check specific destructive event types via DESTRUCTIVE_EVENT_MAP.
  for (const { tokens: matchTokens, eventType } of DESTRUCTIVE_EVENT_MAP) {
    if (tokens.some((t) => matchTokens.has(t))) {
      return eventType;
    }
  }

  // Check network tokens.
  if (tokens.some((t) => NETWORK_TOKENS.has(t))) {
    return "network_egress";
  }

  // No confident classification — return null so callers can apply their
  // own fallback logic (e.g. parameter inspection).
  return null;
}
