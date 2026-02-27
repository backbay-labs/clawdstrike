/**
 * @clawdstrike/openclaw - Tool Call Translator
 *
 * Maps OpenClaw tool calls to canonical PolicyEvent objects using the shared
 * token-based classification system.  This is the OpenClaw equivalent of the
 * Claude adapter's `claudeCuaTranslator` — it normalizes framework-specific
 * tool calls into the canonical event schema consumed by the policy engine.
 *
 * Design: returns `null` for tools that cannot be confidently classified,
 * allowing the BaseToolInterceptor fallback to handle them.
 */

import type {
  AdapterConfig,
  PolicyEvent,
  ToolCallTranslationInput,
  ToolCallTranslator,
} from '@clawdstrike/adapter-core';
import {
  tokenize,
  classifyTool,
  inferEventTypeFromName,
} from '../classification.js';
import {
  isCuaToolCall,
  buildCuaEvent,
  classifyCuaAction,
  extractActionToken,
} from '../hooks/cua-bridge/handler.js';
import { extractPath } from '../hooks/approval-utils.js';

// ── Parameter Extraction Helpers ────────────────────────────────────

function extractFilePath(params: Record<string, unknown>): string {
  return extractPath(params) ?? '';
}

function extractCommand(params: Record<string, unknown>): { command: string; args: string[] } {
  const cmdLine =
    typeof params.command === 'string'
      ? params.command
      : typeof params.cmd === 'string'
        ? params.cmd
        : '';

  const argv =
    Array.isArray(params.argv) && params.argv.every((a) => typeof a === 'string')
      ? (params.argv as string[])
      : Array.isArray(params.args) && params.args.every((a) => typeof a === 'string')
        ? (params.args as string[])
        : null;

  let command = '';
  let args: string[] = [];

  if (cmdLine.trim()) {
    const parts = cmdLine.trim().split(/\s+/).filter(Boolean);
    command = parts[0] ?? '';
    const inlineArgs = parts.slice(1);

    if (inlineArgs.length > 0) {
      args = inlineArgs;
    } else if (argv && argv.length > 0) {
      args = argv[0] === command ? argv.slice(1) : argv;
    }
  } else if (argv && argv.length > 0) {
    [command, ...args] = argv;
  }

  return { command, args };
}

function extractNetworkInfo(params: Record<string, unknown>): { host: string; port: number; url?: string } {
  const url =
    typeof params.url === 'string' ? params.url
    : typeof params.endpoint === 'string' ? params.endpoint
    : typeof params.href === 'string' ? params.href
    : undefined;

  if (url) {
    try {
      const parsed = new URL(url);
      return {
        host: parsed.hostname,
        port: parsed.port
          ? parseInt(parsed.port, 10)
          : (parsed.protocol === 'https:' || parsed.protocol === 'wss:' ? 443 : 80),
        url,
      };
    } catch {
      // Not a valid URL; fall through.
    }
  }

  const host =
    typeof params.host === 'string' ? params.host
    : typeof params.hostname === 'string' ? params.hostname
    : 'unknown';

  const port = typeof params.port === 'number' ? params.port : 80;
  return { host, port, url };
}

function extractPatchInfo(params: Record<string, unknown>): { filePath: string; patchContent: string } {
  const filePath =
    typeof params.filePath === 'string' ? params.filePath
    : typeof params.path === 'string' ? params.path
    : '';
  const patchContent =
    typeof params.patch === 'string' ? params.patch
    : typeof params.diff === 'string' ? params.diff
    : typeof params.content === 'string' ? params.content
    : '';
  return { filePath, patchContent };
}

// ── Parameter-based fallback heuristics ─────────────────────────────

function looksLikePatchApply(params: Record<string, unknown>): boolean {
  return typeof params.patch === 'string'
    || typeof params.diff === 'string'
    || typeof params.patchContent === 'string';
}

function looksLikeCommandExec(params: Record<string, unknown>): boolean {
  if (typeof params.command === 'string' || typeof params.cmd === 'string') return true;
  if (Array.isArray(params.args) && params.args.every((a) => typeof a === 'string')) return true;
  if (Array.isArray(params.argv) && params.argv.every((a) => typeof a === 'string')) return true;
  return false;
}

function looksLikeNetworkEgress(params: Record<string, unknown>): boolean {
  if (typeof params.url === 'string' || typeof params.endpoint === 'string' || typeof params.href === 'string') return true;
  if (typeof params.host === 'string' || typeof params.hostname === 'string') return true;
  return false;
}

function looksLikeFileWrite(params: Record<string, unknown>): boolean {
  if (typeof params.content === 'string') return true;
  if (typeof params.text === 'string') return true;
  if (typeof params.contentBase64 === 'string') return true;
  if (typeof params.base64 === 'string') return true;
  if (typeof params.patch === 'string' || typeof params.diff === 'string') return true;
  if (typeof params.operation === 'string') {
    const op = params.operation.toLowerCase();
    if (op === 'write' || op === 'append' || op === 'delete' || op === 'remove' || op === 'truncate') return true;
  }
  return false;
}

// ── Event ID ────────────────────────────────────────────────────────

function generateEventId(): string {
  return `oclaw-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
}

// ── Core Translator ─────────────────────────────────────────────────

/**
 * OpenClaw tool-call translator.
 *
 * Uses the shared token-based classification system from `classification.ts`
 * to map tool calls to canonical PolicyEvent objects.  CUA tool calls are
 * delegated to the CUA bridge's event builder.
 *
 * Returns `null` when the tool cannot be confidently classified, allowing
 * the BaseToolInterceptor to apply its own fallback logic.
 */
export const openclawTranslator: ToolCallTranslator = (input: ToolCallTranslationInput): PolicyEvent | null => {
  const { toolName, parameters, sessionId } = input;

  // ── CUA Detection ───────────────────────────────────────────────
  if (isCuaToolCall(toolName, parameters)) {
    if (!sessionId) return null;

    const actionToken = extractActionToken(toolName, parameters);
    if (!actionToken) return null;

    const kind = classifyCuaAction(actionToken);
    if (!kind) return null;

    return buildCuaEvent(sessionId, kind, parameters);
  }

  // ── Token-based classification ──────────────────────────────────
  const tokens = tokenize(toolName);
  const classification = classifyTool(tokens);
  const eventType = inferEventTypeFromName(toolName);
  const timestamp = new Date().toISOString();

  // Use the inferred event type from name tokens when available.
  if (eventType) {
    switch (eventType) {
      case 'file_read': {
        const path = extractFilePath(parameters);
        return {
          eventId: generateEventId(),
          eventType: 'file_read',
          timestamp,
          sessionId,
          data: { type: 'file', path, operation: 'read' },
          metadata: { source: 'openclaw-translator', toolName },
        };
      }

      case 'file_write': {
        const path = extractFilePath(parameters);
        return {
          eventId: generateEventId(),
          eventType: 'file_write',
          timestamp,
          sessionId,
          data: {
            type: 'file',
            path,
            operation: 'write',
            ...(typeof parameters.content === 'string' ? { content: parameters.content } : {}),
          },
          metadata: { source: 'openclaw-translator', toolName },
        };
      }

      case 'command_exec': {
        const { command, args } = extractCommand(parameters);
        return {
          eventId: generateEventId(),
          eventType: 'command_exec',
          timestamp,
          sessionId,
          data: {
            type: 'command',
            command,
            args,
            ...(typeof parameters.cwd === 'string' ? { workingDir: parameters.cwd } : {}),
          },
          metadata: { source: 'openclaw-translator', toolName },
        };
      }

      case 'network_egress': {
        const { host, port, url } = extractNetworkInfo(parameters);
        return {
          eventId: generateEventId(),
          eventType: 'network_egress',
          timestamp,
          sessionId,
          data: { type: 'network', host, port, url },
          metadata: { source: 'openclaw-translator', toolName },
        };
      }

      case 'patch_apply': {
        const { filePath, patchContent } = extractPatchInfo(parameters);
        return {
          eventId: generateEventId(),
          eventType: 'patch_apply',
          timestamp,
          sessionId,
          data: { type: 'patch', filePath, patchContent },
          metadata: { source: 'openclaw-translator', toolName },
        };
      }

      default:
        // Other event types (e.g. CUA remote.* types) are already handled above.
        break;
    }
  }

  // ── Parameter-based fallback for unclassified tools ─────────────
  // When token-based classification returns null (unknown), attempt
  // parameter inspection — same heuristics as the preflight handler.

  if (classification === 'unknown') {
    if (looksLikePatchApply(parameters)) {
      const { filePath, patchContent } = extractPatchInfo(parameters);
      return {
        eventId: generateEventId(),
        eventType: 'patch_apply',
        timestamp,
        sessionId,
        data: { type: 'patch', filePath, patchContent },
        metadata: { source: 'openclaw-translator', toolName },
      };
    }

    if (looksLikeCommandExec(parameters)) {
      const { command, args } = extractCommand(parameters);
      return {
        eventId: generateEventId(),
        eventType: 'command_exec',
        timestamp,
        sessionId,
        data: {
          type: 'command',
          command,
          args,
          ...(typeof parameters.cwd === 'string' ? { workingDir: parameters.cwd } : {}),
        },
        metadata: { source: 'openclaw-translator', toolName },
      };
    }

    if (looksLikeNetworkEgress(parameters)) {
      const { host, port, url } = extractNetworkInfo(parameters);
      return {
        eventId: generateEventId(),
        eventType: 'network_egress',
        timestamp,
        sessionId,
        data: { type: 'network', host, port, url },
        metadata: { source: 'openclaw-translator', toolName },
      };
    }

    const path = extractFilePath(parameters);
    if (path) {
      const isWrite = looksLikeFileWrite(parameters);
      return {
        eventId: generateEventId(),
        eventType: isWrite ? 'file_write' : 'file_read',
        timestamp,
        sessionId,
        data: {
          type: 'file',
          path,
          operation: isWrite ? 'write' : 'read',
          ...(isWrite && typeof parameters.content === 'string' ? { content: parameters.content } : {}),
        },
        metadata: { source: 'openclaw-translator', toolName },
      };
    }
  }

  // Cannot confidently classify — return null so BaseToolInterceptor
  // can apply its own default handling.
  return null;
};

// ── Config Composer ─────────────────────────────────────────────────

/**
 * Compose an AdapterConfig that chains the OpenClaw translator before
 * any user-supplied translator.  The OpenClaw translator runs first;
 * if it returns a PolicyEvent, that result is used.  Otherwise, the
 * user-supplied translator (if any) gets a chance to translate.
 */
export function composeOpenClawConfig(config: AdapterConfig = {}): AdapterConfig {
  const userTranslator = config.translateToolCall;
  return {
    ...config,
    translateToolCall: (input) => {
      const translated = openclawTranslator(input);
      if (translated) return translated;
      return userTranslator ? userTranslator(input) : null;
    },
  };
}
