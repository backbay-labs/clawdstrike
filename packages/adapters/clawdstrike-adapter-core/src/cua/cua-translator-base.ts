import type { ToolCallTranslationInput, ToolCallTranslator } from "../adapter.js";
import type { ParseNetworkTargetOptions } from "../network-target.js";
import { parseNetworkTarget } from "../network-target.js";
import { PolicyEventFactory } from "../policy-event-factory.js";
import type { CuaEventData, PolicyEvent } from "../types.js";

/**
 * Configuration for {@link createCuaTranslator}.
 */
export interface CuaTranslatorConfig {
  /** Provider name used in error messages (e.g. "OpenAI", "Claude"). */
  providerName: string;

  /** Set of lowercase tool names recognised as CUA tools (e.g. "computer_use"). */
  cuaToolNames: Set<string>;

  /**
   * Prefixes used both for tool-name detection and for extracting the action
   * from the tool name suffix (e.g. `["computer_use_", "computer_use."]`).
   */
  cuaToolPrefixes: string[];

  /**
   * Optional action normalizer applied after lowercasing.
   * Claude uses this to map `mouse_click` → `click`, `key_type` → `type`, etc.
   */
  normalizeAction?: (action: string) => string;

  /**
   * Set of action names that map to `remote.session.connect`.
   * Defaults to `{"navigate", "open_url", "go_to", "connect"}`.
   */
  connectActions?: Set<string>;

  /**
   * Canonical action name written into the event for connect actions.
   * When `undefined` the original (normalized) action is preserved.
   * Claude sets this to `"navigate"`.
   */
  connectEventAction?: string;
}

// ---------------------------------------------------------------------------
// Canonical constants
// ---------------------------------------------------------------------------

const CANONICAL_INPUT_ACTIONS = new Set([
  "click",
  "type",
  "key",
  "key_chord",
  "scroll",
  "drag",
  "move_mouse",
]);

const DEFAULT_CONNECT_ACTIONS = new Set(["navigate", "open_url", "go_to", "connect"]);

// ---------------------------------------------------------------------------
// Shared helper functions
// ---------------------------------------------------------------------------

function ensureSessionId(sessionId: string | undefined, providerName: string): string {
  if (typeof sessionId !== "string" || sessionId.trim().length === 0) {
    throw new Error(`${providerName} CUA translator requires a sessionId`);
  }
  return sessionId;
}

function withAction(
  event: PolicyEvent,
  cuaAction: string,
  extra?: Partial<CuaEventData>,
): PolicyEvent {
  if (event.data.type !== "cua") {
    throw new Error("CUA translator produced non-CUA event data");
  }
  event.data.cuaAction = cuaAction;
  if (extra) {
    Object.assign(event.data, extra);
  }
  return event;
}

function deriveInputType(action: string, parameters: Record<string, unknown>): string | undefined {
  if (typeof parameters.input_type === "string" && parameters.input_type.trim().length > 0) {
    return parameters.input_type.trim().toLowerCase();
  }
  if (action === "type" || action === "key" || action === "key_chord") {
    return "keyboard";
  }
  if (action === "click" || action === "scroll" || action === "drag" || action === "move_mouse") {
    return "mouse";
  }
  return undefined;
}

function maybeTransferSize(parameters: Record<string, unknown>): number | undefined {
  const value =
    parameters.transfer_size ??
    parameters.transferSize ??
    parameters.size_bytes ??
    parameters.sizeBytes;
  if (typeof value === "number" && Number.isFinite(value) && value >= 0) {
    return Math.trunc(value);
  }
  if (typeof value === "string") {
    const parsed = Number.parseInt(value, 10);
    if (Number.isFinite(parsed) && parsed >= 0) {
      return parsed;
    }
  }
  return undefined;
}

function maybePort(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) {
    const port = Math.trunc(value);
    if (port > 0 && port <= 65535) return port;
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (/^[0-9]+$/.test(trimmed)) {
      const parsed = Number.parseInt(trimmed, 10);
      if (Number.isFinite(parsed) && parsed > 0 && parsed <= 65535) {
        return parsed;
      }
    }
  }
  return undefined;
}

function firstNonEmptyString(values: unknown[]): string | undefined {
  for (const value of values) {
    if (typeof value !== "string") continue;
    const trimmed = value.trim();
    if (trimmed.length > 0) return trimmed;
  }
  return undefined;
}

function deriveConnectMetadata(
  parameters: Record<string, unknown>,
  parseOpts?: ParseNetworkTargetOptions,
): Partial<CuaEventData> {
  const url = firstNonEmptyString([
    parameters.url,
    parameters.endpoint,
    parameters.href,
    parameters.target_url,
    parameters.targetUrl,
  ]);
  const parsed = parseNetworkTarget(url ?? "", parseOpts ?? { emptyPort: "default" });
  const host = firstNonEmptyString([
    parameters.host,
    parameters.hostname,
    parameters.remote_host,
    parameters.remoteHost,
    parameters.destination_host,
    parameters.destinationHost,
    parsed.host,
  ])?.toLowerCase();

  const explicitPort = maybePort(
    parameters.port ??
      parameters.remote_port ??
      parameters.remotePort ??
      parameters.destination_port ??
      parameters.destinationPort,
  );
  const protocol = firstNonEmptyString([parameters.protocol, parameters.scheme])?.toLowerCase();

  const extra: Partial<CuaEventData> = { direction: "outbound" };
  if (host) (extra as Record<string, unknown>).host = host;
  if (explicitPort !== undefined) {
    (extra as Record<string, unknown>).port = explicitPort;
  } else if (parsed.host) {
    (extra as Record<string, unknown>).port = parsed.port;
  }
  if (url) (extra as Record<string, unknown>).url = url;
  if (protocol) (extra as Record<string, unknown>).protocol = protocol;
  return extra;
}

function failUnknownAction(action: string, providerName: string): never {
  throw new Error(`${providerName} CUA translator does not support action '${action}'`);
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

/**
 * Create a provider-specific CUA {@link ToolCallTranslator} from a
 * declarative configuration.
 *
 * The returned translator maps provider tool calls into canonical CUA
 * {@link PolicyEvent}s that the policy engine can evaluate.
 *
 * @example OpenAI (no action normalization)
 * ```ts
 * export const openAICuaTranslator = createCuaTranslator({
 *   providerName: "OpenAI",
 *   cuaToolNames: new Set(["computer_use", "computer.use", "computer-use", "computer"]),
 *   cuaToolPrefixes: ["computer_use_", "computer_use."],
 * });
 * ```
 *
 * @example Claude (with action normalization)
 * ```ts
 * export const claudeCuaTranslator = createCuaTranslator({
 *   providerName: "Claude",
 *   cuaToolNames: new Set(["computer", "computer_use", "computer.use", "computer-use"]),
 *   cuaToolPrefixes: ["computer_", "computer."],
 *   normalizeAction: (a) =>
 *     ({ mouse_click: "click", key_type: "type", key_press: "key", keypress: "key" }[a] ?? a),
 *   connectActions: new Set(["navigate", "connect"]),
 *   connectEventAction: "navigate",
 * });
 * ```
 */
export function createCuaTranslator(config: CuaTranslatorConfig): ToolCallTranslator {
  const {
    providerName,
    cuaToolNames,
    cuaToolPrefixes,
    normalizeAction: userNormalize,
    connectActions = DEFAULT_CONNECT_ACTIONS,
    connectEventAction,
  } = config;

  const factory = new PolicyEventFactory();

  function isCuaTool(toolName: string): boolean {
    const lower = toolName.toLowerCase();
    if (cuaToolNames.has(lower)) return true;
    return cuaToolPrefixes.some((p) => lower.startsWith(p));
  }

  function normalize(action: string): string {
    const lower = action.toLowerCase();
    return userNormalize ? userNormalize(lower) : lower;
  }

  function extractAction(input: ToolCallTranslationInput): string | null {
    const explicit = input.parameters.action;
    if (typeof explicit === "string" && explicit.trim().length > 0) {
      return normalize(explicit.trim());
    }

    const lowerTool = input.toolName.toLowerCase();
    for (const prefix of cuaToolPrefixes) {
      if (lowerTool.startsWith(prefix)) {
        return normalize(lowerTool.slice(prefix.length));
      }
    }

    return null;
  }

  function dispatchAction(
    action: string,
    sessionId: string,
    params: Record<string, unknown>,
  ): PolicyEvent {
    if (CANONICAL_INPUT_ACTIONS.has(action)) {
      const inputType = deriveInputType(action, params);
      const extra: Partial<CuaEventData> = {
        ...(inputType ? { input_type: inputType } : {}),
      };
      return withAction(factory.createCuaInputInjectEvent(sessionId, extra), action);
    }

    if (connectActions.has(action)) {
      const connectMeta = deriveConnectMetadata(params);
      const eventAction = connectEventAction ?? action;
      return withAction(
        factory.createCuaConnectEvent(sessionId, connectMeta),
        eventAction,
        connectMeta,
      );
    }

    switch (action) {
      case "disconnect":
        return withAction(factory.createCuaDisconnectEvent(sessionId), action);
      case "reconnect":
        return withAction(factory.createCuaReconnectEvent(sessionId), action);
      case "screenshot":
        return withAction(factory.createCuaClipboardEvent(sessionId, "read"), action, {
          direction: "read",
        });
      case "clipboard_read":
      case "read_clipboard":
        return withAction(factory.createCuaClipboardEvent(sessionId, "read"), "clipboard_read", {
          direction: "read",
        });
      case "clipboard_write":
      case "write_clipboard":
        return withAction(
          factory.createCuaClipboardEvent(sessionId, "write"),
          "clipboard_write",
          { direction: "write" },
        );
      case "file_transfer":
      case "file_upload":
      case "upload": {
        const transferSize = maybeTransferSize(params);
        return withAction(
          factory.createCuaFileTransferEvent(sessionId, "upload", {
            ...(transferSize !== undefined ? { transfer_size: transferSize } : {}),
          }),
          "file_transfer",
          {
            direction: "upload",
            ...(transferSize !== undefined ? { transfer_size: transferSize } : {}),
          },
        );
      }
      case "file_download":
      case "download": {
        const transferSize = maybeTransferSize(params);
        return withAction(
          factory.createCuaFileTransferEvent(sessionId, "download", {
            ...(transferSize !== undefined ? { transfer_size: transferSize } : {}),
          }),
          "file_transfer",
          {
            direction: "download",
            ...(transferSize !== undefined ? { transfer_size: transferSize } : {}),
          },
        );
      }
      case "session_share":
      case "share_session":
        return withAction(factory.createCuaSessionShareEvent(sessionId), "session_share");
      case "audio":
      case "audio_stream":
        return withAction(factory.createCuaAudioEvent(sessionId), "audio");
      case "drive_mapping":
      case "map_drive":
        return withAction(factory.createCuaDriveMappingEvent(sessionId), "drive_mapping");
      case "printing":
      case "print":
        return withAction(factory.createCuaPrintingEvent(sessionId), "printing");
      default:
        return failUnknownAction(action, providerName);
    }
  }

  return (input: ToolCallTranslationInput): PolicyEvent | null => {
    if (!isCuaTool(input.toolName)) {
      return null;
    }

    const action = extractAction(input);
    if (!action) {
      throw new Error(
        `${providerName} CUA translator could not resolve action for tool '${input.toolName}'`,
      );
    }

    const sessionId = ensureSessionId(input.sessionId, providerName);
    return dispatchAction(action, sessionId, input.parameters);
  };
}
