/**
 * Bridge Protocol Types
 *
 * Defines the typed postMessage envelope that both sides of the plugin bridge
 * speak. The BridgeMessage discriminated union covers request, response, event,
 * and error variants. BRIDGE_METHODS maps every PluginContext API surface to
 * its namespaced bridge method string.
 *
 * This file has zero runtime dependencies -- it is pure types + constants.
 */

// ---- Error Codes ----

/**
 * Error codes returned by the bridge host when a call fails.
 *
 * - METHOD_NOT_FOUND: The bridge method does not exist
 * - INVALID_PARAMS: The parameters are malformed or missing required fields
 * - INTERNAL_ERROR: An unexpected error occurred on the host side
 * - TIMEOUT: The call exceeded BRIDGE_TIMEOUT_MS without a response
 * - PERMISSION_DENIED: The plugin lacks the capability for this method
 * - PLUGIN_REVOKED: The plugin has been revoked fleet-wide
 */
export type BridgeErrorCode =
  | "METHOD_NOT_FOUND"
  | "INVALID_PARAMS"
  | "INTERNAL_ERROR"
  | "TIMEOUT"
  | "PERMISSION_DENIED"
  | "PLUGIN_REVOKED";

/**
 * Structured error returned inside a BridgeErrorResponse.
 */
export interface BridgeError {
  /** Machine-readable error code. */
  code: BridgeErrorCode;
  /** Human-readable error description. */
  message: string;
}

// ---- Message Variants ----

/**
 * A request sent from the plugin iframe to the host.
 * The host dispatches to the appropriate registry and returns a BridgeResponse
 * or BridgeErrorResponse with the same `id`.
 */
export interface BridgeRequest {
  /** Correlation ID for matching the response. */
  id: string;
  /** Discriminant. */
  type: "request";
  /** Namespaced method name (e.g. "guards.register"). */
  method: string;
  /** Serialized arguments for the method. */
  params?: unknown;
}

/**
 * A successful response from the host to the plugin iframe.
 * Carries the result of the dispatched method.
 */
export interface BridgeResponse {
  /** Correlation ID matching the original request. */
  id: string;
  /** Discriminant. */
  type: "response";
  /** Serialized return value from the method. */
  result?: unknown;
}

/**
 * A fire-and-forget event pushed from the host to the plugin.
 * Events have no ID -- they are not correlated with requests.
 */
export interface BridgeEvent {
  /** Discriminant. */
  type: "event";
  /** Namespaced event name (e.g. "policy.changed"). */
  method: string;
  /** Serialized event payload. */
  params?: unknown;
}

/**
 * An error response from the host to the plugin iframe.
 * Returned when a bridge call fails (validation, dispatch, or host error).
 */
export interface BridgeErrorResponse {
  /** Correlation ID matching the original request. */
  id: string;
  /** Discriminant. */
  type: "error";
  /** Structured error details. */
  error: BridgeError;
}

// ---- Discriminated Union ----

/**
 * The discriminated union of all message types that flow over the bridge.
 * Discriminated on the `type` field.
 */
export type BridgeMessage =
  | BridgeRequest
  | BridgeResponse
  | BridgeEvent
  | BridgeErrorResponse;

// ---- Method Map ----

/**
 * Maps every PluginContext API method to its namespaced bridge method string.
 * Typed `as const` for literal type inference.
 */
export const BRIDGE_METHODS = {
  commands: {
    register: "commands.register",
  },
  guards: {
    register: "guards.register",
  },
  fileTypes: {
    register: "fileTypes.register",
  },
  statusBar: {
    register: "statusBar.register",
  },
  sidebar: {
    register: "sidebar.register",
  },
  storage: {
    get: "storage.get",
    set: "storage.set",
  },
} as const;

/**
 * Union type of all bridge method name strings.
 */
type BridgeMethodValues<T> = T extends Record<string, infer V>
  ? V extends string
    ? V
    : BridgeMethodValues<V>
  : never;

export type BridgeMethodName = BridgeMethodValues<typeof BRIDGE_METHODS>;

// ---- Constants ----

/**
 * Default timeout for bridge calls in milliseconds.
 * Calls that exceed this duration are rejected with BridgeError(TIMEOUT).
 */
export const BRIDGE_TIMEOUT_MS = 30_000;

// ---- Type Guard ----

const VALID_TYPES = new Set<string>(["request", "response", "event", "error"]);
const TYPES_REQUIRING_ID = new Set<string>(["request", "response", "error"]);

/**
 * Runtime type guard that validates an unknown value is a valid BridgeMessage.
 *
 * Checks:
 * - data is a non-null object
 * - data.type is one of "request", "response", "event", "error"
 * - If type requires an id (request, response, error), data.id must be a string
 */
export function isBridgeMessage(data: unknown): data is BridgeMessage {
  if (data === null || data === undefined || typeof data !== "object") {
    return false;
  }

  const obj = data as Record<string, unknown>;
  const type = obj.type;

  if (typeof type !== "string" || !VALID_TYPES.has(type)) {
    return false;
  }

  if (TYPES_REQUIRING_ID.has(type) && typeof obj.id !== "string") {
    return false;
  }

  return true;
}
