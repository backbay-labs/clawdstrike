/**
 * Bridge Module Barrel Export
 *
 * Re-exports the complete bridge public API: client, host, error class,
 * protocol types, constants, and type guard.
 */

export { PluginBridgeClient, BridgeError } from "./bridge-client";
export { PluginBridgeHost } from "./bridge-host";
export type { BridgeHandler, BridgeHostOptions } from "./bridge-host";
export {
  checkPermission,
  METHOD_TO_PERMISSION,
  KNOWN_PERMISSIONS,
  checkNetworkPermission,
  extractNetworkPermissions,
} from "./permissions";
export type {
  BridgeMessage,
  BridgeRequest,
  BridgeResponse,
  BridgeEvent,
  BridgeErrorResponse,
  BridgeErrorCode,
  BridgeMethodName,
} from "./types";
export { BRIDGE_METHODS, BRIDGE_TIMEOUT_MS, isBridgeMessage } from "./types";
export type {
  PluginActionReceipt,
  PluginActionReceiptContent,
} from "./receipt-types";
export { createReceiptContent } from "./receipt-types";
export type { ReceiptQueryFilter } from "./receipt-store";
export {
  PluginReceiptStore,
  getPluginReceiptStore,
  usePluginReceipts,
} from "./receipt-store";
export { createReceiptMiddleware } from "./receipt-middleware";
export type { ReceiptMiddlewareOptions } from "./receipt-middleware";
export {
  PluginReceiptForwarder,
  createReceiptForwarder,
} from "./receipt-forwarder";
export type { ReceiptForwarderOptions } from "./receipt-forwarder";
