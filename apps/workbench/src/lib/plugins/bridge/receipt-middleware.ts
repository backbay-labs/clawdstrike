/**
 * Receipt Generation Middleware
 *
 * Wraps bridge host dispatch to generate Ed25519-signed PluginActionReceipts
 * for every bridge call. Permission denials always produce receipts (AUDIT-02).
 *
 * Usage: Create middleware via createReceiptMiddleware(), then call
 * recordAllowed/recordDenied/recordError after each bridge dispatch.
 * The bridge host calls these as fire-and-forget (non-blocking).
 */

import type { PluginTrustTier } from "../types";
import type { PluginActionReceipt } from "./receipt-types";
import { createReceiptContent } from "./receipt-types";
import type { PluginReceiptStore } from "./receipt-store";
import { signCanonical } from "../../workbench/operator-crypto";
import { METHOD_TO_PERMISSION } from "./permissions";

// ---- Options ----

/**
 * Configuration for the receipt generation middleware.
 */
export interface ReceiptMiddlewareOptions {
  /** Plugin identifier. */
  pluginId: string;
  /** Plugin version string. */
  pluginVersion: string;
  /** Plugin publisher. */
  publisher: string;
  /** Plugin trust tier. */
  trustTier: PluginTrustTier;
  /** Ed25519 secret key hex for signing. Null = unsigned (dev mode). */
  secretKeyHex: string | null;
  /** Ed25519 public key hex for the signer_public_key field. */
  publicKeyHex: string;
  /** Receipt store instance (injected for testability). */
  store: PluginReceiptStore;
}

// ---- Middleware Return Type ----

/**
 * The receipt middleware API returned by createReceiptMiddleware.
 */
export interface ReceiptMiddleware {
  /** Record a successful (allowed) bridge call. */
  recordAllowed(
    method: string,
    params: unknown,
    durationMs: number,
  ): Promise<void>;
  /** Record a permission-denied bridge call. Always stored (AUDIT-02). */
  recordDenied(
    method: string,
    params: unknown,
    permissionChecked: string,
  ): Promise<void>;
  /** Record an errored bridge call. */
  recordError(
    method: string,
    params: unknown,
    durationMs: number,
  ): Promise<void>;
}

// ---- Factory ----

/**
 * Create a receipt generation middleware for a specific plugin.
 *
 * Returns an object with recordAllowed, recordDenied, and recordError methods
 * that create signed receipts and store them via the provided PluginReceiptStore.
 */
export function createReceiptMiddleware(
  options: ReceiptMiddlewareOptions,
): ReceiptMiddleware {
  const {
    pluginId,
    pluginVersion,
    publisher,
    trustTier,
    secretKeyHex,
    publicKeyHex,
    store,
  } = options;

  async function createAndStoreReceipt(
    method: string,
    params: unknown,
    result: "allowed" | "denied" | "error",
    permissionChecked: string,
    durationMs: number,
  ): Promise<void> {
    const content = await createReceiptContent(
      pluginId,
      pluginVersion,
      publisher,
      trustTier,
      method,
      params,
      result,
      permissionChecked,
      durationMs,
    );

    let signature = "";
    if (secretKeyHex !== null) {
      signature = await signCanonical(content, secretKeyHex);
    }

    const receipt: PluginActionReceipt = {
      content,
      signature,
      signer_public_key: publicKeyHex,
    };

    store.add(receipt);
  }

  return {
    async recordAllowed(
      method: string,
      params: unknown,
      durationMs: number,
    ): Promise<void> {
      const permissionChecked = METHOD_TO_PERMISSION[method] ?? method;
      await createAndStoreReceipt(
        method,
        params,
        "allowed",
        permissionChecked,
        durationMs,
      );
    },

    async recordDenied(
      method: string,
      params: unknown,
      permissionChecked: string,
    ): Promise<void> {
      // AUDIT-02: Denials are ALWAYS recorded, no verbosity check
      await createAndStoreReceipt(
        method,
        params,
        "denied",
        permissionChecked,
        0,
      );
    },

    async recordError(
      method: string,
      params: unknown,
      durationMs: number,
    ): Promise<void> {
      const permissionChecked = METHOD_TO_PERMISSION[method] ?? method;
      await createAndStoreReceipt(
        method,
        params,
        "error",
        permissionChecked,
        durationMs,
      );
    },
  };
}
