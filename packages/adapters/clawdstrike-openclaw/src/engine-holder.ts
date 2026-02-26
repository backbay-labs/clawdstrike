/**
 * Shared PolicyEngine singleton holder.
 *
 * All hook handlers and the plugin entry point delegate to this module
 * so that a single PolicyEngine instance is created and reused across
 * the entire plugin lifecycle.
 */

import { PolicyEngine } from './policy/engine.js';
import type { ClawdstrikeConfig } from './types.js';

let sharedEngine: PolicyEngine | null = null;

/**
 * Create (or replace) the shared PolicyEngine with the given config.
 * Called once during plugin initialization.
 */
export function initializeEngine(config: ClawdstrikeConfig): PolicyEngine {
  sharedEngine = new PolicyEngine(config);
  return sharedEngine;
}

/**
 * Return the shared PolicyEngine, creating one lazily if needed.
 *
 * Callers that run after `initializeEngine` (the normal case) will
 * always get the pre-configured instance.  The fallback
 * `new PolicyEngine(config ?? {})` exists only as a safety net for
 * edge cases where a handler is invoked before the plugin boots.
 */
export function getSharedEngine(config?: ClawdstrikeConfig): PolicyEngine {
  if (!sharedEngine) {
    sharedEngine = new PolicyEngine(config ?? {});
  }
  return sharedEngine;
}

/**
 * Reset the shared engine to null (useful for tests).
 */
export function resetSharedEngine(): void {
  sharedEngine = null;
}
