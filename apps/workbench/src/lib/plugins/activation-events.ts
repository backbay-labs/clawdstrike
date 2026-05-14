/**
 * Activation Event Matching
 *
 * Pure module for parsing and matching activation event strings.
 * Activation events determine when a plugin should be activated:
 *
 * - "onStartup" -- activate immediately on workbench load
 * - "onFileType:{type}" -- activate when a file of the given type is opened
 * - "onCommand:{id}" -- activate when a specific command is invoked
 * - "onGuardEvaluate:{id}" -- activate when a specific guard is evaluated
 * - "*" -- wildcard, matches any event
 *
 * No side effects, no external dependencies beyond types.
 */

// ---- Types ----

/**
 * Parsed representation of an activation event string.
 * The `value` field is present for parameterized events (onFileType, onCommand, onGuardEvaluate).
 */
export type ActivationEventMatcher = {
  type: "onStartup" | "onFileType" | "onCommand" | "onGuardEvaluate" | "wildcard";
  value?: string;
};

// ---- Parsing ----

/**
 * Parse an activation event string into its structured form.
 *
 * @param event - Raw activation event string (e.g. "onFileType:sigma_rule")
 * @returns Parsed activation event matcher
 *
 * @example
 * parseActivationEvent("onStartup")
 * // => { type: "onStartup" }
 *
 * @example
 * parseActivationEvent("onFileType:sigma_rule")
 * // => { type: "onFileType", value: "sigma_rule" }
 *
 * @example
 * parseActivationEvent("onCommand:my-plugin:scan")
 * // => { type: "onCommand", value: "my-plugin:scan" }
 */
export function parseActivationEvent(event: string): ActivationEventMatcher {
  if (event === "*") {
    return { type: "wildcard" };
  }

  if (event === "onStartup") {
    return { type: "onStartup" };
  }

  // Split on the first colon only -- value may contain additional colons
  const colonIndex = event.indexOf(":");
  if (colonIndex === -1) {
    // Unknown event type without colon, treat as onStartup-like (no value)
    return { type: "onStartup" };
  }

  const prefix = event.slice(0, colonIndex);
  const value = event.slice(colonIndex + 1);

  switch (prefix) {
    case "onFileType":
      return { type: "onFileType", value };
    case "onCommand":
      return { type: "onCommand", value };
    case "onGuardEvaluate":
      return { type: "onGuardEvaluate", value };
    default:
      // Unknown prefix -- treat as onStartup (will match onStartup events)
      return { type: "onStartup" };
  }
}

// ---- Matching ----

/**
 * Check if any of the declared activation events match a fired event.
 *
 * Matching rules:
 * - Wildcard "*" matches any event
 * - "onStartup" matches "onStartup"
 * - "onFileType:X" matches "onFileType:X" (exact match on type + value)
 * - "onCommand:X" matches "onCommand:X" (exact match on type + value)
 * - "onGuardEvaluate:X" matches "onGuardEvaluate:X" (exact match on type + value)
 * - No partial matching -- type and value must both match exactly
 *
 * @param declaredEvents - The plugin's declared activation events
 * @param firedEvent - The event that was fired
 * @returns true if any declared event matches the fired event
 */
export function matchActivationEvent(
  declaredEvents: string[],
  firedEvent: string,
): boolean {
  const fired = parseActivationEvent(firedEvent);

  for (const declared of declaredEvents) {
    const parsed = parseActivationEvent(declared);

    // Wildcard matches anything
    if (parsed.type === "wildcard") {
      return true;
    }

    // Types must match
    if (parsed.type !== fired.type) {
      continue;
    }

    // For parameterized types, values must match exactly
    if (parsed.value !== undefined || fired.value !== undefined) {
      if (parsed.value === fired.value) {
        return true;
      }
      continue;
    }

    // Non-parameterized types match (e.g. onStartup === onStartup)
    return true;
  }

  return false;
}

// ---- Convenience ----

/**
 * Check if a plugin should activate immediately on startup.
 * Returns true if any activation event is "onStartup" or "*".
 *
 * @param activationEvents - The plugin's declared activation events
 * @returns true if the plugin should activate on startup
 */
export function shouldActivateOnStartup(activationEvents: string[]): boolean {
  for (const event of activationEvents) {
    if (event === "onStartup" || event === "*") {
      return true;
    }
  }
  return false;
}
