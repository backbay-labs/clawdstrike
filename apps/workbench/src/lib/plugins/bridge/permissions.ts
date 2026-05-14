/**
 * Bridge Permission Mapping
 *
 * Maps every bridge method string (dot notation, e.g. "guards.register") to
 * the PluginPermission string (colon notation, e.g. "guards:register") that
 * a plugin must declare to invoke that method.
 *
 * The checkPermission function is the single enforcement point: it looks up
 * the required permission for a method and checks whether the plugin has
 * declared it. Unknown methods are denied (fail-closed).
 */

import type { PluginPermission, NetworkPermission } from "../types";

/**
 * Set of all valid PluginPermission strings.
 * Used by the manifest validator to reject unknown permissions at install time.
 */
export const KNOWN_PERMISSIONS: Set<string> = new Set<string>([
  "guards:register",
  "guards:read",
  "commands:register",
  "commands:execute",
  "fileTypes:register",
  "statusBar:register",
  "sidebar:register",
  "storage:read",
  "storage:write",
  "policy:read",
  "policy:write",
  "network:fetch",
  "clipboard:read",
  "clipboard:write",
  "notifications:show",
]);

/**
 * Maps every bridge method string to the PluginPermission required to call it.
 *
 * Bridge methods use dot notation (e.g. "guards.register").
 * Permissions use colon notation (e.g. "guards:register").
 */
export const METHOD_TO_PERMISSION: Record<string, PluginPermission> = {
  "commands.register": "commands:register",
  "guards.register": "guards:register",
  "fileTypes.register": "fileTypes:register",
  "statusBar.register": "statusBar:register",
  "sidebar.register": "sidebar:register",
  "storage.get": "storage:read",
  "storage.set": "storage:write",
  "network.fetch": "network:fetch",
};

/**
 * Check whether a plugin with the given granted permissions is allowed
 * to call the specified bridge method.
 *
 * Returns false if:
 * - The method has no entry in METHOD_TO_PERMISSION (unknown method, fail-closed)
 * - The required permission is not in the granted set
 *
 * @param grantedPermissions - Set of permission strings the plugin declared
 * @param method - Bridge method name (dot notation, e.g. "guards.register")
 * @returns true if the call is allowed, false otherwise
 */
export function checkPermission(
  grantedPermissions: Set<string>,
  method: string,
): boolean {
  const required = METHOD_TO_PERMISSION[method];
  if (!required) {
    return false; // Unknown method -- fail-closed
  }
  return grantedPermissions.has(required);
}

/**
 * Check whether a URL is allowed by the given domain allowlist.
 *
 * Supports:
 * - Exact domain match: `"api.virustotal.com"` matches `https://api.virustotal.com/...`
 * - Wildcard subdomain: `"*.virustotal.com"` matches `https://sub.api.virustotal.com/...`
 *   but NOT `https://virustotal.com/...` (the base domain itself)
 *
 * Returns false (fail-closed) if:
 * - The URL cannot be parsed
 * - The domain list is empty
 * - No domain pattern matches the URL hostname
 *
 * @param url - The full URL to check (e.g. "https://api.virustotal.com/v3/files")
 * @param allowedDomains - Array of domain patterns (exact or wildcard)
 * @returns true if the URL hostname matches any allowed domain pattern
 */
export function checkNetworkPermission(
  url: string,
  allowedDomains: string[],
): boolean {
  let hostname: string;
  try {
    hostname = new URL(url).hostname;
  } catch {
    return false; // Invalid URL -- fail-closed
  }

  for (const domain of allowedDomains) {
    // Wildcard subdomain: *.example.com matches sub.example.com but NOT example.com
    if (domain.startsWith("*.")) {
      const suffix = domain.slice(1); // ".example.com"
      if (hostname.endsWith(suffix) && hostname !== domain.slice(2)) {
        return true;
      }
    } else if (hostname === domain) {
      // Exact match
      return true;
    }
  }

  return false;
}

/**
 * Extract NetworkPermission objects from a mixed permissions array.
 *
 * Filters the array to return only objects with `type: "network:fetch"`,
 * discarding plain string PluginPermission entries.
 *
 * @param permissions - Array of PluginPermission strings and/or NetworkPermission objects
 * @returns Array of NetworkPermission objects found in the input
 */
export function extractNetworkPermissions(
  permissions: (PluginPermission | NetworkPermission)[],
): NetworkPermission[] {
  return permissions.filter(
    (p): p is NetworkPermission =>
      typeof p === "object" && p !== null && p.type === "network:fetch",
  );
}
