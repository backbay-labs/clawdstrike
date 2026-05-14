/**
 * Plugin Revocation Badge
 *
 * Displays a warning badge for revoked plugins with reason, duration,
 * and explanation text. Returns null when the plugin is not revoked.
 *
 * Also exports isPluginRevoked() helper for marketplace UI to disable
 * Install/Activate buttons on revoked plugins.
 */

import type { PluginLifecycleState } from "@/lib/plugins/types";
import type { PluginRevocationStore } from "@/lib/plugins/revocation-store";

// ---- Props ----

interface PluginRevocationBadgeProps {
  /** ID of the plugin to check. */
  pluginId: string;
  /** Current lifecycle state of the plugin. */
  pluginState: PluginLifecycleState;
  /** Revocation store instance for querying revocation entries. */
  revocationStore: PluginRevocationStore;
}

// ---- Helpers ----

/**
 * Check whether a plugin is currently revoked.
 * Used by marketplace UI to disable Install/Activate buttons.
 */
export function isPluginRevoked(
  pluginId: string,
  revocationStore: PluginRevocationStore,
): boolean {
  return revocationStore.isRevoked(pluginId);
}

/**
 * Format an ISO-8601 date string for display.
 */
function formatDate(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString();
  } catch {
    return iso;
  }
}

// ---- Component ----

/**
 * Warning badge shown when a plugin is revoked.
 *
 * Displays:
 * - Warning icon + "Revoked" label
 * - Reason text from the revocation entry
 * - Duration: "Permanent" or "Until {date}"
 * - Explanation text about operator revocation
 *
 * Returns null when pluginState is not "revoked".
 */
export function PluginRevocationBadge({
  pluginId,
  pluginState,
  revocationStore,
}: PluginRevocationBadgeProps) {
  // Do not render when not revoked
  if (pluginState !== "revoked") {
    return null;
  }

  // Find the revocation entry
  const entry = revocationStore
    .getAll()
    .find((e) => e.pluginId === pluginId);

  // Determine reason and duration
  const reason = entry?.reason ?? "No reason provided";
  const isPermanent = entry?.until === null || entry?.until === undefined;
  const durationText = isPermanent
    ? "Permanent"
    : `Until ${formatDate(entry!.until!)}`;

  return (
    <div
      role="alert"
      style={{
        border: "1px solid #c45c5c",
        borderRadius: "6px",
        padding: "12px 16px",
        backgroundColor: "rgba(196, 92, 92, 0.08)",
        marginBottom: "8px",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "8px",
          marginBottom: "8px",
        }}
      >
        <span style={{ fontSize: "16px" }}>{"\u26A0\uFE0F"}</span>
        <span
          style={{
            fontWeight: "bold",
            color: "#c45c5c",
            fontSize: "13px",
          }}
        >
          Revoked
        </span>
      </div>

      <div
        style={{
          color: "#ece7dc",
          fontSize: "12px",
          marginBottom: "4px",
        }}
      >
        {reason}
      </div>

      <div
        style={{
          color: "#6f7f9a",
          fontSize: "11px",
          marginBottom: "8px",
        }}
      >
        {durationText}
      </div>

      <div
        style={{
          color: "#6f7f9a",
          fontSize: "11px",
          fontStyle: "italic",
        }}
      >
        This plugin has been revoked by an operator and cannot be reactivated.
      </div>
    </div>
  );
}
