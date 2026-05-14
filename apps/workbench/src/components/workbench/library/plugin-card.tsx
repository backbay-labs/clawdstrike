import { cn } from "@/lib/utils";
import type {
  PluginManifest,
  PluginLifecycleState,
  PluginTrustTier,
} from "@/lib/plugins/types";
import {
  IconDownload,
  IconTrash,
  IconLoader2,
  IconAlertTriangle,
  IconRefreshDot,
} from "@tabler/icons-react";

interface PluginCardProps {
  manifest: PluginManifest;
  state: PluginLifecycleState;
  error?: string;
  onInstall?: () => void;
  onUninstall?: () => void;
}

const TRUST_BADGE: Record<
  PluginTrustTier,
  { label: string; className: string }
> = {
  internal: {
    label: "Internal",
    className:
      "bg-[#3dbf84]/10 text-[#3dbf84] border-[#3dbf84]/20",
  },
  community: {
    label: "Community",
    className:
      "bg-[#8b5cf6]/10 text-[#8b5cf6] border-[#8b5cf6]/20",
  },
  mcp: {
    label: "MCP",
    className:
      "bg-[#d4a84b]/10 text-[#d4a84b] border-[#d4a84b]/20",
  },
};

export function PluginCard({
  manifest,
  state,
  error,
  onInstall,
  onUninstall,
}: PluginCardProps) {
  const badge = TRUST_BADGE[manifest.trust];

  return (
    <div className="flex flex-col justify-between rounded-xl border border-[#2d3240]/60 bg-[#0b0d13] p-4 min-h-[160px] hover:border-[#2d3240] transition-colors card-shadow">
      <div>
        {/* Top row: name + version/trust badges */}
        <div className="flex items-start justify-between gap-2 mb-1">
          <h3 className="font-syne font-bold text-sm text-[#ece7dc] truncate">
            {manifest.displayName}
          </h3>
          <div className="flex items-center gap-1 shrink-0">
            <span className="inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono bg-[#131721] text-[#6f7f9a] border border-[#2d3240] rounded">
              v{manifest.version}
            </span>
            <span
              className={cn(
                "inline-flex items-center px-1.5 py-0.5 text-[9px] font-mono border rounded",
                badge.className,
              )}
            >
              {badge.label}
            </span>
          </div>
        </div>

        {/* Publisher */}
        <p className="text-[11px] text-[#6f7f9a] mb-2">
          {manifest.publisher}
        </p>

        {/* Description */}
        <p className="text-xs text-[#6f7f9a] line-clamp-2 leading-relaxed">
          {manifest.description || "No description"}
        </p>
      </div>

      {/* Bottom row: action button + state */}
      <div className="flex items-center gap-2 mt-3">
        <ActionButton
          state={state}
          error={error}
          onInstall={onInstall}
          onUninstall={onUninstall}
        />
      </div>
    </div>
  );
}

function ActionButton({
  state,
  error,
  onInstall,
  onUninstall,
}: {
  state: PluginLifecycleState;
  error?: string;
  onInstall?: () => void;
  onUninstall?: () => void;
}) {
  switch (state) {
    case "not-installed":
      return (
        <button
          onClick={onInstall}
          className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
        >
          <IconDownload size={12} stroke={1.5} />
          Install
        </button>
      );

    case "installed":
    case "activated":
      return (
        <>
          <span className="text-[10px] font-mono text-[#3dbf84]/70">
            {state === "activated" ? "Active" : "Installed"}
          </span>
          <button
            onClick={onUninstall}
            className="flex items-center gap-1 px-2.5 py-1 rounded-md text-[#c45c5c]/60 text-[11px] font-medium hover:text-[#c45c5c] hover:bg-[#c45c5c]/10 transition-colors ml-auto"
          >
            <IconTrash size={12} stroke={1.5} />
            Uninstall
          </button>
        </>
      );

    case "installing":
    case "activating":
      return (
        <button
          disabled
          className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-[#131721] text-[#6f7f9a] text-[11px] font-medium cursor-wait"
        >
          <IconLoader2 size={12} stroke={1.5} className="animate-spin" />
          {state === "installing" ? "Installing..." : "Activating..."}
        </button>
      );

    case "error":
      return (
        <div className="flex items-center gap-1.5 min-w-0">
          <IconAlertTriangle size={12} className="text-[#c45c5c] shrink-0" />
          <span className="text-[10px] text-[#c45c5c] truncate">
            {error || "Unknown error"}
          </span>
        </div>
      );

    case "deactivated":
      return (
        <button
          onClick={onInstall}
          className="flex items-center gap-1 px-2.5 py-1 rounded-md bg-[#d4a84b]/10 text-[#d4a84b] text-[11px] font-medium hover:bg-[#d4a84b]/20 transition-colors"
        >
          <IconRefreshDot size={12} stroke={1.5} />
          Reinstall
        </button>
      );

    default:
      return null;
  }
}
