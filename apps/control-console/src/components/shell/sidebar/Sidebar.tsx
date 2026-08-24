import type { ConsoleStatus } from "../../../hooks/useConsoleStatus";
import type { EffectiveSidebarVariant } from "../../../state/useShellPreferences";
import { useShellPreferences } from "../../../state/useShellPreferences";
import { SidebarExpanded } from "./SidebarExpanded";
import { SidebarRail } from "./SidebarRail";
import { SidebarTwoPane } from "./SidebarTwoPane";

export type { ConsoleStatus } from "../../../hooks/useConsoleStatus";

/** Keyboard shortcut that toggles the collapsed state (VS Code parity). */
export const SIDEBAR_TOGGLE_SHORTCUT = "⌘\\";

export interface SidebarProps {
  onCmdK: () => void;
  status: ConsoleStatus;
  /** Resolved variant (rail/expanded/twopane), computed once by the shell. */
  variant: EffectiveSidebarVariant;
  /** Collapsed flag — only meaningful for the expanded variant. */
  collapsed: boolean;
}

/**
 * Left navigation shell. Renders the matching sidebar for the already-resolved
 * variant. For the expanded variant the collapsed flag drives an in-place width
 * morph rather than a component swap. Status is passed in to avoid a second SSE
 * subscription.
 */
export function Sidebar({ onCmdK, status, variant, collapsed }: SidebarProps) {
  const toggleSidebarCollapsed = useShellPreferences((s) => s.toggleSidebarCollapsed);

  switch (variant) {
    case "rail":
      return <SidebarRail />;
    case "twopane":
      return <SidebarTwoPane status={status} />;
    case "expanded":
      return (
        <SidebarExpanded
          onCmdK={onCmdK}
          onToggleCollapse={toggleSidebarCollapsed}
          status={status}
          collapsed={collapsed}
          toggleShortcut={SIDEBAR_TOGGLE_SHORTCUT}
        />
      );
  }
}
