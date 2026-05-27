import type { ConsoleStatus } from "../../../hooks/useConsoleStatus";
import type { EffectiveSidebarVariant } from "../../../state/useShellPreferences";
import { useShellPreferences } from "../../../state/useShellPreferences";
import { SidebarExpanded } from "./SidebarExpanded";
import { SidebarRail } from "./SidebarRail";
import { SidebarTwoPane } from "./SidebarTwoPane";

export type { ConsoleStatus } from "../../../hooks/useConsoleStatus";

export interface SidebarProps {
  onCmdK: () => void;
  status: ConsoleStatus;
  /** Resolved variant (rail/expanded/twopane), computed once by the shell. */
  variant: EffectiveSidebarVariant;
}

/**
 * Left navigation shell. Renders the matching sidebar for the already-resolved
 * variant. Status is passed in to avoid a second SSE subscription.
 */
export function Sidebar({ onCmdK, status, variant }: SidebarProps) {
  const setSidebarCollapsed = useShellPreferences((s) => s.setSidebarCollapsed);

  switch (variant) {
    case "rail":
      return <SidebarRail />;
    case "twopane":
      return <SidebarTwoPane status={status} />;
    case "expanded":
      return (
        <SidebarExpanded
          onCmdK={onCmdK}
          onCollapse={() => setSidebarCollapsed(true)}
          status={status}
        />
      );
  }
}
