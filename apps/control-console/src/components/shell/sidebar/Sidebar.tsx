import type { ConsoleStatus } from "../../../hooks/useConsoleStatus";
import { useShellPreferences } from "../../../state/useShellPreferences";
import { SidebarExpanded } from "./SidebarExpanded";
import { SidebarRail } from "./SidebarRail";

export type { ConsoleStatus } from "../../../hooks/useConsoleStatus";

export interface SidebarProps {
  onCmdK: () => void;
  status: ConsoleStatus;
}

/**
 * Left navigation shell. Resolves the persisted variant against the collapsed
 * flag, then renders the matching sidebar. Status is passed in to avoid a second
 * SSE subscription.
 */
export function Sidebar({ onCmdK, status }: SidebarProps) {
  const { sidebarVariant, sidebarCollapsed, setSidebarCollapsed } = useShellPreferences();

  const effectiveVariant =
    sidebarVariant === "expanded" && sidebarCollapsed ? "rail" : sidebarVariant;

  switch (effectiveVariant) {
    case "rail":
      return <SidebarRail />;
    // Task 4 replaces this with the dedicated SidebarTwoPane branch.
    case "twopane":
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
