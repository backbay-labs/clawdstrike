/**
 * Bottom Panel Registry - Maps BottomPanelTabId to lazy React components.
 */
import React from "react";
import type { BottomPanelTabId } from "./workbenchState";

export interface BottomPanelRegistryEntry {
  component: React.LazyExoticComponent<React.ComponentType<any>>;
  icon: string;
  label: string;
}

// Wrapper that pulls connection context via hooks so BottomPanel doesn't need to thread props
const TapePanelWrapper = React.lazy(() =>
  Promise.all([
    import("@/features/forensics/policy-workbench/ChronicleWorkbenchShelf"),
    import("@/context/ConnectionContext"),
    import("@/features/forensics/policy-workbench/featureFlags"),
  ]).then(([shelfMod, connMod, flagsMod]) => ({
    default: function TapePanel() {
      const { status, daemonUrl } = connMod.useConnection();
      const policyWorkbenchEnabled = React.useMemo(() => flagsMod.isPolicyWorkbenchEnabled(), []);
      return React.createElement(shelfMod.ChronicleWorkbenchShelf, {
        daemonUrl,
        connected: status === "connected",
        policyWorkbenchEnabled,
      });
    },
  })),
);

function makePlaceholderComponent(text: string): React.FC {
  const Placeholder: React.FC = () =>
    React.createElement(
      "div",
      {
        className: "flex items-center justify-center h-full",
        style: { color: "var(--color-text-muted, #6b7280)", fontFamily: "monospace", fontSize: 11 },
      },
      text,
    );
  Placeholder.displayName = `PanelPlaceholder(${text})`;
  return Placeholder;
}

function makePlaceholder(text: string) {
  const Placeholder = makePlaceholderComponent(text);
  return React.lazy(() => Promise.resolve({ default: Placeholder }));
}

const workspaceTerminalModules = import.meta.glob<{
  WorkspaceTerminalPanel: React.ComponentType<any>;
}>("../../features/workspace/terminal/WorkspaceTerminalPanel.tsx");

const WorkspaceTerminalFallback = makePlaceholderComponent(
  "Workspace terminal unavailable in this build",
);

const WorkspaceTerminalPanel: React.LazyExoticComponent<React.ComponentType<any>> = React.lazy(
  async (): Promise<{ default: React.ComponentType<any> }> => {
  const loadTerminalPanel =
    workspaceTerminalModules["../../features/workspace/terminal/WorkspaceTerminalPanel.tsx"];

  if (!loadTerminalPanel) {
    return { default: WorkspaceTerminalFallback };
  }

  const module = await loadTerminalPanel();
  return { default: module.WorkspaceTerminalPanel };
  },
);

const ReceiptsPlaceholder = makePlaceholder("Receipt browser \u2014 coming soon");
const TasksPlaceholder = makePlaceholder("Task queue \u2014 coming soon");
const ReplayPlaceholder = makePlaceholder("Session replay \u2014 coming soon");
const DiffPlaceholder = makePlaceholder("Diff viewer \u2014 coming soon");

export const BOTTOM_PANEL_REGISTRY: Record<BottomPanelTabId, BottomPanelRegistryEntry> = {
  tape: {
    component: TapePanelWrapper,
    icon: "scroll",
    label: "Tape",
  },
  terminal: {
    component: WorkspaceTerminalPanel,
    icon: "terminal",
    label: "Terminal",
  },
  receipts: {
    component: ReceiptsPlaceholder,
    icon: "shield",
    label: "Receipts",
  },
  tasks: {
    component: TasksPlaceholder,
    icon: "list",
    label: "Tasks",
  },
  replay: {
    component: ReplayPlaceholder,
    icon: "play",
    label: "Replay",
  },
  diff: {
    component: DiffPlaceholder,
    icon: "diff",
    label: "Diff",
  },
};

export function getBottomPanelEntry(tabId: BottomPanelTabId): BottomPanelRegistryEntry | undefined {
  return BOTTOM_PANEL_REGISTRY[tabId];
}
