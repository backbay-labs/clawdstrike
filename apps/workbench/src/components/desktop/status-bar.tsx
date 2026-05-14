import {
  useState,
  useRef,
  useEffect,
  useLayoutEffect,
  useSyncExternalStore,
  useCallback,
} from "react";
import { useNavigate } from "react-router-dom";
import { useWorkbenchState, usePolicyTabs } from "@/features/policy/hooks/use-policy-actions";
import { useFleetConnection } from "@/features/fleet/use-fleet-connection";
import { PresenceStatusIndicator } from "@/features/presence/components/presence-status-indicator";
import { usePaneStore, getActivePane } from "@/features/panes/pane-store";
import { getPaneActiveView } from "@/features/panes/pane-tree";
import { useMcpStatus } from "@/lib/workbench/use-mcp-status";
import { isDesktop } from "@/lib/tauri-bridge";
import { FILE_TYPE_REGISTRY } from "@/lib/workbench/file-type-registry";
import { GUARD_REGISTRY } from "@/lib/workbench/guard-registry";
import type { GuardId } from "@/lib/workbench/types";
import { cn } from "@/lib/utils";
import {
  getStatusBarItems,
  onStatusBarChange,
  registerStatusBarItem,
  unregisterStatusBarItem,
} from "@/lib/workbench/status-bar-registry";
import type { StatusBarItem } from "@/lib/workbench/status-bar-registry";
import {
  IconPlugConnected,
  IconRefresh,
  IconPlayerStop,
  IconLoader2,
} from "@tabler/icons-react";

function useActivePaneContext() {
  const paneRoot = usePaneStore((store) => store.root);
  const activePaneId = usePaneStore((store) => store.activePaneId);
  const activePane = getActivePane(paneRoot, activePaneId);
  const activePaneView = activePane ? getPaneActiveView(activePane) : null;
  const isFileRoute = activePaneView?.route?.startsWith("/file/") ?? false;

  return { activePaneView, isFileRoute };
}

function ValidationSegment() {
  const { state } = useWorkbenchState();
  const { activeTab: currentTab } = usePolicyTabs();
  const { activePolicy, validation, nativeValidation } = state;
  const desktop = isDesktop();
  const rawFileType = currentTab?.fileType ?? "clawdstrike_policy";
  const fileDescriptor = FILE_TYPE_REGISTRY[rawFileType as keyof typeof FILE_TYPE_REGISTRY];
  const policyTab = fileDescriptor?.id === "clawdstrike_policy";

  const prefersNativeDetectionValidation = desktop && !policyTab;
  const nativeValidationPending = prefersNativeDetectionValidation && nativeValidation.loading;
  const useNativeDetectionValidation =
    prefersNativeDetectionValidation &&
    !nativeValidationPending &&
    nativeValidation.valid !== null;
  const nativeErrorCount =
    nativeValidation.topLevelErrors.length +
    Object.values(nativeValidation.guardErrors).reduce(
      (count, issues) => count + issues.length,
      0,
    );
  const errorCount = useNativeDetectionValidation
    ? nativeErrorCount
    : validation.errors.length;
  const warningCount = useNativeDetectionValidation
    ? nativeValidation.topLevelWarnings.length
    : validation.warnings.length;

  let statusIcon: string;
  let statusText: string;
  let statusColor: string;

  if (nativeValidationPending) {
    statusIcon = "\u2026";
    statusText = "Validating...";
    statusColor = "#6f7f9a";
  } else if (errorCount > 0) {
    statusIcon = "\u2718";
    statusText = `${errorCount} error${errorCount !== 1 ? "s" : ""}`;
    statusColor = "#c45c5c";
  } else if (warningCount > 0) {
    statusIcon = "\u26a0";
    statusText = `${warningCount} warning${warningCount !== 1 ? "s" : ""}`;
    statusColor = "#d4a84b";
  } else {
    statusIcon = "\u2714";
    statusText = "Valid";
    statusColor = "#3dbf84";
  }

  return (
    <span className="flex items-center gap-1.5" style={{ color: statusColor }}>
      <span className="text-[9px] leading-none">{statusIcon}</span>
      <span>{statusText}</span>
    </span>
  );
}

function GuardCountSegment() {
  const { state } = useWorkbenchState();
  const { activePolicy } = state;

  const enabledGuards = GUARD_REGISTRY.filter((guard) => {
    const cfg = activePolicy.guards[guard.id as GuardId];
    return cfg && "enabled" in cfg && cfg.enabled;
  }).length;

  return (
    <span className="text-[#6f7f9a]/80">
      {enabledGuards}/{GUARD_REGISTRY.length} guards
    </span>
  );
}

function PolicyVersionSegment() {
  const { state } = useWorkbenchState();
  return <span className="text-[#6f7f9a]/80">v{state.activePolicy.version}</span>;
}

function FileTypeSegment() {
  const { activeTab: currentTab } = usePolicyTabs();
  const rawFileType = currentTab?.fileType ?? "clawdstrike_policy";
  const fileDescriptor = FILE_TYPE_REGISTRY[rawFileType as keyof typeof FILE_TYPE_REGISTRY];
  return <span className="text-[#6f7f9a]/80">{fileDescriptor?.label ?? rawFileType}</span>;
}

function GuardCountOrFileTypeSegment() {
  const { activeTab: currentTab } = usePolicyTabs();
  const rawFileType = currentTab?.fileType ?? "clawdstrike_policy";
  const fileDescriptor = FILE_TYPE_REGISTRY[rawFileType as keyof typeof FILE_TYPE_REGISTRY];

  if (fileDescriptor?.id === "clawdstrike_policy") {
    return <GuardCountSegment />;
  }
  return <FileTypeSegment />;
}

function PolicyVersionOrNullSegment() {
  const { activeTab: currentTab } = usePolicyTabs();
  const rawFileType = currentTab?.fileType ?? "clawdstrike_policy";
  const fileDescriptor = FILE_TYPE_REGISTRY[rawFileType as keyof typeof FILE_TYPE_REGISTRY];

  if (fileDescriptor?.id !== "clawdstrike_policy") {
    return null;
  }
  return <PolicyVersionSegment />;
}

function FleetStatusSegment() {
  const { connection } = useFleetConnection();
  const navigate = useNavigate();

  return (
    <button
      onClick={() => navigate("/settings")}
      className="flex items-center gap-1.5 transition-colors hover:text-[#ece7dc]"
      title={
        connection.connected
          ? `Connected to ${connection.hushdUrl}`
          : "Click to configure fleet connection"
      }
    >
      <span
        className="inline-block h-[6px] w-[6px] rounded-full"
        style={{ backgroundColor: connection.connected ? "#3dbf84" : "#6f7f9a40" }}
      />
      <span className={connection.connected ? "text-[#6f7f9a]" : "text-[#6f7f9a]/50"}>
        {connection.connected
          ? `Fleet: ${connection.agentCount} agent${connection.agentCount !== 1 ? "s" : ""}`
          : "Local"}
      </span>
    </button>
  );
}

function PresenceSegment() {
  return <PresenceStatusIndicator />;
}

function McpStatusSegment() {
  if (!isDesktop()) return null;
  return <McpStatusIndicator />;
}

function EvalCountSegment() {
  const { connection } = useFleetConnection();

  return (
    <span
      className="font-mono text-[10px] text-[#6f7f9a]/70"
      title={
        connection.connected
          ? "Total evaluations processed by fleet"
          : "Not connected to fleet"
      }
    >
      {connection.connected
        ? `${connection.hushdHealth?.total_evaluations != null ? connection.hushdHealth.total_evaluations.toLocaleString() : "..."} evals`
        : "\u2014"}
    </span>
  );
}

function ActivePaneContextSegment() {
  const { state } = useWorkbenchState();
  const { activePaneView, isFileRoute } = useActivePaneContext();
  const paneFileName = activePaneView?.label ?? null;
  const paneFileDirty = activePaneView?.dirty ?? false;
  const paneFileType = activePaneView?.fileType ?? null;

  if (!activePaneView || !paneFileName) {
    return null;
  }

  return (
    <span
      className="flex max-w-[240px] items-center gap-1 truncate text-[#ece7dc]/70"
      title={`Active: ${paneFileName}${paneFileDirty ? " (unsaved)" : ""}`}
    >
      {(paneFileDirty || state.dirty) && isFileRoute && (
        <span className="inline-block h-[6px] w-[6px] shrink-0 rounded-full bg-[#d4a84b]" />
      )}
      <span className="truncate">{paneFileName}</span>
      {isFileRoute && paneFileType && (
        <span className="font-mono text-[10px] text-[#6f7f9a]/60">{paneFileType}</span>
      )}
    </span>
  );
}

function TabCountSegment() {
  const { tabs } = usePolicyTabs();
  if (tabs.length <= 1) return null;
  return <span className="text-[#6f7f9a]/60">{tabs.length} tabs</span>;
}

function ActivePolicySegment() {
  const { state } = useWorkbenchState();
  const { activeTab: currentTab } = usePolicyTabs();
  const name = currentTab?.name || state.activePolicy.name;

  return (
    <span
      className="flex max-w-[200px] items-center gap-1 truncate text-[#ece7dc]/70"
      title={`Active policy: ${name}${state.dirty ? " (unsaved changes)" : ""}`}
    >
      {state.dirty && (
        <span className="inline-block h-[6px] w-[6px] shrink-0 rounded-full bg-[#d4a84b]" />
      )}
      <span className="truncate">{name}</span>
    </span>
  );
}

function FilePathSegment() {
  const { state } = useWorkbenchState();
  const { isFileRoute } = useActivePaneContext();
  if (state.filePath) {
    return (
      <span
        className="max-w-[400px] truncate text-[#6f7f9a]/70"
        title={state.filePath}
      >
        {state.filePath}
      </span>
    );
  }
  if (isFileRoute) {
    return null;
  }
  return <span className="italic text-[#6f7f9a]/30">unsaved</span>;
}

const builtinStatusBarDisposers = new Map<string, () => void>();

function registerBuiltinStatusBarItem(item: StatusBarItem): void {
  builtinStatusBarDisposers.get(item.id)?.();
  unregisterStatusBarItem(item.id);
  const dispose = registerStatusBarItem(item);
  builtinStatusBarDisposers.set(item.id, () => {
    builtinStatusBarDisposers.delete(item.id);
    dispose();
  });
}

registerBuiltinStatusBarItem({
  id: "builtin:validation",
  side: "left",
  priority: 10,
  render: () => <ValidationSegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:guard-count-or-file-type",
  side: "left",
  priority: 20,
  render: () => <GuardCountOrFileTypeSegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:policy-version",
  side: "left",
  priority: 25,
  render: () => <PolicyVersionOrNullSegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:fleet-status",
  side: "left",
  priority: 30,
  render: () => <FleetStatusSegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:presence",
  side: "left",
  priority: 35,
  render: () => <PresenceSegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:mcp-status",
  side: "left",
  priority: 40,
  render: () => <McpStatusSegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:eval-count",
  side: "right",
  priority: 10,
  render: () => <EvalCountSegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:active-pane-context",
  side: "right",
  priority: 15,
  render: () => <ActivePaneContextSegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:tab-count",
  side: "right",
  priority: 20,
  render: () => <TabCountSegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:active-policy",
  side: "right",
  priority: 30,
  render: () => <ActivePolicySegment />,
});

registerBuiltinStatusBarItem({
  id: "builtin:file-path",
  side: "right",
  priority: 40,
  render: () => <FilePathSegment />,
});

if (import.meta.hot) {
  import.meta.hot.dispose(() => {
    for (const dispose of Array.from(builtinStatusBarDisposers.values())) {
      dispose();
    }
    builtinStatusBarDisposers.clear();
  });
}

function useStatusBarItems(side: "left" | "right") {
  const getSnapshot = useCallback(() => getStatusBarItems(side), [side]);
  return useSyncExternalStore(onStatusBarChange, getSnapshot, getSnapshot);
}

const Separator = () => <span className="h-3 w-px bg-[#2d3240]/60" />;

function StatusBarSegment({ item }: { item: StatusBarItem }) {
  return <>{item.render()}</>;
}

function StatusBarSegmentWithSeparator({
  item,
  showSeparator,
}: {
  item: StatusBarItem;
  showSeparator: boolean;
}) {
  const contentRef = useRef<HTMLSpanElement>(null);
  const [hasContent, setHasContent] = useState(false);

  const checkContent = useCallback(() => {
    setHasContent((contentRef.current?.childNodes.length ?? 0) > 0);
  }, []);

  useLayoutEffect(() => {
    checkContent();
    const node = contentRef.current;
    if (!node) return;

    const observer = new MutationObserver(checkContent);
    observer.observe(node, {
      childList: true,
      subtree: true,
      characterData: true,
    });

    return () => observer.disconnect();
  }, [checkContent]);

  return (
    <>
      {showSeparator && hasContent && <Separator />}
      <span ref={contentRef} className={hasContent ? undefined : "hidden"}>
        <StatusBarSegment item={item} />
      </span>
    </>
  );
}

export function StatusBar() {
  const leftItems = useStatusBarItems("left");
  const rightItems = useStatusBarItems("right");

  return (
    <footer className="desktop-statusbar shrink-0 select-none">
      <div className="flex items-center gap-4">
        {leftItems.map((item, index) => (
          <StatusBarSegmentWithSeparator
            key={item.id}
            item={item}
            showSeparator={index > 0}
          />
        ))}
      </div>

      <div className="flex min-w-0 items-center gap-3">
        {rightItems.map((item, index) => (
          <StatusBarSegmentWithSeparator
            key={item.id}
            item={item}
            showSeparator={index > 0}
          />
        ))}
      </div>
    </footer>
  );
}

function McpStatusIndicator() {
  const {
    status,
    isRestarting,
    isStopping,
    handleRestart,
    handleStop,
  } = useMcpStatus();
  const [open, setOpen] = useState(false);
  const popoverRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;

    function onMouseDown(event: MouseEvent) {
      if (
        popoverRef.current &&
        !popoverRef.current.contains(event.target as Node) &&
        buttonRef.current &&
        !buttonRef.current.contains(event.target as Node)
      ) {
        setOpen(false);
      }
    }

    document.addEventListener("mousedown", onMouseDown);
    return () => document.removeEventListener("mousedown", onMouseDown);
  }, [open]);

  const running = status?.running ?? false;

  return (
    <div className="relative">
      <button
        ref={buttonRef}
        onClick={() => setOpen((value) => !value)}
        className="flex items-center gap-1.5 transition-colors hover:text-[#ece7dc]"
        title={
          running
            ? "MCP sidecar running — click to manage"
            : "MCP sidecar stopped — click to manage"
        }
      >
        <IconPlugConnected
          size={11}
          stroke={1.5}
          className={running ? "text-[#3dbf84]" : "text-[#6f7f9a]/40"}
        />
        <span className={running ? "text-[#6f7f9a]" : "text-[#6f7f9a]/50"}>
          {running ? "MCP" : "MCP off"}
        </span>
        <span
          className="inline-block h-[6px] w-[6px] rounded-full"
          style={{ backgroundColor: running ? "#3dbf84" : "#c45c5c" }}
        />
      </button>

      {open && (
        <div
          ref={popoverRef}
          className="absolute bottom-full left-0 z-50 mb-2 w-56 rounded-lg border border-[#2d3240] bg-[#0b0d13] shadow-xl"
        >
          <div className="border-b border-[#2d3240]/60 px-3 py-2.5">
            <div className="flex items-center gap-2">
              <IconPlugConnected size={12} stroke={1.5} className="text-[#d4a84b]" />
              <span className="text-[11px] font-mono font-medium text-[#ece7dc]">
                MCP Sidecar
              </span>
              <span
                className={cn(
                  "ml-auto text-[9px] font-mono",
                  running ? "text-[#3dbf84]" : "text-[#c45c5c]",
                )}
              >
                {running ? "running" : "stopped"}
              </span>
            </div>
            {running && status?.url && (
              <div className="mt-1.5 truncate text-[9px] font-mono text-[#6f7f9a]/60">
                {status.url}
              </div>
            )}
            {!running && status?.error && (
              <div className="mt-1.5 truncate text-[9px] font-mono text-[#c45c5c]/80">
                {status.error}
              </div>
            )}
          </div>

          <div className="flex items-center gap-1.5 px-3 py-2">
            <button
              onClick={() => {
                handleRestart();
                setOpen(false);
              }}
              disabled={isRestarting || isStopping}
              className={cn(
                "flex h-6 flex-1 items-center justify-center gap-1 rounded border text-[10px] font-medium transition-colors",
                isRestarting
                  ? "cursor-wait border-[#2d3240] bg-[#131721] text-[#6f7f9a]"
                  : "border-[#2d3240] bg-[#131721] text-[#ece7dc] hover:border-[#d4a84b]/40 hover:text-[#d4a84b]",
              )}
            >
              {isRestarting ? (
                <IconLoader2 size={10} stroke={1.5} className="animate-spin" />
              ) : (
                <IconRefresh size={10} stroke={1.5} />
              )}
              {running ? "Restart" : "Start"}
            </button>
            {running && (
              <button
                onClick={() => {
                  handleStop();
                  setOpen(false);
                }}
                disabled={isRestarting || isStopping}
                className={cn(
                  "flex h-6 flex-1 items-center justify-center gap-1 rounded border text-[10px] font-medium transition-colors",
                  isStopping
                    ? "cursor-wait border-[#2d3240] bg-[#131721] text-[#6f7f9a]"
                    : "border-[#c45c5c]/30 bg-[#131721] text-[#ece7dc] hover:border-[#c45c5c]/60 hover:text-[#c45c5c]",
                )}
              >
                {isStopping ? (
                  <IconLoader2 size={10} stroke={1.5} className="animate-spin" />
                ) : (
                  <IconPlayerStop size={10} stroke={1.5} />
                )}
                Stop
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
