import { useState, useCallback, useMemo } from "react";
import {
  IconServer,
  IconRefresh,
  IconChevronDown,
  IconChevronRight,
  IconArrowsSort,
  IconAlertTriangle,
  IconTable,
  IconTopologyStar3,
  IconRocket,
  IconLoader2,
  IconX,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { PageHeader } from "../shared/page-header";
import { AGENT_POLL_MS, useFleetConnection } from "@/features/fleet/use-fleet-connection";
import { useFleetConnectionStore } from "@/features/fleet/use-fleet-connection";
import type { AgentInfo } from "@/features/fleet/fleet-client";
import {
  deployPolicy,
  validateRemotely,
} from "@/features/fleet/fleet-client";
import { usePaneStore } from "@/features/panes/pane-store";
import { Link } from "react-router-dom";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { useToast } from "@/components/ui/toast";
import { FleetTopologyView } from "./fleet-topology-view";

const STALE_THRESHOLD_SECS = 90;

type StatusFilter = "all" | "online" | "stale" | "drift";
type SortColumn =
  | "status"
  | "agent_id"
  | "posture"
  | "policy_version"
  | "daemon_version"
  | "last_heartbeat"
  | "runtimes"
  | "drift";

const POSTURE_COLORS: Record<string, string> = {
  strict: "#3dbf84",
  default: "#d4a84b",
  permissive: "#c45c5c",
};

function relativeTime(isoDate: string): string {
  const now = Date.now();
  const then = new Date(isoDate).getTime();
  if (isNaN(then)) return "unknown";
  const diffSecs = Math.floor((now - then) / 1000);
  if (diffSecs < 60) return `${diffSecs}s ago`;
  if (diffSecs < 3600) return `${Math.floor(diffSecs / 60)}m ago`;
  if (diffSecs < 86400) return `${Math.floor(diffSecs / 3600)}h ago`;
  return `${Math.floor(diffSecs / 86400)}d ago`;
}

function agentStatus(agent: AgentInfo): "online" | "stale" | "offline" {
  if (agent.drift.stale) return "stale";
  if (
    agent.seconds_since_heartbeat !== undefined &&
    agent.seconds_since_heartbeat > STALE_THRESHOLD_SECS
  )
    return "stale";
  if (!agent.online) return "offline";
  return "online";
}

const STATUS_DOT_COLORS: Record<string, string> = {
  online: "#3dbf84",
  stale: "#d4a84b",
  offline: "#c45c5c",
};

// ---- Deploy confirmation text (matches deploy-panel.tsx safety pattern) ----
const CONFIRM_TEXT = "deploy";

export function FleetDashboard() {
  const { connection, agents, refreshAgents, pollError, secureStorageWarning, getAuthenticatedConnection } = useFleetConnection();
  const sseState = useFleetConnectionStore.use.sseState();
  const remotePolicyInfo = useFleetConnectionStore.use.remotePolicyInfo();

  const [filter, setFilter] = useState<StatusFilter>("all");
  const [sortCol, setSortCol] = useState<SortColumn>("agent_id");
  const [sortAsc, setSortAsc] = useState(true);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);

  // View toggle: table or topology
  const [view, setView] = useState<"table" | "topology">("table");

  // Bulk selection
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  // Deploy dialog
  const [deployDialogOpen, setDeployDialogOpen] = useState(false);
  const [deployTargetIds, setDeployTargetIds] = useState<string[]>([]);

  const handleRefresh = useCallback(async () => {
    setIsRefreshing(true);
    try { await refreshAgents(); } finally { setIsRefreshing(false); }
  }, [refreshAgents]);

  const counts = useMemo(() => {
    let online = 0;
    let stale = 0;
    let policyDrift = 0;
    for (const a of agents) {
      const s = agentStatus(a);
      if (s === "online") online++;
      if (s === "stale") stale++;
      if (a.drift.policy_drift) policyDrift++;
    }
    return { total: agents.length, online, stale, policyDrift };
  }, [agents]);

  const activePolicyVersion = useMemo(() => {
    const freq = new Map<string, number>();
    for (const a of agents) {
      const v = a.policy_version ?? "unknown";
      freq.set(v, (freq.get(v) ?? 0) + 1);
    }
    let best = "---";
    let bestCount = 0;
    for (const [v, c] of freq) {
      if (c > bestCount) {
        best = v;
        bestCount = c;
      }
    }
    return best;
  }, [agents]);

  const filteredAgents = useMemo(() => {
    let list = [...agents];
    if (filter === "online")
      list = list.filter((a) => agentStatus(a) === "online");
    if (filter === "stale")
      list = list.filter((a) => agentStatus(a) === "stale");
    if (filter === "drift")
      list = list.filter((a) => a.drift.policy_drift || a.drift.daemon_drift);

    list.sort((a, b) => {
      let cmp = 0;
      switch (sortCol) {
        case "status": {
          const order = { online: 0, stale: 1, offline: 2 };
          cmp = order[agentStatus(a)] - order[agentStatus(b)];
          break;
        }
        case "agent_id":
          cmp = a.endpoint_agent_id.localeCompare(b.endpoint_agent_id);
          break;
        case "posture":
          cmp = (a.posture ?? "").localeCompare(b.posture ?? "");
          break;
        case "policy_version":
          cmp = (a.policy_version ?? "").localeCompare(b.policy_version ?? "");
          break;
        case "daemon_version":
          cmp = (a.daemon_version ?? "").localeCompare(b.daemon_version ?? "");
          break;
        case "last_heartbeat":
          cmp =
            new Date(a.last_heartbeat_at).getTime() -
            new Date(b.last_heartbeat_at).getTime();
          break;
        case "runtimes":
          cmp = (a.runtime_count ?? 0) - (b.runtime_count ?? 0);
          break;
        case "drift": {
          const driftScore = (x: AgentInfo) =>
            (x.drift.policy_drift ? 2 : 0) + (x.drift.daemon_drift ? 1 : 0);
          cmp = driftScore(a) - driftScore(b);
          break;
        }
      }
      return sortAsc ? cmp : -cmp;
    });

    return list;
  }, [agents, filter, sortCol, sortAsc]);

  const handleSort = useCallback(
    (col: SortColumn) => {
      if (sortCol === col) {
        setSortAsc((prev) => !prev);
      } else {
        setSortCol(col);
        setSortAsc(true);
      }
    },
    [sortCol],
  );

  // Bulk select handlers
  const handleToggleSelect = useCallback((agentId: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(agentId)) {
        next.delete(agentId);
      } else {
        next.add(agentId);
      }
      return next;
    });
  }, []);

  const handleSelectAll = useCallback(() => {
    if (selectedIds.size === filteredAgents.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filteredAgents.map((a) => a.endpoint_agent_id)));
    }
  }, [selectedIds.size, filteredAgents]);

  const handleClearSelection = useCallback(() => {
    setSelectedIds(new Set());
  }, []);

  // Open deploy dialog for selected agents (bulk push)
  const handleBulkDeploy = useCallback(() => {
    setDeployTargetIds(Array.from(selectedIds));
    setDeployDialogOpen(true);
  }, [selectedIds]);

  // Click-to-detail navigation
  const handleAgentClick = useCallback((agentId: string) => {
    usePaneStore.getState().openApp("/fleet/" + agentId, agentId);
  }, []);

  // SSE indicator text
  const sseIndicator = useMemo(() => {
    switch (sseState) {
      case "connected":
        return { dot: "#3dbf84", text: "Live", pulse: true };
      case "connecting":
        return { dot: "#d4a84b", text: "Connecting...", pulse: false };
      case "disconnected":
      case "error":
        return { dot: "#6f7f9a", text: "Polling", pulse: false };
      default:
        return null;
    }
  }, [sseState]);

  const subtitleContent = useMemo(() => {
    const baseText =
      sseState === "connected"
        ? "Live updates via SSE"
        : `auto-refresh every ${AGENT_POLL_MS / 1000}s`;
    return (
      <span className="flex items-center gap-2">
        {counts.total} agent{counts.total !== 1 ? "s" : ""} registered{" "}
        <span className="text-[#6f7f9a]/30">|</span> {baseText}
        {sseIndicator && (
          <>
            <span className="text-[#6f7f9a]/30">|</span>
            <span className="flex items-center gap-1">
              <span
                className={cn(
                  "inline-block h-1.5 w-1.5 rounded-full",
                  sseIndicator.pulse && "animate-pulse",
                )}
                style={{ backgroundColor: sseIndicator.dot }}
              />
              <span
                className="text-[10px]"
                style={{ color: sseIndicator.dot }}
                data-testid="sse-indicator"
              >
                {sseIndicator.text}
              </span>
            </span>
          </>
        )}
      </span>
    );
  }, [counts.total, sseState, sseIndicator]);

  if (!connection.connected) {
    return (
      <div className="flex h-full w-full flex-col items-center justify-center gap-4 bg-[#05060a]">
        <IconServer size={32} className="text-[#6f7f9a]/30" />
        <div className="text-center">
          <p className="text-[13px] text-[#ece7dc]/70">
            Connect to fleet to view agents
          </p>
          <p className="mt-1 text-[11px] text-[#6f7f9a]/50">
            Configure your hushd connection in{" "}
            <Link
              to="/settings"
              className="text-[#d4a84b] hover:text-[#d4a84b]/80 underline underline-offset-2"
            >
              Settings
            </Link>
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      {/* Header */}
      <PageHeader
        title="Fleet Dashboard"
        subtitle={subtitleContent}
        icon={IconServer}
        sectionAccent="#7b6b8b"
      >
        {/* View toggle */}
        <div className="flex items-center rounded-md border border-[#2d3240] overflow-hidden">
          <button
            onClick={() => setView("table")}
            className={cn(
              "flex items-center gap-1 px-2.5 py-1.5 text-[10px] transition-colors",
              view === "table"
                ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                : "text-[#6f7f9a] hover:text-[#ece7dc]",
            )}
            title="Table view"
          >
            <IconTable size={13} stroke={1.5} />
          </button>
          <button
            onClick={() => setView("topology")}
            className={cn(
              "flex items-center gap-1 px-2.5 py-1.5 text-[10px] transition-colors border-l border-[#2d3240]",
              view === "topology"
                ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                : "text-[#6f7f9a] hover:text-[#ece7dc]",
            )}
            title="Topology view"
          >
            <IconTopologyStar3 size={13} stroke={1.5} />
          </button>
        </div>
        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className={cn(
            "flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] transition-colors active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]",
            isRefreshing
              ? "text-[#6f7f9a]/40 cursor-not-allowed"
              : "text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#d4a84b]/30",
          )}
        >
          <IconRefresh
            size={13}
            stroke={1.5}
            className={isRefreshing ? "animate-spin" : ""}
          />
          Refresh
        </button>
      </PageHeader>

      {/* Warning banners */}
      {secureStorageWarning && (
        <div className="shrink-0 border-b border-[#d4a84b]/20 bg-[#d4a84b]/5 px-6 py-2 flex items-center gap-2">
          <IconAlertTriangle size={13} stroke={1.5} className="text-[#d4a84b] shrink-0" />
          <span className="text-[10px] text-[#d4a84b]">
            Credentials stored in browser session only — use desktop app for secure storage.
          </span>
        </div>
      )}
      {pollError && (
        <div className="shrink-0 border-b border-[#c45c5c]/20 bg-[#c45c5c]/5 px-6 py-2 flex items-center gap-2">
          <IconAlertTriangle size={13} stroke={1.5} className="text-[#c45c5c] shrink-0" />
          <span className="text-[10px] text-[#c45c5c]">
            {pollError}
          </span>
        </div>
      )}
      {/* Summary cards */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
        <div className="flex items-stretch gap-3">
          <SummaryCard label="Total Agents" value={counts.total} />
          <SummaryCard
            label="Online"
            value={counts.online}
            dotColor="#3dbf84"
          />
          <SummaryCard
            label="Stale"
            value={counts.stale}
            dotColor="#d4a84b"
          />
          <SummaryCard
            label="Policy Drift"
            value={counts.policyDrift}
            dotColor="#c45c5c"
          />
          <SummaryCard
            label="Active Policy"
            value={activePolicyVersion}
            mono
          />
        </div>
      </div>

      {/* Filter bar */}
      <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-2.5 flex items-center gap-2">
        <span className="text-[10px] uppercase tracking-wider text-[#6f7f9a]/50 mr-1">
          Filter
        </span>
        {(["all", "online", "stale", "drift"] as StatusFilter[]).map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={cn(
              "rounded-md px-2.5 py-1 text-[10px] font-medium capitalize transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]",
              filter === f
                ? "bg-[#d4a84b]/10 text-[#d4a84b]"
                : "text-[#6f7f9a]/60 hover:text-[#ece7dc] hover:bg-[#131721]/40",
            )}
          >
            {f}
          </button>
        ))}
        <span className="ml-auto text-[10px] text-[#6f7f9a]/40">
          {filteredAgents.length} result{filteredAgents.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Main content area: table or topology */}
      {view === "topology" ? (
        <div className="flex-1 overflow-hidden">
          <FleetTopologyView />
        </div>
      ) : (
        <div className="flex-1 overflow-auto">
          <table className="w-full min-w-[750px]">
            <thead className="sticky top-0 z-10 bg-[#0b0d13]/60">
              <tr className="border-b border-[#2d3240]/60">
                {/* Checkbox column */}
                <th className="w-10 px-3 py-2.5">
                  <input
                    type="checkbox"
                    checked={
                      filteredAgents.length > 0 &&
                      selectedIds.size === filteredAgents.length
                    }
                    ref={(el) => {
                      if (el) {
                        el.indeterminate =
                          selectedIds.size > 0 &&
                          selectedIds.size < filteredAgents.length;
                      }
                    }}
                    onChange={handleSelectAll}
                    className="accent-[#d4a84b] w-3.5 h-3.5 cursor-pointer"
                    aria-label="Select all agents"
                  />
                </th>
                <SortableHeader
                  label=""
                  column="status"
                  currentSort={sortCol}
                  asc={sortAsc}
                  onSort={handleSort}
                  className="w-10"
                />
                <SortableHeader
                  label="Agent ID"
                  column="agent_id"
                  currentSort={sortCol}
                  asc={sortAsc}
                  onSort={handleSort}
                />
                <SortableHeader
                  label="Posture"
                  column="posture"
                  currentSort={sortCol}
                  asc={sortAsc}
                  onSort={handleSort}
                  title="Resource usage limits and automated state transitions for agent capabilities"
                />
                <SortableHeader
                  label="Policy"
                  column="policy_version"
                  currentSort={sortCol}
                  asc={sortAsc}
                  onSort={handleSort}
                />
                <SortableHeader
                  label="Daemon"
                  column="daemon_version"
                  currentSort={sortCol}
                  asc={sortAsc}
                  onSort={handleSort}
                />
                <SortableHeader
                  label="Last Heartbeat"
                  column="last_heartbeat"
                  currentSort={sortCol}
                  asc={sortAsc}
                  onSort={handleSort}
                />
                <SortableHeader
                  label="Runtimes"
                  column="runtimes"
                  currentSort={sortCol}
                  asc={sortAsc}
                  onSort={handleSort}
                />
                <SortableHeader
                  label="Drift"
                  column="drift"
                  currentSort={sortCol}
                  asc={sortAsc}
                  onSort={handleSort}
                />
              </tr>
            </thead>
            <tbody>
              {filteredAgents.map((agent, index) => {
                const status = agentStatus(agent);
                const isExpanded = expandedId === agent.endpoint_agent_id;
                const isSelected = selectedIds.has(agent.endpoint_agent_id);

                return (
                  <AgentRow
                    key={agent.endpoint_agent_id}
                    agent={agent}
                    status={status}
                    isExpanded={isExpanded}
                    isSelected={isSelected}
                    index={index}
                    onToggle={() =>
                      setExpandedId(
                        isExpanded ? null : agent.endpoint_agent_id,
                      )
                    }
                    onSelect={() => handleToggleSelect(agent.endpoint_agent_id)}
                    onNavigate={() => handleAgentClick(agent.endpoint_agent_id)}
                  />
                );
              })}
              {filteredAgents.length === 0 && (
                <tr>
                  <td
                    colSpan={9}
                    className="py-12 text-center text-[12px] text-[#6f7f9a]/40"
                  >
                    No agents match the current filter
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Bulk selection action bar */}
      {selectedIds.size > 0 && (
        <div
          className="shrink-0 border-t border-[#2d3240]/60 bg-[#0b0d13] px-6 py-3 flex items-center gap-3"
          data-testid="bulk-action-bar"
        >
          <span className="text-[11px] text-[#ece7dc]/70 font-medium">
            {selectedIds.size} agent{selectedIds.size !== 1 ? "s" : ""} selected
          </span>
          <div className="flex items-center gap-2 ml-auto">
            <button
              onClick={handleBulkDeploy}
              className="flex items-center gap-1.5 rounded-md bg-[#d4a84b] text-[#05060a] px-3 py-1.5 text-[10px] font-medium hover:bg-[#e8c36a] transition-colors"
            >
              <IconRocket size={12} stroke={2} />
              Push Policy
            </button>
            <button
              onClick={handleClearSelection}
              className="flex items-center gap-1.5 rounded-md border border-[#2d3240] px-3 py-1.5 text-[10px] text-[#6f7f9a] hover:text-[#ece7dc] hover:border-[#6f7f9a]/30 transition-colors"
            >
              Clear Selection
            </button>
          </div>
        </div>
      )}

      {/* Deploy confirmation dialog */}
      <DeployConfirmDialog
        open={deployDialogOpen}
        onOpenChange={setDeployDialogOpen}
        targetAgentIds={deployTargetIds}
        remotePolicyYaml={remotePolicyInfo?.yaml ?? ""}
        remotePolicyHash={remotePolicyInfo?.policyHash ?? remotePolicyInfo?.version ?? "---"}
        getAuthenticatedConnection={getAuthenticatedConnection}
        refreshAgents={refreshAgents}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Deploy Confirmation Dialog (type-to-confirm safety pattern)
// ---------------------------------------------------------------------------

function DeployConfirmDialog({
  open,
  onOpenChange,
  targetAgentIds,
  remotePolicyYaml,
  remotePolicyHash,
  getAuthenticatedConnection,
  refreshAgents,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  targetAgentIds: string[];
  remotePolicyYaml: string;
  remotePolicyHash: string;
  getAuthenticatedConnection: () => import("@/features/fleet/fleet-client").FleetConnection;
  refreshAgents: () => Promise<void>;
}) {
  const { toast } = useToast();
  const [confirmText, setConfirmText] = useState("");
  const [isDeploying, setIsDeploying] = useState(false);

  const canDeploy = confirmText.toLowerCase() === CONFIRM_TEXT && !isDeploying;

  const handleDeploy = useCallback(async () => {
    if (!canDeploy || !remotePolicyYaml) return;
    setIsDeploying(true);
    try {
      const conn = getAuthenticatedConnection();

      // Validate first
      const validation = await validateRemotely(conn, remotePolicyYaml);
      if (validation && "valid" in validation && !validation.valid) {
        toast({
          type: "error",
          title: "Validation failed",
          description: validation.errors?.join(", ") ?? "Policy validation failed",
        });
        setIsDeploying(false);
        return;
      }

      // Deploy
      const result = await deployPolicy(conn, remotePolicyYaml);
      if (result.success) {
        toast({
          type: "success",
          title: "Policy deployed",
          description: `Policy pushed to ${targetAgentIds.length} agent${targetAgentIds.length !== 1 ? "s" : ""}`,
        });
        onOpenChange(false);
        setConfirmText("");
        await refreshAgents();
      } else {
        toast({
          type: "error",
          title: "Deploy failed",
          description: result.error ?? "Unknown error",
        });
      }
    } catch (err) {
      toast({
        type: "error",
        title: "Deploy failed",
        description: err instanceof Error ? err.message : "Unknown error",
      });
    } finally {
      setIsDeploying(false);
    }
  }, [canDeploy, remotePolicyYaml, getAuthenticatedConnection, targetAgentIds, toast, onOpenChange, refreshAgents]);

  return (
    <Dialog
      open={open}
      onOpenChange={(isOpen) => {
        if (!isOpen) setConfirmText("");
        onOpenChange(isOpen);
      }}
    >
      <DialogContent className="sm:max-w-md bg-[#0b0d13] border border-[#2d3240]">
        <DialogHeader>
          <DialogTitle className="text-[#ece7dc]">Push Policy to Fleet</DialogTitle>
          <DialogDescription className="text-[#6f7f9a]">
            This will deploy the current policy to {targetAgentIds.length} agent
            {targetAgentIds.length !== 1 ? "s" : ""}.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-3 py-3">
          {/* Target agents */}
          <div className="rounded-md border border-[#2d3240]/60 bg-[#05060a] p-3 max-h-[120px] overflow-auto">
            <p className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/50 mb-2">
              Target Agents
            </p>
            {targetAgentIds.map((id) => (
              <div key={id} className="text-[10px] font-mono text-[#ece7dc]/60 py-0.5">
                {id}
              </div>
            ))}
          </div>

          {/* Policy hash */}
          <div className="text-[10px] text-[#6f7f9a]">
            Policy version: <span className="font-mono text-[#ece7dc]/50">{remotePolicyHash}</span>
          </div>

          {/* Type-to-confirm */}
          <div className="flex flex-col gap-1.5">
            <label
              htmlFor="deploy-confirm"
              className="text-[10px] text-[#d4a84b]"
            >
              Type &quot;{CONFIRM_TEXT}&quot; to confirm
            </label>
            <input
              id="deploy-confirm"
              type="text"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder={CONFIRM_TEXT}
              className="w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2 text-[11px] font-mono text-[#ece7dc] placeholder-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40"
              autoComplete="off"
            />
          </div>
        </div>

        <DialogFooter className="gap-2">
          <button
            onClick={() => {
              setConfirmText("");
              onOpenChange(false);
            }}
            className="rounded-md border border-[#2d3240] px-3 py-1.5 text-[11px] text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleDeploy}
            disabled={!canDeploy}
            className={cn(
              "flex items-center gap-1.5 rounded-md px-4 py-1.5 text-[11px] font-medium transition-colors",
              canDeploy
                ? "bg-[#d4a84b] text-[#05060a] hover:bg-[#e8c36a]"
                : "bg-[#d4a84b]/20 text-[#d4a84b]/40 cursor-not-allowed",
            )}
          >
            {isDeploying ? (
              <>
                <IconLoader2 size={12} className="animate-spin" />
                Deploying...
              </>
            ) : (
              <>
                <IconRocket size={12} stroke={2} />
                Deploy
              </>
            )}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---------------------------------------------------------------------------
// Subcomponents (unchanged from original, with new props on AgentRow)
// ---------------------------------------------------------------------------

function SummaryCard({
  label,
  value,
  dotColor,
  mono,
}: {
  label: string;
  value: number | string;
  dotColor?: string;
  mono?: boolean;
}) {
  return (
    <div className="flex flex-col rounded-lg border border-[#2d3240]/60 bg-[#0b0d13] px-4 py-3 min-w-[120px]">
      <span className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/50">
        {label}
      </span>
      <div className="mt-1.5 flex items-center gap-2">
        {dotColor && (
          <span
            className="h-2 w-2 rounded-full shrink-0"
            style={{ backgroundColor: dotColor }}
          />
        )}
        <span
          className={cn(
            "text-[18px] font-semibold text-[#ece7dc]",
            mono && "font-mono text-[14px]",
          )}
        >
          {value}
        </span>
      </div>
    </div>
  );
}

function SortableHeader({
  label,
  column,
  currentSort,
  asc,
  onSort,
  className,
  title,
}: {
  label: string;
  column: SortColumn;
  currentSort: SortColumn;
  asc: boolean;
  onSort: (col: SortColumn) => void;
  className?: string;
  title?: string;
}) {
  const active = currentSort === column;

  return (
    <th
      className={cn(
        "px-3 py-2.5 text-left text-[9px] uppercase tracking-[0.08em] font-semibold select-none cursor-pointer transition-colors",
        active ? "text-[#d4a84b]" : "text-[#6f7f9a]/80 hover:text-[#6f7f9a]",
        className,
      )}
      onClick={() => onSort(column)}
      title={title}
    >
      <span className="flex items-center gap-1">
        {label}
        {active && (
          <IconArrowsSort
            size={10}
            className={cn("transition-transform", !asc && "rotate-180")}
          />
        )}
      </span>
    </th>
  );
}

function AgentRow({
  agent,
  status,
  isExpanded,
  isSelected,
  index,
  onToggle,
  onSelect,
  onNavigate,
}: {
  agent: AgentInfo;
  status: "online" | "stale" | "offline";
  isExpanded: boolean;
  isSelected: boolean;
  index: number;
  onToggle: () => void;
  onSelect: () => void;
  onNavigate: () => void;
}) {
  const dotColor = STATUS_DOT_COLORS[status];
  const postureColor =
    POSTURE_COLORS[agent.posture?.toLowerCase() ?? ""] ?? "#6f7f9a";

  return (
    <>
      <tr
        onClick={onNavigate}
        className={cn(
          "border-b border-[#2d3240]/30 cursor-pointer transition-colors",
          isExpanded
            ? "bg-[#131721] border-l-2 border-l-[#d4a84b]"
            : "hover:bg-[#131721] border-l-2 border-l-transparent",
          !isExpanded && (index % 2 === 0 ? "bg-[#05060a]" : "bg-[#0b0d13]/40"),
        )}
        data-testid={`agent-row-${agent.endpoint_agent_id}`}
      >
        {/* Checkbox column */}
        <td className="px-3 py-2.5 text-center" onClick={(e) => e.stopPropagation()}>
          <input
            type="checkbox"
            checked={isSelected}
            onChange={onSelect}
            className="accent-[#d4a84b] w-3.5 h-3.5 cursor-pointer"
            aria-label={`Select ${agent.endpoint_agent_id}`}
          />
        </td>

        <td className="px-3 py-2.5 text-center">
          <span
            className="inline-block h-2 w-2 rounded-full"
            style={{ backgroundColor: dotColor }}
          />
        </td>

        <td className="px-3 py-2.5">
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onToggle();
              }}
              className="shrink-0"
              aria-label={isExpanded ? "Collapse details" : "Expand details"}
            >
              {isExpanded ? (
                <IconChevronDown size={11} className="text-[#6f7f9a]/40" />
              ) : (
                <IconChevronRight size={11} className="text-[#6f7f9a]/40" />
              )}
            </button>
            <span className="font-mono text-[11px] text-[#ece7dc]/80 truncate max-w-[180px] inline-block">
              {agent.endpoint_agent_id}
            </span>
          </div>
        </td>

        <td className="px-3 py-2.5">
          {agent.posture ? (
            <span
              className="rounded px-1.5 py-0.5 text-[9px] font-medium uppercase"
              style={{
                backgroundColor: postureColor + "15",
                color: postureColor,
              }}
            >
              {agent.posture}
            </span>
          ) : (
            <span className="text-[10px] text-[#6f7f9a]/30">---</span>
          )}
        </td>

        <td className="px-3 py-2.5 font-mono text-[10px] text-[#ece7dc]/50 max-w-[120px] truncate">
          {agent.policy_version ?? "---"}
        </td>

        <td className="px-3 py-2.5 font-mono text-[10px] text-[#ece7dc]/50 max-w-[120px] truncate">
          {agent.daemon_version ?? "---"}
        </td>

        <td className="px-3 py-2.5 font-mono text-[10px] text-[#6f7f9a]/60">
          {relativeTime(agent.last_heartbeat_at)}
        </td>

        <td className="px-3 py-2.5 text-center font-mono text-[10px] text-[#ece7dc]/50">
          {agent.runtime_count ?? 0}
        </td>

        <td className="px-3 py-2.5">
          <div className="flex gap-1">
            {agent.drift.policy_drift && (
              <DriftBadge label="policy" color="#c45c5c" />
            )}
            {agent.drift.daemon_drift && (
              <DriftBadge label="daemon" color="#d4a84b" />
            )}
            {agent.drift.stale && (
              <DriftBadge label="stale" color="#6f7f9a" />
            )}
            {!agent.drift.policy_drift &&
              !agent.drift.daemon_drift &&
              !agent.drift.stale && (
                <span className="text-[10px] text-[#6f7f9a]/50">---</span>
              )}
          </div>
        </td>
      </tr>

      {isExpanded && (
        <tr className="border-b border-[#2d3240]/30">
          <td colSpan={9} className="bg-[#0b0d13] px-6 py-4">
            <AgentDetail agent={agent} />
          </td>
        </tr>
      )}
    </>
  );
}

function AgentDetail({ agent }: { agent: AgentInfo }) {
  const absTime = new Date(agent.last_heartbeat_at).toLocaleString();

  return (
    <div className="flex gap-8">
      <div className="flex flex-col gap-2 min-w-[240px]">
        <DetailSectionLabel text="Agent Info" />
        <DetailRow label="Agent ID" value={agent.endpoint_agent_id} mono />
        <DetailRow label="Posture" value={agent.posture ?? "---"} title="Resource usage limits and automated state transitions for agent capabilities" />
        <DetailRow label="Policy Version" value={agent.policy_version ?? "---"} mono />
        <DetailRow label="Daemon Version" value={agent.daemon_version ?? "---"} mono />
        <DetailRow label="Session ID" value={agent.last_session_id ?? "---"} mono />
        <DetailRow label="Last Seen IP" value={agent.last_seen_ip ?? "---"} mono />
        <DetailRow
          label="Last Heartbeat"
          value={`${relativeTime(agent.last_heartbeat_at)} (${absTime})`}
        />
      </div>

      <div className="flex flex-col gap-2 min-w-[180px]">
        <DetailSectionLabel text="Drift Flags" />
        <DetailRow
          label="Policy Drift"
          value={agent.drift.policy_drift ? "YES" : "No"}
          valueColor={agent.drift.policy_drift ? "#c45c5c" : "#3dbf84"}
        />
        <DetailRow
          label="Daemon Drift"
          value={agent.drift.daemon_drift ? "YES" : "No"}
          valueColor={agent.drift.daemon_drift ? "#d4a84b" : "#3dbf84"}
        />
        <DetailRow
          label="Stale"
          value={agent.drift.stale ? "YES" : "No"}
          valueColor={agent.drift.stale ? "#d4a84b" : "#3dbf84"}
        />
      </div>

      <div className="flex flex-col gap-2 min-w-[140px]">
        <DetailSectionLabel text="Runtimes" />
        <div className="text-[11px] text-[#ece7dc]/50 font-mono">
          {agent.runtime_count ?? 0} registered
        </div>
      </div>
    </div>
  );
}

function DriftBadge({ label, color }: { label: string; color: string }) {
  return (
    <span
      className="rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase"
      style={{
        backgroundColor: color + "15",
        color,
      }}
    >
      {label}
    </span>
  );
}

function DetailSectionLabel({ text }: { text: string }) {
  return (
    <h4 className="text-[9px] font-semibold uppercase tracking-wider text-[#6f7f9a]/50 mb-1">
      {text}
    </h4>
  );
}

function DetailRow({
  label,
  value,
  mono,
  valueColor,
  title,
}: {
  label: string;
  value: string;
  mono?: boolean;
  valueColor?: string;
  title?: string;
}) {
  return (
    <div className="flex items-baseline gap-3 text-[10px]">
      <span className="text-[#6f7f9a]/50 shrink-0 w-[100px]" title={title}>{label}</span>
      <span
        className={cn(
          "text-[#ece7dc]/70 truncate",
          mono && "font-mono",
        )}
        style={valueColor ? { color: valueColor } : undefined}
      >
        {value}
      </span>
    </div>
  );
}
