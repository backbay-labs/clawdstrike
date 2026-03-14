import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { motion } from "motion/react";
import {
  IconSearch,
  IconDatabase,
  IconTestPipe,
  IconX,
  IconCheck,
  IconBan,
  IconClock,
  IconChevronDown,
  IconAlertTriangle,
  IconShieldCheck,
  IconShieldOff,
  IconClockHour4,
  IconFilter,
  IconChevronRight,
  IconRefresh,
  IconPlugConnected,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import { fleetClient } from "@/lib/workbench/fleet-client";
import { useFleetConnection } from "@/lib/workbench/use-fleet-connection";
import { useOperator } from "@/lib/workbench/operator-store";
import type {
  ApprovalRequest,
  ApprovalDecision,
  ApprovalScope,
  ApprovalStatus,
  RiskLevel,
  OriginProvider,
} from "@/lib/workbench/approval-types";
import {
  DEMO_APPROVAL_REQUESTS,
  DEMO_APPROVAL_DECISIONS,
} from "@/lib/workbench/approval-demo-data";

const ALL_STATUSES: ApprovalStatus[] = ["pending", "approved", "denied", "expired"];
const ALL_RISK_LEVELS: RiskLevel[] = ["critical", "high", "medium", "low"];
const ALL_PROVIDERS: OriginProvider[] = ["slack", "teams", "github", "jira", "email", "discord", "webhook", "cli", "api"];

const STATUS_CONFIG: Record<ApprovalStatus, { label: string; color: string; bg: string }> = {
  pending: { label: "Pending", color: "#d4a84b", bg: "#d4a84b20" },
  approved: { label: "Approved", color: "#3dbf84", bg: "#3dbf8420" },
  denied: { label: "Denied", color: "#c45c5c", bg: "#c45c5c20" },
  expired: { label: "Expired", color: "#6f7f9a", bg: "#6f7f9a20" },
};

const RISK_CONFIG: Record<RiskLevel, { label: string; color: string; bg: string }> = {
  critical: { label: "Critical", color: "#c45c5c", bg: "#c45c5c20" },
  high: { label: "High", color: "#f59e0b", bg: "#f59e0b20" },
  medium: { label: "Medium", color: "#d4a84b", bg: "#d4a84b20" },
  low: { label: "Low", color: "#3dbf84", bg: "#3dbf8420" },
};

const PROVIDER_CONFIG: Record<OriginProvider, { label: string; color: string; abbr: string }> = {
  slack: { label: "Slack", color: "#4A154B", abbr: "S" },
  teams: { label: "Teams", color: "#6264A7", abbr: "T" },
  github: { label: "GitHub", color: "#8b949e", abbr: "G" },
  jira: { label: "Jira", color: "#0052CC", abbr: "J" },
  email: { label: "Email", color: "#D44638", abbr: "E" },
  discord: { label: "Discord", color: "#5865F2", abbr: "D" },
  webhook: { label: "Webhook", color: "#FF6B35", abbr: "W" },
  cli: { label: "CLI", color: "#6f7f9a", abbr: "C" },
  api: { label: "API", color: "#5b8def", abbr: "A" },
};

const SCOPE_PRESETS: { label: string; description: string; scope: ApprovalScope }[] = [
  {
    label: "Allow Once",
    description: "10 minute TTL, this tool only",
    scope: { ttlSeconds: 600, toolOnly: true },
  },
  {
    label: "Allow for Session",
    description: "6 hour TTL, this thread only",
    scope: { ttlSeconds: 21_600, threadOnly: true },
  },
  {
    label: "Allow Always",
    description: "7 day TTL, no restrictions",
    scope: { ttlSeconds: 604_800 },
  },
];

function formatCountdown(expiresAt: string): { text: string; urgency: "green" | "yellow" | "red" | "expired" } {
  const diff = new Date(expiresAt).getTime() - Date.now();
  if (diff <= 0) return { text: "Expired", urgency: "expired" };

  const totalSeconds = Math.floor(diff / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  let text: string;
  if (hours > 0) {
    text = `${hours}h ${minutes}m`;
  } else if (minutes > 0) {
    text = `${minutes}m ${seconds}s`;
  } else {
    text = `${seconds}s`;
  }

  let urgency: "green" | "yellow" | "red" | "expired";
  if (totalSeconds > 1800) urgency = "green";
  else if (totalSeconds > 300) urgency = "yellow";
  else urgency = "red";

  return { text, urgency };
}

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function ApprovalQueue({ currentUser }: { currentUser?: string } = {}) {
  const { connection } = useFleetConnection();
  const { currentOperator } = useOperator();
  const fleetConnected = connection.connected;
  const controlApiConfigured = connection.controlApiUrl.trim().length > 0;
  const liveApprovalsReady = fleetConnected && controlApiConfigured;
  const liveApprovalsHint = !fleetConnected
    ? "Connect to fleet in Settings to view live approvals"
    : !controlApiConfigured
      ? "Configure control-api in Settings to view live approvals"
      : null;
  const decidedByUser = currentOperator?.fingerprint ?? currentUser ?? "workbench-anonymous";

  const [requests, setRequests] = useState<ApprovalRequest[]>(DEMO_APPROVAL_REQUESTS);
  const [decisions, setDecisions] = useState<ApprovalDecision[]>(DEMO_APPROVAL_DECISIONS);
  const [isLiveData, setIsLiveData] = useState(false);
  const [liveFetchError, setLiveFetchError] = useState<string | null>(null);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const [statusFilter, setStatusFilter] = useState<ApprovalStatus | "all">("all");
  const [riskFilter, setRiskFilter] = useState<RiskLevel | "all">("all");
  const [providerFilter, setProviderFilter] = useState<OriginProvider | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");

  const [selectedRequest, setSelectedRequest] = useState<ApprovalRequest | null>(null);
  const [confirmAction, setConfirmAction] = useState<{
    requestId: string;
    type: "approve" | "deny";
    scope?: ApprovalScope;
  } | null>(null);
  const [denyReason, setDenyReason] = useState("");
  const [scopeDropdownOpen, setScopeDropdownOpen] = useState<string | null>(null);

    const [tick, setTick] = useState(0);
  useEffect(() => {
    const interval = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const now = Date.now();
    setRequests((prev) => {
      let changed = false;
      const updated = prev.map((r) => {
        if (r.status === "pending" && new Date(r.expiresAt).getTime() <= now) {
          changed = true;
          return { ...r, status: "expired" as const };
        }
        return r;
      });
      return changed ? updated : prev;
    });
  }, [tick]);

  const fetchLiveApprovals = useCallback(async (force?: boolean) => {
    // Guard: only clear/fetch when actually in live mode. In demo mode the
    // callback can still fire (e.g. via the poll timer race) and would
    // otherwise wipe the demo data.  The `force` param lets
    // toggleDataSource bypass this check when it has just set isLiveData
    // (avoiding stale closure).
    if (!force && !isLiveData) return;

    if (!liveApprovalsReady) {
      if (isLiveData) {
        setRequests([]);
        setDecisions([]);
      }
      setLiveFetchError(liveApprovalsHint);
      return;
    }
    try {
      const result = await fleetClient.fetchApprovals();
      if (result && result.requests.length > 0) {
        setRequests(result.requests);
        setDecisions(result.decisions);
        setLiveFetchError(null);
      } else {
        setRequests([]);
        setDecisions([]);
        setLiveFetchError("No pending approvals from fleet");
      }
    } catch {
      setLiveFetchError("Failed to fetch approvals from fleet");
      setRequests([]);
      setDecisions([]);
    }
  }, [isLiveData, liveApprovalsHint, liveApprovalsReady]);

  useEffect(() => {
    if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    pollTimerRef.current = null;
    if (isLiveData && liveApprovalsReady) {
      void fetchLiveApprovals();
      pollTimerRef.current = setInterval(fetchLiveApprovals, 30_000);
    }
    return () => { if (pollTimerRef.current) clearInterval(pollTimerRef.current); };
  }, [isLiveData, liveApprovalsReady, fetchLiveApprovals]);

  const toggleDataSource = useCallback(async () => {
    if (isLiveData) {
      setRequests(DEMO_APPROVAL_REQUESTS);
      setDecisions(DEMO_APPROVAL_DECISIONS);
      setIsLiveData(false);
      setLiveFetchError(null);
    } else if (liveApprovalsReady) {
      setIsLiveData(true);
      await fetchLiveApprovals(true);
    }
    setSelectedRequest(null);
    setConfirmAction(null);
  }, [fetchLiveApprovals, isLiveData, liveApprovalsReady]);

  const filteredRequests = useMemo(() => {
    let list = [...requests];
    if (statusFilter !== "all") list = list.filter((r) => r.status === statusFilter);
    if (riskFilter !== "all") list = list.filter((r) => r.riskLevel === riskFilter);
    if (providerFilter !== "all") list = list.filter((r) => r.originContext.provider === providerFilter);

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (r) =>
          r.toolName.toLowerCase().includes(q) ||
          (r.agentName?.toLowerCase().includes(q) ?? false) ||
          r.reason.toLowerCase().includes(q) ||
          r.requestedBy.toLowerCase().includes(q),
      );
    }

    const riskOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    list.sort((a, b) => {
      if (a.status === "pending" && b.status !== "pending") return -1;
      if (a.status !== "pending" && b.status === "pending") return 1;
      if (a.status === "pending" && b.status === "pending") {
        const riskA = riskOrder[a.riskLevel ?? "medium"] ?? 2;
        const riskB = riskOrder[b.riskLevel ?? "medium"] ?? 2;
        if (riskA !== riskB) return riskA - riskB;
        return new Date(a.expiresAt).getTime() - new Date(b.expiresAt).getTime();
      }
      return new Date(b.requestedAt).getTime() - new Date(a.requestedAt).getTime();
    });

    return list;
  }, [requests, statusFilter, riskFilter, providerFilter, searchQuery]);

  const counts = useMemo(() => ({
    pending: requests.filter((r) => r.status === "pending").length,
    approved: requests.filter((r) => r.status === "approved").length,
    denied: requests.filter((r) => r.status === "denied").length,
    expired: requests.filter((r) => r.status === "expired").length,
  }), [requests]);

  const decisionMap = useMemo(() => {
    const map = new Map<string, ApprovalDecision>();
    for (const d of decisions) map.set(d.requestId, d);
    return map;
  }, [decisions]);

  const handleApprove = useCallback((requestId: string, scope: ApprovalScope) => {
    setConfirmAction({ requestId, type: "approve", scope });
    setScopeDropdownOpen(null);
  }, []);

  const handleDenyInit = useCallback((requestId: string) => {
    setConfirmAction({ requestId, type: "deny" });
    setDenyReason("");
    setScopeDropdownOpen(null);
  }, []);

  const executeAction = useCallback(async () => {
    if (!confirmAction) return;

    const now = new Date().toISOString();
    const decision: "approved" | "denied" =
      confirmAction.type === "approve" ? "approved" : "denied";

    if (isLiveData && liveApprovalsReady) {
      const result = await fleetClient.resolveApproval(
        confirmAction.requestId,
        decision,
        {
          scope: confirmAction.scope,
          reason: confirmAction.type === "deny" ? denyReason || undefined : undefined,
          decidedBy: decidedByUser,
        },
      );
      if (!result.success) {
        setConfirmAction(null);
        setDenyReason("");
        return;
      }
    }

    if (confirmAction.type === "approve") {
      setRequests((prev) =>
        prev.map((r) =>
          r.id === confirmAction.requestId ? { ...r, status: "approved" as const } : r,
        ),
      );
      setDecisions((prev) => [
        ...prev,
        {
          requestId: confirmAction.requestId,
          decision: "approved",
          scope: confirmAction.scope,
          decidedBy: decidedByUser,
          decidedAt: now,
        },
      ]);
    } else {
      setRequests((prev) =>
        prev.map((r) =>
          r.id === confirmAction.requestId ? { ...r, status: "denied" as const } : r,
        ),
      );
      setDecisions((prev) => [
        ...prev,
        {
          requestId: confirmAction.requestId,
          decision: "denied",
          reason: denyReason || undefined,
          decidedBy: decidedByUser,
          decidedAt: now,
        },
      ]);
    }

    if (selectedRequest?.id === confirmAction.requestId) {
      setSelectedRequest((prev) =>
        prev
          ? { ...prev, status: confirmAction.type === "approve" ? "approved" : "denied" }
          : null,
      );
    }

    setConfirmAction(null);
    setDenyReason("");
  }, [confirmAction, decidedByUser, denyReason, isLiveData, liveApprovalsReady, selectedRequest]);

  const cancelAction = useCallback(() => {
    setConfirmAction(null);
    setDenyReason("");
  }, []);

  const relatedRequests = useMemo(() => {
    if (!selectedRequest) return [];
    return requests.filter(
      (r) =>
        r.id !== selectedRequest.id &&
        (r.agentId === selectedRequest.agentId || r.toolName === selectedRequest.toolName),
    );
  }, [selectedRequest, requests]);

  return (
    <div className="flex h-full w-full overflow-hidden bg-[#0b0d13]">
      <div className="flex flex-1 flex-col overflow-hidden">
        <div className="flex items-center gap-4 border-b border-[#2d3240] bg-[#131721]/60 px-5 py-3">
          <div className="flex items-center gap-3">
            <SummaryBadge
              label="Pending"
              count={counts.pending}
              color="#d4a84b"
              pulse={counts.pending > 0}
            />
            <SummaryBadge label="Approved" count={counts.approved} color="#3dbf84" />
            <SummaryBadge label="Denied" count={counts.denied} color="#c45c5c" />
            <SummaryBadge label="Expired" count={counts.expired} color="#6f7f9a" />
          </div>

          <div className="flex-1" />

          {isLiveData && liveApprovalsReady && (
            <button
              onClick={() => fetchLiveApprovals()}
              className="flex h-7 items-center gap-1 rounded-md bg-[#2d3240]/50 px-2 text-[10px] text-[#6f7f9a] transition-colors hover:text-[#ece7dc] active:scale-[0.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]"
              title="Refresh live approvals"
            >
              <IconRefresh size={13} stroke={1.5} />
            </button>
          )}

          <button
            onClick={toggleDataSource}
            disabled={!isLiveData && !liveApprovalsReady}
            className={cn(
              "flex h-7 items-center gap-1.5 rounded-md px-2.5 text-[10px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]",
              isLiveData
                ? "bg-[#3dbf84]/15 text-[#3dbf84]"
                : !liveApprovalsReady
                  ? "bg-[#2d3240]/30 text-[#6f7f9a]/40 cursor-not-allowed"
                  : "bg-[#2d3240]/50 text-[#6f7f9a] hover:text-[#ece7dc]",
            )}
            title={!isLiveData ? liveApprovalsHint ?? undefined : undefined}
          >
            {isLiveData ? <IconDatabase size={13} stroke={1.5} /> : <IconTestPipe size={13} stroke={1.5} />}
            {isLiveData ? "Live" : "Demo"}
            {liveApprovalsReady && !isLiveData && (
              <span className="ml-1 h-1.5 w-1.5 rounded-full bg-[#3dbf84]" title="Live data available" />
            )}
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2 border-b border-[#2d3240] bg-[#131721]/30 px-5 py-2.5">
          <IconFilter size={13} className="text-[#6f7f9a]" />

          <FilterSelect
            value={statusFilter}
            onChange={(v) => setStatusFilter(v as ApprovalStatus | "all")}
            options={[
              { value: "all", label: "All Status" },
              ...ALL_STATUSES.map((s) => ({ value: s, label: STATUS_CONFIG[s].label })),
            ]}
          />

          <FilterSelect
            value={riskFilter}
            onChange={(v) => setRiskFilter(v as RiskLevel | "all")}
            options={[
              { value: "all", label: "All Risk" },
              ...ALL_RISK_LEVELS.map((r) => ({ value: r, label: RISK_CONFIG[r].label })),
            ]}
          />

          <FilterSelect
            value={providerFilter}
            onChange={(v) => setProviderFilter(v as OriginProvider | "all")}
            options={[
              { value: "all", label: "All Providers" },
              ...ALL_PROVIDERS.map((p) => ({ value: p, label: PROVIDER_CONFIG[p].label })),
            ]}
          />

          <div className="flex-1" />

          <div className="relative">
            <IconSearch
              size={13}
              className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#6f7f9a]"
            />
            <input
              type="text"
              placeholder="Search tool, agent, reason..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-56 rounded-md border border-[#2d3240] bg-[#0b0d13] py-1.5 pl-8 pr-3 text-xs text-[#ece7dc] placeholder-[#6f7f9a]/50 outline-none focus:border-[#d4a84b]/50"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-5 py-3">
          {isLiveData && liveFetchError && (
            <div className="mb-3 flex items-center gap-2 rounded-md border border-[#2d3240] bg-[#131721]/60 px-4 py-2.5">
              <IconPlugConnected size={14} className="text-[#6f7f9a] shrink-0" />
              <span className="text-[11px] text-[#6f7f9a]">{liveFetchError}</span>
            </div>
          )}
          {!isLiveData && liveApprovalsHint && (
            <div className="mb-3 flex items-center gap-2 rounded-md border border-[#2d3240] bg-[#131721]/40 px-4 py-2.5">
              <IconPlugConnected size={14} className="text-[#6f7f9a]/50 shrink-0" />
              <span className="text-[11px] text-[#6f7f9a]/60">
                {liveApprovalsHint}
              </span>
            </div>
          )}
          {filteredRequests.length === 0 ? (
            <div className="flex h-48 flex-col items-center justify-center text-[#6f7f9a]">
              <IconShieldCheck size={32} stroke={1} className="mb-2 opacity-40" />
              <span className="text-xs">
                {isLiveData && liveFetchError
                  ? liveFetchError
                  : "No approval requests match your filters."}
              </span>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {filteredRequests.map((request, index) => (
                <motion.div
                  key={request.id}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.25, delay: Math.min(index * 0.03, 0.3) }}
                >
                  <ApprovalCard
                    request={request}
                    decision={decisionMap.get(request.id)}
                    isSelected={selectedRequest?.id === request.id}
                    confirmAction={confirmAction?.requestId === request.id ? confirmAction : null}
                    denyReason={denyReason}
                    scopeDropdownOpen={scopeDropdownOpen === request.id}
                    onSelect={() => setSelectedRequest(request)}
                    onApprove={(scope) => handleApprove(request.id, scope)}
                    onDeny={() => handleDenyInit(request.id)}
                    onConfirm={executeAction}
                    onCancel={cancelAction}
                    onDenyReasonChange={setDenyReason}
                    onToggleScopeDropdown={() =>
                      setScopeDropdownOpen((prev) => (prev === request.id ? null : request.id))
                    }
                  />
                </motion.div>
              ))}
            </div>
          )}
        </div>
      </div>

      {selectedRequest && (
        <motion.div
          key={selectedRequest.id}
          initial={{ x: 40, opacity: 0 }}
          animate={{ x: 0, opacity: 1 }}
          transition={{ type: "spring", bounce: 0.08, duration: 0.35 }}
        >
          <DetailDrawer
            request={selectedRequest}
            decision={decisionMap.get(selectedRequest.id)}
            relatedRequests={relatedRequests}
            onClose={() => setSelectedRequest(null)}
          />
        </motion.div>
      )}
    </div>
  );
}

function SummaryBadge({
  label,
  count,
  color,
  pulse = false,
}: {
  label: string;
  count: number;
  color: string;
  pulse?: boolean;
}) {
  const isPending = pulse && count > 0;

  return (
    <div
      className={cn(
        "flex items-center gap-2 rounded-md px-2.5 py-1.5 transition-colors",
        isPending
          ? "border border-[#d4a84b]/40 bg-[#d4a84b]/[0.06] shadow-[0_0_8px_rgba(212,168,75,0.10)]"
          : "border border-transparent",
      )}
    >
      <span
        className={cn(
          "text-[10px] font-medium uppercase tracking-wider",
          isPending ? "text-[#d4a84b]" : "text-[#6f7f9a]",
        )}
      >
        {label}
      </span>
      <span
        className={cn(
          "inline-flex items-center justify-center rounded-full",
          isPending
            ? "h-6 min-w-[24px] px-2 text-[12px] font-bold animate-pulse"
            : "h-5 min-w-[20px] px-1.5 text-[10px] font-semibold",
        )}
        style={{ backgroundColor: color + "20", color }}
      >
        {count}
      </span>
    </div>
  );
}

function FilterSelect({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (value: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <Select value={value} onValueChange={(v) => { if (v !== null) onChange(v); }}>
      <SelectTrigger className="h-7 text-[11px] bg-[#131721] border-[#2d3240] text-[#ece7dc]">
        <SelectValue placeholder="Select..." />
      </SelectTrigger>
      <SelectContent className="bg-[#131721] border-[#2d3240]">
        {options.map((opt) => (
          <SelectItem key={opt.value} value={opt.value} className="text-[11px] text-[#ece7dc]">
            {opt.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

function ApprovalCard({
  request,
  decision,
  isSelected,
  confirmAction,
  denyReason,
  scopeDropdownOpen,
  onSelect,
  onApprove,
  onDeny,
  onConfirm,
  onCancel,
  onDenyReasonChange,
  onToggleScopeDropdown,
}: {
  request: ApprovalRequest;
  decision?: ApprovalDecision;
  isSelected: boolean;
  confirmAction: { requestId: string; type: "approve" | "deny"; scope?: ApprovalScope } | null;
  denyReason: string;
  scopeDropdownOpen: boolean;
  onSelect: () => void;
  onApprove: (scope: ApprovalScope) => void;
  onDeny: () => void;
  onConfirm: () => void;
  onCancel: () => void;
  onDenyReasonChange: (reason: string) => void;
  onToggleScopeDropdown: () => void;
}) {
  const isPending = request.status === "pending";
  const isExpiredOrResolved = request.status === "expired" || request.status === "approved" || request.status === "denied";
  const provider = PROVIDER_CONFIG[request.originContext.provider];
  const risk = request.riskLevel ? RISK_CONFIG[request.riskLevel] : null;
  const status = STATUS_CONFIG[request.status];
  const countdown = isPending ? formatCountdown(request.expiresAt) : null;

  const urgencyColor: Record<string, string> = {
    green: "#3dbf84",
    yellow: "#f59e0b",
    red: "#c45c5c",
    expired: "#6f7f9a",
  };

  return (
    <div
      className={cn(
        "group relative rounded-lg border transition-all duration-150",
        isSelected
          ? "border-[#d4a84b]/40 bg-[#131721]"
          : "border-[#2d3240] bg-[#131721]/60 hover:border-[#2d3240]/80 hover:bg-[#131721]/80",
        isExpiredOrResolved && !isPending && "opacity-70",
      )}
    >
      <div className="flex items-start gap-3 px-4 py-3 cursor-pointer" onClick={onSelect}>
        <div className="flex flex-col items-center gap-1.5 pt-0.5">
          <div
            className="flex h-8 w-8 items-center justify-center rounded-lg text-xs font-bold text-white"
            style={{ backgroundColor: provider.color }}
            title={provider.label}
          >
            {provider.abbr}
          </div>
          {risk && (
            <span
              className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase"
              style={{ backgroundColor: risk.bg, color: risk.color }}
            >
              {risk.label}
            </span>
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-[#ece7dc]">
              {request.toolName}
            </span>
            {!isPending && (
              <span
                className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase"
                style={{ backgroundColor: status.bg, color: status.color }}
              >
                {status.label}
              </span>
            )}
          </div>
          {request.agentName && (
            <div className="mt-0.5 text-xs text-[#6f7f9a]">
              {request.agentName}
              {request.capability && (
                <span className="ml-1.5 rounded bg-[#2d3240] px-1 py-0.5 text-[9px]">
                  {request.capability}
                </span>
              )}
            </div>
          )}
          <div className="mt-1 text-[11px] leading-relaxed text-[#ece7dc]/60 line-clamp-2">
            {request.reason}
          </div>
          <div className="mt-1.5 flex items-center gap-2 text-[10px] text-[#6f7f9a]">
            <span>
              {request.originContext.space_id && `#${request.originContext.space_id}`}
              {request.originContext.space_type && ` (${request.originContext.space_type})`}
            </span>
            <span className="text-[#2d3240]">|</span>
            <span>Requested {formatRelativeTime(request.requestedAt)}</span>
          </div>
        </div>

        <div className="flex flex-col items-end gap-2 shrink-0">
          {isPending && countdown && (
            <div className="flex items-center gap-1.5">
              <IconClock size={12} style={{ color: urgencyColor[countdown.urgency] }} />
              <span
                className="text-xs font-mono font-medium"
                style={{ color: urgencyColor[countdown.urgency] }}
              >
                {countdown.text}
              </span>
            </div>
          )}
          {decision && (
            <div className="text-right">
              <div className="text-[10px] text-[#6f7f9a]">
                by {decision.decidedBy.split("@")[0]}
              </div>
              <div className="text-[9px] text-[#6f7f9a]/60">
                {formatRelativeTime(decision.decidedAt)}
              </div>
            </div>
          )}
        </div>
      </div>

      {isPending && (
        <div className="flex items-center gap-2 border-t border-[#2d3240]/60 px-4 py-2">
          {confirmAction ? (
            <div className="flex flex-1 items-center gap-2">
              {confirmAction.type === "approve" ? (
                <>
                  <IconShieldCheck size={14} className="text-[#3dbf84]" />
                  <span className="text-xs text-[#ece7dc]">
                    Approve with{" "}
                    <strong className="text-[#3dbf84]">
                      {SCOPE_PRESETS.find(
                        (p) => p.scope.ttlSeconds === confirmAction.scope?.ttlSeconds,
                      )?.label ?? "custom scope"}
                    </strong>
                    ?
                  </span>
                </>
              ) : (
                <div className="flex flex-1 flex-col gap-1.5">
                  <div className="flex items-center gap-1.5">
                    <IconShieldOff size={14} className="text-[#c45c5c]" />
                    <span className="text-xs text-[#ece7dc]">Deny this request?</span>
                  </div>
                  <input
                    type="text"
                    placeholder="Reason (optional)..."
                    value={denyReason}
                    onChange={(e) => onDenyReasonChange(e.target.value)}
                    onClick={(e) => e.stopPropagation()}
                    className="w-full rounded border border-[#2d3240] bg-[#0b0d13] px-2 py-1 text-[11px] text-[#ece7dc] placeholder-[#6f7f9a]/50 outline-none focus:border-[#c45c5c]/50"
                  />
                </div>
              )}
              <div className="flex items-center gap-1.5 ml-auto">
                <motion.button
                  whileTap={{ scale: 0.92 }}
                  transition={{ type: "spring", bounce: 0.4, duration: 0.2 }}
                  onClick={(e) => { e.stopPropagation(); onConfirm(); }}
                  className={cn(
                    "flex h-7 items-center gap-1 rounded-md px-3 text-[11px] font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]",
                    confirmAction.type === "approve"
                      ? "bg-[#3dbf84]/15 text-[#3dbf84] hover:bg-[#3dbf84]/25"
                      : "bg-[#c45c5c]/15 text-[#c45c5c] hover:bg-[#c45c5c]/25",
                  )}
                >
                  <IconCheck size={13} />
                  Confirm
                </motion.button>
                <motion.button
                  whileTap={{ scale: 0.92 }}
                  transition={{ type: "spring", bounce: 0.4, duration: 0.2 }}
                  onClick={(e) => { e.stopPropagation(); onCancel(); }}
                  className="flex h-7 items-center gap-1 rounded-md bg-[#2d3240]/50 px-3 text-[11px] text-[#6f7f9a] transition-colors hover:text-[#ece7dc] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]"
                >
                  Cancel
                </motion.button>
              </div>
            </div>
          ) : (
            <>
              <div className="relative">
                <motion.button
                  whileTap={{ scale: 0.92 }}
                  transition={{ type: "spring", bounce: 0.4, duration: 0.2 }}
                  onClick={(e) => { e.stopPropagation(); onToggleScopeDropdown(); }}
                  className="flex h-7 items-center gap-1 rounded-md bg-[#3dbf84]/10 px-3 text-[11px] font-medium text-[#3dbf84] transition-colors hover:bg-[#3dbf84]/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]"
                >
                  <IconCheck size={13} />
                  Approve
                  <IconChevronDown size={11} />
                </motion.button>

                {scopeDropdownOpen && (
                  <div className="absolute left-0 top-full z-30 mt-1 w-56 rounded-lg border border-[#2d3240] bg-[#131721] py-1 shadow-xl">
                    {SCOPE_PRESETS.map((preset) => (
                      <button
                        key={preset.label}
                        onClick={(e) => { e.stopPropagation(); onApprove(preset.scope); }}
                        className="flex w-full flex-col px-3 py-2 text-left transition-colors hover:bg-[#2d3240]/50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]"
                      >
                        <span className="text-xs font-medium text-[#ece7dc]">
                          {preset.label}
                        </span>
                        <span className="text-[10px] text-[#6f7f9a]">
                          {preset.description}
                        </span>
                      </button>
                    ))}
                  </div>
                )}
              </div>

              <motion.button
                whileTap={{ scale: 0.92 }}
                transition={{ type: "spring", bounce: 0.4, duration: 0.2 }}
                onClick={(e) => { e.stopPropagation(); onDeny(); }}
                className="flex h-7 items-center gap-1 rounded-md bg-[#c45c5c]/10 px-3 text-[11px] font-medium text-[#c45c5c] transition-colors hover:bg-[#c45c5c]/20 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]"
              >
                <IconBan size={13} />
                Deny
              </motion.button>

              <div className="flex-1" />

              {countdown?.urgency === "red" && (
                <div className="flex items-center gap-1 text-[10px] text-[#c45c5c]">
                  <IconAlertTriangle size={12} />
                  Expiring soon
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}

function DetailDrawer({
  request,
  decision,
  relatedRequests,
  onClose,
}: {
  request: ApprovalRequest;
  decision?: ApprovalDecision;
  relatedRequests: ApprovalRequest[];
  onClose: () => void;
}) {
  const provider = PROVIDER_CONFIG[request.originContext.provider];
  const risk = request.riskLevel ? RISK_CONFIG[request.riskLevel] : null;
  const status = STATUS_CONFIG[request.status];

  return (
    <div className="flex w-80 flex-col border-l border-lifted bg-[#131721]/80 backdrop-blur-md max-lg:hidden">
      <div className="flex items-center justify-between border-b border-[#2d3240] px-4 py-3">
        <h2 className="font-syne text-xs font-semibold uppercase tracking-wider text-[#6f7f9a]">
          Request Details
        </h2>
        <button
          onClick={onClose}
          className="text-[#6f7f9a] transition-colors hover:text-[#ece7dc] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#d4a84b]/40 focus-visible:ring-offset-1 focus-visible:ring-offset-[#05060a]"
        >
          <IconX size={14} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="border-b border-[#2d3240] px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="text-sm font-semibold text-[#ece7dc]">{request.toolName}</span>
            <span
              className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase"
              style={{ backgroundColor: status.bg, color: status.color }}
            >
              {status.label}
            </span>
          </div>
          {risk && (
            <div className="mt-1.5 flex items-center gap-1.5">
              <IconAlertTriangle size={12} style={{ color: risk.color }} />
              <span className="text-[11px]" style={{ color: risk.color }}>
                {risk.label} Risk
              </span>
            </div>
          )}
          <p className="mt-2 text-[11px] leading-relaxed text-[#ece7dc]/70">
            {request.reason}
          </p>
        </div>

        <div className="border-b border-[#2d3240] px-4 py-3">
          <h3 className="font-syne mb-2 text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
            Origin Context
          </h3>
          <div className="flex flex-col gap-1.5">
            <DetailRow label="Provider">
              <div className="flex items-center gap-1.5">
                <span
                  className="flex h-4 w-4 items-center justify-center rounded text-[8px] font-bold text-white"
                  style={{ backgroundColor: provider.color }}
                >
                  {provider.abbr}
                </span>
                <span className="text-[11px] text-[#ece7dc]/80">{provider.label}</span>
              </div>
            </DetailRow>
            {request.originContext.tenant_id && (
              <DetailRow label="Tenant">{request.originContext.tenant_id}</DetailRow>
            )}
            {request.originContext.space_id && (
              <DetailRow label="Space">
                #{request.originContext.space_id}
                {request.originContext.space_type && ` (${request.originContext.space_type})`}
              </DetailRow>
            )}
            {request.originContext.actor_name && (
              <DetailRow label="Actor">{request.originContext.actor_name}</DetailRow>
            )}
            {request.originContext.visibility && (
              <DetailRow label="Visibility">{request.originContext.visibility}</DetailRow>
            )}
            {request.enclaveId && (
              <DetailRow label="Enclave">{request.enclaveId}</DetailRow>
            )}
          </div>
        </div>

        <div className="border-b border-[#2d3240] px-4 py-3">
          <h3 className="font-syne mb-2 text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
            Agent Identity
          </h3>
          <div className="flex flex-col gap-1.5">
            {request.agentId && (
              <DetailRow label="Agent ID">
                <span className="font-mono text-[10px]">{request.agentId}</span>
              </DetailRow>
            )}
            {request.agentName && (
              <DetailRow label="Name">{request.agentName}</DetailRow>
            )}
            {request.capability && (
              <DetailRow label="Capability">
                <span className="rounded bg-[#d4a84b]/10 px-1.5 py-0.5 text-[10px] text-[#d4a84b]">
                  {request.capability}
                </span>
              </DetailRow>
            )}
            <DetailRow label="Requested By">{request.requestedBy}</DetailRow>
          </div>
        </div>

        <div className="border-b border-[#2d3240] px-4 py-3">
          <h3 className="font-syne mb-2 text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
            Timeline
          </h3>
          <div className="flex flex-col gap-2">
            <TimelineEntry
              icon={<IconClockHour4 size={12} />}
              label="Requested"
              time={request.requestedAt}
              color="#6f7f9a"
            />
            <TimelineEntry
              icon={<IconClock size={12} />}
              label="Expires"
              time={request.expiresAt}
              color={
                request.status === "pending"
                  ? new Date(request.expiresAt).getTime() > Date.now()
                    ? "#d4a84b"
                    : "#c45c5c"
                  : "#6f7f9a"
              }
            />
            {decision && (
              <TimelineEntry
                icon={
                  decision.decision === "approved" ? (
                    <IconShieldCheck size={12} />
                  ) : (
                    <IconShieldOff size={12} />
                  )
                }
                label={decision.decision === "approved" ? "Approved" : "Denied"}
                time={decision.decidedAt}
                color={decision.decision === "approved" ? "#3dbf84" : "#c45c5c"}
              />
            )}
          </div>
        </div>

        {decision && (
          <div className="border-b border-[#2d3240] px-4 py-3">
            <h3 className="font-syne mb-2 text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
              Decision
            </h3>
            <div className="flex flex-col gap-1.5">
              <DetailRow label="By">{decision.decidedBy}</DetailRow>
              {decision.reason && (
                <div className="mt-1 text-[11px] leading-relaxed text-[#ece7dc]/60">
                  {decision.reason}
                </div>
              )}
              {decision.scope && (
                <div className="mt-1 flex flex-wrap gap-1">
                  {decision.scope.ttlSeconds && (
                    <span className="rounded bg-[#2d3240] px-1.5 py-0.5 text-[9px] text-[#6f7f9a]">
                      TTL: {Math.round(decision.scope.ttlSeconds / 60)}m
                    </span>
                  )}
                  {decision.scope.threadOnly && (
                    <span className="rounded bg-[#2d3240] px-1.5 py-0.5 text-[9px] text-[#6f7f9a]">
                      Thread Only
                    </span>
                  )}
                  {decision.scope.toolOnly && (
                    <span className="rounded bg-[#2d3240] px-1.5 py-0.5 text-[9px] text-[#6f7f9a]">
                      Tool Only
                    </span>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {relatedRequests.length > 0 && (
          <div className="px-4 py-3">
            <h3 className="font-syne mb-2 text-[10px] font-semibold uppercase tracking-wider text-[#6f7f9a]">
              Related ({relatedRequests.length})
            </h3>
            <div className="flex flex-col gap-1.5">
              {relatedRequests.map((r) => {
                const rStatus = STATUS_CONFIG[r.status];
                return (
                  <div
                    key={r.id}
                    className="flex items-center gap-2 rounded border border-[#2d3240] bg-[#0b0d13]/50 px-2 py-1.5"
                  >
                    <span
                      className="h-1.5 w-1.5 rounded-full"
                      style={{ backgroundColor: rStatus.color }}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[10px] text-[#ece7dc]/80">
                        {r.toolName}
                      </div>
                      <div className="text-[9px] text-[#6f7f9a]">
                        {r.agentName ?? r.requestedBy} &middot; {rStatus.label}
                      </div>
                    </div>
                    <IconChevronRight size={10} className="text-[#6f7f9a]" />
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function DetailRow({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="flex items-start justify-between gap-2">
      <span className="shrink-0 text-[10px] text-[#6f7f9a]">{label}</span>
      <span className="text-right text-[11px] text-[#ece7dc]/80">{children}</span>
    </div>
  );
}

function TimelineEntry({
  icon,
  label,
  time,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  time: string;
  color: string;
}) {
  const date = new Date(time);
  const timeStr = date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  const dateStr = date.toLocaleDateString([], { month: "short", day: "numeric" });

  return (
    <div className="flex items-center gap-2">
      <span style={{ color }}>{icon}</span>
      <span className="text-[10px] font-medium" style={{ color }}>
        {label}
      </span>
      <span className="flex-1" />
      <span className="text-[10px] text-[#ece7dc]/60">
        {dateStr} {timeStr}
      </span>
    </div>
  );
}
