import { useState, useMemo, useCallback } from "react";
import { formatRelativeTime } from "@/lib/workbench/format-utils";
import {
  IconSearch,
  IconFilter,
  IconChevronRight,
  IconCheck,
  IconX,
  IconBan,
  IconArrowUpRight,
  IconAlertTriangle,
  IconCircleDot,
  IconCircleCheck,
  IconCircleX,
  IconArchive,
  IconSortDescending,
  IconSquare,
  IconSquareCheck,
  IconEye,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectContent,
  SelectItem,
} from "@/components/ui/select";
import type {
  Finding,
  FindingStatus,
} from "@/lib/workbench/finding-engine";
import type { Severity } from "@/lib/workbench/hunt-types";
import {
  SEVERITY_COLORS,
  SEVERITY_LABELS_SHORT as SEVERITY_LABELS,
  SEVERITY_ORDER,
  STATUS_CONFIG,
} from "@/lib/workbench/finding-constants";

interface FindingsListProps {
  findings: Finding[];
  onSelect: (findingId: string) => void;
  onConfirm: (findingId: string) => void;
  onDismiss: (findingId: string) => void;
  onPromote: (findingId: string) => void;
  onMarkFalsePositive: (findingId: string) => void;
  onBulkAction?: (findingIds: string[], action: BulkAction) => void;
  selectedId?: string | null;
}

type BulkAction = "confirm" | "dismiss" | "false_positive";

type SortField = "newest" | "severity" | "confidence";

const ALL_STATUSES: FindingStatus[] = [
  "emerging",
  "confirmed",
  "promoted",
  "dismissed",
  "false_positive",
  "archived",
];

const ALL_SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SORT_OPTIONS: { value: SortField; label: string }[] = [
  { value: "newest", label: "Newest" },
  { value: "severity", label: "Severity" },
  { value: "confidence", label: "Confidence" },
];

function isActionableStatus(status: FindingStatus): boolean {
  return status === "emerging" || status === "confirmed";
}

export function FindingsList({
  findings,
  onSelect,
  onConfirm,
  onDismiss,
  onPromote,
  onMarkFalsePositive,
  onBulkAction,
  selectedId,
}: FindingsListProps) {
  const [statusFilter, setStatusFilter] = useState<FindingStatus | "all">("all");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortField, setSortField] = useState<SortField>("newest");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const status of ALL_STATUSES) {
      counts[status] = findings.filter((f) => f.status === status).length;
    }
    return counts;
  }, [findings]);

  const filteredFindings = useMemo(() => {
    let list = [...findings];

    if (statusFilter !== "all") {
      list = list.filter((f) => f.status === statusFilter);
    }

    if (severityFilter !== "all") {
      list = list.filter((f) => f.severity === severityFilter);
    }

    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.annotations.some((a) => a.text.toLowerCase().includes(q)) ||
          f.createdBy.toLowerCase().includes(q),
      );
    }

    switch (sortField) {
      case "newest":
        list.sort((a, b) => b.createdAt - a.createdAt);
        break;
      case "severity":
        list.sort(
          (a, b) =>
            (SEVERITY_ORDER[b.severity] ?? 0) - (SEVERITY_ORDER[a.severity] ?? 0),
        );
        break;
      case "confidence":
        list.sort((a, b) => b.confidence - a.confidence);
        break;
    }

    return list;
  }, [findings, statusFilter, severityFilter, searchQuery, sortField]);

  const handleToggleSelect = useCallback((id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  const handleSelectAll = useCallback(() => {
    const actionableIds = filteredFindings
      .filter((f) => isActionableStatus(f.status))
      .map((f) => f.id);
    setSelectedIds((prev) => {
      if (prev.size === actionableIds.length && actionableIds.every((id) => prev.has(id))) {
        return new Set();
      }
      return new Set(actionableIds);
    });
  }, [filteredFindings]);

  const handleBulkAction = useCallback(
    (action: BulkAction) => {
      if (selectedIds.size === 0 || !onBulkAction) return;
      onBulkAction(Array.from(selectedIds), action);
      setSelectedIds(new Set());
    },
    [selectedIds, onBulkAction],
  );

  const actionableSelectedCount = useMemo(
    () =>
      filteredFindings.filter(
        (f) => selectedIds.has(f.id) && isActionableStatus(f.status),
      ).length,
    [filteredFindings, selectedIds],
  );

  return (
    <div className="flex h-full w-full flex-col overflow-hidden bg-[#05060a]">
      <div className="shrink-0 border-b border-[#2d3240]/60 px-5 py-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <IconEye size={16} className="text-[#d4a84b]" stroke={1.5} />
            <span className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
              Findings
            </span>
          </div>
          <div className="flex items-center gap-2">
            {ALL_STATUSES.map((status) => {
              const config = STATUS_CONFIG[status];
              const count = statusCounts[status] ?? 0;
              const isActive = statusFilter === status;
              return (
                <button
                  key={status}
                  onClick={() =>
                    setStatusFilter(isActive ? "all" : status)
                  }
                  className={cn(
                    "flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-medium transition-colors border",
                    isActive
                      ? "border-opacity-40"
                      : "border-transparent hover:bg-[#131721]/60",
                  )}
                  style={{
                    borderColor: isActive ? config.color + "60" : undefined,
                    backgroundColor: isActive ? config.bg : undefined,
                    color: isActive ? config.color : count > 0 ? config.color : "#6f7f9a40",
                  }}
                >
                  {status === "emerging" && count > 0 && (
                    <span
                      className="inline-block w-1.5 h-1.5 rounded-full animate-pulse"
                      style={{ backgroundColor: config.color }}
                    />
                  )}
                  <span className="font-mono">{count}</span>
                  <span className="hidden sm:inline">{config.label}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <div className="shrink-0 flex flex-wrap items-center gap-2 border-b border-[#2d3240]/60 bg-[#0b0d13] px-5 py-2.5">
        <IconFilter size={13} className="text-[#6f7f9a]" stroke={1.5} />

        <Select
          value={severityFilter}
          onValueChange={(v) => {
            if (v) setSeverityFilter(v as Severity | "all");
          }}
        >
          <SelectTrigger className="h-7 text-[11px] bg-[#131721] border-[#2d3240] text-[#ece7dc] min-w-[110px]">
            <SelectValue placeholder="All Severity" />
          </SelectTrigger>
          <SelectContent className="bg-[#131721] border-[#2d3240]">
            <SelectItem value="all" className="text-[11px] text-[#ece7dc]">
              All Severity
            </SelectItem>
            {ALL_SEVERITIES.map((s) => (
              <SelectItem key={s} value={s} className="text-[11px] text-[#ece7dc]">
                <span className="flex items-center gap-2">
                  <span
                    className="inline-block w-2 h-2 rounded-full"
                    style={{ backgroundColor: SEVERITY_COLORS[s] }}
                  />
                  {s.charAt(0).toUpperCase() + s.slice(1)}
                </span>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Select
          value={sortField}
          onValueChange={(v) => {
            if (v) setSortField(v as SortField);
          }}
        >
          <SelectTrigger className="h-7 text-[11px] bg-[#131721] border-[#2d3240] text-[#ece7dc] min-w-[110px]">
            <IconSortDescending size={11} className="mr-1 text-[#6f7f9a]" stroke={1.5} />
            <SelectValue placeholder="Sort..." />
          </SelectTrigger>
          <SelectContent className="bg-[#131721] border-[#2d3240]">
            {SORT_OPTIONS.map((opt) => (
              <SelectItem key={opt.value} value={opt.value} className="text-[11px] text-[#ece7dc]">
                {opt.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <div className="flex-1" />

        <div className="relative">
          <IconSearch
            size={13}
            className="absolute left-2.5 top-1/2 -translate-y-1/2 text-[#6f7f9a]/40"
            stroke={1.5}
          />
          <input
            type="text"
            placeholder="Search findings..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="h-7 w-56 rounded-md border border-[#2d3240] bg-[#131721] pl-8 pr-3 text-[11px] text-[#ece7dc] placeholder:text-[#6f7f9a]/40 outline-none focus:border-[#d4a84b]/50 transition-colors"
          />
        </div>

        <span className="text-[10px] font-mono text-[#6f7f9a]/40 shrink-0">
          {filteredFindings.length} finding{filteredFindings.length !== 1 ? "s" : ""}
        </span>
      </div>

      {selectedIds.size > 0 && onBulkAction && (
        <div className="shrink-0 flex items-center gap-3 border-b border-[#d4a84b]/20 bg-[#d4a84b]/5 px-5 py-2">
          <button
            onClick={handleSelectAll}
            className="flex items-center gap-1.5 text-[10px] font-medium text-[#d4a84b] hover:text-[#ece7dc] transition-colors"
          >
            <IconSquareCheck size={13} stroke={1.5} />
            {selectedIds.size} selected
          </button>

          <div className="h-3 w-px bg-[#2d3240]" />

          {actionableSelectedCount > 0 && (
            <>
              <button
                onClick={() => handleBulkAction("confirm")}
                className="flex items-center gap-1 rounded-md bg-[#d4a84b]/10 px-2.5 py-1 text-[10px] font-medium text-[#d4a84b] hover:bg-[#d4a84b]/20 transition-colors"
              >
                <IconCheck size={11} stroke={2} />
                Confirm
              </button>
              <button
                onClick={() => handleBulkAction("dismiss")}
                className="flex items-center gap-1 rounded-md bg-[#6f7f9a]/10 px-2.5 py-1 text-[10px] font-medium text-[#6f7f9a] hover:bg-[#6f7f9a]/20 transition-colors"
              >
                <IconBan size={11} stroke={1.5} />
                Dismiss
              </button>
              <button
                onClick={() => handleBulkAction("false_positive")}
                className="flex items-center gap-1 rounded-md bg-[#6f7f9a]/10 px-2.5 py-1 text-[10px] font-medium text-[#6f7f9a] hover:bg-[#6f7f9a]/20 transition-colors"
              >
                <IconX size={11} stroke={1.5} />
                Mark FP
              </button>
            </>
          )}

          <div className="flex-1" />
          <button
            onClick={() => setSelectedIds(new Set())}
            className="text-[10px] text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
          >
            Clear selection
          </button>
        </div>
      )}

      <div className="shrink-0 flex items-center gap-0 bg-[#0b0d13] border-b border-[#2d3240]/60 px-5 py-2">
        {onBulkAction && (
          <span className="w-7 shrink-0">
            <button
              onClick={handleSelectAll}
              className="text-[#6f7f9a]/40 hover:text-[#d4a84b] transition-colors"
            >
              {selectedIds.size > 0 ? (
                <IconSquareCheck size={13} stroke={1.5} />
              ) : (
                <IconSquare size={13} stroke={1.5} />
              )}
            </button>
          </span>
        )}
        <span className={cn(TH_CELL, "w-[50px]")}>Sev</span>
        <span className={cn(TH_CELL, "flex-1 min-w-[200px]")}>Title</span>
        <span className={cn(TH_CELL, "w-[90px]")}>Status</span>
        <span className={cn(TH_CELL, "w-[60px] text-right")}>Signals</span>
        <span className={cn(TH_CELL, "w-[80px] text-right")}>Confidence</span>
        <span className={cn(TH_CELL, "w-[70px] text-right")}>Age</span>
        <span className={cn(TH_CELL, "w-[100px]")}>Sentinel</span>
        <span className={cn(TH_CELL, "w-[200px] text-right")}>Actions</span>
      </div>

      <div className="flex-1 overflow-y-auto">
        {filteredFindings.length === 0 ? (
          <EmptyState hasFilters={statusFilter !== "all" || severityFilter !== "all" || searchQuery.length > 0} />
        ) : (
          <div className="min-w-[800px]">
            {filteredFindings.map((finding) => (
              <FindingRow
                key={finding.id}
                finding={finding}
                isSelected={selectedId === finding.id}
                isBatchSelected={selectedIds.has(finding.id)}
                showCheckbox={!!onBulkAction}
                onSelect={() => onSelect(finding.id)}
                onToggleBatch={() => handleToggleSelect(finding.id)}
                onConfirm={() => onConfirm(finding.id)}
                onDismiss={() => onDismiss(finding.id)}
                onPromote={() => onPromote(finding.id)}
                onMarkFalsePositive={() => onMarkFalsePositive(finding.id)}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

const TH_CELL =
  "text-[9px] uppercase tracking-[0.08em] font-semibold text-[#6f7f9a]/50 select-none";

function FindingRow({
  finding,
  isSelected,
  isBatchSelected,
  showCheckbox,
  onSelect,
  onToggleBatch,
  onConfirm,
  onDismiss,
  onPromote,
  onMarkFalsePositive,
}: {
  finding: Finding;
  isSelected: boolean;
  isBatchSelected: boolean;
  showCheckbox: boolean;
  onSelect: () => void;
  onToggleBatch: () => void;
  onConfirm: () => void;
  onDismiss: () => void;
  onPromote: () => void;
  onMarkFalsePositive: () => void;
}) {
  const sevColor = SEVERITY_COLORS[finding.severity] ?? "#6f7f9a";
  const statusConfig = STATUS_CONFIG[finding.status] ?? STATUS_CONFIG.emerging;
  const confidencePct = Math.round(finding.confidence * 100);

  return (
    <div
      className={cn(
        "flex items-center gap-0 px-5 py-2.5 border-b border-[#2d3240]/20 cursor-pointer transition-colors group",
        isSelected
          ? "bg-[#131721] border-l-2 border-l-[#d4a84b]"
          : "hover:bg-[#0b0d13] border-l-2 border-l-transparent",
      )}
    >
      {showCheckbox && (
        <span className="w-7 shrink-0">
          <button
            onClick={(e) => {
              e.stopPropagation();
              onToggleBatch();
            }}
            className={cn(
              "transition-colors",
              isBatchSelected
                ? "text-[#d4a84b]"
                : "text-[#6f7f9a]/30 hover:text-[#6f7f9a]",
            )}
          >
            {isBatchSelected ? (
              <IconSquareCheck size={13} stroke={1.5} />
            ) : (
              <IconSquare size={13} stroke={1.5} />
            )}
          </button>
        </span>
      )}

      <button
        type="button"
        onClick={onSelect}
        className="w-[50px] shrink-0 flex items-center gap-1.5"
      >
        <span
          className="inline-block w-2.5 h-2.5 rounded-full shrink-0"
          style={{ backgroundColor: sevColor }}
        />
        <span
          className="font-mono text-[9px] font-semibold"
          style={{ color: sevColor }}
        >
          {SEVERITY_LABELS[finding.severity]}
        </span>
      </button>

      <button
        type="button"
        onClick={onSelect}
        className="flex-1 min-w-[200px] text-left pr-3"
      >
        <span className="text-[11px] font-medium text-[#ece7dc]/80 truncate block">
          {finding.title}
        </span>
      </button>

      <button
        type="button"
        onClick={onSelect}
        className="w-[90px] shrink-0"
      >
        <span
          className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase border"
          style={{
            borderColor: statusConfig.color + "30",
            backgroundColor: statusConfig.bg,
            color: statusConfig.color,
          }}
        >
          <StatusIcon status={finding.status} />
          {statusConfig.label}
        </span>
      </button>

      <button
        type="button"
        onClick={onSelect}
        className="w-[60px] shrink-0 text-right"
      >
        <span className="font-mono text-[10px] text-[#ece7dc]/60">
          {finding.signalCount}
        </span>
      </button>

      <button
        type="button"
        onClick={onSelect}
        className="w-[80px] shrink-0 flex items-center justify-end gap-2"
      >
        <div className="w-10 h-1.5 rounded-full bg-[#2d3240]/40 overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-300"
            style={{
              width: `${confidencePct}%`,
              backgroundColor: confidencePct >= 80 ? "#3dbf84" : confidencePct >= 50 ? "#d4a84b" : "#6f7f9a",
            }}
          />
        </div>
        <span className="font-mono text-[10px] text-[#ece7dc]/50 w-7 text-right">
          {confidencePct}%
        </span>
      </button>

      <button
        type="button"
        onClick={onSelect}
        className="w-[70px] shrink-0 text-right"
      >
        <span className="text-[10px] text-[#6f7f9a]/50">
          {formatRelativeTime(finding.createdAt)}
        </span>
      </button>

      <button
        type="button"
        onClick={onSelect}
        className="w-[100px] shrink-0 truncate"
      >
        <span className="text-[10px] text-[#ece7dc]/50 truncate">
          {finding.createdBy}
        </span>
      </button>

      <div className="w-[200px] shrink-0 flex items-center justify-end gap-1.5">
        {finding.status === "emerging" && (
          <>
            <InlineAction
              label="Confirm"
              icon={<IconCheck size={11} stroke={2} />}
              color="#d4a84b"
              onClick={onConfirm}
            />
            <InlineAction
              label="Dismiss"
              icon={<IconBan size={11} stroke={1.5} />}
              color="#6f7f9a"
              onClick={onDismiss}
            />
          </>
        )}
        {finding.status === "confirmed" && (
          <>
            <InlineAction
              label="Promote"
              icon={<IconArrowUpRight size={11} stroke={2} />}
              color="#3dbf84"
              onClick={onPromote}
            />
            <InlineAction
              label="FP"
              icon={<IconX size={11} stroke={1.5} />}
              color="#6f7f9a"
              onClick={onMarkFalsePositive}
            />
          </>
        )}
        {finding.status === "promoted" && finding.promotedToIntel && (
          <span className="text-[9px] font-mono text-[#3dbf84]/60 truncate">
            {finding.promotedToIntel}
          </span>
        )}
        {(finding.status === "dismissed" || finding.status === "false_positive") && (
          <span className="text-[9px] text-[#6f7f9a]/30 italic">
            {finding.status === "false_positive" ? "False positive" : "Dismissed"}
          </span>
        )}
        <button
          onClick={onSelect}
          className="shrink-0 text-[#6f7f9a]/30 hover:text-[#d4a84b] transition-colors ml-1"
        >
          <IconChevronRight size={13} stroke={1.5} />
        </button>
      </div>
    </div>
  );
}

function StatusIcon({ status }: { status: FindingStatus }) {
  switch (status) {
    case "emerging":
      return <IconCircleDot size={9} stroke={2} />;
    case "confirmed":
      return <IconAlertTriangle size={9} stroke={2} />;
    case "promoted":
      return <IconCircleCheck size={9} stroke={2} />;
    case "dismissed":
      return <IconBan size={9} stroke={1.5} />;
    case "false_positive":
      return <IconCircleX size={9} stroke={1.5} />;
    case "archived":
      return <IconArchive size={9} stroke={1.5} />;
    default:
      return <IconCircleDot size={9} stroke={2} />;
  }
}

function InlineAction({
  label,
  icon,
  color,
  onClick,
}: {
  label: string;
  icon: React.ReactNode;
  color: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      className="flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-medium transition-colors border"
      style={{
        color,
        borderColor: color + "25",
        backgroundColor: color + "08",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = color + "18";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = color + "08";
      }}
    >
      {icon}
      {label}
    </button>
  );
}

function EmptyState({ hasFilters }: { hasFilters: boolean }) {
  return (
    <div className="flex h-full items-center justify-center">
      <div className="flex flex-col items-center gap-3">
        <IconEye size={28} className="text-[#6f7f9a]/15" stroke={1.5} />
        <span className="text-[12px] text-[#6f7f9a]/40">
          {hasFilters
            ? "No findings match the current filters"
            : "No findings yet. Sentinels will create findings when signals correlate above threshold."}
        </span>
      </div>
    </div>
  );
}
