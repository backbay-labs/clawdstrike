import { useState, useMemo, useCallback } from "react";
import { useNavigate, Link } from "react-router-dom";
import {
  IconCheck,
  IconBan,
  IconArrowUpRight,
  IconArrowLeft,
  IconX,
  IconChevronDown,
  IconChevronRight,
  IconUser,
  IconShieldCheck,
  IconShieldX,
  IconNote,
  IconSend,
  IconCircleDot,
  IconActivity,
  IconMessage,
  IconChartBar,
} from "@tabler/icons-react";
import { cn } from "@/lib/utils";
import { EnrichmentSidebar } from "./enrichment-sidebar";
import type {
  Finding,
  FindingStatus,
  TimelineEntry,
} from "@/lib/workbench/finding-engine";
import type { Severity, Annotation } from "@/lib/workbench/hunt-types";

// ---------------------------------------------------------------------------
// Props
// ---------------------------------------------------------------------------

interface FindingDetailProps {
  finding: Finding;
  onConfirm: (findingId: string) => void;
  onDismiss: (findingId: string) => void;
  onPromote: (findingId: string) => void;
  onMarkFalsePositive: (findingId: string) => void;
  onAddAnnotation: (findingId: string, text: string) => void;
  onRunEnrichment?: (findingId: string) => void;
  onBack?: () => void;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#c45c5c",
  high: "#d4784b",
  medium: "#d4a84b",
  low: "#6b9b8b",
  info: "#6f7f9a",
};

const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

const STATUS_CONFIG: Record<FindingStatus, { label: string; color: string; bg: string }> = {
  emerging: { label: "Emerging", color: "#d4a84b", bg: "#d4a84b20" },
  confirmed: { label: "Confirmed", color: "#d4784b", bg: "#d4784b20" },
  promoted: { label: "Promoted", color: "#3dbf84", bg: "#3dbf8420" },
  dismissed: { label: "Dismissed", color: "#6f7f9a", bg: "#6f7f9a20" },
  false_positive: { label: "False Positive", color: "#6f7f9a", bg: "#6f7f9a20" },
  archived: { label: "Archived", color: "#6f7f9a", bg: "#6f7f9a15" },
};

const TIMELINE_TYPE_CONFIG: Record<
  TimelineEntry["type"],
  { icon: typeof IconActivity; color: string; label: string; title?: string }
> = {
  signal_added: { icon: IconActivity, color: "#d4a84b", label: "Signal" },
  enrichment_added: { icon: IconChartBar, color: "#6ea8d9", label: "Enrichment" },
  status_changed: { icon: IconCircleDot, color: "#d4784b", label: "Status" },
  annotation_added: { icon: IconNote, color: "#a78bfa", label: "Annotation" },
  verdict_set: { icon: IconShieldCheck, color: "#3dbf84", label: "Verdict" },
  action_taken: { icon: IconCheck, color: "#d4a84b", label: "Action" },
  promoted: { icon: IconArrowUpRight, color: "#3dbf84", label: "Promoted" },
  speakeasy_opened: { icon: IconMessage, color: "#d4a84b", label: "Speakeasy", title: "Encrypted inter-sentinel communication channel for sharing threat intelligence" },
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function formatTimestamp(ms: number): string {
  try {
    const d = new Date(ms);
    return d.toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch {
    return String(ms);
  }
}

function formatRelativeTime(ms: number): string {
  const diff = Date.now() - ms;
  const minutes = Math.floor(diff / 60_000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function formatTimeRange(start: string, end: string): string {
  try {
    const s = new Date(start);
    const e = new Date(end);
    const fmt = (d: Date) =>
      d.toLocaleString(undefined, {
        month: "short",
        day: "numeric",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      });
    return `${fmt(s)} - ${fmt(e)}`;
  } catch {
    return `${start} - ${end}`;
  }
}

// ---------------------------------------------------------------------------
// Main Component
// ---------------------------------------------------------------------------

export function FindingDetail({
  finding,
  onConfirm,
  onDismiss,
  onPromote,
  onMarkFalsePositive,
  onAddAnnotation,
  onRunEnrichment,
  onBack,
}: FindingDetailProps) {
  const navigate = useNavigate();
  const handleBack = onBack ?? (() => navigate(-1));
  const [annotationText, setAnnotationText] = useState("");
  const [expandedEntryId, setExpandedEntryId] = useState<string | null>(null);

  const sevColor = SEVERITY_COLORS[finding.severity] ?? "#6f7f9a";
  const statusConfig = STATUS_CONFIG[finding.status] ?? STATUS_CONFIG.emerging;
  const confidencePct = Math.round(finding.confidence * 100);

  // Sort timeline chronologically
  const sortedTimeline = useMemo(
    () => [...finding.timeline].sort((a, b) => a.timestamp - b.timestamp),
    [finding.timeline],
  );

  const handleSubmitAnnotation = useCallback(() => {
    if (!annotationText.trim()) return;
    onAddAnnotation(finding.id, annotationText.trim());
    setAnnotationText("");
  }, [finding.id, annotationText, onAddAnnotation]);

  return (
    <div className="flex h-full w-full overflow-hidden bg-[#05060a]">
      {/* ----------------------------------------------------------------- */}
      {/* Left column: header + signal timeline + annotations (2/3)         */}
      {/* ----------------------------------------------------------------- */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        {/* Header */}
        <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
          {/* Back button */}
          <button onClick={handleBack} className="flex items-center gap-1 text-[11px] text-[#6f7f9a] hover:text-[#ece7dc] transition-colors mb-3">
            <IconArrowLeft size={12} /> Back
          </button>
          {/* Title row */}
          <div className="flex items-start gap-3">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="font-syne text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
                  {finding.title}
                </h1>

                {/* Severity badge */}
                <span
                  className="rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase border"
                  style={{
                    borderColor: sevColor + "30",
                    backgroundColor: sevColor + "15",
                    color: sevColor,
                  }}
                >
                  {SEVERITY_LABELS[finding.severity]}
                </span>

                {/* Status badge */}
                <span
                  className="rounded-full px-2 py-0.5 text-[9px] font-semibold uppercase border"
                  style={{
                    borderColor: statusConfig.color + "30",
                    backgroundColor: statusConfig.bg,
                    color: statusConfig.color,
                  }}
                >
                  {statusConfig.label}
                </span>

                {/* Confidence meter */}
                <div className="flex items-center gap-2">
                  <div className="w-16 h-1.5 rounded-full bg-[#2d3240]/40 overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-300"
                      style={{
                        width: `${confidencePct}%`,
                        backgroundColor:
                          confidencePct >= 80
                            ? "#3dbf84"
                            : confidencePct >= 50
                              ? "#d4a84b"
                              : "#6f7f9a",
                      }}
                    />
                  </div>
                  <span className="font-mono text-[10px] text-[#ece7dc]/50">
                    {confidencePct}%
                  </span>
                </div>
              </div>

              {/* Meta line: sentinel, signal count, time range */}
              <div className="mt-1.5 flex items-center gap-3 text-[10px] text-[#6f7f9a]">
                <span className="inline-flex items-center gap-1.5">
                  Sentinel: <span className="text-[#ece7dc]/60">{finding.createdBy}</span>
                  <Link to={`/sentinels/${finding.createdBy}`} className="text-[#d4a84b] hover:underline text-[11px]">
                    View Sentinel &rarr;
                  </Link>
                </span>
                <span className="text-[#2d3240]">|</span>
                <span>
                  {finding.signalCount} signal{finding.signalCount !== 1 ? "s" : ""}
                </span>
                <span className="text-[#2d3240]">|</span>
                <span>{formatRelativeTime(finding.createdAt)}</span>
                {finding.id && (
                  <>
                    <span className="text-[#2d3240]">|</span>
                    <span className="font-mono text-[#6f7f9a]/40">{finding.id}</span>
                  </>
                )}
              </div>
            </div>

            {/* Action buttons */}
            <div className="flex items-center gap-1.5 shrink-0">
              {finding.status === "emerging" && (
                <>
                  <ActionButton
                    label="Confirm"
                    icon={<IconCheck size={12} stroke={2} />}
                    color="#d4a84b"
                    onClick={() => onConfirm(finding.id)}
                  />
                  <ActionButton
                    label="Dismiss"
                    icon={<IconBan size={12} stroke={1.5} />}
                    color="#6f7f9a"
                    onClick={() => onDismiss(finding.id)}
                  />
                </>
              )}
              {finding.status === "confirmed" && (
                <>
                  <ActionButton
                    label="Promote to Intel"
                    icon={<IconArrowUpRight size={12} stroke={2} />}
                    color="#3dbf84"
                    onClick={() => onPromote(finding.id)}
                  />
                  <ActionButton
                    label="Mark FP"
                    icon={<IconX size={12} stroke={1.5} />}
                    color="#6f7f9a"
                    onClick={() => onMarkFalsePositive(finding.id)}
                  />
                </>
              )}
            </div>
          </div>
        </div>

        {/* Scope bar */}
        <div className="shrink-0 flex items-center gap-4 border-b border-[#2d3240]/40 bg-[#0b0d13] px-6 py-2">
          <ScopeItem label="Agents" value={finding.scope.agentIds.length.toString()} />
          <ScopeItem label="Sessions" value={finding.scope.sessionIds.length.toString()} />
          <ScopeItem
            label="Time Range"
            value={formatTimeRange(finding.scope.timeRange.start, finding.scope.timeRange.end)}
          />
        </div>

        {/* Signal timeline + annotations */}
        <div className="flex-1 overflow-y-auto">
          {/* Signal Timeline */}
          <div className="px-6 py-5">
            <SectionHeader
              icon={IconActivity}
              title="Signal Timeline"
              badge={`${sortedTimeline.length} entries`}
            />
            <div className="relative ml-3">
              {/* Vertical connector line */}
              <div className="absolute left-[5px] top-2 bottom-2 w-px bg-[#2d3240]/40" />

              <div className="flex flex-col gap-0">
                {sortedTimeline.map((entry, idx) => {
                  const entryKey = `${entry.type}-${entry.timestamp}-${idx}`;
                  const config = TIMELINE_TYPE_CONFIG[entry.type] ?? TIMELINE_TYPE_CONFIG.signal_added;
                  const EntryIcon = config.icon;
                  const isExpanded = expandedEntryId === entryKey;

                  return (
                    <div key={entryKey} className="relative pl-6 py-2 group">
                      {/* Timeline dot */}
                      <div
                        className="absolute left-0 top-3 w-[11px] h-[11px] rounded-full border-2 bg-[#05060a]"
                        style={{ borderColor: config.color }}
                      />

                      <button
                        type="button"
                        onClick={() =>
                          setExpandedEntryId(isExpanded ? null : entryKey)
                        }
                        className="w-full text-left"
                      >
                        <div className="flex items-start gap-3">
                          {/* Timestamp */}
                          <span className="shrink-0 w-[120px] font-mono text-[9px] text-[#6f7f9a]/50 pt-0.5">
                            {formatTimestamp(entry.timestamp)}
                          </span>

                          {/* Icon + type label */}
                          <span className="flex items-center gap-1.5 shrink-0 w-[90px]">
                            <EntryIcon
                              size={12}
                              stroke={1.5}
                              style={{ color: config.color }}
                            />
                            <span
                              className="text-[9px] font-semibold uppercase"
                              style={{ color: config.color }}
                              title={config.title}
                            >
                              {config.label}
                            </span>
                          </span>

                          {/* Source attribution */}
                          <span className="shrink-0 text-[10px] text-[#ece7dc]/40 w-[80px] truncate">
                            {entry.actor}
                          </span>

                          {/* Summary */}
                          <span className="flex-1 min-w-0 text-[10px] text-[#ece7dc]/70 truncate">
                            {entry.summary}
                          </span>

                          {/* Expand chevron */}
                          <span className="shrink-0">
                            {isExpanded ? (
                              <IconChevronDown
                                size={11}
                                className="text-[#6f7f9a]/40"
                              />
                            ) : (
                              <IconChevronRight
                                size={11}
                                className="text-[#6f7f9a]/40 opacity-0 group-hover:opacity-100 transition-opacity"
                              />
                            )}
                          </span>
                        </div>
                      </button>

                      {/* Expanded detail */}
                      {isExpanded && (
                        <div className="mt-2 ml-[123px] rounded-lg border border-[#2d3240]/40 bg-[#0b0d13] p-3">
                          <div className="flex flex-col gap-1.5">
                            <DetailRow
                              label="Type"
                              value={entry.type}
                              mono
                            />
                            <DetailRow
                              label="Timestamp"
                              value={new Date(entry.timestamp).toISOString()}
                              mono
                            />
                            <DetailRow
                              label="Actor"
                              value={entry.actor}
                            />
                            <DetailRow
                              label="Summary"
                              value={entry.summary}
                            />
                            {entry.refId && (
                              <DetailRow
                                label="Ref ID"
                                value={entry.refId}
                                mono
                              />
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* Separator */}
          <div className="mx-6 border-t border-[#2d3240]/40" />

          {/* Receipt section */}
          {finding.receipt && (
            <>
              <div className="px-6 py-5">
                <SectionHeader icon={IconShieldCheck} title="Receipt" />
                <div className="rounded-lg border border-[#2d3240]/60 bg-[#131721] p-4">
                  <div className="flex items-center gap-3">
                    <span
                      className={cn(
                        "inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-[10px] font-semibold border",
                        finding.receipt.valid
                          ? "text-[#3dbf84] border-[#3dbf84]/25 bg-[#3dbf84]/10"
                          : "text-[#c45c5c] border-[#c45c5c]/25 bg-[#c45c5c]/10",
                      )}
                    >
                      {finding.receipt.valid ? (
                        <IconShieldCheck size={11} stroke={2} />
                      ) : (
                        <IconShieldX size={11} stroke={2} />
                      )}
                      {finding.receipt.valid ? "Verified" : "Unverified"}
                    </span>
                    <span className="font-mono text-[10px] text-[#6f7f9a]/40 truncate">
                      {finding.receipt.id}
                    </span>
                  </div>
                  <div className="mt-3 flex flex-col gap-1.5">
                    <DetailRow
                      label="Guard"
                      value={finding.receipt.guard}
                      mono
                    />
                    <DetailRow
                      label="Verdict"
                      value={finding.receipt.verdict}
                    />
                    <DetailRow
                      label="Policy"
                      value={finding.receipt.policyName}
                    />
                    {finding.receipt.signature && (
                      <DetailRow
                        label="Signature"
                        value={finding.receipt.signature.slice(0, 32) + "..."}
                        mono
                      />
                    )}
                  </div>
                </div>
              </div>
              <div className="mx-6 border-t border-[#2d3240]/40" />
            </>
          )}

          {/* Annotation thread */}
          <div className="px-6 py-5">
            <SectionHeader
              icon={IconNote}
              title="Annotations"
              badge={
                finding.annotations.length > 0
                  ? `${finding.annotations.length}`
                  : undefined
              }
            />

            {/* Existing annotations */}
            {finding.annotations.length > 0 ? (
              <div className="flex flex-col gap-2.5 mb-4">
                {finding.annotations.map((annotation) => (
                  <AnnotationCard key={annotation.id} annotation={annotation} />
                ))}
              </div>
            ) : (
              <p className="text-[11px] text-[#6f7f9a]/40 mb-4">
                No annotations yet.
              </p>
            )}

            {/* Add annotation form */}
            <div className="flex items-start gap-2">
              <div className="flex-1">
                <textarea
                  value={annotationText}
                  onChange={(e) => setAnnotationText(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                      handleSubmitAnnotation();
                    }
                  }}
                  placeholder="Add annotation..."
                  rows={2}
                  className="w-full rounded-md border border-[#2d3240] bg-[#131721] px-3 py-2 text-[11px] text-[#ece7dc] placeholder:text-[#6f7f9a]/30 outline-none focus:border-[#d4a84b]/40 transition-colors resize-none"
                />
              </div>
              <button
                onClick={handleSubmitAnnotation}
                disabled={!annotationText.trim()}
                className={cn(
                  "flex items-center gap-1 rounded-md px-3 py-2 text-[11px] font-medium transition-colors",
                  annotationText.trim()
                    ? "text-[#d4a84b] bg-[#d4a84b]/10 border border-[#d4a84b]/20 hover:bg-[#d4a84b]/20"
                    : "text-[#6f7f9a]/30 bg-transparent border border-[#2d3240]/50 cursor-not-allowed",
                )}
              >
                <IconSend size={12} stroke={1.5} />
                Post
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* ----------------------------------------------------------------- */}
      {/* Right column: enrichment sidebar (1/3)                            */}
      {/* ----------------------------------------------------------------- */}
      <div className="w-80 shrink-0 border-l border-[#2d3240]/60 overflow-y-auto bg-[#0b0d13]">
        <EnrichmentSidebar
          enrichments={finding.enrichments}
          onRunEnrichment={
            onRunEnrichment
              ? () => onRunEnrichment(finding.id)
              : undefined
          }
        />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Section Header
// ---------------------------------------------------------------------------

function SectionHeader({
  icon: Icon,
  title,
  badge,
}: {
  icon: typeof IconActivity;
  title: string;
  badge?: string;
}) {
  return (
    <div className="flex items-center gap-2 mb-3">
      <Icon size={14} stroke={1.5} className="text-[#d4a84b]" />
      <h3 className="font-syne text-[11px] font-semibold uppercase tracking-wider text-[#ece7dc]/80">
        {title}
      </h3>
      {badge && (
        <span className="text-[9px] font-mono text-[#6f7f9a]/50 ml-auto">
          {badge}
        </span>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Action Button
// ---------------------------------------------------------------------------

function ActionButton({
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
      onClick={onClick}
      className="flex items-center gap-1.5 rounded-md px-3 py-1.5 text-[11px] font-medium transition-colors border"
      style={{
        color,
        borderColor: color + "25",
        backgroundColor: color + "10",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.backgroundColor = color + "20";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.backgroundColor = color + "10";
      }}
    >
      {icon}
      {label}
    </button>
  );
}

// ---------------------------------------------------------------------------
// Scope Item
// ---------------------------------------------------------------------------

function ScopeItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[9px] uppercase tracking-wider text-[#6f7f9a]/40">
        {label}
      </span>
      <span className="text-[10px] font-mono text-[#ece7dc]/60">{value}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Detail Row
// ---------------------------------------------------------------------------

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div className="flex items-baseline gap-3 text-[10px]">
      <span className="text-[#6f7f9a]/50 shrink-0 w-[80px]">{label}</span>
      <span
        className={cn("text-[#ece7dc]/70 break-all", mono && "font-mono")}
      >
        {value}
      </span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Annotation Card
// ---------------------------------------------------------------------------

function AnnotationCard({ annotation }: { annotation: Annotation }) {
  return (
    <div className="rounded-lg border border-[#2d3240]/40 bg-[#131721] p-3">
      <div className="flex items-center gap-2 mb-1.5">
        <IconUser size={12} className="text-[#6f7f9a]/60" stroke={1.5} />
        <span className="text-[10px] font-medium text-[#ece7dc]/70">
          {annotation.createdBy}
        </span>
        <span className="text-[9px] text-[#6f7f9a]/40 ml-auto">
          {formatRelativeTime(new Date(annotation.createdAt).getTime())}
        </span>
      </div>
      <p className="text-[11px] leading-relaxed text-[#ece7dc]/60">
        {annotation.text}
      </p>
    </div>
  );
}
