import { useState, useMemo, useCallback } from "react";
import { formatRelativeTime } from "@/lib/workbench/format-utils";
import {
  IconCheck,
  IconArrowUpRight,
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
import { FindingDetailActions } from "./finding-detail-actions";
import { ConfidenceBreakdown } from "./confidence-breakdown";
import { useEnrichmentBridge } from "@/lib/plugins/threat-intel/enrichment-bridge";
import { enrichmentOrchestrator } from "@/lib/workbench/enrichment-orchestrator";
import { secureStore } from "@/lib/workbench/secure-store";
import { useSignalStore } from "@/features/findings/stores/signal-store";
import type {
  Finding,
  TimelineEntry,
} from "@/lib/workbench/finding-engine";
import type { Annotation } from "@/lib/workbench/hunt-types";
import {
  SEVERITY_COLORS,
  SEVERITY_LABELS,
  STATUS_CONFIG,
} from "@/lib/workbench/finding-constants";

interface FindingDetailProps {
  finding: Finding;
  onConfirm: (findingId: string) => void;
  onDismiss: (findingId: string) => void;
  onPromote: (findingId: string) => void;
  onMarkFalsePositive: (findingId: string) => void;
  onAddAnnotation: (findingId: string, text: string) => void;
  onRunEnrichment?: (findingId: string) => void;
  onDraftDetection?: (findingId: string) => void;
  onDraftGuard?: (findingId: string) => void;
  onBack?: () => void;
}

const TIMELINE_TYPE_CONFIG: Record<
  TimelineEntry["type"],
  { icon: typeof IconActivity; color: string; label: string }
> = {
  signal_added: { icon: IconActivity, color: "#d4a84b", label: "Signal" },
  enrichment_added: { icon: IconChartBar, color: "#6ea8d9", label: "Enrichment" },
  status_changed: { icon: IconCircleDot, color: "#d4784b", label: "Status" },
  annotation_added: { icon: IconNote, color: "#a78bfa", label: "Annotation" },
  verdict_set: { icon: IconShieldCheck, color: "#3dbf84", label: "Verdict" },
  action_taken: { icon: IconCheck, color: "#d4a84b", label: "Action" },
  promoted: { icon: IconArrowUpRight, color: "#3dbf84", label: "Promoted" },
  speakeasy_opened: { icon: IconMessage, color: "#d4a84b", label: "Speakeasy" },
};

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

export function FindingDetail({
  finding,
  onConfirm,
  onDismiss,
  onPromote,
  onMarkFalsePositive,
  onAddAnnotation,
  onRunEnrichment,
  onDraftDetection,
  onDraftGuard,
  onBack,
}: FindingDetailProps) {
  const [annotationText, setAnnotationText] = useState("");
  const [expandedEntryId, setExpandedEntryId] = useState<string | null>(null);

  const enrichmentBridge = useEnrichmentBridge(enrichmentOrchestrator);
  const allSignals = useSignalStore.use.signals();
  const findingSignals = useMemo(
    () => allSignals.filter((s) => finding.signalIds.includes(s.id)),
    [allSignals, finding.signalIds],
  );

  const sevColor = SEVERITY_COLORS[finding.severity] ?? "#6f7f9a";
  const statusConfig = STATUS_CONFIG[finding.status] ?? STATUS_CONFIG.emerging;
  const confidencePct = Math.round(finding.confidence * 100);

  const sortedTimeline = useMemo(
    () => [...finding.timeline].sort((a, b) => b.timestamp - a.timestamp),
    [finding.timeline],
  );

  const handleSubmitAnnotation = useCallback(() => {
    if (!annotationText.trim()) return;
    onAddAnnotation(finding.id, annotationText.trim());
    setAnnotationText("");
  }, [finding.id, annotationText, onAddAnnotation]);

  return (
    <div className="flex h-full w-full overflow-hidden bg-[#05060a]">
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <div className="shrink-0 border-b border-[#2d3240]/60 px-6 py-4">
          <div className="flex items-start gap-3">
            {onBack && (
              <button
                onClick={onBack}
                className="mt-0.5 text-[#6f7f9a] hover:text-[#ece7dc] transition-colors shrink-0"
              >
                <IconChevronRight size={14} className="rotate-180" stroke={1.5} />
              </button>
            )}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2.5 flex-wrap">
                <h1 className="text-sm font-semibold text-[#ece7dc] tracking-[-0.01em]">
                  {finding.title}
                </h1>

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

              <div className="mt-1.5 flex items-center gap-3 text-[10px] text-[#6f7f9a]">
                <span>
                  Sentinel: <span className="text-[#ece7dc]/60">{finding.createdBy}</span>
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

              <details className="mt-2">
                <summary className="cursor-pointer text-[10px] text-[#6f7f9a]/60 hover:text-[#6f7f9a] transition-colors select-none list-none flex items-center gap-1">
                  <IconChevronRight size={10} stroke={1.5} className="transition-transform details-open:rotate-90" />
                  Score breakdown
                </summary>
                <div className="mt-2">
                  <ConfidenceBreakdown finding={finding} signals={findingSignals} />
                </div>
              </details>
            </div>

            <div className="shrink-0">
              <FindingDetailActions
                finding={finding}
                onConfirm={onConfirm}
                onDismiss={onDismiss}
                onPromote={onPromote}
                onMarkFalsePositive={onMarkFalsePositive}
                getApiKey={(service) =>
                  secureStore.get(`plugin:clawdstrike.${service}:api_key`)
                }
              />
            </div>
          </div>
        </div>

        <div className="shrink-0 flex items-center gap-4 border-b border-[#2d3240]/40 bg-[#0b0d13] px-6 py-2">
          <ScopeItem label="Agents" value={finding.scope.agentIds.length.toString()} />
          <ScopeItem label="Sessions" value={finding.scope.sessionIds.length.toString()} />
          <ScopeItem
            label="Time Range"
            value={formatTimeRange(finding.scope.timeRange.start, finding.scope.timeRange.end)}
          />
        </div>

        <div className="flex-1 overflow-y-auto">
          <div className="px-6 py-5">
            <SectionHeader
              icon={IconActivity}
              title="Signal Timeline"
              badge={`${sortedTimeline.length} entries`}
            />
            <div className="relative ml-3">
              <div className="absolute left-[5px] top-2 bottom-2 w-px bg-[#2d3240]/40" />

              <div className="flex flex-col gap-0">
                {sortedTimeline.map((entry, idx) => {
                  const entryKey = `${entry.type}-${entry.timestamp}-${idx}`;
                  const config = TIMELINE_TYPE_CONFIG[entry.type] ?? TIMELINE_TYPE_CONFIG.signal_added;
                  const EntryIcon = config.icon;
                  const isExpanded = expandedEntryId === entryKey;

                  return (
                    <div key={entryKey} className="relative pl-6 py-2 group">
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
                          <span className="shrink-0 w-[120px] font-mono text-[9px] text-[#6f7f9a]/50 pt-0.5">
                            {formatTimestamp(entry.timestamp)}
                          </span>

                          <span className="flex items-center gap-1.5 shrink-0 w-[90px]">
                            <EntryIcon
                              size={12}
                              stroke={1.5}
                              style={{ color: config.color }}
                            />
                            <span
                              className="text-[9px] font-semibold uppercase"
                              style={{ color: config.color }}
                            >
                              {config.label}
                            </span>
                          </span>

                          <span className="shrink-0 text-[10px] text-[#ece7dc]/40 w-[80px] truncate">
                            {entry.actor}
                          </span>

                          <span className="flex-1 min-w-0 text-[10px] text-[#ece7dc]/70 truncate">
                            {entry.summary}
                          </span>

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

          <div className="mx-6 border-t border-[#2d3240]/40" />

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

      <div className="w-80 shrink-0 border-l border-[#2d3240]/60 overflow-y-auto bg-[#0b0d13]">
        <EnrichmentSidebar
          enrichments={finding.enrichments}
          onRunEnrichment={() => {
            enrichmentBridge.runEnrichment(finding);
            onRunEnrichment?.(finding.id);
          }}
          sourceStatuses={enrichmentBridge.sourceStatuses}
          isEnriching={enrichmentBridge.isEnriching}
          onCancel={enrichmentBridge.cancel}
        />
      </div>
    </div>
  );
}

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
      <h3 className="text-[11px] font-semibold uppercase tracking-[0.06em] text-[#ece7dc]/80">
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

function ScopeItem({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-[9px] uppercase tracking-[0.08em] text-[#6f7f9a]/40">
        {label}
      </span>
      <span className="text-[10px] font-mono text-[#ece7dc]/60">{value}</span>
    </div>
  );
}

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
