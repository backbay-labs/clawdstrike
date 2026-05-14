import { useState, useMemo, useCallback } from "react";
import {
  IconAlertTriangle,
  IconX,
  IconSend,
  IconCheck,
  IconLoader2,
} from "@tabler/icons-react";
import type { Finding, ExtractedIoc } from "@/lib/workbench/finding-engine";
import {
  reportToAbuseIPDB,
  reportToMisp,
} from "@/lib/workbench/threat-reporting";
import type { ReportResult } from "@/lib/workbench/threat-reporting";
import { IOC_TYPE_COLORS } from "@/lib/workbench/ioc-constants";

type ReportTarget = "abuseipdb" | "misp";

interface ReportThreatDialogProps {
  open: boolean;
  onClose: () => void;
  finding: Finding;
  indicators: ExtractedIoc[];
  getApiKey: (service: string) => Promise<string | null>;
  mispBaseUrl?: string;
}

const ABUSEIPDB_CATEGORIES = [
  { id: 14, label: "Port Scan" },
  { id: 15, label: "Brute Force" },
  { id: 18, label: "DDoS Attack" },
  { id: 21, label: "Exploited Host" },
  { id: 22, label: "SSH Brute Force" },
] as const;

export function ReportThreatDialog({
  open,
  onClose,
  finding,
  indicators,
  getApiKey,
  mispBaseUrl = "",
}: ReportThreatDialogProps) {
  const [selectedTarget, setSelectedTarget] = useState<ReportTarget>("abuseipdb");
  const [selectedIndicatorIdx, setSelectedIndicatorIdx] = useState(0);
  const [comment, setComment] = useState("");
  const [eventInfo, setEventInfo] = useState(finding.title);
  const [selectedCategories, setSelectedCategories] = useState<number[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<ReportResult | null>(null);

  // Filter indicators by target: AbuseIPDB only shows IP-type
  const filteredIndicators = useMemo(() => {
    if (selectedTarget === "abuseipdb") {
      return indicators.filter((ioc) => ioc.iocType === "ip");
    }
    return indicators;
  }, [indicators, selectedTarget]);

  // Reset selected indicator when target changes
  const handleTargetChange = useCallback((target: ReportTarget) => {
    setSelectedTarget(target);
    setSelectedIndicatorIdx(0);
    setResult(null);
  }, []);

  const toggleCategory = useCallback((id: number) => {
    setSelectedCategories((prev) =>
      prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id],
    );
  }, []);

  const handleSubmit = useCallback(async () => {
    if (filteredIndicators.length === 0) return;
    const indicator = filteredIndicators[selectedIndicatorIdx];
    if (!indicator) return;

    setSubmitting(true);
    setResult(null);

    try {
      const apiKey = await getApiKey(selectedTarget);
      if (!apiKey) {
        setResult({
          success: false,
          error: `No API key configured for ${selectedTarget === "abuseipdb" ? "AbuseIPDB" : "MISP"}. Configure it in Settings > Secrets.`,
        });
        setSubmitting(false);
        return;
      }

      let reportResult: ReportResult;

      if (selectedTarget === "abuseipdb") {
        reportResult = await reportToAbuseIPDB(
          {
            ip: indicator.indicator,
            categories: selectedCategories.length > 0 ? selectedCategories : [21],
            comment: comment || `Reported from ClawdStrike finding ${finding.id}`,
          },
          apiKey,
        );
      } else {
        reportResult = await reportToMisp(
          {
            indicator: indicator.indicator,
            iocType: indicator.iocType,
            eventInfo: eventInfo || finding.title,
            severity: mapFindingSeverity(finding.severity),
          },
          apiKey,
          mispBaseUrl,
        );
      }

      setResult(reportResult);
    } catch (err) {
      setResult({
        success: false,
        error: err instanceof Error ? err.message : String(err),
      });
    } finally {
      setSubmitting(false);
    }
  }, [
    filteredIndicators,
    selectedIndicatorIdx,
    selectedTarget,
    selectedCategories,
    comment,
    eventInfo,
    finding,
    getApiKey,
    mispBaseUrl,
  ]);

  if (!open) return null;

  const selectedIndicator = filteredIndicators[selectedIndicatorIdx];
  const targetLabel = selectedTarget === "abuseipdb" ? "AbuseIPDB" : "MISP";

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center"
      onKeyDown={(e) => e.key === "Escape" && onClose()}
    >
      <div
        aria-hidden="true"
        className="absolute inset-0 bg-black/60"
        onClick={onClose}
      />

      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-dialog-title"
        className="relative z-10 w-full max-w-md rounded-lg border border-[#2d3240] bg-[#0b0d13] shadow-xl"
      >
        <div className="flex items-center justify-between border-b border-[#2d3240]/60 px-5 py-3.5">
          <div className="flex items-center gap-2">
            <IconAlertTriangle size={15} className="text-[#d4a84b]" stroke={1.5} />
            <h2 id="report-dialog-title" className="text-sm font-semibold text-[#ece7dc]">Report Threat</h2>
          </div>
          <button
            onClick={onClose}
            className="text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
          >
            <IconX size={16} stroke={1.5} />
          </button>
        </div>

        <div className="px-5 py-4 flex flex-col gap-4 max-h-[70vh] overflow-y-auto">
          <div>
            <label className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50 mb-2 block">
              Report to
            </label>
            <div className="flex gap-2">
              <TargetButton
                label="AbuseIPDB"
                active={selectedTarget === "abuseipdb"}
                onClick={() => handleTargetChange("abuseipdb")}
                color="#d4784b"
              />
              <TargetButton
                label="MISP"
                active={selectedTarget === "misp"}
                onClick={() => handleTargetChange("misp")}
                color="#1A237E"
              />
            </div>
          </div>

          <div>
            <label className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50 mb-2 block">
              Indicator
            </label>
            {filteredIndicators.length === 0 ? (
              <p className="text-[11px] text-[#6f7f9a]/50 italic">
                No {selectedTarget === "abuseipdb" ? "IP " : ""}indicators available for this finding.
              </p>
            ) : (
              <div className="flex flex-col gap-1.5">
                {filteredIndicators.map((ioc, idx) => {
                  const typeColor = IOC_TYPE_COLORS[ioc.iocType] ?? "#6f7f9a";
                  const isSelected = idx === selectedIndicatorIdx;
                  return (
                    <button
                      key={`${ioc.iocType}:${ioc.indicator}`}
                      onClick={() => setSelectedIndicatorIdx(idx)}
                      className="flex items-center gap-2 rounded-md border px-3 py-2 text-left transition-colors"
                      style={{
                        borderColor: isSelected ? typeColor + "40" : "#2d3240",
                        backgroundColor: isSelected ? typeColor + "10" : "transparent",
                      }}
                    >
                      <span
                        className="shrink-0 rounded px-1.5 py-0.5 text-[8px] font-semibold uppercase border"
                        style={{
                          color: typeColor,
                          borderColor: typeColor + "30",
                          backgroundColor: typeColor + "10",
                        }}
                      >
                        {ioc.iocType}
                      </span>
                      <span className="font-mono text-[11px] text-[#ece7dc]/70 truncate">
                        {ioc.indicator}
                      </span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>

          {selectedTarget === "abuseipdb" && (
            <div>
              <label className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50 mb-2 block">
                Abuse Categories
              </label>
              <div className="flex flex-wrap gap-2">
                {ABUSEIPDB_CATEGORIES.map((cat) => {
                  const isChecked = selectedCategories.includes(cat.id);
                  return (
                    <button
                      key={cat.id}
                      onClick={() => toggleCategory(cat.id)}
                      className="flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-[10px] font-medium transition-colors"
                      style={{
                        borderColor: isChecked ? "#d4a84b40" : "#2d324060",
                        backgroundColor: isChecked ? "#d4a84b15" : "transparent",
                        color: isChecked ? "#d4a84b" : "#6f7f9a",
                      }}
                    >
                      {isChecked && <IconCheck size={10} stroke={2} />}
                      {cat.label}
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {selectedTarget === "misp" && (
            <div>
              <label className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50 mb-2 block">
                Event Info
              </label>
              <input
                type="text"
                value={eventInfo}
                onChange={(e) => setEventInfo(e.target.value)}
                placeholder="Event description..."
                className="w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2 text-[11px] text-[#ece7dc] placeholder-[#6f7f9a]/30 focus:border-[#d4a84b]/40 focus:outline-none"
              />
            </div>
          )}

          <div>
            <label className="text-[10px] font-semibold uppercase tracking-[0.08em] text-[#6f7f9a]/50 mb-2 block">
              Comment
            </label>
            <textarea
              value={comment}
              onChange={(e) => setComment(e.target.value)}
              placeholder="Additional context for the report..."
              rows={3}
              className="w-full rounded-md border border-[#2d3240] bg-[#05060a] px-3 py-2 text-[11px] text-[#ece7dc] placeholder-[#6f7f9a]/30 focus:border-[#d4a84b]/40 focus:outline-none resize-none"
            />
          </div>

          {result && (
            <div
              className="rounded-md border px-3 py-2.5"
              style={{
                borderColor: result.success ? "#3dbf8430" : "#c45c5c30",
                backgroundColor: result.success ? "#3dbf8410" : "#c45c5c10",
              }}
            >
              {result.success ? (
                <div className="flex items-center gap-2">
                  <IconCheck size={13} className="text-[#3dbf84] shrink-0" stroke={2} />
                  <span className="text-[11px] text-[#3dbf84]">
                    Successfully reported to {targetLabel}.
                    {result.eventId && ` Event ID: ${result.eventId}`}
                  </span>
                </div>
              ) : (
                <div className="flex items-start gap-2">
                  <IconAlertTriangle size={13} className="text-[#c45c5c] shrink-0 mt-0.5" stroke={1.5} />
                  <span className="text-[11px] text-[#c45c5c]">{result.error}</span>
                </div>
              )}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-2 border-t border-[#2d3240]/60 px-5 py-3">
          <button
            onClick={onClose}
            className="rounded-md px-3 py-1.5 text-[11px] font-medium text-[#6f7f9a] hover:text-[#ece7dc] transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={handleSubmit}
            disabled={submitting || filteredIndicators.length === 0}
            className="flex items-center gap-1.5 rounded-md px-4 py-1.5 text-[11px] font-medium transition-colors border disabled:opacity-40 disabled:cursor-not-allowed"
            style={{
              color: "#d4a84b",
              borderColor: "#d4a84b25",
              backgroundColor: "#d4a84b10",
            }}
            onMouseEnter={(e) => {
              if (!submitting) e.currentTarget.style.backgroundColor = "#d4a84b20";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.backgroundColor = "#d4a84b10";
            }}
          >
            {submitting ? (
              <IconLoader2 size={12} stroke={1.5} className="animate-spin" />
            ) : (
              <IconSend size={12} stroke={1.5} />
            )}
            {submitting ? "Reporting..." : `Report to ${targetLabel}`}
          </button>
        </div>
      </div>
    </div>
  );
}

function TargetButton({
  label,
  active,
  onClick,
  color,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
  color: string;
}) {
  return (
    <button
      onClick={onClick}
      className="flex-1 rounded-md border px-3 py-2 text-[11px] font-medium transition-colors text-center"
      style={{
        borderColor: active ? color + "40" : "#2d324060",
        backgroundColor: active ? color + "15" : "transparent",
        color: active ? color : "#6f7f9a",
      }}
    >
      {label}
    </button>
  );
}

function mapFindingSeverity(
  severity: string,
): "low" | "medium" | "high" | "critical" {
  switch (severity) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
    case "info":
    default:
      return "low";
  }
}
