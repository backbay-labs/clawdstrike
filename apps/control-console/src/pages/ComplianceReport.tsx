import { useCallback, useState } from "react";
import { type AuditEvent, fetchAuditEvents, fetchPolicy } from "../api/client";
import { ReportTemplate } from "../components/advanced/ReportTemplate";
import { GlassButton } from "../components/ui";
import {
  downloadReportHTML,
  generateReportHTML,
  printReport,
  type ReportConfig,
} from "../utils/reportGenerator";

export function ComplianceReport(_props: { windowId?: string }) {
  const [timeRange, setTimeRange] = useState<"7d" | "30d" | "90d">("7d");
  const [framework, setFramework] = useState<"SOC2" | "HIPAA" | "Custom">("SOC2");
  const [config, setConfig] = useState<ReportConfig | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generate = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [auditData, policyData] = await Promise.all([
        fetchAuditEvents({ limit: 1000 }),
        fetchPolicy(),
      ]);
      const events = auditData.events;
      const blocked = events.filter((e) => e.decision === "blocked");
      const guardCounts = new Map<string, number>();
      for (const e of blocked) {
        if (e.guard) guardCounts.set(e.guard, (guardCounts.get(e.guard) || 0) + 1);
      }
      const topViolations = [...guardCounts.entries()]
        .sort((a, b) => b[1] - a[1])
        .map(([guard, count]) => ({ guard, count }));
      const activeGuards = [...new Set(events.map((e) => e.guard).filter(Boolean) as string[])];
      const cfg: ReportConfig = {
        timeRange,
        framework,
        events,
        stats: {
          total: events.length,
          blocked: blocked.length,
          blockedPct: events.length ? (blocked.length / events.length) * 100 : 0,
          activeGuards,
          policyVersion: policyData.version ?? "unknown",
          topViolations,
        },
      };
      setConfig(cfg);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate");
    } finally {
      setLoading(false);
    }
  }, [timeRange, framework]);

  return (
    <div
      className="space-y-5"
      style={{ padding: 20, color: "var(--text)", overflow: "auto", height: "100%" }}
    >
      <div style={{ display: "flex", gap: 8, alignItems: "end", flexWrap: "wrap" }}>
        <label className="flex flex-col gap-1">
          <span
            className="font-mono"
            style={{
              fontSize: 10,
              textTransform: "uppercase",
              letterSpacing: "0.1em",
              color: "rgba(214,177,90,0.55)",
            }}
          >
            Time Range
          </span>
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value as "7d" | "30d" | "90d")}
            className="glass-input font-mono rounded px-2 py-1.5 text-sm outline-none"
            style={{ color: "var(--text)" }}
          >
            <option value="7d" style={{ background: "#0b0d10" }}>
              7 Days
            </option>
            <option value="30d" style={{ background: "#0b0d10" }}>
              30 Days
            </option>
            <option value="90d" style={{ background: "#0b0d10" }}>
              90 Days
            </option>
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span
            className="font-mono"
            style={{
              fontSize: 10,
              textTransform: "uppercase",
              letterSpacing: "0.1em",
              color: "rgba(214,177,90,0.55)",
            }}
          >
            Framework
          </span>
          <select
            value={framework}
            onChange={(e) => setFramework(e.target.value as "SOC2" | "HIPAA" | "Custom")}
            className="glass-input font-mono rounded px-2 py-1.5 text-sm outline-none"
            style={{ color: "var(--text)" }}
          >
            <option value="SOC2" style={{ background: "#0b0d10" }}>
              SOC2
            </option>
            <option value="HIPAA" style={{ background: "#0b0d10" }}>
              HIPAA
            </option>
            <option value="Custom" style={{ background: "#0b0d10" }}>
              Custom
            </option>
          </select>
        </label>
        <GlassButton variant="primary" onClick={generate} disabled={loading}>
          {loading ? "Generating..." : "Generate"}
        </GlassButton>
      </div>
      {error && (
        <p className="font-mono" style={{ fontSize: 12, color: "var(--crimson)" }}>
          {error}
        </p>
      )}
      {config && (
        <>
          <ReportTemplate config={config} />
          <div style={{ display: "flex", gap: 8 }}>
            <GlassButton
              onClick={() => {
                const html = generateReportHTML(config);
                downloadReportHTML(html, `clawdstrike-${config.framework}-${config.timeRange}`);
              }}
            >
              Download HTML
            </GlassButton>
            <GlassButton
              onClick={() => {
                const html = generateReportHTML(config);
                printReport(html);
              }}
            >
              Print PDF
            </GlassButton>
          </div>
        </>
      )}
    </div>
  );
}
