import { NoiseGrain, Stamp, Plate } from "../ui";
import type { ReportConfig } from "../../utils/reportGenerator";

export function ReportTemplate({ config }: { config: ReportConfig }) {
  const { framework, timeRange, stats } = config;
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span className="font-display" style={{ fontSize: 18, color: "var(--text)" }}>Compliance Report</span>
        <Stamp variant="allowed">{framework}</Stamp>
        <span className="font-mono" style={{ fontSize: 11, color: "var(--muted)" }}>{timeRange}</span>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 8 }}>
        <Plate className="p-3"><div className="font-mono relative z-10" style={{ fontSize: 9, textTransform: "uppercase", color: "var(--muted)" }}>Total</div><div className="font-display relative z-10" style={{ fontSize: 20, fontWeight: 700, color: "var(--text)" }}>{stats.total}</div></Plate>
        <Plate className="p-3"><div className="font-mono relative z-10" style={{ fontSize: 9, textTransform: "uppercase", color: "var(--muted)" }}>Blocked %</div><div className="font-display relative z-10" style={{ fontSize: 20, fontWeight: 700, color: "var(--crimson)" }}>{stats.blockedPct.toFixed(1)}%</div></Plate>
        <Plate className="p-3"><div className="font-mono relative z-10" style={{ fontSize: 9, textTransform: "uppercase", color: "var(--muted)" }}>Guards</div><div className="font-display relative z-10" style={{ fontSize: 20, fontWeight: 700, color: "var(--text)" }}>{stats.activeGuards.length}</div></Plate>
        <Plate className="p-3"><div className="font-mono relative z-10" style={{ fontSize: 9, textTransform: "uppercase", color: "var(--muted)" }}>Policy</div><div className="font-mono relative z-10" style={{ fontSize: 12, color: "var(--text)", marginTop: 4 }}>{stats.policyVersion}</div></Plate>
      </div>
      {stats.topViolations.length > 0 && (
        <div className="glass-panel" style={{ overflow: "hidden" }}>
          <NoiseGrain />
          <table className="relative w-full text-left text-sm" style={{ borderCollapse: "separate" }}>
            <thead><tr>{["Guard", "Violations"].map((h) => <th key={h} className="font-mono px-4 py-2 text-[10px] uppercase" style={{ letterSpacing: "0.1em", color: "rgba(154,167,181,0.6)", fontWeight: 500 }}>{h}</th>)}</tr></thead>
            <tbody>{stats.topViolations.map((v) => (
              <tr key={v.guard} className="hover-row"><td className="font-mono px-4 py-2 text-sm" style={{ color: "var(--text)" }}>{v.guard}</td><td className="font-mono px-4 py-2 text-sm" style={{ color: "var(--crimson)" }}>{v.count}</td></tr>
            ))}</tbody>
          </table>
        </div>
      )}
    </div>
  );
}
