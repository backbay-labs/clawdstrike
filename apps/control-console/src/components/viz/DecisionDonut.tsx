import { useMemo } from "react";
import type { SSEEvent } from "../../hooks/useSSE";
import { computeDecisionRatio } from "../../utils/vizHelpers";

const R = 60;
const CX = 80;
const CY = 80;
const STROKE_WIDTH = 20;
const CIRCUMFERENCE = 2 * Math.PI * R;

export function DecisionDonut({ events }: { events: SSEEvent[] }) {
  const ratio = useMemo(() => computeDecisionRatio(events), [events]);
  const total = ratio.allowed + ratio.blocked + ratio.warn;

  const segments = useMemo(() => {
    if (total === 0) return [];
    const items = [
      { key: "allowed", count: ratio.allowed, color: "var(--stamp-allowed)" },
      { key: "blocked", count: ratio.blocked, color: "var(--stamp-blocked)" },
      { key: "warn", count: ratio.warn, color: "var(--stamp-warn)" },
    ];
    let offset = 0;
    return items.map((s) => {
      const pct = s.count / total;
      const dash = pct * CIRCUMFERENCE;
      const seg = { ...s, dasharray: `${dash} ${CIRCUMFERENCE}`, dashoffset: -offset };
      offset += dash;
      return seg;
    });
  }, [ratio, total]);

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
      <svg viewBox="0 0 160 160" width={140} height={140}>
        {total === 0 ? (
          <circle
            cx={CX}
            cy={CY}
            r={R}
            fill="none"
            stroke="var(--slate)"
            strokeWidth={STROKE_WIDTH}
          />
        ) : (
          segments.map((s) => (
            <circle
              key={s.key}
              cx={CX}
              cy={CY}
              r={R}
              fill="none"
              stroke={s.color}
              strokeWidth={STROKE_WIDTH}
              strokeDasharray={s.dasharray}
              strokeDashoffset={s.dashoffset}
              strokeLinecap="butt"
              transform={`rotate(-90 ${CX} ${CY})`}
            />
          ))
        )}
        <text
          x={CX}
          y={CY}
          textAnchor="middle"
          dominantBaseline="central"
          className="font-display"
          style={{ fontSize: 22, fontWeight: 700 }}
          fill="var(--text)"
        >
          {total}
        </text>
      </svg>
      <div style={{ display: "flex", gap: 12 }}>
        {[
          { label: "Allowed", count: ratio.allowed, color: "var(--stamp-allowed)" },
          { label: "Blocked", count: ratio.blocked, color: "var(--stamp-blocked)" },
          { label: "Warn", count: ratio.warn, color: "var(--stamp-warn)" },
        ].map((item) => (
          <div key={item.label} style={{ display: "flex", alignItems: "center", gap: 4 }}>
            <span
              style={{
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: item.color,
                display: "inline-block",
              }}
            />
            <span className="font-mono" style={{ fontSize: 10, color: "var(--muted)" }}>
              {item.label} {item.count}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
