import { useMemo } from "react";
import type { SSEEvent } from "../../hooks/useSSE";
import { bucketByTime } from "../../utils/vizHelpers";

export function ViolationSparkline({ events }: { events: SSEEvent[] }) {
  const violations = useMemo(
    () => events.filter((e) => e.event_type === "violation" || e.allowed === false),
    [events],
  );
  const buckets = useMemo(() => bucketByTime(violations, 5, 12), [violations]);
  const max = Math.max(...buckets, 1);

  return (
    <svg viewBox="0 0 240 40" width="100%" height={40} preserveAspectRatio="none">
      {/* Axis line */}
      <line
        x1={0}
        y1={39}
        x2={240}
        y2={39}
        stroke="var(--gold)"
        strokeOpacity={0.3}
        strokeWidth={1}
      />
      {buckets.map((count, i) => {
        const h = (count / max) * 36;
        return (
          <rect
            key={i}
            x={i * 20 + 2}
            y={39 - h}
            width={16}
            height={h}
            rx={2}
            fill="var(--crimson)"
            fillOpacity={count > 0 ? 0.3 + (count / max) * 0.7 : 0.05}
          />
        );
      })}
    </svg>
  );
}
