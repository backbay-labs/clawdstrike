import { useMemo } from "react";
import { computeGuardFrequency } from "../../utils/vizHelpers";
import type { SSEEvent } from "../../hooks/useSSE";

const GUARDS = [
  "ForbiddenPathGuard",
  "EgressAllowlistGuard",
  "SecretLeakGuard",
  "PatchIntegrityGuard",
  "McpToolGuard",
  "PromptInjectionGuard",
  "JailbreakGuard",
];

function shortName(guard: string): string {
  return guard.replace(/Guard$/, "");
}

export function GuardHeatmap({ events }: { events: SSEEvent[] }) {
  const freq = useMemo(() => computeGuardFrequency(events), [events]);
  const maxFreq = Math.max(...GUARDS.map((g) => freq[g] || 0), 1);

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(90px, 1fr))", gap: 4 }}>
      {GUARDS.map((guard) => {
        const count = freq[guard] || 0;
        const opacity = count > 0 ? 0.05 + (count / maxFreq) * 0.55 : 0.03;
        return (
          <div
            key={guard}
            style={{
              background: `rgba(47,167,160,${opacity})`,
              borderRadius: 6,
              padding: 8,
              minHeight: 48,
              display: "flex",
              flexDirection: "column",
              justifyContent: "center",
              alignItems: "center",
              gap: 2,
            }}
          >
            <span
              className="font-mono"
              style={{
                fontSize: 9,
                textTransform: "uppercase",
                letterSpacing: "0.06em",
                color: "var(--teal)",
                textAlign: "center",
                lineHeight: 1.2,
              }}
            >
              {shortName(guard)}
            </span>
            <span
              className="font-mono"
              style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}
            >
              {count}
            </span>
          </div>
        );
      })}
    </div>
  );
}
