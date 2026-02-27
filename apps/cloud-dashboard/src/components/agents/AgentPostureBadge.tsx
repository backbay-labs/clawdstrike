const POSTURE_STYLES: Record<string, { bg: string; border: string; color: string; label: string }> = {
  nominal: { bg: "rgba(47,167,160,0.12)", border: "rgba(47,167,160,0.35)", color: "var(--teal)", label: "NOMINAL" },
  elevated: { bg: "rgba(210,163,75,0.12)", border: "rgba(210,163,75,0.35)", color: "var(--stamp-warn)", label: "ELEVATED" },
  critical: { bg: "rgba(194,59,59,0.12)", border: "rgba(194,59,59,0.35)", color: "var(--stamp-blocked)", label: "CRITICAL" },
};

export function AgentPostureBadge({ posture }: { posture: "nominal" | "elevated" | "critical" }) {
  const s = POSTURE_STYLES[posture];
  return (
    <span
      className="font-mono"
      style={{
        display: "inline-block",
        background: s.bg,
        border: `1px solid ${s.border}`,
        borderRadius: 4,
        color: s.color,
        fontSize: 9,
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.08em",
        padding: "2px 8px",
      }}
    >
      {s.label}
    </span>
  );
}
