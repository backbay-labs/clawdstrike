import { NoiseGrain } from "./NoiseGrain";

type StampVariant = "allowed" | "blocked" | "warn";

const VARIANT_STYLES: Record<StampVariant, { bg: string; border: string; color: string }> = {
  allowed: {
    bg: "rgba(45,170,106,0.10)",
    border: "rgba(45,170,106,0.35)",
    color: "var(--stamp-allowed)",
  },
  blocked: {
    bg: "rgba(194,59,59,0.10)",
    border: "rgba(194,59,59,0.35)",
    color: "var(--stamp-blocked)",
  },
  warn: {
    bg: "rgba(210,163,75,0.10)",
    border: "rgba(210,163,75,0.35)",
    color: "var(--stamp-warn)",
  },
};

export function Stamp({
  variant,
  children,
}: {
  variant: StampVariant;
  children: React.ReactNode;
}) {
  const s = VARIANT_STYLES[variant];

  return (
    <span
      className="font-mono inline-block overflow-hidden"
      style={{
        position: "relative",
        borderRadius: "var(--radius-stamp)",
        border: `1px solid ${s.border}`,
        background: s.bg,
        color: s.color,
        fontSize: "0.65rem",
        fontWeight: 600,
        textTransform: "uppercase",
        letterSpacing: "0.08em",
        padding: "2px 8px",
        animation: "stamp-press 0.3s ease-out",
      }}
    >
      <NoiseGrain opacity={0.06} />
      <span style={{ position: "relative", zIndex: 1 }}>{children}</span>
    </span>
  );
}
