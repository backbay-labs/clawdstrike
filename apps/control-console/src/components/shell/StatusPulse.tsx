import type { CSSProperties } from "react";

export type StatusPulseTone = "gold" | "teal" | "crimson";
export type StatusPulseLayout = "card" | "chip";

export interface StatusPulseProps {
  label: string;
  value: string;
  tone?: StatusPulseTone;
  layout?: StatusPulseLayout;
  pulse?: boolean;
  mono?: boolean;
}

const TONE_COLOR: Record<StatusPulseTone, string> = {
  gold: "var(--gold)",
  teal: "var(--teal)",
  crimson: "var(--crimson)",
};

const SHARED_CONTAINER: CSSProperties = {
  borderRadius: 8,
  border: "1px solid rgba(27,34,48,0.85)",
  background: "rgba(0,0,0,0.4)",
};

export function StatusPulse({
  label,
  value,
  tone = "gold",
  layout = "card",
  pulse = false,
  mono = false,
}: StatusPulseProps) {
  const color = TONE_COLOR[tone];

  if (layout === "chip") {
    return (
      <div
        style={{
          ...SHARED_CONTAINER,
          display: "flex",
          flexDirection: "row",
          alignItems: "center",
          gap: 8,
          padding: "5px 10px",
        }}
      >
        {pulse && (
          <span
            data-testid="pulse-dot"
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: color,
              boxShadow: `0 0 6px ${color}`,
              animation: "pulse 2s infinite",
              flexShrink: 0,
            }}
          />
        )}
        <span
          className="font-mono"
          style={{
            fontSize: 9,
            letterSpacing: "0.16em",
            textTransform: "uppercase",
            color: "rgba(154,167,181,0.55)",
          }}
        >
          {label}
        </span>
        <span
          className="font-mono"
          style={{
            fontSize: 11,
            letterSpacing: "0.06em",
            color,
            fontFeatureSettings: mono ? '"tnum"' : undefined,
          }}
        >
          {value}
        </span>
      </div>
    );
  }

  // card layout (default) — vertical, from SystemPulse design
  return (
    <div
      style={{
        ...SHARED_CONTAINER,
        display: "flex",
        flexDirection: "column",
        gap: 3,
        padding: "8px 10px",
      }}
    >
      <span
        className="font-mono"
        style={{
          fontSize: 8.5,
          letterSpacing: "0.16em",
          textTransform: "uppercase",
          color: "rgba(154,167,181,0.55)",
        }}
      >
        {label}
      </span>
      <span
        className="font-mono"
        style={{
          fontSize: 15,
          fontWeight: 500,
          color,
          letterSpacing: "0.04em",
          lineHeight: 1,
          fontFeatureSettings: mono ? '"tnum"' : undefined,
        }}
      >
        {value}
      </span>
    </div>
  );
}
