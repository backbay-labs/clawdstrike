import type { CSSProperties } from "react";
import type { Hunt } from "../../huntTypes";
import {
  deriveHuntSpiritRuntimeState,
  getHuntSpiritMeta,
  isBoundHuntSpirit,
} from "..";

const CONTOUR_PATHS: Record<string, string> = {
  "reticle-vector": "M8 3v2M8 11v2M3 8h2M11 8h2M8 5.25a2.75 2.75 0 110 5.5 2.75 2.75 0 010-5.5z",
  "aperture-reveal": "M8 3.2c2.6 0 4.6 2.1 4.6 4.8S10.6 12.8 8 12.8 3.4 10.7 3.4 8 5.4 3.2 8 3.2zm0 1.9c-1.6 0-2.8 1.3-2.8 2.9S6.4 10.9 8 10.9s2.8-1.3 2.8-2.9S9.6 5.1 8 5.1z",
  "chamber-bracket": "M4.1 4.2h2.2M4.1 4.2v7.6M4.1 11.8h2.2M11.9 4.2H9.7M11.9 4.2v7.6M11.9 11.8H9.7M6.3 6.1h3.4v3.8H6.3z",
  "thread-arc": "M3.2 9.8c1.4-3.8 4.5-5.9 9.6-6.3M4.1 4.5c2.2 0 3.6 1 4.3 3M7.8 7.5c1.1 0 2 .9 2 2s-.9 2-2 2-2-.9-2-2 .9-2 2-2z",
  "proof-stack": "M4.1 5.1h7.8M4.1 8h7.8M4.1 10.9h5.6M2.9 4h1.2M2.9 6.9h1.2M2.9 9.8h1.2",
};

const MOOD_LABELS: Record<string, string> = {
  dormant: "Quiet field",
  attuned: "Attuned",
  focused: "Focused",
  pressured: "Pressured",
  witnessing: "Witnessing",
  transit: "Transit",
};

const STANCE_LABELS: Record<string, string> = {
  idle: "Holding position",
  attune: "Reading the field",
  focus: "Leaning forward",
  witness: "Building proof",
  absorb: "Pulling material inward",
  transit: "Repositioning",
};

function buildContourPath(contour: string | null | undefined): string {
  return CONTOUR_PATHS[contour ?? ""] ?? CONTOUR_PATHS["reticle-vector"];
}

export function getSpiritBiasLine(hunt: Hunt): string {
  const spirit = hunt.spirit;
  if (!isBoundHuntSpirit(spirit)) {
    return "No spirit bound yet";
  }

  const runtime = deriveHuntSpiritRuntimeState(spirit, { isActive: true });
  const emphasis = runtime.emphasis
    .filter(Boolean)
    .slice(0, 3)
    .map((entry) => entry.replace(/-/g, " "));

  if (emphasis.length > 0) {
    return `Biasing ${emphasis.join(", ")}`;
  }

  return spirit.bindReason ?? "Spirit bias is standing by";
}

export function getSpiritDetailLine(hunt: Hunt): string {
  const spirit = hunt.spirit;
  if (!isBoundHuntSpirit(spirit)) {
    return "Add spirit when the hunt posture is clear";
  }

  return spirit.thesis ?? spirit.bindReason ?? "Bound spirit is shaping local surfaces";
}

export function getSpiritActionLabel(hunt: Hunt): string {
  if (!isBoundHuntSpirit(hunt.spirit)) {
    return "Add Spirit";
  }
  return hunt.spirit.isPinned ? "Spirit Pinned" : "Pin Spirit";
}

export function getSpiritSecondaryActionLabel(hunt: Hunt): string {
  return isBoundHuntSpirit(hunt.spirit) ? "Rebind Spirit" : "Bind Sheet";
}

export function SpiritGlyph({
  hunt,
  size = 16,
  glow = false,
}: {
  hunt: Hunt;
  size?: number;
  glow?: boolean;
}) {
  const spirit = hunt.spirit;
  const meta = getHuntSpiritMeta(spirit?.kind);
  const accentColor = meta?.accentColor ?? hunt.color;
  const path = isBoundHuntSpirit(spirit)
    ? buildContourPath(meta?.contour)
    : "M4 8h8M8 4v8";
  const runtime = spirit ? deriveHuntSpiritRuntimeState(spirit, { isActive: true }) : null;

  return (
    <span
      className="inline-flex items-center justify-center rounded-[7px]"
      style={{
        width: size,
        height: size,
        background: isBoundHuntSpirit(spirit) ? `${accentColor}14` : `${hunt.color}12`,
        boxShadow: glow && isBoundHuntSpirit(spirit)
          ? `0 0 ${Math.max(6, size * 0.45)}px ${accentColor}26`
          : undefined,
      }}
      data-testid="spirit-glyph"
    >
      <svg
        viewBox="0 0 16 16"
        width={Math.round(size * 0.8)}
        height={Math.round(size * 0.8)}
        fill="none"
        stroke={accentColor}
        strokeWidth="1.2"
        strokeLinecap="round"
        strokeLinejoin="round"
        style={{
          opacity: runtime?.shouldRender === false ? 0.7 : 1,
        }}
      >
        <path d={path} />
      </svg>
    </span>
  );
}

export function SpiritInlineSummary({
  hunt,
  showBias = true,
  compact = false,
}: {
  hunt: Hunt;
  showBias?: boolean;
  compact?: boolean;
}) {
  const spirit = hunt.spirit;
  const meta = getHuntSpiritMeta(spirit?.kind);
  const runtime = spirit
    ? deriveHuntSpiritRuntimeState(spirit, { isActive: true })
    : null;
  const accentColor = meta?.accentColor ?? hunt.color;
  const detail = getSpiritDetailLine(hunt);
  const bias = getSpiritBiasLine(hunt);

  return (
    <div className="flex min-w-0 items-center gap-2" data-testid="spirit-inline-summary">
      <SpiritGlyph hunt={hunt} size={compact ? 18 : 20} glow={Boolean(runtime?.fieldStrength && runtime.fieldStrength > 0.45)} />
      <div className="min-w-0">
        <div className="flex min-w-0 items-center gap-1.5">
          <span
            className="truncate font-mono uppercase"
            style={{
              fontSize: compact ? 10 : 11,
              letterSpacing: "0.08em",
              color: isBoundHuntSpirit(spirit) ? accentColor : "rgba(213,173,87,0.58)",
            }}
          >
            {meta?.label ?? "Add Spirit"}
          </span>
          {isBoundHuntSpirit(spirit) && (
            <span
              className="shrink-0 rounded-full border px-1.5 py-[1px] font-mono uppercase"
              style={{
                fontSize: 8,
                letterSpacing: "0.08em",
                borderColor: `${accentColor}33`,
                color: "rgba(232,230,222,0.56)",
              }}
            >
              {spirit.isPinned ? "Pinned" : MOOD_LABELS[spirit.liveMood] ?? spirit.liveMood}
            </span>
          )}
        </div>
        <div
          className="truncate"
          style={{
            fontSize: compact ? 10 : 11,
            color: "rgba(182,183,193,0.62)",
            lineHeight: 1.3,
          }}
        >
          {showBias ? bias : detail}
        </div>
      </div>
    </div>
  );
}

export function SpiritConsoleCard({
  hunt,
  style,
}: {
  hunt: Hunt;
  style?: CSSProperties;
}) {
  const spirit = hunt.spirit;
  const meta = getHuntSpiritMeta(spirit?.kind);
  const runtime = spirit
    ? deriveHuntSpiritRuntimeState(spirit, { isActive: true })
    : null;
  const accentColor = meta?.accentColor ?? hunt.color;

  return (
    <div
      className="rounded-lg border px-2.5 py-2"
      style={{
        borderColor: isBoundHuntSpirit(spirit) ? `${accentColor}33` : "rgba(213,173,87,0.12)",
        background: isBoundHuntSpirit(spirit) ? `${accentColor}12` : "rgba(232,230,222,0.02)",
        ...style,
      }}
      data-testid="spirit-console-card"
    >
      <div className="flex items-start justify-between gap-3">
        <SpiritInlineSummary hunt={hunt} showBias compact />
        {runtime && (
          <span
            className="shrink-0 font-mono uppercase"
            style={{
              fontSize: 9,
              letterSpacing: "0.08em",
              color: "rgba(232,230,222,0.56)",
            }}
          >
            {STANCE_LABELS[runtime.stance] ?? runtime.stance}
          </span>
        )}
      </div>
      <div
        className="mt-2 truncate"
        style={{ fontSize: 10, color: "rgba(236,233,225,0.78)" }}
      >
        {getSpiritDetailLine(hunt)}
      </div>
    </div>
  );
}

export function SpiritActionButton({
  label,
  disabled = false,
}: {
  label: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      disabled={disabled}
      aria-disabled={disabled}
      className="font-mono"
      style={{
        fontSize: 9,
        color: disabled ? "rgba(182,183,193,0.28)" : "rgba(182,183,193,0.46)",
        background: "transparent",
        border: "none",
        cursor: disabled ? "not-allowed" : "pointer",
        padding: "1px 4px",
        borderRadius: 3,
        transition: "color 100ms ease",
      }}
      title={disabled ? "Shared spirit action wiring is still owned by ORCH" : undefined}
      data-testid={`spirit-action-${label.toLowerCase().replace(/\s+/g, "-")}`}
    >
      {label}
    </button>
  );
}
