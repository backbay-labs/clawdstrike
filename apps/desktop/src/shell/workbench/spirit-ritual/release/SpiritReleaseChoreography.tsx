import { useEffect } from "react";
import type { SpiritManifestationModel } from "../canvas";
import type { HuntSpiritState } from "../../spirit";

const RELEASE_PHASES = {
  primed: {
    eyebrow: "Release ready",
    verb: "The release seam is drawing tight around the crossing",
  },
  releasing: {
    eyebrow: "Releasing",
    verb: "The spirit is crossing into the live hunt field",
  },
  released: {
    eyebrow: "Afterglow",
    verb: "The crossing has struck dock, wake, and station",
  },
} as const;

export type SpiritReleasePhase = keyof typeof RELEASE_PHASES;
export type SpiritReleaseChoreographyVariant = "full" | "room";
export const SPIRIT_SURFACE_RECEIVE_MS = 1600;
export const SPIRIT_SURFACE_AFTERMATH_MS = 2200;
export type SpiritSurfaceReceiveState = "idle" | "receiving" | "aftermath";

export function getSpiritReleaseCueTimestamp(
  spirit: Pick<HuntSpiritState, "boundAt" | "reboundAt"> | null | undefined,
): number | null {
  if (!spirit) return null;
  return Math.max(spirit.boundAt, spirit.reboundAt ?? 0);
}

export function resolveSpiritSurfaceReceiveState(elapsedMs: number): SpiritSurfaceReceiveState {
  if (elapsedMs < 0) return "idle";
  if (elapsedMs < SPIRIT_SURFACE_RECEIVE_MS) return "receiving";
  if (elapsedMs < SPIRIT_SURFACE_RECEIVE_MS + SPIRIT_SURFACE_AFTERMATH_MS) return "aftermath";
  return "idle";
}

function getSurfaceCopy(
  phase: SpiritReleasePhase,
  stationLabel: string,
): Array<{ label: string; detail: string }> {
  switch (phase) {
    case "primed":
      return [
        { label: "Dock", detail: "waiting at the rail" },
        { label: "Wake", detail: "listening for the crossing" },
        { label: stationLabel, detail: "holding the receive line" },
      ];
    case "released":
      return [
        { label: "Dock", detail: "still ringing with the new contour" },
        { label: "Wake", detail: "reading the contour left in the field" },
        { label: stationLabel, detail: "holding the struck line" },
      ];
    case "releasing":
    default:
      return [
        { label: "Dock", detail: "catching the first surge" },
        { label: "Wake", detail: "turning toward the new read" },
        { label: stationLabel, detail: "taking the live receive" },
      ];
  }
}

export function SpiritReleaseChoreography({
  model,
  phase,
  reducedMotion = false,
  onRest,
  restMs,
  className,
  variant = "full",
}: {
  model: SpiritManifestationModel;
  phase: SpiritReleasePhase;
  reducedMotion?: boolean;
  onRest?: () => void;
  restMs?: number;
  className?: string;
  variant?: SpiritReleaseChoreographyVariant;
}) {
  useEffect(() => {
    if (phase !== "releasing" || !onRest) return undefined;
    const timer = window.setTimeout(
      onRest,
      restMs ?? (reducedMotion ? 0 : model.release.durationMs),
    );
    return () => window.clearTimeout(timer);
  }, [model.release.durationMs, onRest, phase, reducedMotion, restMs]);

  const phaseCopy = RELEASE_PHASES[phase];
  const progress = phase === "released" ? 1 : phase === "releasing" ? 0.82 : 0.24;
  const origin = { x: 108, y: 34 };
  const surfaces = getSurfaceCopy(phase, model.stationLabel);
  const targets = [
    { x: 48, y: 130, ...surfaces[0] },
    { x: 156, y: 140, ...surfaces[1] },
    { x: 274, y: 102, ...surfaces[2] },
  ];

  if (variant === "room") {
    return (
      <div
        aria-hidden="true"
        className={className}
        data-testid="spirit-release-choreography"
        style={{
          position: "absolute",
          inset: 0,
          pointerEvents: "none",
          display: "grid",
          alignItems: "end",
          justifyItems: "center",
          padding: "0 20px 84px",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
            maxWidth: 540,
            borderRadius: 9999,
            border: `1px solid ${model.accentColor}22`,
            background: "linear-gradient(180deg, rgba(8,12,20,0.2), rgba(8,12,20,0.52))",
            boxShadow: `0 18px 40px rgba(0,0,0,0.2), inset 0 1px 0 ${model.accentColor}14`,
            padding: "10px 14px",
            backdropFilter: "blur(10px)",
          }}
        >
          <div
            className="font-mono text-[10px] uppercase tracking-[0.14em]"
            style={{ color: model.accentColor, opacity: 0.84, whiteSpace: "nowrap" }}
          >
            {phaseCopy.eyebrow}
          </div>
          <div
            style={{
              width: 1,
              alignSelf: "stretch",
              background: `${model.accentColor}22`,
            }}
          />
          <div className="min-w-0">
            <div className="truncate text-[12px]" style={{ color: "rgba(236,233,225,0.88)" }}>
              {phase === "released"
                ? `${model.label} is still marking ${model.stationLabel}.`
                : model.release.title}
            </div>
          </div>
          <div
            className="rounded-full border px-2.5 py-1 font-mono text-[9px] uppercase tracking-[0.12em]"
            style={{
              borderColor: `${model.accentColor}2c`,
              background: `${model.accentColor}10`,
              color: "rgba(236,233,225,0.74)",
              whiteSpace: "nowrap",
            }}
          >
            {model.stationLabel}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div
      aria-hidden="true"
      className={className}
      data-testid="spirit-release-choreography"
      style={{
        position: "absolute",
        inset: 0,
        pointerEvents: "none",
        display: "grid",
        alignItems: "end",
        padding: 20,
      }}
    >
      <div
        style={{
          borderRadius: 20,
          border: `1px solid ${model.accentColor}26`,
          background: "linear-gradient(180deg, rgba(8,12,20,0.18), rgba(8,12,20,0.68))",
          boxShadow: `0 20px 36px rgba(0,0,0,0.24), inset 0 1px 0 ${model.accentColor}16`,
          padding: 16,
          backdropFilter: "blur(12px)",
        }}
      >
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
          <div>
            <div
              className="font-mono text-[10px] uppercase tracking-[0.14em]"
              style={{ color: model.accentColor, opacity: 0.84 }}
            >
              {phaseCopy.eyebrow}
            </div>
            <div className="mt-1 text-[13px]" style={{ color: "rgba(236,233,225,0.88)" }}>
              {model.release.title}
            </div>
          </div>
          <div
            className="rounded-full border px-3 py-1 font-mono text-[10px] uppercase tracking-[0.1em]"
            style={{
              borderColor: `${model.accentColor}36`,
              background: `${model.accentColor}12`,
              color: "rgba(236,233,225,0.8)",
            }}
          >
            {model.release.actionLabel}
          </div>
        </div>

        <div className="mt-3 text-[12px]" style={{ color: "rgba(182,183,193,0.78)", lineHeight: 1.5 }}>
          {phaseCopy.verb}. {model.release.subtitle}
        </div>
        <div
          className="mt-2 font-mono text-[10px] uppercase tracking-[0.12em]"
          style={{ color: "rgba(236,233,225,0.56)" }}
        >
          {phase === "released"
            ? "Dock, wake, and station keep the contour for one more beat."
            : "Release will leave a short mark across receiving surfaces."}
        </div>

        <div className="mt-4" style={{ display: "grid", gap: 10 }}>
          <div
            data-testid="spirit-release-transit"
            style={{
              position: "relative",
              minHeight: 154,
              borderRadius: 18,
              border: `1px solid ${model.accentColor}1a`,
              background:
                "radial-gradient(circle at 32% 22%, rgba(236,233,225,0.06), rgba(7,10,16,0.14) 42%, rgba(7,10,16,0.54))",
              overflow: "hidden",
            }}
          >
            <svg
              viewBox="0 0 320 160"
              width="100%"
              height="100%"
              style={{ position: "absolute", inset: 0 }}
            >
              <defs>
                <linearGradient id={`spirit-release-gradient-${model.label}`} x1="0%" x2="100%" y1="0%" y2="0%">
                  <stop offset="0%" stopColor={`${model.accentColor}cc`} />
                  <stop offset="100%" stopColor={`${model.accentColor}22`} />
                </linearGradient>
              </defs>

              <circle
                cx={origin.x}
                cy={origin.y}
                r={phase === "released" ? 22 : phase === "releasing" ? 18 : 12}
                fill={`${model.accentColor}${phase === "primed" ? "10" : "16"}`}
                opacity={phase === "released" ? 0.42 : 0.26}
              />
              <circle
                data-testid="spirit-release-origin-afterimage"
                cx={origin.x}
                cy={origin.y}
                r={phase === "released" ? 28 : phase === "releasing" ? 22 : 16}
                fill="none"
                stroke={`${model.accentColor}${phase === "primed" ? "32" : "68"}`}
                strokeWidth="1.2"
                opacity={phase === "primed" ? 0.38 : 0.82}
              />

              {targets.map((target) => {
                const beadX = origin.x + (target.x - origin.x) * progress;
                const beadY = origin.y + (target.y - origin.y) * progress;
                return (
                  <g key={target.label}>
                    <line
                      x1={origin.x}
                      y1={origin.y}
                      x2={target.x}
                      y2={target.y}
                      pathLength={100}
                      stroke="rgba(182,183,193,0.12)"
                      strokeWidth="1.2"
                    />
                    <line
                      x1={origin.x}
                      y1={origin.y}
                      x2={target.x}
                      y2={target.y}
                      pathLength={100}
                      stroke={`url(#spirit-release-gradient-${model.label})`}
                      strokeWidth={phase === "releasing" ? 2.4 : 1.8}
                      strokeLinecap="round"
                      strokeDasharray={`${Math.round(progress * 100)} 100`}
                      opacity={phase === "primed" ? 0.5 : 0.94}
                    />
                    {!reducedMotion && phase !== "primed" ? (
                      <circle
                        cx={beadX}
                        cy={beadY}
                        r={phase === "released" ? 0 : 2.8}
                        fill={model.accentColor}
                        opacity={phase === "released" ? 0 : 0.92}
                      />
                    ) : null}
                    <circle
                      cx={target.x}
                      cy={target.y}
                      r={phase === "primed" ? 4 : 5.6}
                      fill={`${model.accentColor}${phase === "primed" ? "52" : "aa"}`}
                    />
                    <circle
                      cx={target.x}
                      cy={target.y}
                      r={phase === "primed" ? 7 : phase === "releasing" ? 12 : 14}
                      fill="none"
                      stroke={`${model.accentColor}${phase === "primed" ? "20" : "44"}`}
                      strokeWidth="1"
                      opacity={phase === "primed" ? 0.34 : 0.82}
                    />
                  </g>
                );
              })}
            </svg>

            <div
              className="rounded-full border px-2 py-1 font-mono text-[10px] uppercase tracking-[0.12em]"
              style={{
                position: "absolute",
                left: origin.x - 44,
                top: origin.y + 14,
                borderColor: `${model.accentColor}22`,
                background: "rgba(7,10,16,0.76)",
                color: "rgba(236,233,225,0.78)",
              }}
            >
              Release seam
            </div>

            {targets.map((target) => (
              <div
                key={target.label}
                className="rounded-xl border px-3 py-2"
                style={{
                  position: "absolute",
                  left: Math.max(10, target.x - 42),
                  top: Math.min(112, target.y + 12),
                  width: 112,
                  borderColor:
                    phase === "primed"
                      ? "rgba(182,183,193,0.14)"
                      : `${model.accentColor}${target.label === model.stationLabel ? "34" : "22"}`,
                  background:
                    phase === "primed"
                      ? "rgba(7,10,16,0.42)"
                      : `${model.accentColor}${target.label === model.stationLabel ? "14" : "0d"}`,
                  boxShadow:
                    phase === "primed"
                      ? undefined
                      : `0 0 18px ${model.accentColor}${target.label === model.stationLabel ? "18" : "12"}`,
                }}
              >
                <div className="font-mono text-[10px] uppercase tracking-[0.1em]" style={{ color: "rgba(236,233,225,0.72)" }}>
                  {target.label}
                </div>
                <div className="mt-1 text-[11px]" style={{ color: "rgba(182,183,193,0.74)", lineHeight: 1.4 }}>
                  {target.detail}
                </div>
              </div>
            ))}
          </div>

          <div
            style={{
              position: "relative",
              height: 2,
              borderRadius: 9999,
              background: "rgba(182,183,193,0.18)",
              overflow: "hidden",
            }}
          >
            <div
              style={{
                position: "absolute",
                inset: 0,
                width: `${Math.round(progress * 100)}%`,
                background: `linear-gradient(90deg, ${model.accentColor}aa, ${model.accentColor})`,
                boxShadow: `0 0 12px ${model.accentColor}88`,
                transform: reducedMotion ? undefined : `scaleX(${model.release.pulseScale})`,
                transformOrigin: "left center",
              }}
            />
          </div>
        </div>

        <div
          data-testid="spirit-release-afterglow-note"
          className="mt-3 rounded-xl border px-3 py-2 font-mono text-[10px] uppercase tracking-[0.1em]"
          style={{
            borderColor: `${model.accentColor}1e`,
            background: `${model.accentColor}0c`,
            color: "rgba(236,233,225,0.62)",
          }}
        >
          {phase === "released"
            ? `${model.label} is still marking the rail, wake, and ${model.stationLabel}.`
            : `${model.label} is about to strike the rail, wake, and ${model.stationLabel}.`}
        </div>
      </div>
    </div>
  );
}
