// Ported from huntronomer spirit-ritual/canvas/SpiritManifestationCanvas.tsx
// Only change: import path adjusted to ./model (same directory).
// No R3F imports — pure CSS/SVG.
import type { CSSProperties, ReactNode } from "react";
import {
  type SpiritManifestationGrammar,
  type SpiritManifestationModel,
  type SpiritManifestationRing,
  type SpiritManifestationStage,
  type SpiritManifestationTether,
} from "./model";

const CANVAS_KEYFRAMES = `
@keyframes spirit-ritual-core-breathe {
  0%, 100% { transform: translate(-50%, -50%) scale(0.985); opacity: 0.82; }
  50% { transform: translate(-50%, -50%) scale(1.025); opacity: 1; }
}

@keyframes spirit-ritual-ring-drift {
  0% { transform: translate(-50%, -50%) rotate(0deg) scale(0.99); }
  50% { transform: translate(-50%, -50%) rotate(4deg) scale(1.015); }
  100% { transform: translate(-50%, -50%) rotate(8deg) scale(0.995); }
}

@keyframes spirit-ritual-beam-pulse {
  0%, 100% { opacity: 0.2; transform: translate(-50%, -50%) scaleY(0.92); }
  50% { opacity: 0.5; transform: translate(-50%, -50%) scaleY(1.08); }
}

@keyframes spirit-ritual-inscription-trace {
  0% { opacity: 0; transform: translateY(4px) scaleX(0.9); }
  50% { opacity: 0.82; transform: translateY(0) scaleX(1); }
  100% { opacity: 0.5; transform: translateY(-2px) scaleX(1.02); }
}

@keyframes spirit-ritual-ghost-hover {
  0%, 100% { transform: translate(-50%, -50%) scale(var(--ghost-scale, 1)); opacity: var(--ghost-opacity, 0.2); }
  50% { transform: translate(-50%, calc(-50% - 10px)) scale(calc(var(--ghost-scale, 1) + 0.03)); opacity: calc(var(--ghost-opacity, 0.2) + 0.08); }
}

@keyframes spirit-ritual-tether-pulse {
  0%, 100% { stroke-dashoffset: 0; opacity: 0.42; }
  50% { stroke-dashoffset: -18; opacity: 0.88; }
}

@keyframes spirit-ritual-stage-radiance {
  0%, 100% { opacity: 0.32; transform: translate(-50%, -50%) scale(0.96); }
  50% { opacity: 0.56; transform: translate(-50%, -50%) scale(1.04); }
}
`;

const DEFAULT_STAGE_GRAMMAR: SpiritManifestationGrammar = {
  vesselShellRadius: "50% 50% 46% 46% / 40% 40% 60% 60%",
  vesselCoreRadius: "50%",
  shellWidthPercent: 28,
  shellHeightPercent: 24,
  coreWidthPercent: 20,
  coreHeightPercent: 18,
  shellTiltDeg: 0,
  contourScale: 1,
  contourStrokeWidth: 1.12,
  contourOpacity: 0.92,
  ringScaleY: 1,
  ringRotationDeg: 0,
  ringOffsetXPercent: 0,
  ringOffsetYPercent: 0,
  ringGlowOpacity: 0.2,
  beamWidthPercent: 42,
  beamHeightPercent: 14,
  beamLeftPercent: 50,
  beamTopPercent: 49,
  beamRotationDeg: 0,
  beamOpacity: 0.18,
  haloWidthPercent: 40,
  haloHeightPercent: 40,
  haloTopPercent: 49,
  haloBlurPx: 12,
  floorGlowWidthPercent: 56,
  floorGlowHeightPercent: 18,
  floorGlowTopPercent: 58,
  floorGlowBlurPx: 22,
  tetherCharacter: "taut",
  ghostCharacter: "reticle",
  exitCharacter: "pursuit",
  ornamentCount: 2,
};

function ringStyle(
  model: SpiritManifestationModel,
  ring: SpiritManifestationRing,
): CSSProperties {
  const scaleY = ring.scaleY ?? 1;
  const rotateDeg = ring.rotateDeg ?? 0;
  const offsetXPercent = ring.offsetXPercent ?? 0;
  const offsetYPercent = ring.offsetYPercent ?? 0;
  const glowOpacity = ring.glowOpacity ?? 0.2;

  return {
    position: "absolute",
    left: `calc(50% + ${offsetXPercent}%)`,
    top: `calc(52% + ${offsetYPercent}%)`,
    width: `${ring.radiusPercent}%`,
    height: `${ring.radiusPercent * scaleY}%`,
    borderRadius: 9999,
    borderWidth: ring.strokeWidth,
    borderStyle: ring.dashPattern ? "dashed" : "solid",
    borderColor: model.accentColor,
    opacity: ring.opacity,
    transform: `translate(-50%, -50%) rotate(${rotateDeg}deg)`,
    boxShadow: `0 0 ${22 + glowOpacity * 32}px ${model.accentColor}24`,
    animation: `spirit-ritual-ring-drift ${ring.driftMs}ms linear infinite`,
  };
}

function anchoredChipStyle(accentColor: string, tintOpacity: string): CSSProperties {
  return {
    borderRadius: 9999,
    border: `1px solid ${accentColor}26`,
    background: `linear-gradient(180deg, ${accentColor}${tintOpacity}, rgba(7, 10, 16, 0.68))`,
    backdropFilter: "blur(12px)",
    boxShadow: `0 12px 24px ${accentColor}12`,
  };
}

function buildTetherPath(
  tether: SpiritManifestationTether,
  stage: SpiritManifestationStage,
): string {
  const grammar = stage.grammar ?? DEFAULT_STAGE_GRAMMAR;
  const curveBias = tether.curveBias ?? 0;
  const midX = (tether.startXPercent + tether.endXPercent) / 2;
  const midY = (tether.startYPercent + tether.endYPercent) / 2;
  switch (grammar.tetherCharacter) {
    case "witness":
      return `M ${tether.startXPercent} ${tether.startYPercent} Q ${midX} ${Math.min(tether.startYPercent, tether.endYPercent) - curveBias} ${tether.endXPercent} ${tether.endYPercent}`;
    case "forge":
      return `M ${tether.startXPercent} ${tether.startYPercent} L ${midX + curveBias} ${tether.startYPercent} L ${tether.endXPercent} ${tether.endYPercent}`;
    case "woven":
      return `M ${tether.startXPercent} ${tether.startYPercent} C ${tether.startXPercent + curveBias} ${tether.startYPercent - curveBias} ${tether.endXPercent - curveBias} ${tether.endYPercent + curveBias * 0.35} ${tether.endXPercent} ${tether.endYPercent}`;
    case "stepped":
      return `M ${tether.startXPercent} ${tether.startYPercent} L ${midX} ${tether.startYPercent} L ${midX} ${tether.endYPercent} L ${tether.endXPercent} ${tether.endYPercent}`;
    case "taut":
    default:
      return `M ${tether.startXPercent} ${tether.startYPercent} Q ${midX} ${midY - curveBias} ${tether.endXPercent} ${tether.endYPercent}`;
  }
}

function renderGhostShell(model: SpiritManifestationModel, stage: SpiritManifestationStage, scale: number) {
  const grammar = stage.grammar ?? DEFAULT_STAGE_GRAMMAR;
  const width = 150 * scale;
  const height = 150 * scale;
  switch (grammar.ghostCharacter) {
    case "beam":
      return (
        <div
          style={{
            width: width * 0.78,
            height: height * 1.06,
            borderRadius: "50% 50% 42% 42% / 28% 28% 72% 72%",
            display: "grid",
            placeItems: "center",
            background: `linear-gradient(180deg, ${model.accentColor}24, ${model.accentColor}08 72%, transparent)`,
            border: `1px solid ${model.accentColor}22`,
            boxShadow: `0 0 26px ${model.accentColor}18`,
          }}
        />
      );
    case "ember":
      return (
        <div
          style={{
            width: width * 0.84,
            height: height * 0.74,
            borderRadius: "28% 28% 36% 36% / 24% 24% 44% 44%",
            transform: "rotate(-12deg)",
            background: `radial-gradient(circle at 30% 32%, ${model.accentColor}2e, ${model.accentColor}08 70%)`,
            border: `1px solid ${model.accentColor}26`,
            boxShadow: `0 0 24px ${model.accentColor}1a`,
          }}
        />
      );
    case "thread":
      return (
        <div
          style={{
            width,
            height: height * 0.9,
            position: "relative",
          }}
        >
          {[0, 1, 2].map((index) => (
            <span
              key={index}
              style={{
                position: "absolute",
                left: "12%",
                right: "12%",
                top: `${30 + index * 18}%`,
                height: 1,
                transform: `rotate(${index === 1 ? 0 : index === 0 ? -18 : 18}deg)`,
                background: `linear-gradient(90deg, transparent, ${model.accentColor}94, transparent)`,
              }}
            />
          ))}
        </div>
      );
    case "stack":
      return (
        <div
          style={{
            width: width * 0.86,
            height: height * 0.82,
            display: "grid",
            gap: 10 * scale,
            alignContent: "center",
          }}
        >
          {[0, 1, 2].map((index) => (
            <span
              key={index}
              style={{
                display: "block",
                height: 12 * scale,
                borderRadius: 9999,
                border: `1px solid ${model.accentColor}24`,
                background: `${model.accentColor}${index === 1 ? "1a" : "10"}`,
              }}
            />
          ))}
        </div>
      );
    case "reticle":
    default:
      return (
        <div
          style={{
            width,
            height,
            borderRadius: "50%",
            display: "grid",
            placeItems: "center",
            border: `1px solid ${model.accentColor}20`,
            background: `radial-gradient(circle, ${model.accentColor}12, transparent 70%)`,
            boxShadow: `0 0 24px ${model.accentColor}12`,
          }}
        />
      );
  }
}

function renderVesselOrnaments(model: SpiritManifestationModel, stage: SpiritManifestationStage) {
  const kind = stage.kind ?? "tracker";
  const grammar = stage.grammar ?? DEFAULT_STAGE_GRAMMAR;
  switch (kind) {
    case "tracker":
      return (
        <>
          <span style={{ position: "absolute", left: "16%", right: "16%", top: "50%", height: 1, background: `linear-gradient(90deg, transparent, ${model.accentColor}7a, transparent)` }} />
          <span style={{ position: "absolute", top: "16%", bottom: "16%", left: "50%", width: 1, background: `linear-gradient(180deg, transparent, ${model.accentColor}70, transparent)` }} />
        </>
      );
    case "lantern":
      return (
        <>
          <span style={{ position: "absolute", left: "44%", top: "10%", width: "12%", height: "54%", background: `linear-gradient(180deg, ${model.accentColor}50, transparent)`, filter: "blur(5px)", opacity: 0.7 }} />
          <span style={{ position: "absolute", left: "22%", right: "22%", top: "18%", height: 1, background: `linear-gradient(90deg, transparent, ${model.accentColor}88, transparent)` }} />
        </>
      );
    case "forge":
      return (
        <>
          <span style={{ position: "absolute", left: "16%", top: "20%", width: "18%", height: "18%", borderLeft: `1px solid ${model.accentColor}80`, borderTop: `1px solid ${model.accentColor}80`, transform: "rotate(-10deg)" }} />
          <span style={{ position: "absolute", right: "16%", bottom: "20%", width: "18%", height: "18%", borderRight: `1px solid ${model.accentColor}80`, borderBottom: `1px solid ${model.accentColor}80`, transform: "rotate(-10deg)" }} />
          <span style={{ position: "absolute", left: "28%", right: "28%", top: "50%", height: 1, transform: "rotate(-16deg)", background: `linear-gradient(90deg, transparent, ${model.accentColor}9a, transparent)` }} />
        </>
      );
    case "loom":
      return (
        <>
          {Array.from({ length: grammar.ornamentCount }).map((_, index) => (
            <span
              key={`loom-thread-${index}`}
              style={{
                position: "absolute",
                left: "12%",
                right: "12%",
                top: `${28 + index * 12}%`,
                height: 1,
                transform: `rotate(${index % 2 === 0 ? -18 : 18}deg)`,
                background: `linear-gradient(90deg, transparent, ${model.accentColor}86, transparent)`,
              }}
            />
          ))}
        </>
      );
    case "ledger":
      return (
        <>
          {Array.from({ length: grammar.ornamentCount }).map((_, index) => (
            <span
              key={`ledger-band-${index}`}
              style={{
                position: "absolute",
                left: "18%",
                right: "18%",
                top: `${34 + index * 12}%`,
                height: 1,
                background: `linear-gradient(90deg, transparent, ${model.accentColor}${index === 1 ? "8a" : "5c"}, transparent)`,
              }}
            />
          ))}
        </>
      );
    default:
      return null;
  }
}

function renderStageFieldSignature(
  model: SpiritManifestationModel,
  stage: SpiritManifestationStage,
  mode: SpiritManifestationModel["mode"],
) {
  const kind = stage.kind ?? "tracker";
  const quietFactor = mode === "quick" ? 0.58 : 1;
  const baseOpacity = 0.26 * quietFactor;

  switch (kind) {
    case "forge":
      return (
        <>
          <span
            aria-hidden="true"
            style={{
              position: "absolute",
              left: "50%",
              top: "49%",
              width: "36%",
              height: "12%",
              transform: "translate(-44%, -62%) rotate(-16deg)",
              background: `linear-gradient(90deg, ${model.accentColor}00, ${model.accentColor}8a, transparent)`,
              filter: "blur(10px)",
              opacity: baseOpacity + 0.08,
            }}
          />
          <span
            aria-hidden="true"
            style={{
              position: "absolute",
              left: "50%",
              top: "49%",
              width: "32%",
              height: "10%",
              transform: "translate(-30%, -28%) rotate(-22deg)",
              background: `linear-gradient(90deg, ${model.accentColor}00, ${model.accentColor}6c, transparent)`,
              filter: "blur(8px)",
              opacity: baseOpacity + 0.04,
            }}
          />
        </>
      );
    case "loom":
      return (
        <>
          {[-24, -8, 8, 24].map((rotation) => (
            <span
              key={rotation}
              aria-hidden="true"
              style={{
                position: "absolute",
                left: "50%",
                top: "49%",
                width: "52%",
                height: 1,
                transform: `translate(-50%, -50%) rotate(${rotation}deg)`,
                background: `linear-gradient(90deg, transparent, ${model.accentColor}7e, transparent)`,
                opacity: baseOpacity + (rotation === -8 || rotation === 8 ? 0.08 : 0),
              }}
            />
          ))}
        </>
      );
    case "lantern":
      return (
        <>
          <span
            aria-hidden="true"
            style={{
              position: "absolute",
              left: "50%",
              top: "36%",
              width: "16%",
              height: "34%",
              transform: "translateX(-50%)",
              background: `linear-gradient(180deg, ${model.accentColor}00, ${model.accentColor}6e, ${model.accentColor}10 78%, transparent)`,
              filter: "blur(10px)",
              opacity: baseOpacity + 0.12,
            }}
          />
          <span
            aria-hidden="true"
            style={{
              position: "absolute",
              left: "50%",
              top: "46%",
              width: "44%",
              height: "44%",
              transform: "translate(-50%, -50%)",
              borderRadius: "50%",
              border: `1px solid ${model.accentColor}18`,
              opacity: baseOpacity + 0.08,
            }}
          />
        </>
      );
    case "ledger":
      return (
        <>
          {[0, 1, 2, 3].map((index) => (
            <span
              key={index}
              aria-hidden="true"
              style={{
                position: "absolute",
                left: "34%",
                right: "34%",
                top: `${39 + index * 5}%`,
                height: 1,
                background: `linear-gradient(90deg, transparent, ${model.accentColor}${index === 1 ? "9a" : "62"}, transparent)`,
                opacity: baseOpacity + (index === 1 ? 0.08 : 0),
              }}
            />
          ))}
        </>
      );
    case "tracker":
    default:
      return (
        <>
          <span
            aria-hidden="true"
            style={{
              position: "absolute",
              left: "52%",
              top: "48%",
              width: "42%",
              height: "8%",
              transform: "translate(-4%, -50%) rotate(-10deg)",
              background: `linear-gradient(90deg, ${model.accentColor}00, ${model.accentColor}7c, transparent)`,
              filter: "blur(8px)",
              opacity: baseOpacity + 0.06,
            }}
          />
          <span
            aria-hidden="true"
            style={{
              position: "absolute",
              right: "24%",
              top: "48%",
              width: 28,
              height: 28,
              transform: "translate(50%, -50%)",
              borderRadius: "50%",
              border: `1px solid ${model.accentColor}22`,
              boxShadow: `0 0 16px ${model.accentColor}12`,
              opacity: baseOpacity + 0.1,
            }}
          />
        </>
      );
  }
}

function renderExitSeam(
  model: SpiritManifestationModel,
  stage: SpiritManifestationStage,
  mode: SpiritManifestationModel["mode"],
  seamSummary: string | null,
) {
  const grammar = stage.grammar ?? DEFAULT_STAGE_GRAMMAR;
  const quietOpacity = mode === "quick" ? 0.46 : 0.76;

  return (
    <div
      style={{
        position: "absolute",
        right: 30,
        top: "22%",
        bottom: "18%",
        width: 152,
        pointerEvents: "none",
      }}
    >
      {grammar.exitCharacter === "pursuit" ? (
        <>
          <span style={{ position: "absolute", left: 0, top: "48%", width: 112, height: 1, background: `linear-gradient(90deg, ${model.accentColor}aa, transparent)`, opacity: quietOpacity }} />
          <span style={{ position: "absolute", left: 0, top: "52%", width: 88, height: 1, background: `linear-gradient(90deg, ${model.accentColor}6e, transparent)`, opacity: quietOpacity * 0.8 }} />
          <span style={{ position: "absolute", left: 0, top: "50%", width: 10, height: 10, transform: "translate(-45%, -50%)", borderRadius: 9999, background: `${model.accentColor}88`, boxShadow: `0 0 14px ${model.accentColor}48` }} />
        </>
      ) : null}
      {grammar.exitCharacter === "witness" ? (
        <>
          <span style={{ position: "absolute", left: -2, top: "50%", width: 22, height: 120, transform: "translateY(-50%)", borderRadius: 9999, background: `linear-gradient(180deg, transparent, ${model.accentColor}7a, transparent)`, filter: "blur(6px)", opacity: quietOpacity }} />
          <span style={{ position: "absolute", left: 6, top: "50%", width: 96, height: 1, background: `linear-gradient(90deg, ${model.accentColor}7a, transparent)`, opacity: quietOpacity }} />
        </>
      ) : null}
      {grammar.exitCharacter === "forge" ? (
        <>
          <span style={{ position: "absolute", left: 0, top: "46%", width: 108, height: 1, transform: "rotate(-12deg)", background: `linear-gradient(90deg, ${model.accentColor}b0, transparent)`, opacity: quietOpacity }} />
          <span style={{ position: "absolute", left: 10, top: "54%", width: 92, height: 1, transform: "rotate(-18deg)", background: `linear-gradient(90deg, ${model.accentColor}80, transparent)`, opacity: quietOpacity * 0.82 }} />
        </>
      ) : null}
      {grammar.exitCharacter === "woven" ? (
        <>
          {[-10, 0, 10].map((rotation) => (
            <span
              key={rotation}
              style={{
                position: "absolute",
                left: 0,
                top: "50%",
                width: 104,
                height: 1,
                transform: `rotate(${rotation}deg)`,
                background: `linear-gradient(90deg, ${model.accentColor}84, transparent)`,
                opacity: quietOpacity,
              }}
            />
          ))}
        </>
      ) : null}
      {grammar.exitCharacter === "ledger" ? (
        <>
          {[0, 1, 2].map((index) => (
            <span
              key={index}
              style={{
                position: "absolute",
                left: 0,
                top: `${44 + index * 6}%`,
                width: 102 - index * 10,
                height: 1,
                background: `linear-gradient(90deg, ${model.accentColor}${index === 1 ? "9a" : "70"}, transparent)`,
                opacity: quietOpacity,
              }}
            />
          ))}
        </>
      ) : null}
      <div
        style={{
          position: "absolute",
          left: 18,
          top: "50%",
          width: 128,
          transform: "translateY(-50%)",
        }}
      >
        <div
          className="font-mono text-[9px] uppercase tracking-[0.18em]"
          style={{ color: `${model.accentColor}`, opacity: 0.78 }}
        >
          {stage.exitLabel}
        </div>
        {seamSummary ? (
          <div className="mt-2 text-[11px]" style={{ color: "rgba(182,183,193,0.64)", lineHeight: 1.4 }}>
            {seamSummary}
          </div>
        ) : null}
      </div>
    </div>
  );
}

export function SpiritManifestationCanvas({
  model,
  className,
  children,
  showLegend = true,
}: {
  model: SpiritManifestationModel;
  className?: string;
  children?: ReactNode;
  showLegend?: boolean;
}) {
  const mode = model.mode ?? "other";
  const stage = model.stage ?? {
    kind: "tracker" as const,
    mode,
    modeLabel: "Spirit field",
    subtitle: model.reasonLine,
    stateLabel: model.moodLabel,
    intentLine: model.reasonLine,
    consequenceLine: model.focusLine ? `Pulls toward ${model.focusLine.replace(/ • /g, ", ")}` : model.biasLine,
    exitLabel: `to ${model.stationLabel}`,
    dominance: 0.78,
    vesselScale: 1,
    haloOpacity: 0.32,
    floorGlowOpacity: 0.24,
    grammar: DEFAULT_STAGE_GRAMMAR,
    inscriptions: [],
    tethers: [],
    ghosts: [],
  };
  const stageWidth = 32 + stage.dominance * 18;
  const kind = stage.kind ?? "tracker";
  const grammar = stage.grammar ?? DEFAULT_STAGE_GRAMMAR;
  const seamSummary = null;

  return (
    <section
      aria-label={model.chamberTitle}
      className={className}
      data-testid="spirit-manifestation-canvas"
      style={{
        position: "relative",
        overflow: "hidden",
        borderRadius: 32,
        minHeight: 560,
        border: `1px solid ${model.accentColor}24`,
        background:
          `radial-gradient(circle at 50% 38%, ${model.accentColor}12, transparent 30%), ` +
          `radial-gradient(circle at 16% 78%, ${model.accentColor}10, transparent 26%), ` +
          `radial-gradient(circle at 82% 24%, ${model.accentColor}10, transparent 26%), ` +
          "linear-gradient(180deg, rgba(8, 12, 20, 0.98), rgba(4, 6, 12, 1))",
        boxShadow: `inset 0 1px 0 ${model.accentColor}16, 0 32px 72px rgba(0,0,0,0.42)`,
      }}
    >
      <style>{CANVAS_KEYFRAMES}</style>

      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          inset: 0,
          background:
            `radial-gradient(circle at 50% 48%, transparent 0, rgba(3, 5, 8, 0.08) 42%, rgba(2, 3, 6, 0.54) 94%), ` +
            `radial-gradient(circle at 50% 46%, ${model.accentColor}0e, transparent 42%), ` +
            "linear-gradient(135deg, rgba(255,255,255,0.03), transparent 26%)",
        }}
      />

      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          left: "50%",
          top: `${grammar.floorGlowTopPercent}%`,
          width: `${grammar.floorGlowWidthPercent + stage.dominance * 8}%`,
          height: `${grammar.floorGlowHeightPercent + stage.dominance * 4}%`,
          transform: "translate(-50%, -50%)",
          borderRadius: "50%",
          background: `radial-gradient(circle, ${model.accentColor}18, transparent 72%)`,
          opacity: stage.floorGlowOpacity,
          filter: `blur(${grammar.floorGlowBlurPx}px)`,
        }}
      />

      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          left: "50%",
          top: `${grammar.haloTopPercent}%`,
          width: `${grammar.haloWidthPercent + stageWidth * 0.4}%`,
          height: `${grammar.haloHeightPercent + stage.dominance * 8}%`,
          transform: "translate(-50%, -50%)",
          borderRadius: "50%",
          background: `radial-gradient(circle, ${model.accentColor}18, ${model.accentColor}05 60%, transparent 76%)`,
          opacity: stage.haloOpacity,
          filter: `blur(${grammar.haloBlurPx}px)`,
          animation: "spirit-ritual-stage-radiance 5200ms ease-in-out infinite",
        }}
      />

      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          left: `${grammar.beamLeftPercent}%`,
          top: `${grammar.beamTopPercent}%`,
          width: `${grammar.beamWidthPercent + model.runtime.motion.openness * 8}%`,
          height: `${grammar.beamHeightPercent + model.runtime.motion.aura * 6}%`,
          transform: `translate(-50%, -50%) rotate(${grammar.beamRotationDeg}deg)`,
          background: `linear-gradient(180deg, ${model.accentColor}00, ${model.accentColor}44, ${model.accentColor}00)`,
          filter: "blur(16px)",
          opacity: grammar.beamOpacity + model.runtime.motion.pulse * (mode === "quick" ? 0.06 : 0.14),
          animation: `spirit-ritual-beam-pulse ${Math.round(2500 - model.runtime.motion.pulse * 900)}ms ease-in-out infinite`,
        }}
      />

      {model.rings.map((ring, index) => (
        <div
          key={`${ring.radiusPercent}-${index}`}
          aria-hidden="true"
          style={ringStyle(model, ring)}
        />
      ))}

      {renderStageFieldSignature(model, stage, mode)}

      {stage.ghosts.map((ghost) => (
        <div
          key={ghost.id}
          aria-hidden="true"
          style={{
            position: "absolute",
            left: `${ghost.leftPercent}%`,
            top: `${ghost.topPercent}%`,
            transform: `translate(-50%, -50%) rotate(${ghost.rotationDeg}deg)`,
            animation: `spirit-ritual-ghost-hover ${ghost.driftMs}ms ease-in-out infinite`,
            ["--ghost-scale" as string]: ghost.scale.toString(),
            ["--ghost-opacity" as string]: ghost.opacity.toString(),
          }}
        >
          <div style={{ display: "grid", placeItems: "center" }}>
            {renderGhostShell(model, stage, ghost.scale)}
            <svg
              viewBox="0 0 16 16"
              width={96 * ghost.scale}
              height={96 * ghost.scale}
              fill="none"
              stroke={model.accentColor}
              strokeWidth="1.1"
              strokeLinecap="round"
              strokeLinejoin="round"
              style={{ opacity: ghost.opacity, position: "absolute" }}
            >
              <path d={ghost.contourPath} />
            </svg>
          </div>
        </div>
      ))}

      {stage.inscriptions.map((inscription) => (
        <div
          key={inscription.id}
          aria-hidden="true"
          style={{
            position: "absolute",
            left: `${inscription.leftPercent}%`,
            top: `${inscription.topPercent}%`,
            width: `${inscription.widthPercent}%`,
            transform: `rotate(${inscription.rotationDeg}deg)`,
            animation: `spirit-ritual-inscription-trace 3600ms ease-in-out ${inscription.delayMs}ms infinite`,
            opacity: inscription.emphasis,
          }}
        >
          <div
            style={{
              height: 1,
              background: `linear-gradient(90deg, transparent, ${model.accentColor}cc, transparent)`,
              boxShadow: `0 0 12px ${model.accentColor}33`,
            }}
          />
          <div
            className="mt-2 font-mono text-[10px] uppercase tracking-[0.18em]"
            style={{ color: `${model.accentColor}`, textShadow: `0 0 10px ${model.accentColor}33` }}
          >
            {inscription.text}
          </div>
        </div>
      ))}

      {stage.tethers.length > 0 ? (
        <svg
          aria-hidden="true"
          viewBox="0 0 100 100"
          preserveAspectRatio="none"
          style={{
            position: "absolute",
            inset: 0,
            width: "100%",
            height: "100%",
            overflow: "visible",
          }}
        >
          {stage.tethers.map((tether) => (
            <path
              key={tether.id}
              d={buildTetherPath(tether, stage)}
              stroke={model.accentColor}
              strokeWidth={0.25 + tether.strength * 0.28}
              strokeLinecap="round"
              strokeDasharray={tether.dashPattern}
              fill="none"
              opacity={0.38 + tether.strength * 0.36}
              style={{
                filter: `drop-shadow(0 0 5px ${model.accentColor}44)`,
                animation: `spirit-ritual-tether-pulse ${Math.round(2400 - tether.strength * 600)}ms linear ${tether.delayMs}ms infinite`,
              }}
            />
          ))}
        </svg>
      ) : null}

      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          left: "50%",
          top: "49%",
          width: `${grammar.shellWidthPercent + stage.vesselScale * 11}%`,
          height: `${grammar.shellHeightPercent + stage.vesselScale * 12}%`,
          transform: `translate(-50%, -50%) rotate(${grammar.shellTiltDeg}deg)`,
          borderRadius: grammar.vesselShellRadius,
          border: `1px solid ${model.accentColor}${kind === "forge" ? "34" : kind === "lantern" ? "2a" : "26"}`,
          background:
            `radial-gradient(circle at 50% 34%, ${model.accentColor}${kind === "forge" ? "1e" : "14"}, rgba(5, 8, 14, 0.08) 58%, transparent 76%)`,
          boxShadow: `0 0 ${kind === "forge" ? 54 : 42}px ${model.accentColor}16, inset 0 0 ${kind === "ledger" ? 18 : 28}px ${model.accentColor}${kind === "loom" ? "18" : "12"}`,
        }}
      >
        {renderVesselOrnaments(model, stage)}
      </div>

      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          left: "50%",
          top: "49%",
          width: `${grammar.coreWidthPercent + stage.vesselScale * 9}%`,
          height: `${grammar.coreHeightPercent + stage.vesselScale * 10}%`,
          transform: `translate(-50%, -50%) rotate(${grammar.shellTiltDeg * 0.5}deg)`,
          borderRadius: grammar.vesselCoreRadius,
          background: `radial-gradient(circle at 38% 32%, ${model.accentColor}40, ${model.accentColor}0b 58%, transparent 78%)`,
          filter: `blur(${kind === "ledger" ? 8 : kind === "forge" ? 11 : 10}px)`,
          opacity: 0.44 + model.runtime.motion.aura * 0.2 + (kind === "lantern" ? 0.05 : 0),
          animation: `spirit-ritual-core-breathe ${Math.round(2400 - model.runtime.motion.pulse * 850)}ms ease-in-out infinite`,
        }}
      />

      <div
        aria-hidden="true"
        style={{
          position: "absolute",
          left: "50%",
          top: "49%",
          width: `${grammar.coreWidthPercent - 2 + stage.vesselScale * 8}%`,
          height: `${grammar.coreHeightPercent - 1 + stage.vesselScale * 8}%`,
          transform: `translate(-50%, -50%) rotate(${grammar.shellTiltDeg * 0.35}deg)`,
          display: "grid",
          placeItems: "center",
          borderRadius: grammar.vesselCoreRadius,
          border: `1px solid ${model.accentColor}30`,
          background:
            `radial-gradient(circle at 35% 30%, ${model.accentColor}14, rgba(7,10,16,0.04) 62%, transparent 72%)`,
          boxShadow: `0 0 28px ${model.accentColor}16, inset 0 0 28px ${model.accentColor}12`,
        }}
      >
        <div
          style={{
            position: "absolute",
            inset: "10%",
            borderRadius: "50%",
            border: `1px solid ${model.accentColor}18`,
          }}
        />
        <svg
          viewBox="0 0 16 16"
          width={(112 + stage.vesselScale * 18) * grammar.contourScale}
          height={(112 + stage.vesselScale * 18) * grammar.contourScale}
          fill="none"
          stroke={model.accentColor}
          strokeWidth={grammar.contourStrokeWidth}
          strokeLinecap="round"
          strokeLinejoin="round"
          style={{
            opacity: grammar.contourOpacity,
            filter: `drop-shadow(0 0 18px ${model.accentColor}52)`,
          }}
        >
          <path d={model.contourPath} />
        </svg>
      </div>

      <div style={{ position: "relative", zIndex: 2, minHeight: 560, padding: 28 }}>
        <div
          style={{
            position: "absolute",
            left: "50%",
            top: mode === "quick" ? "65%" : "66.5%",
            width: 296,
            maxWidth: "calc(100% - 120px)",
            transform: "translateX(-50%)",
            textAlign: "center",
            padding: "10px 14px 0",
          }}
        >
          <div
            className="font-mono text-[10px] uppercase tracking-[0.18em]"
            style={{ color: `${model.accentColor}`, opacity: 0.82 }}
          >
            {model.label}
          </div>
          {showLegend ? (
            <div className="mt-3 text-[13px]" style={{ color: "rgba(236,233,225,0.82)", lineHeight: 1.45 }}>
              {stage.intentLine}
            </div>
          ) : null}
        </div>

        {renderExitSeam(model, stage, mode, seamSummary)}

        {stage.tethers.map((tether) => (
          <div
            key={`chip-${tether.id}`}
            style={{
              position: "absolute",
              left: `${tether.startXPercent}%`,
              top: `${tether.startYPercent}%`,
              transform: "translate(-50%, -50%)",
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "5px 8px",
              ...anchoredChipStyle(model.accentColor, "08"),
            }}
          >
            <span
              aria-hidden="true"
              style={{
                width: 4,
                height: 4,
                borderRadius: 9999,
                background: `${model.accentColor}82`,
                boxShadow: `0 0 8px ${model.accentColor}44`,
              }}
            />
            <div
              className="font-mono text-[8px] uppercase tracking-[0.18em]"
              style={{ color: "rgba(236,233,225,0.58)" }}
            >
              {tether.kindLabel}
            </div>
          </div>
        ))}

        {children ? (
          <div
            style={{
              position: "absolute",
              right: 28,
              top: 120,
              zIndex: 3,
              maxWidth: 260,
            }}
          >
            {children}
          </div>
        ) : null}
      </div>
    </section>
  );
}
