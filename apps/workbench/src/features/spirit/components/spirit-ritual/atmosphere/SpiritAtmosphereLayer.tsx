// Ported from huntronomer spirit-ritual/atmosphere/SpiritAtmosphereLayer.tsx
// Only change: import path adjusted to ../canvas/model (was ../canvas which re-exported from model.ts).
// No R3F imports — pure CSS particles.
import type { CSSProperties } from "react";
import type {
  SpiritManifestationGrammar,
  SpiritManifestationModel,
  SpiritManifestationStage,
} from "../canvas/model";

const ATMOSPHERE_KEYFRAMES = `
@keyframes spirit-ritual-atmosphere-drift {
  0%, 100% { transform: translate3d(0, 0, 0) scale(0.97); opacity: 0.18; }
  50% { transform: translate3d(4px, -10px, 0) scale(1.03); opacity: 0.34; }
}

@keyframes spirit-ritual-grain-float {
  0% { transform: translate3d(0, 0, 0); opacity: 0.1; }
  50% { transform: translate3d(5px, -8px, 0); opacity: 0.28; }
  100% { transform: translate3d(-3px, -14px, 0); opacity: 0.05; }
}

@keyframes spirit-ritual-sweep {
  0%, 100% { transform: rotate(-8deg) scale(0.98); opacity: 0.12; }
  50% { transform: rotate(6deg) scale(1.03); opacity: 0.22; }
}

@keyframes spirit-ritual-beacon {
  0%, 100% { opacity: 0.12; transform: translate(-50%, -50%) scale(0.92); }
  50% { opacity: 0.3; transform: translate(-50%, -50%) scale(1.08); }
}
`;

function fallbackGrains(model: SpiritManifestationModel) {
  return Array.from({ length: model.atmosphere.particleCount }, (_, index) => ({
    id: `fallback-grain-${index}`,
    leftPercent: 10 + ((index * 17) % 78),
    topPercent: 12 + ((index * 23) % 68),
    sizePx: 2 + (index % 4) * 0.6,
    opacity: 0.09 + (index % 5) * 0.02,
    blurPx: 0.6 + (index % 3) * 0.2,
    driftMs: model.atmosphere.driftMs + index * 120,
    delayMs: index * -90,
  }));
}

function buildGrainStyle(
  model: SpiritManifestationModel,
  grain: NonNullable<SpiritManifestationModel["atmosphere"]["grains"]>[number],
  reducedMotion: boolean,
): CSSProperties {
  return {
    position: "absolute",
    left: `${grain.leftPercent}%`,
    top: `${grain.topPercent}%`,
    width: `${grain.sizePx}px`,
    height: `${grain.sizePx}px`,
    borderRadius: 9999,
    background: model.accentColor,
    opacity: grain.opacity * (model.atmosphere.grainOpacity ?? 1),
    filter: `blur(${grain.blurPx}px)`,
    boxShadow: `0 0 ${4 + grain.sizePx * 2}px ${model.accentColor}33`,
    animation: reducedMotion
      ? undefined
      : `spirit-ritual-grain-float ${grain.driftMs}ms ease-in-out ${grain.delayMs}ms infinite`,
  };
}

function sweepStyle(
  model: SpiritManifestationModel,
  stageDominance: number,
  mode: SpiritManifestationModel["mode"],
  rotationDeg: number,
  reducedMotion: boolean,
): CSSProperties {
  return {
    position: "absolute",
    left: "50%",
    top: "50%",
    width: `${52 + stageDominance * 18}%`,
    height: `${22 + stageDominance * 8}%`,
    borderRadius: "50%",
    borderWidth: 1,
    borderStyle: "solid",
    borderLeftColor: `${model.accentColor}1c`,
    borderRightColor: `${model.accentColor}1c`,
    borderTopColor: `${model.accentColor}44`,
    borderBottomColor: "transparent",
    transform: `translate(-50%, -50%) rotate(${rotationDeg}deg)`,
    opacity: mode === "quick" ? 0.08 : 0.14,
    animation: reducedMotion
      ? undefined
      : `spirit-ritual-sweep ${Math.round(model.atmosphere.driftMs * 0.92)}ms ease-in-out infinite`,
  };
}

const DEFAULT_STAGE_GRAMMAR: SpiritManifestationGrammar = {
  vesselShellRadius: "50%",
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

function renderFieldResidue(
  model: SpiritManifestationModel,
  stage: SpiritManifestationStage,
  reducedMotion: boolean,
) {
  const kind = stage.kind ?? "tracker";
  const duration = Math.round(model.atmosphere.driftMs * 0.92);
  switch (kind) {
    case "tracker":
      return (
        <>
          <div
            data-testid="spirit-atmosphere-residue"
            style={{
              position: "absolute",
              left: "54%",
              top: "48%",
              width: "42%",
              height: "10%",
              transform: "translateY(-50%) rotate(-8deg)",
              background: `linear-gradient(90deg, ${model.accentColor}00, ${model.accentColor}36, transparent)`,
              filter: "blur(10px)",
              opacity: 0.28,
            }}
          />
          <div
            data-testid="spirit-atmosphere-residue"
            style={{
              position: "absolute",
              right: "12%",
              top: "48%",
              width: 34,
              height: 34,
              borderRadius: "50%",
              border: `1px solid ${model.accentColor}32`,
              boxShadow: `0 0 22px ${model.accentColor}18`,
              animation: reducedMotion ? undefined : `spirit-ritual-beacon ${duration}ms ease-in-out infinite`,
            }}
          />
        </>
      );
    case "lantern":
      return (
        <>
          <div
            data-testid="spirit-atmosphere-residue"
            style={{
              position: "absolute",
              left: "50%",
              top: "32%",
              width: "18%",
              height: "56%",
              transform: "translate(-50%, -20%)",
              borderRadius: "50%",
              background: `linear-gradient(180deg, ${model.accentColor}00, ${model.accentColor}32, ${model.accentColor}08 72%, transparent)`,
              filter: "blur(14px)",
              opacity: 0.3,
            }}
          />
          <div
            data-testid="spirit-atmosphere-residue"
            style={{
              position: "absolute",
              left: "50%",
              top: "44%",
              width: "44%",
              height: "44%",
              transform: "translate(-50%, -50%)",
              borderRadius: "50%",
              border: `1px solid ${model.accentColor}18`,
              opacity: 0.42,
            }}
          />
        </>
      );
    case "forge":
      return (
        <>
          {[-18, -10].map((rotation) => (
            <div
              key={rotation}
              data-testid="spirit-atmosphere-residue"
              style={{
                position: "absolute",
                left: "54%",
                top: "50%",
                width: "44%",
                height: "12%",
                transform: `translate(-20%, -50%) rotate(${rotation}deg)`,
                background: `linear-gradient(90deg, ${model.accentColor}00, ${model.accentColor}34, transparent)`,
                filter: "blur(12px)",
                opacity: 0.28,
              }}
            />
          ))}
        </>
      );
    case "loom":
      return (
        <>
          {[-18, 0, 18].map((rotation) => (
            <div
              key={rotation}
              data-testid="spirit-atmosphere-residue"
              style={{
                position: "absolute",
                left: "50%",
                top: "50%",
                width: "76%",
                height: 1,
                transform: `translate(-50%, -50%) rotate(${rotation}deg)`,
                background: `linear-gradient(90deg, transparent, ${model.accentColor}52, transparent)`,
                opacity: 0.42,
              }}
            />
          ))}
        </>
      );
    case "ledger":
      return (
        <>
          {[0, 1, 2].map((index) => (
            <div
              key={index}
              data-testid="spirit-atmosphere-residue"
              style={{
                position: "absolute",
                left: "18%",
                right: "18%",
                top: `${42 + index * 7}%`,
                height: 1,
                background: `linear-gradient(90deg, transparent, ${model.accentColor}${index === 1 ? "6c" : "4a"}, transparent)`,
                opacity: 0.42,
              }}
            />
          ))}
        </>
      );
    default:
      return null;
  }
}

function renderStagePressure(
  model: SpiritManifestationModel,
  stage: SpiritManifestationStage,
  mode: SpiritManifestationModel["mode"],
  reducedMotion: boolean,
) {
  const kind = stage.kind ?? "tracker";
  const quietFactor = mode === "quick" ? 0.62 : 1;
  const pulse = Math.round(model.atmosphere.pulseMs * 0.88);

  switch (kind) {
    case "forge":
      return (
        <>
          <div
            data-testid="spirit-atmosphere-pressure"
            style={{
              position: "absolute",
              left: "50%",
              top: "49%",
              width: "28%",
              height: "10%",
              transform: "translate(-44%, -56%) rotate(-18deg)",
              background: `linear-gradient(90deg, ${model.accentColor}00, ${model.accentColor}82, transparent)`,
              filter: "blur(10px)",
              opacity: 0.22 * quietFactor,
            }}
          />
          <div
            data-testid="spirit-atmosphere-pressure"
            style={{
              position: "absolute",
              left: "50%",
              top: "49%",
              width: 24,
              height: 24,
              transform: "translate(-8%, -44%)",
              borderRadius: "50%",
              background: `${model.accentColor}22`,
              boxShadow: `0 0 22px ${model.accentColor}38`,
              animation: reducedMotion ? undefined : `spirit-ritual-beacon ${pulse}ms ease-in-out infinite`,
            }}
          />
        </>
      );
    case "loom":
      return (
        <>
          {[-22, -8, 8, 22].map((rotation) => (
            <div
              key={rotation}
              data-testid="spirit-atmosphere-pressure"
              style={{
                position: "absolute",
                left: "50%",
                top: "49%",
                width: "44%",
                height: 1,
                transform: `translate(-50%, -50%) rotate(${rotation}deg)`,
                background: `linear-gradient(90deg, transparent, ${model.accentColor}${rotation === -8 || rotation === 8 ? "7e" : "56"}, transparent)`,
                opacity: 0.3 * quietFactor,
              }}
            />
          ))}
        </>
      );
    case "lantern":
      return (
        <>
          <div
            data-testid="spirit-atmosphere-pressure"
            style={{
              position: "absolute",
              left: "50%",
              top: "40%",
              width: "14%",
              height: "34%",
              transform: "translateX(-50%)",
              background: `linear-gradient(180deg, ${model.accentColor}00, ${model.accentColor}78, ${model.accentColor}10 80%, transparent)`,
              filter: "blur(11px)",
              opacity: 0.26 * quietFactor,
            }}
          />
          <div
            data-testid="spirit-atmosphere-pressure"
            style={{
              position: "absolute",
              left: "50%",
              top: "52%",
              width: "34%",
              height: "18%",
              transform: "translate(-50%, -50%)",
              borderRadius: "50%",
              border: `1px solid ${model.accentColor}24`,
              opacity: 0.3 * quietFactor,
            }}
          />
        </>
      );
    case "ledger":
      return (
        <>
          {[0, 1, 2, 3].map((index) => (
            <div
              key={index}
              data-testid="spirit-atmosphere-pressure"
              style={{
                position: "absolute",
                left: "36%",
                right: "36%",
                top: `${43 + index * 4}%`,
                height: 1,
                background: `linear-gradient(90deg, transparent, ${model.accentColor}${index === 1 ? "90" : "5a"}, transparent)`,
                opacity: 0.28 * quietFactor,
              }}
            />
          ))}
        </>
      );
    case "tracker":
    default:
      return (
        <>
          <div
            data-testid="spirit-atmosphere-pressure"
            style={{
              position: "absolute",
              left: "52%",
              top: "48%",
              width: "34%",
              height: "8%",
              transform: "translate(-4%, -50%) rotate(-10deg)",
              background: `linear-gradient(90deg, ${model.accentColor}00, ${model.accentColor}72, transparent)`,
              filter: "blur(8px)",
              opacity: 0.24 * quietFactor,
            }}
          />
          <div
            data-testid="spirit-atmosphere-pressure"
            style={{
              position: "absolute",
              right: "26%",
              top: "48%",
              width: 20,
              height: 20,
              transform: "translate(50%, -50%)",
              borderRadius: "50%",
              border: `1px solid ${model.accentColor}24`,
              boxShadow: `0 0 16px ${model.accentColor}20`,
              animation: reducedMotion ? undefined : `spirit-ritual-beacon ${pulse}ms ease-in-out infinite`,
            }}
          />
        </>
      );
  }
}

export function SpiritAtmosphereLayer({
  model,
  reducedMotion = false,
  className,
}: {
  model: SpiritManifestationModel;
  reducedMotion?: boolean;
  className?: string;
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
  const grammar = stage.grammar ?? DEFAULT_STAGE_GRAMMAR;
  const kind = stage.kind ?? "tracker";
  const grains = model.atmosphere.grains ?? fallbackGrains(model);

  return (
    <div
      aria-hidden="true"
      className={className}
      data-testid="spirit-atmosphere-layer"
      style={{
        position: "absolute",
        inset: 0,
        pointerEvents: "none",
        overflow: "hidden",
      }}
    >
      <style>{ATMOSPHERE_KEYFRAMES}</style>

      <div
        style={{
          position: "absolute",
          inset: "-18%",
          background:
            `radial-gradient(circle at ${grammar.beamLeftPercent}% ${grammar.haloTopPercent - 2}%, ${mode === "quick" ? `${model.accentColor}${kind === "forge" ? "16" : "12"}` : `${model.accentColor}${kind === "lantern" ? "28" : "24"}`}, transparent 34%), ` +
            `radial-gradient(circle at 26% 74%, ${model.accentColor}${mode === "anchors" ? "18" : "12"}, transparent 24%), ` +
            `radial-gradient(circle at 74% 30%, ${model.accentColor}${mode === "manual" ? "18" : "12"}, transparent 24%)`,
          opacity: mode === "quick" ? model.atmosphere.veilOpacity * 0.8 : model.atmosphere.veilOpacity,
          filter: `blur(${24 + grammar.haloBlurPx}px)`,
          animation: reducedMotion
            ? undefined
            : `spirit-ritual-atmosphere-drift ${model.atmosphere.pulseMs}ms ease-in-out infinite`,
        }}
      />

      <div
        style={{
          position: "absolute",
          left: "50%",
          top: `${grammar.floorGlowTopPercent}%`,
          width: `${grammar.floorGlowWidthPercent + stage.dominance * 10}%`,
          height: `${grammar.floorGlowHeightPercent + stage.dominance * 10}%`,
          transform: "translate(-50%, -50%)",
          borderRadius: "50%",
          background: `radial-gradient(circle, ${model.accentColor}14, transparent 70%)`,
          opacity: mode === "quick" ? model.atmosphere.bloomOpacity * 0.78 : model.atmosphere.bloomOpacity,
          filter: `blur(${grammar.floorGlowBlurPx + 10}px)`,
        }}
      />

      {renderStagePressure(model, stage, mode, reducedMotion)}

      <div style={sweepStyle(model, stage.dominance, mode, grammar.ringRotationDeg || (mode === "quick" ? 0 : -12), reducedMotion)} />
      {mode !== "quick" ? <div style={sweepStyle(model, stage.dominance, mode, grammar.ringRotationDeg * -1 || 12, reducedMotion)} /> : null}

      {renderFieldResidue(model, stage, reducedMotion)}

      <div
        style={{
          position: "absolute",
          left: "8%",
          right: "8%",
          bottom: "12%",
          height: 1,
          background: `linear-gradient(90deg, transparent, ${model.accentColor}a8, transparent)`,
          opacity: model.atmosphere.railOpacity,
        }}
      />

      <div
        style={{
          position: "absolute",
          inset: 0,
          background:
            "radial-gradient(circle at 50% 50%, transparent 0, transparent 28%, rgba(2, 4, 7, 0.14) 56%, rgba(1, 2, 4, 0.54) 100%)",
          opacity: 0.94,
        }}
      />

      {stage.tethers.map((tether) => (
        <div
          key={`beacon-${tether.id}`}
          style={{
            position: "absolute",
            left: `${tether.startXPercent}%`,
            top: `${tether.startYPercent}%`,
            width: 14,
            height: 14,
            borderRadius: 9999,
            background: `${model.accentColor}18`,
            border: `1px solid ${model.accentColor}44`,
            boxShadow: `0 0 16px ${model.accentColor}36`,
            animation: reducedMotion
              ? undefined
              : `spirit-ritual-beacon ${Math.round(model.atmosphere.pulseMs * 0.82)}ms ease-in-out ${tether.delayMs}ms infinite`,
          }}
        />
      ))}

      {grains.map((grain) => (
        <span
          key={grain.id}
          data-testid="spirit-atmosphere-grain"
          style={buildGrainStyle(model, grain, reducedMotion)}
        />
      ))}
    </div>
  );
}
