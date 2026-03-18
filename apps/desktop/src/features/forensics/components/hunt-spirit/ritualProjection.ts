import type { SpiritManifestationModel } from "@/shell/workbench/spirit-ritual/canvas";
import type { SpiritReleasePhase } from "@/shell/workbench/spirit-ritual/release";
import type { HuntSpiritRuntimeState } from "@/shell/workbench/spirit";
import type { HuntSpiritSceneActor } from "./runtime";

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function titleCaseWords(value: string | null | undefined): string {
  if (!value) return "Workbench Field";
  return value
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function buildRuntime(actor: HuntSpiritSceneActor): HuntSpiritRuntimeState {
  const mood =
    actor.cue?.kind === "bind"
      ? "transit"
      : actor.cue?.kind === "witness"
        ? "witnessing"
        : actor.stance === "focus"
          ? "focused"
          : "attuned";

  return {
    kind: null,
    label: actor.label,
    accentColor: actor.accentColor,
    contour: actor.contour,
    mood,
    stance: actor.stance,
    reason: actor.reason,
    emphasis: actor.emphasis,
    fieldStrength: actor.presenceStrength,
    shouldRender: true,
    motion: {
      arousal: clamp01(0.34 + actor.presenceStrength * 0.5),
      valence: clamp01(0.42 + actor.presenceStrength * 0.26),
      openness: clamp01(0.3 + actor.altitude * 0.2),
      aura: clamp01(0.26 + actor.presenceStrength * 0.46),
      pulse: clamp01(0.18 + actor.focusBeam * 0.72),
      tilt: clamp01(0.08 + Math.abs(actor.laneBias) * 0.2),
    },
    activeStationId: actor.activeStationId,
    currentShell: "forensics",
    currentLens: null,
  };
}

function buildReleaseCopy(actor: HuntSpiritSceneActor, stationLabel: string) {
  switch (actor.cue?.kind) {
    case "bind":
      return {
        title: `Receive ${actor.label} into the river field`,
        subtitle: `${actor.label} is settling over ${stationLabel} and the active hunt lane.`,
        actionLabel: "Receive into Forensics",
        durationMs: 2400,
        tetherStrength: 0.88,
        pulseScale: 1.16,
      };
    case "witness":
      return {
        title: `${actor.label} is catching proof`,
        subtitle: "Receipts and evidence are sealing into the hunt field instead of floating loose.",
        actionLabel: "Witness on the lane",
        durationMs: 2000,
        tetherStrength: 0.72,
        pulseScale: 1.08,
      };
    case "absorb":
      return {
        title: `${actor.label} is drawing material inward`,
        subtitle: "Entities, targets, and files are being pulled into the active investigative posture.",
        actionLabel: "Absorb into the field",
        durationMs: 1800,
        tetherStrength: 0.7,
        pulseScale: 1.06,
      };
    case "focus":
      return {
        title: `${actor.label} is sharpening the river lane`,
        subtitle: `The active field is leaning toward ${stationLabel} before the operator commits.`,
        actionLabel: "Focus the lane",
        durationMs: 1600,
        tetherStrength: 0.64,
        pulseScale: 1.04,
      };
    default:
      return {
        title: `${actor.label} is holding the river field`,
        subtitle: "The hunt spirit is present without forcing a fresh receive surge.",
        actionLabel: "Hold field posture",
        durationMs: 1400,
        tetherStrength: 0.58,
        pulseScale: 1,
      };
  }
}

export function resolveForensicsSpiritReleasePhase(
  actor: HuntSpiritSceneActor | null,
): SpiritReleasePhase | null {
  if (!actor?.cue) return null;
  switch (actor.cue.kind) {
    case "bind":
      return "releasing";
    case "witness":
    case "absorb":
    case "focus":
      return "released";
    default:
      return "primed";
  }
}

export function projectForensicsSpiritRitualModel(
  actor: HuntSpiritSceneActor,
): SpiritManifestationModel {
  const stationLabel = titleCaseWords(actor.activeStationId);
  const release = buildReleaseCopy(actor, stationLabel);

  return {
    label: actor.label,
    accentColor: actor.accentColor,
    contour: actor.contour,
    contourPath: "M8 3v10M3 8h10",
    stance: actor.stance,
    motionLabel: actor.presenceStrength >= 0.75 ? "high field" : actor.presenceStrength >= 0.5 ? "steady field" : "warming field",
    moodLabel: actor.cue?.kind === "bind" ? "Receiving" : actor.stance.charAt(0).toUpperCase() + actor.stance.slice(1),
    fieldStrength: clamp01(actor.presenceStrength),
    fieldPercent: Math.round(clamp01(actor.presenceStrength) * 100),
    reasonLine: actor.cue?.reason ?? actor.reason ?? "Holding field over the active river lane.",
    biasLine:
      actor.emphasis.length > 0
        ? `Biasing ${actor.emphasis.map((item) => item.replaceAll("-", " ")).join(", ")} through the active lane.`
        : "Biasing the active river lane from the current hunt posture.",
    thesisLine: null,
    focusLine:
      actor.emphasis.length > 0
        ? actor.emphasis.map((item) => item.replaceAll("-", " ")).join(" • ")
        : "river lane • active proof",
    chamberTitle: `${actor.label} river receive`,
    stationLabel,
    rings: [
      {
        radiusPercent: 46,
        opacity: 0.16,
        strokeWidth: 1.4,
        dashPattern: null,
        driftMs: 5200,
        scaleY: 1,
        rotateDeg: 0,
        offsetXPercent: 0,
        offsetYPercent: 0,
        glowOpacity: 0.18,
      },
      {
        radiusPercent: 60,
        opacity: 0.12,
        strokeWidth: 1.2,
        dashPattern: "8 12",
        driftMs: 6200,
        scaleY: 1,
        rotateDeg: 0,
        offsetXPercent: 0,
        offsetYPercent: 0,
        glowOpacity: 0.15,
      },
      {
        radiusPercent: 74,
        opacity: 0.08,
        strokeWidth: 1,
        dashPattern: null,
        driftMs: 7400,
        scaleY: 1,
        rotateDeg: 0,
        offsetXPercent: 0,
        offsetYPercent: 0,
        glowOpacity: 0.12,
      },
    ],
    atmosphere: {
      veilOpacity: 0.08 + clamp01(actor.presenceStrength) * 0.14,
      bloomOpacity: 0.1 + actor.focusBeam * 0.16,
      particleCount: 6 + Math.round(clamp01(actor.presenceStrength) * 6),
      pulseMs: 2400,
      driftMs: 7600,
      railOpacity: 0.1 + clamp01(actor.presenceStrength) * 0.12,
    },
    release: {
      ...release,
      targetLabel: `the active river lane around ${stationLabel}`,
    },
    runtime: buildRuntime(actor),
  };
}
