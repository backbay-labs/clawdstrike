import type { SpiritManifestationModel } from "@/shell/workbench/spirit-ritual/canvas";
import type { SpiritReleasePhase } from "@/shell/workbench/spirit-ritual/release";
import type { HuntSpiritRuntimeState } from "@/shell/workbench/spirit";
import type { NexusSpiritSceneActor } from "./runtime";

function clamp01(value: number): number {
  if (!Number.isFinite(value)) return 0;
  return Math.max(0, Math.min(1, value));
}

function titleCaseWords(value: string | null | undefined): string {
  if (!value) return "Nexus";
  return value
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function buildRuntime(actor: NexusSpiritSceneActor): HuntSpiritRuntimeState {
  const mood =
    actor.cue?.kind === "transit"
      ? "transit"
      : actor.cue?.kind === "focus"
        ? "focused"
        : actor.cue?.kind === "bind"
          ? "attuned"
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
      arousal: clamp01(0.3 + actor.presenceStrength * 0.48),
      valence: clamp01(0.42 + actor.presenceStrength * 0.22),
      openness: clamp01(0.3 + actor.altitude * 0.18),
      aura: clamp01(0.24 + actor.presenceStrength * 0.44),
      pulse: clamp01(0.16 + actor.focusBeam * 0.74),
      tilt: clamp01(0.08 + (actor.stationAffinities[actor.anchorStrikecellId] ?? 0) * 0.2),
    },
    activeStationId: actor.likelyStationId ?? actor.anchorStrikecellId,
    currentShell: "nexus",
    currentLens: null,
  };
}

function buildReleaseCopy(actor: NexusSpiritSceneActor, anchorLabel: string, likelyLabel: string) {
  switch (actor.cue?.kind) {
    case "bind":
      return {
        title: `Settle ${actor.label} into ${anchorLabel}`,
        subtitle: `${actor.label} is taking station as a companion object, not replacing topology.`,
        actionLabel: "Settle into Nexus",
        durationMs: 2400,
        tetherStrength: 0.86,
        pulseScale: 1.14,
      };
    case "transit":
      return {
        title: `Transit ${actor.label} toward ${likelyLabel}`,
        subtitle: "The active hunt field is moving with strikecell focus instead of teleporting between contexts.",
        actionLabel: "Transit across stations",
        durationMs: 2500,
        tetherStrength: 0.9,
        pulseScale: 1.18,
      };
    case "recenter":
      return {
        title: `Recenter ${actor.label} on ${anchorLabel}`,
        subtitle: "The current station is rehearsing the spirit rationale without losing the broader field.",
        actionLabel: "Recenter the field",
        durationMs: 1800,
        tetherStrength: 0.72,
        pulseScale: 1.06,
      };
    case "focus":
      return {
        title: `${actor.label} is biasing ${likelyLabel}`,
        subtitle: "Station emphasis is tightening around the likely next operational locus.",
        actionLabel: "Focus station emphasis",
        durationMs: 1700,
        tetherStrength: 0.66,
        pulseScale: 1.04,
      };
    default:
      return {
        title: `${actor.label} is holding the Nexus field`,
        subtitle: "The spirit remains present without forcing a station transfer.",
        actionLabel: "Hold station posture",
        durationMs: 1400,
        tetherStrength: 0.58,
        pulseScale: 1,
      };
  }
}

export function resolveNexusSpiritReleasePhase(
  actor: NexusSpiritSceneActor | null,
): SpiritReleasePhase | null {
  if (!actor?.cue) return null;
  switch (actor.cue.kind) {
    case "bind":
    case "transit":
    case "recenter":
      return "releasing";
    case "focus":
      return "released";
    default:
      return "primed";
  }
}

export function projectNexusSpiritRitualModel(
  actor: NexusSpiritSceneActor,
): SpiritManifestationModel {
  const anchorLabel = titleCaseWords(actor.anchorStrikecellId);
  const likelyLabel = titleCaseWords(actor.likelyStationId ?? actor.anchorStrikecellId);
  const release = buildReleaseCopy(actor, anchorLabel, likelyLabel);

  return {
    label: actor.label,
    accentColor: actor.accentColor,
    contour: actor.contour,
    contourPath: "M8 2.8l3.8 5.2L8 13.2 4.2 8z",
    stance: actor.stance,
    motionLabel: actor.presenceStrength >= 0.78 ? "high field" : actor.presenceStrength >= 0.52 ? "steady field" : "warming field",
    moodLabel: actor.cue?.kind === "transit" ? "Transit" : actor.stance.charAt(0).toUpperCase() + actor.stance.slice(1),
    fieldStrength: clamp01(actor.presenceStrength),
    fieldPercent: Math.round(clamp01(actor.presenceStrength) * 100),
    reasonLine: actor.cue?.reason ?? actor.reason ?? "Holding posture against the active strikecell.",
    biasLine:
      actor.emphasis.length > 0
        ? `Biasing ${actor.emphasis.map((item) => item.replaceAll("-", " ")).join(", ")} across nearby strikecells.`
        : "Biasing the current strikecell constellation from the active hunt posture.",
    thesisLine: null,
    focusLine:
      actor.emphasis.length > 0
        ? actor.emphasis.map((item) => item.replaceAll("-", " ")).join(" • ")
        : `${anchorLabel} • ${likelyLabel}`,
    chamberTitle: `${actor.label} nexus receive`,
    stationLabel: likelyLabel,
    rings: [
      {
        radiusPercent: 42,
        opacity: 0.14,
        strokeWidth: 1.4,
        dashPattern: null,
        driftMs: 5400,
        scaleY: 1,
        rotateDeg: 0,
        offsetXPercent: 0,
        offsetYPercent: 0,
        glowOpacity: 0.18,
      },
      {
        radiusPercent: 56,
        opacity: 0.1,
        strokeWidth: 1.1,
        dashPattern: "8 12",
        driftMs: 6400,
        scaleY: 1,
        rotateDeg: 0,
        offsetXPercent: 0,
        offsetYPercent: 0,
        glowOpacity: 0.14,
      },
      {
        radiusPercent: 70,
        opacity: 0.08,
        strokeWidth: 1,
        dashPattern: null,
        driftMs: 7600,
        scaleY: 1,
        rotateDeg: 0,
        offsetXPercent: 0,
        offsetYPercent: 0,
        glowOpacity: 0.12,
      },
    ],
    atmosphere: {
      veilOpacity: 0.06 + clamp01(actor.presenceStrength) * 0.12,
      bloomOpacity: 0.08 + actor.focusBeam * 0.18,
      particleCount: 5 + Math.round(clamp01(actor.presenceStrength) * 5),
      pulseMs: 2500,
      driftMs: 7800,
      railOpacity: 0.08 + clamp01(actor.presenceStrength) * 0.12,
    },
    release: {
      ...release,
      targetLabel: `${anchorLabel} and the adjacent strikecell field`,
    },
    runtime: buildRuntime(actor),
  };
}
