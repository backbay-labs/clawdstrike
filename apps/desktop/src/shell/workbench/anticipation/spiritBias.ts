import {
  deriveHuntSpiritRuntimeState,
  getHuntSpiritMeta,
  type HuntSpiritState,
} from "../spirit";
import type { DropSemantic, IntentType } from "./types";
import type { LensId, ShellMode } from "../workbenchState";

export interface AnticipationSpiritBias {
  kind: string;
  label: string;
  mood: string;
  stance: string;
  preferredLens: LensId;
  preferredIntent: IntentType;
  preferredSemantics: DropSemantic[];
  wakeLabel: string;
  reason: string;
  confidenceGatePassed: boolean;
}

interface BuildAnticipationSpiritBiasInput {
  spirit: HuntSpiritState | null | undefined;
  currentShell: ShellMode;
  currentLens: LensId;
  likelyIntent: IntentType | null;
  confidenceScore: number;
  isAttachMode: boolean;
  hasActiveRun: boolean;
}

const SPIRIT_BIAS_BY_KIND = {
  tracker: {
    preferredLens: "entities",
    preferredIntent: "attach-target",
    preferredSemantics: ["target", "watch"],
    wakeLabel: "Follow likely target pivots",
    domainLabel: "targets and watch pivots",
  },
  lantern: {
    preferredLens: "notes",
    preferredIntent: "attach-evidence",
    preferredSemantics: ["evidence", "cite", "notes"],
    wakeLabel: "Collect proof into notes",
    domainLabel: "proof and witness surfaces",
  },
  forge: {
    preferredLens: "files",
    preferredIntent: "mount",
    preferredSemantics: ["mount", "run-input", "evidence"],
    wakeLabel: "Seat likely file inputs",
    domainLabel: "mounts and run inputs",
  },
  loom: {
    preferredLens: "scopes",
    preferredIntent: "watch",
    preferredSemantics: ["watch", "target", "compare"],
    wakeLabel: "Weave the next scope pivot",
    domainLabel: "scope and relation pivots",
  },
  ledger: {
    preferredLens: "notes",
    preferredIntent: "cite",
    preferredSemantics: ["cite", "compare", "notes"],
    wakeLabel: "Lock proof into case notes",
    domainLabel: "proof and case-ready notes",
  },
} as const satisfies Record<
  string,
  {
    preferredLens: LensId;
    preferredIntent: IntentType;
    preferredSemantics: DropSemantic[];
    wakeLabel: string;
    domainLabel: string;
  }
>;

function resolveSpiritBiasReason(
  label: string,
  stance: string,
  domainLabel: string,
  confidenceGatePassed: boolean,
): string {
  if (confidenceGatePassed) {
    return `${label} is in ${stance} stance, biasing ${domainLabel}.`;
  }
  return `${label} is present, but spirit bias stays quiet until confidence firms up.`;
}

export function buildAnticipationSpiritBias(
  input: BuildAnticipationSpiritBiasInput,
): AnticipationSpiritBias | null {
  if (!input.spirit) return null;

  const meta = getHuntSpiritMeta(input.spirit.kind);
  const biasDefaults = SPIRIT_BIAS_BY_KIND[input.spirit.kind];
  if (!meta || !biasDefaults) return null;

  const runtime = deriveHuntSpiritRuntimeState(input.spirit, {
    currentShell: input.currentShell,
    currentLens: input.currentLens,
    likelyIntent: input.likelyIntent,
    confidenceScore: input.confidenceScore,
    isAttachMode: input.isAttachMode,
    isActive: true,
  });

  const preferredLens =
    input.spirit.kind === "forge" && input.hasActiveRun ? "sandboxes" : biasDefaults.preferredLens;
  const preferredIntent =
    input.spirit.kind === "ledger" && input.currentShell === "case"
      ? "cite"
      : biasDefaults.preferredIntent;
  const spiritBiasScore = Math.round(
    ((input.confidenceScore * 0.55) + (input.spirit.confidenceScore * 0.45))
      + (runtime.stance === "focus" || runtime.stance === "absorb" || runtime.stance === "witness"
        ? 6
        : 0),
  );
  const confidenceGatePassed = spiritBiasScore >= 58;

  return {
    kind: input.spirit.kind,
    label: meta.label,
    mood: runtime.mood,
    stance: runtime.stance,
    preferredLens,
    preferredIntent,
    preferredSemantics: biasDefaults.preferredSemantics,
    wakeLabel: biasDefaults.wakeLabel,
    reason: resolveSpiritBiasReason(
      meta.label,
      runtime.stance,
      biasDefaults.domainLabel,
      confidenceGatePassed,
    ),
    confidenceGatePassed,
  };
}
