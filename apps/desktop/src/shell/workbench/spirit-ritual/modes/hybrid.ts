import type {
  SpiritRitualContext,
  SpiritRitualDraft,
  SpiritRitualPanelMode,
  SpiritRitualRecommendation,
  SpiritRitualSynthesis,
} from "../state/types";
import { analyzeDrawMode } from "./draw";
import { analyzeIntentionMode } from "./intention";
import {
  addKindScore,
  createKindScoreMap,
  deriveConfidenceScore,
  deriveLiveMood,
  focusSurfacesForKind,
  formatBiasLine,
  labelForKind,
  rankKindScores,
  summarizeRationale,
  uniqueStrings,
  uniqueSuggestions,
} from "./shared";
import { analyzeUploadMode } from "./upload";

function deriveRecommendation(
  context: SpiritRitualContext,
  _draft: SpiritRitualDraft,
  modeAnalyses: SpiritRitualSynthesis["modeAnalyses"],
  engagedModes: SpiritRitualPanelMode[],
): SpiritRitualRecommendation {
  const scores = createKindScoreMap();
  const rationale: string[] = [];
  const focusSurfaces: string[] = [];

  const applyWeightedAnalysis = (
    mode: SpiritRitualPanelMode,
    weight: number,
  ) => {
    const analysis = modeAnalyses[mode];
    if (!analysis || (!analysis.engaged && engagedModes.length > 0)) return;
    for (const entry of analysis.scoredKinds) {
      addKindScore(scores, entry.kind, entry.score * weight);
    }
    rationale.push(...analysis.rationale);
    focusSurfaces.push(...analysis.focusSurfaces);
  };

  applyWeightedAnalysis("intention", 1.1);
  applyWeightedAnalysis("draw", 0.95);
  applyWeightedAnalysis("upload", 1.05);

  if (context.hunt.spirit) {
    addKindScore(scores, context.hunt.spirit.kind, engagedModes.length === 0 ? 16 : 8);
    rationale.push(
      engagedModes.length === 0
        ? "The current spirit seed remains the starting posture until more ritual signal arrives."
        : "The current spirit seed is still influencing the draft.",
    );
  }

  const ranking = rankKindScores(scores);
  const primaryKind = ranking[0]?.kind ?? context.hunt.spirit?.kind ?? "tracker";
  const confidenceScore = engagedModes.length === 0 && context.hunt.spirit
    ? Math.max(52, context.hunt.spirit.confidenceScore)
    : deriveConfidenceScore(ranking, engagedModes.length > 1 ? 8 : engagedModes.length * 4);
  const resolvedFocus = uniqueStrings([
    ...focusSurfacesForKind(primaryKind),
    ...focusSurfaces,
  ]).slice(0, 4);

  return {
    kind: primaryKind,
    label: labelForKind(primaryKind),
    confidenceScore,
    rationale: summarizeRationale(
      rationale,
      context.hunt.spirit?.bindReason
        ?? "The ritual draft is gathering enough signal to choose a living posture.",
    ),
    alternates: ranking
      .slice(1, 3)
      .map((entry) => entry.kind)
      .filter((kind) => kind !== primaryKind),
    biasLine: formatBiasLine(resolvedFocus),
    focusSurfaces: resolvedFocus,
    liveMood: deriveLiveMood(
      primaryKind,
      confidenceScore,
      engagedModes,
      context.hunt.spirit?.liveMood ?? null,
    ),
  };
}

export function deriveSpiritRitualSynthesis(
  context: SpiritRitualContext,
  draft: SpiritRitualDraft,
): SpiritRitualSynthesis {
  const intention = analyzeIntentionMode(context, draft.intention);
  const draw = analyzeDrawMode(draft.draw);
  const upload = analyzeUploadMode(context, draft.upload);
  const modeAnalyses = {
    intention,
    draw,
    upload,
  } satisfies SpiritRitualSynthesis["modeAnalyses"];

  const engagedModes = (["intention", "draw", "upload"] as const).filter(
    (mode) => modeAnalyses[mode]?.engaged,
  );
  const resolvedMode = engagedModes.length > 1
    ? "hybrid"
    : engagedModes[0] ?? draft.activePanel;
  const recommendation = deriveRecommendation(context, draft, modeAnalyses, engagedModes);
  const suggestions = uniqueSuggestions([
    ...intention.suggestions,
    ...draw.suggestions,
    ...upload.suggestions,
  ]);
  const thesis = intention.thesis;
  const anchorArtifactIds = uniqueStrings([
    ...upload.anchorArtifactIds,
    ...(context.hunt.spirit?.anchorArtifactIds ?? []),
  ]).slice(0, 3);
  const readiness = {
    canRelease: Boolean(context.hunt.spirit) || engagedModes.length > 0,
    blockingReasons:
      Boolean(context.hunt.spirit) || engagedModes.length > 0
        ? []
        : ["No spirit seed or ritual signal is available yet."],
  };

  return {
    resolvedMode,
    engagedModes: [...engagedModes],
    modeAnalyses,
    suggestions,
    recommendation,
    thesis,
    anchorArtifactIds,
    readiness,
  };
}
