import type {
  ArtifactKind,
  SemanticAssignmentIndex,
  SemanticAttachment,
} from "../../huntTypes";
import type {
  SpiritRitualContext,
  SpiritRitualUploadDraft,
  SpiritRitualUploadItem,
} from "../state/types";
import { addKindScore, clamp, createKindScoreMap, rankKindScores, uniqueStrings } from "../modes/shared";
import type { SpiritUploadSelectionSummary } from "./types";

function appendSemanticHint(
  semanticHints: Record<string, Set<SemanticAttachment>>,
  assignments: SemanticAssignmentIndex,
): void {
  for (const [semantic, artifactIds] of Object.entries(assignments) as Array<
    [SemanticAttachment, string[]]
  >) {
    for (const artifactId of artifactIds) {
      semanticHints[artifactId] ??= new Set<SemanticAttachment>();
      semanticHints[artifactId].add(semantic);
    }
  }
}

function inferArtifactKindFromExternalFile(input: {
  mimeType?: string | null;
  extension?: string | null;
}): ArtifactKind {
  const mime = input.mimeType?.toLowerCase() ?? "";
  const extension = input.extension?.toLowerCase() ?? "";

  if (mime.includes("pdf") || extension === "pdf") return "receipt";
  if (mime.startsWith("image/") || ["png", "jpg", "jpeg", "heic"].includes(extension)) {
    return "evidence";
  }
  if (mime.startsWith("text/") || ["md", "txt", "rtf"].includes(extension)) {
    return "note";
  }
  return "file";
}

function toExtension(label: string): string | null {
  const parts = label.split(".");
  if (parts.length < 2) return null;
  return parts[parts.length - 1]?.toLowerCase() ?? null;
}

export function buildArtifactUploadItems(
  context: SpiritRitualContext,
): SpiritRitualUploadItem[] {
  const semanticHints: Record<string, Set<SemanticAttachment>> = {};
  appendSemanticHint(semanticHints, context.hunt.semanticAssignments);
  for (const runId of context.hunt.runIds) {
    const run = context.runs[runId];
    if (!run) continue;
    appendSemanticHint(semanticHints, run.semanticAssignments);
  }

  return context.hunt.artifactIds
    .map((artifactId) => context.artifacts[artifactId])
    .filter((artifact): artifact is NonNullable<typeof artifact> => Boolean(artifact))
    .map((artifact) => ({
      id: `artifact:${artifact.id}`,
      kind: "artifact-anchor",
      label: artifact.title,
      artifactId: artifact.id,
      artifactKind: artifact.kind,
      semanticHints: [...(semanticHints[artifact.id] ?? new Set<SemanticAttachment>())],
      mimeType: null,
      extension: toExtension(artifact.title),
      byteSize: null,
    }));
}

export function createExternalUploadItem(input: {
  id?: string;
  label: string;
  mimeType?: string | null;
  extension?: string | null;
  artifactKind?: ArtifactKind | null;
  byteSize?: number | null;
  semanticHints?: SemanticAttachment[];
}): SpiritRitualUploadItem {
  const extension = input.extension ?? toExtension(input.label);
  return {
    id: input.id ?? `upload:${input.label.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`,
    kind: "external-file",
    label: input.label,
    artifactId: null,
    artifactKind: input.artifactKind ?? inferArtifactKindFromExternalFile({
      mimeType: input.mimeType,
      extension,
    }),
    semanticHints: input.semanticHints ?? [],
    mimeType: input.mimeType ?? null,
    extension,
    byteSize: input.byteSize ?? null,
  };
}

export function summarizeSpiritUploadSelection(
  items: SpiritRitualUploadItem[],
): SpiritUploadSelectionSummary {
  const artifactKindCounts: Partial<Record<ArtifactKind, number>> = {};
  const semanticCounts: Partial<Record<SemanticAttachment, number>> = {};

  for (const item of items) {
    if (item.artifactKind) {
      artifactKindCounts[item.artifactKind] = (artifactKindCounts[item.artifactKind] ?? 0) + 1;
    }
    for (const semantic of item.semanticHints) {
      semanticCounts[semantic] = (semanticCounts[semantic] ?? 0) + 1;
    }
  }

  return {
    selectedCount: items.length,
    artifactKindCounts,
    semanticCounts,
  };
}

export function analyzeSpiritUploadDraft(
  draft: SpiritRitualUploadDraft,
): {
  summary: SpiritUploadSelectionSummary;
  scoredKinds: Array<{ kind: keyof ReturnType<typeof createKindScoreMap>; score: number }>;
  rationale: string[];
  focusSurfaces: string[];
  confidence: number;
  anchorArtifactIds: string[];
} {
  const selectedIdSet = new Set(draft.selectedItemIds);
  const selectedItems = draft.items.filter((item) => selectedIdSet.has(item.id));
  const summary = summarizeSpiritUploadSelection(selectedItems);
  const scores = createKindScoreMap();
  const focusSurfaces: string[] = [];
  const rationale: string[] = [];

  const addFocus = (...items: string[]) => {
    focusSurfaces.push(...items);
  };

  const artifactCounts = summary.artifactKindCounts;
  const semanticCounts = summary.semanticCounts;

  if ((artifactCounts.receipt ?? 0) > 0 || (artifactCounts.evidence ?? 0) > 0) {
    addKindScore(scores, "lantern", (artifactCounts.receipt ?? 0) * 18 + (artifactCounts.evidence ?? 0) * 14);
    addKindScore(scores, "ledger", (artifactCounts.receipt ?? 0) * 10 + (artifactCounts.evidence ?? 0) * 8);
    addFocus("Receipts", "Evidence");
    rationale.push("The selected anchors are proof-heavy and want a witness posture.");
  }

  if ((artifactCounts.file ?? 0) > 0 || (semanticCounts.mount ?? 0) > 0 || (semanticCounts["run-input"] ?? 0) > 0) {
    addKindScore(scores, "forge", (artifactCounts.file ?? 0) * 18 + (semanticCounts.mount ?? 0) * 16 + (semanticCounts["run-input"] ?? 0) * 18);
    addFocus("Files", "Mounts", "Run Input");
    rationale.push("The anchor set is full of mounted or executable material.");
  }

  if ((artifactCounts.entity ?? 0) > 0 || (artifactCounts.signal ?? 0) > 0 || (semanticCounts.target ?? 0) > 0 || (semanticCounts.watch ?? 0) > 0) {
    addKindScore(scores, "tracker", (artifactCounts.entity ?? 0) * 16 + (artifactCounts.signal ?? 0) * 12 + (semanticCounts.target ?? 0) * 16 + (semanticCounts.watch ?? 0) * 14);
    addKindScore(scores, "loom", (artifactCounts.entity ?? 0) * 8 + (artifactCounts.signal ?? 0) * 10);
    addFocus("Entities", "Watch", "Targets");
    rationale.push("The anchors are still pulling the hunt toward live targets and watched entities.");
  }

  if ((artifactCounts.note ?? 0) > 0 || (semanticCounts.notes ?? 0) > 0 || (semanticCounts.cite ?? 0) > 0 || (semanticCounts.compare ?? 0) > 0) {
    addKindScore(scores, "ledger", (artifactCounts.note ?? 0) * 16 + (semanticCounts.notes ?? 0) * 14 + (semanticCounts.cite ?? 0) * 14 + (semanticCounts.compare ?? 0) * 12);
    addKindScore(scores, "lantern", (semanticCounts.cite ?? 0) * 10);
    addFocus("Notes", "Citations", "Compare");
    rationale.push("The anchor set wants durable proof structure and comparison surfaces.");
  }

  if ((artifactCounts.query ?? 0) > 0 || (artifactCounts.snapshot ?? 0) > 0) {
    addKindScore(scores, "loom", (artifactCounts.query ?? 0) * 12 + (artifactCounts.snapshot ?? 0) * 8);
    addFocus("History", "Scopes");
    rationale.push("The anchors are clustering across multiple threads instead of one straight line.");
  }

  const ranking = rankKindScores(scores);
  const confidence = clamp(
    Math.round(40 + Math.min(24, selectedItems.length * 8) + Math.min(18, ranking[0]?.score ?? 0)),
    32,
    94,
  );
  const anchorArtifactIds = draft.preferredAnchorIds.length > 0
    ? draft.preferredAnchorIds.slice(0, 3)
    : selectedItems
        .map((item) => item.artifactId)
        .filter((artifactId): artifactId is string => Boolean(artifactId))
        .slice(0, 3);

  if (rationale.length === 0 && selectedItems.length > 0) {
    rationale.push("The selected anchors are giving the spirit a center of gravity.");
  }

  return {
    summary,
    scoredKinds: ranking,
    rationale,
    focusSurfaces: uniqueStrings(focusSurfaces),
    confidence,
    anchorArtifactIds,
  };
}

