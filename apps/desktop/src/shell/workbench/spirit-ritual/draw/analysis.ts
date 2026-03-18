import type { HuntSpiritKind } from "../../spirit";
import type { SpiritRitualDrawDraft, SpiritRitualDrawStroke } from "../state/types";
import { addKindScore, clamp, createKindScoreMap, rankKindScores } from "../modes/shared";
import type { SpiritDrawAnalysis, SpiritDrawFeatures } from "./types";

interface Bounds {
  minX: number;
  maxX: number;
  minY: number;
  maxY: number;
}

function distance(left: { x: number; y: number }, right: { x: number; y: number }): number {
  return Math.hypot(right.x - left.x, right.y - left.y);
}

function classifyAngle(dx: number, dy: number): "horizontal" | "vertical" | "diagonal" {
  const absX = Math.abs(dx);
  const absY = Math.abs(dy);
  if (absX >= absY * 1.8) return "horizontal";
  if (absY >= absX * 1.8) return "vertical";
  return "diagonal";
}

function initBounds(): Bounds {
  return {
    minX: Number.POSITIVE_INFINITY,
    maxX: Number.NEGATIVE_INFINITY,
    minY: Number.POSITIVE_INFINITY,
    maxY: Number.NEGATIVE_INFINITY,
  };
}

function updateBounds(bounds: Bounds, x: number, y: number): void {
  bounds.minX = Math.min(bounds.minX, x);
  bounds.maxX = Math.max(bounds.maxX, x);
  bounds.minY = Math.min(bounds.minY, y);
  bounds.maxY = Math.max(bounds.maxY, y);
}

function overlaps(left: Bounds, right: Bounds): boolean {
  return left.minX <= right.maxX
    && left.maxX >= right.minX
    && left.minY <= right.maxY
    && left.maxY >= right.minY;
}

function strokeBounds(stroke: SpiritRitualDrawStroke): Bounds {
  const bounds = initBounds();
  for (const point of stroke.points) {
    updateBounds(bounds, point.x, point.y);
  }
  return bounds;
}

function buildEmptyFeatures(): SpiritDrawFeatures {
  return {
    strokeCount: 0,
    pointCount: 0,
    totalLength: 0,
    coverageRatio: 0,
    closureRatio: 0,
    orthogonalRatio: 0,
    horizontalRatio: 0,
    diagonalRatio: 0,
    crossingRatio: 0,
    centeredness: 0,
    jaggedness: 0,
    layeredness: 0,
  };
}

function emptyAnalysis(): SpiritDrawAnalysis {
  return {
    features: buildEmptyFeatures(),
    scoredKinds: [],
    rationale: [],
    focusSurfaces: [],
    confidence: 0,
  };
}

function deriveFeatures(draft: SpiritRitualDrawDraft): SpiritDrawFeatures {
  if (draft.strokes.length === 0) {
    return buildEmptyFeatures();
  }

  const globalBounds = initBounds();
  const boundsByStroke = draft.strokes.map((stroke) => strokeBounds(stroke));
  let pointCount = 0;
  let totalLength = 0;
  let closedCount = 0;
  let orthogonalCount = 0;
  let horizontalCount = 0;
  let diagonalCount = 0;
  let turnDelta = 0;
  let turnSamples = 0;
  let centroidDistance = 0;
  const canvasCenterX = draft.canvasWidth / 2;
  const canvasCenterY = draft.canvasHeight / 2;

  draft.strokes.forEach((stroke) => {
    pointCount += stroke.points.length;
    for (const point of stroke.points) {
      updateBounds(globalBounds, point.x, point.y);
      centroidDistance += distance(point, { x: canvasCenterX, y: canvasCenterY });
    }

    if (stroke.points.length >= 2) {
      const first = stroke.points[0];
      const last = stroke.points[stroke.points.length - 1];
      const strokeLength = stroke.points.slice(1).reduce((sum, point, index) => {
        const previous = stroke.points[index];
        return sum + distance(previous, point);
      }, 0);
      totalLength += strokeLength;

      if (strokeLength > 0 && distance(first, last) <= strokeLength * 0.16) {
        closedCount += 1;
      }
    }

    for (let index = 1; index < stroke.points.length; index += 1) {
      const previous = stroke.points[index - 1];
      const current = stroke.points[index];
      const dx = current.x - previous.x;
      const dy = current.y - previous.y;
      const classification = classifyAngle(dx, dy);

      if (classification === "horizontal" || classification === "vertical") {
        orthogonalCount += 1;
      }
      if (classification === "horizontal") {
        horizontalCount += 1;
      }
      if (classification === "diagonal") {
        diagonalCount += 1;
      }

      if (index >= 2) {
        const before = stroke.points[index - 2];
        const a1 = Math.atan2(previous.y - before.y, previous.x - before.x);
        const a2 = Math.atan2(current.y - previous.y, current.x - previous.x);
        turnDelta += Math.abs(a2 - a1);
        turnSamples += 1;
      }
    }
  });

  let overlapsCount = 0;
  const possibleOverlaps = Math.max(1, (boundsByStroke.length * (boundsByStroke.length - 1)) / 2);
  for (let left = 0; left < boundsByStroke.length; left += 1) {
    for (let right = left + 1; right < boundsByStroke.length; right += 1) {
      if (overlaps(boundsByStroke[left], boundsByStroke[right])) {
        overlapsCount += 1;
      }
    }
  }

  const bboxWidth = Math.max(1, globalBounds.maxX - globalBounds.minX);
  const bboxHeight = Math.max(1, globalBounds.maxY - globalBounds.minY);
  const coverageRatio = clamp((bboxWidth * bboxHeight) / (draft.canvasWidth * draft.canvasHeight), 0, 1);
  const avgCentroidDistance = pointCount > 0 ? centroidDistance / pointCount : 0;
  const maxCentroidDistance = Math.hypot(canvasCenterX, canvasCenterY);
  const centeredness = clamp(1 - avgCentroidDistance / Math.max(1, maxCentroidDistance), 0, 1);
  const layeredness = clamp(
    horizontalCount > 0
      ? (draft.strokes.length * (bboxHeight / Math.max(1, draft.canvasHeight))) * 0.8
      : 0,
    0,
    1,
  );

  const segmentCount = Math.max(1, pointCount - draft.strokes.length);

  return {
    strokeCount: draft.strokes.length,
    pointCount,
    totalLength,
    coverageRatio,
    closureRatio: clamp(closedCount / draft.strokes.length, 0, 1),
    orthogonalRatio: clamp(orthogonalCount / segmentCount, 0, 1),
    horizontalRatio: clamp(horizontalCount / segmentCount, 0, 1),
    diagonalRatio: clamp(diagonalCount / segmentCount, 0, 1),
    crossingRatio: clamp(overlapsCount / possibleOverlaps, 0, 1),
    centeredness,
    jaggedness: clamp(turnSamples > 0 ? turnDelta / (turnSamples * Math.PI) : 0, 0, 1),
    layeredness,
  };
}

function describe(features: SpiritDrawFeatures): string[] {
  const lines: string[] = [];
  if (features.closureRatio >= 0.4 && features.centeredness >= 0.45) {
    lines.push("The sketch keeps closing back on the center.");
  }
  if (features.orthogonalRatio >= 0.45) {
    lines.push("The geometry leans into brackets, rails, and mounted structure.");
  }
  if (features.crossingRatio >= 0.3) {
    lines.push("The lines are weaving across each other like a relationship map.");
  }
  if (features.horizontalRatio >= 0.3 && features.layeredness >= 0.2) {
    lines.push("The sketch stacks into ledger-like bands.");
  }
  if (lines.length === 0 && features.pointCount > 0) {
    lines.push("The sketch is starting to establish a posture, but it still wants more signal.");
  }
  return lines;
}

function focusSurfacesForTopKinds(kinds: HuntSpiritKind[]): string[] {
  const surfaces: string[] = [];
  for (const kind of kinds) {
    switch (kind) {
      case "tracker":
        surfaces.push("Entities", "Watch");
        break;
      case "lantern":
        surfaces.push("Receipts", "Evidence");
        break;
      case "forge":
        surfaces.push("Files", "Mounts");
        break;
      case "loom":
        surfaces.push("History", "Scopes");
        break;
      case "ledger":
        surfaces.push("Notes", "Citations");
        break;
    }
  }
  return [...new Set(surfaces)];
}

export function analyzeSpiritDrawDraft(
  draft: SpiritRitualDrawDraft,
): SpiritDrawAnalysis {
  if (draft.strokes.length === 0) {
    return emptyAnalysis();
  }

  const features = deriveFeatures(draft);
  const scores = createKindScoreMap();

  addKindScore(scores, "tracker", features.closureRatio * 24 + features.centeredness * 18 + features.diagonalRatio * 14);
  addKindScore(scores, "lantern", features.closureRatio * 18 + features.centeredness * 16 + (1 - features.coverageRatio) * 8);
  addKindScore(scores, "forge", features.orthogonalRatio * 26 + features.jaggedness * 12 + features.coverageRatio * 8);
  addKindScore(scores, "loom", features.crossingRatio * 30 + features.coverageRatio * 18 + features.diagonalRatio * 8);
  addKindScore(scores, "ledger", features.horizontalRatio * 24 + features.layeredness * 20 + features.orthogonalRatio * 8);

  const ranking = rankKindScores(scores);
  const focusKinds = ranking.slice(0, 2).map((entry) => entry.kind);
  const confidence = clamp(
    Math.round(
      32
        + Math.min(24, draft.strokes.length * 6)
        + Math.min(18, features.pointCount / 8)
        + Math.min(18, ranking[0]?.score ?? 0),
    ),
    24,
    92,
  );

  return {
    features,
    scoredKinds: ranking,
    rationale: describe(features),
    focusSurfaces: focusSurfacesForTopKinds(focusKinds),
    confidence,
  };
}

