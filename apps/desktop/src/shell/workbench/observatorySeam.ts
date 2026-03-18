import {
  HUNT_STATION_LABELS,
  HUNT_STATION_ORDER,
  type HuntStationId,
} from "@/features/hunt-observatory";
import type { ArtifactKind, Hunt, HuntStore, SemanticAssignmentIndex } from "./huntTypes";

const HUNT_STATION_CODES: Record<HuntStationId, string> = {
  signal: "SIG",
  targets: "TGT",
  run: "RUN",
  receipts: "RCP",
  "case-notes": "CAS",
  watch: "WTC",
};

export interface HuntObservatorySeamStation {
  stationId: HuntStationId;
  label: string;
  code: string;
  count: number;
}

export interface HuntObservatorySeamSummary {
  primaryStationId: HuntStationId | null;
  stations: HuntObservatorySeamStation[];
  activeRunLabel: string | null;
  caseTitle: string | null;
}

function addCount(
  counts: Partial<Record<HuntStationId, number>>,
  stationId: HuntStationId,
  amount: number,
): void {
  if (amount <= 0) return;
  counts[stationId] = (counts[stationId] ?? 0) + amount;
}

function addSemanticAssignments(
  counts: Partial<Record<HuntStationId, number>>,
  assignments: SemanticAssignmentIndex | null | undefined,
): void {
  if (!assignments) return;
  addCount(counts, "targets", assignments.target?.length ?? 0);
  addCount(counts, "receipts", assignments.evidence?.length ?? 0);
  addCount(counts, "run", assignments["run-input"]?.length ?? 0);
  addCount(counts, "run", assignments.mount?.length ?? 0);
  addCount(counts, "case-notes", assignments.notes?.length ?? 0);
  addCount(counts, "case-notes", assignments.cite?.length ?? 0);
  addCount(counts, "receipts", assignments.compare?.length ?? 0);
  addCount(counts, "watch", assignments.watch?.length ?? 0);
}

function addArtifactKind(
  counts: Partial<Record<HuntStationId, number>>,
  kind: ArtifactKind,
): void {
  switch (kind) {
    case "signal":
      addCount(counts, "signal", 1);
      break;
    case "entity":
      addCount(counts, "targets", 1);
      break;
    case "file":
      addCount(counts, "run", 1);
      break;
    case "receipt":
    case "evidence":
      addCount(counts, "receipts", 1);
      break;
    case "note":
      addCount(counts, "case-notes", 1);
      break;
    default:
      break;
  }
}

export function buildHuntObservatorySeamSummary(
  hunt: Hunt,
  huntStore: HuntStore,
): HuntObservatorySeamSummary {
  const counts: Partial<Record<HuntStationId, number>> = {};

  for (const artifactId of hunt.artifactIds) {
    const artifact = huntStore.artifacts[artifactId];
    if (!artifact) continue;
    addArtifactKind(counts, artifact.kind);
  }

  addSemanticAssignments(counts, hunt.semanticAssignments);

  let activeRunLabel: string | null = null;
  for (const runId of hunt.runIds) {
    const run = huntStore.runs[runId];
    if (!run) continue;
    if (run.status === "running" && !activeRunLabel) {
      activeRunLabel = run.label;
    }
    if (run.status === "running") addCount(counts, "run", 1);
    addSemanticAssignments(counts, run.semanticAssignments);
  }

  const caseTitle = hunt.caseId ? (huntStore.cases[hunt.caseId]?.title ?? null) : null;
  if (caseTitle) addCount(counts, "case-notes", 1);

  const stations = HUNT_STATION_ORDER.map((stationId) => ({
    stationId,
    label: HUNT_STATION_LABELS[stationId],
    code: HUNT_STATION_CODES[stationId],
    count: counts[stationId] ?? 0,
  }))
    .filter((station) => station.count > 0)
    .sort((left, right) => {
      if (right.count !== left.count) return right.count - left.count;
      return HUNT_STATION_ORDER.indexOf(left.stationId) - HUNT_STATION_ORDER.indexOf(right.stationId);
    });

  return {
    primaryStationId: stations[0]?.stationId ?? null,
    stations,
    activeRunLabel,
    caseTitle,
  };
}
