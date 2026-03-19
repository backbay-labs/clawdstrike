// Ported verbatim from huntronomer apps/desktop/src/features/hunt-observatory/stations.ts
// Contains HUNT_STATION_PLACEMENTS, HUNT_STATION_LABELS, HUNT_STATION_ORDER constants.
// Pure constant data — no external imports.

import type { HuntStationId, HuntStationPlacement } from "./types";

export const HUNT_STATION_ORDER: HuntStationId[] = [
  "signal",
  "targets",
  "run",
  "receipts",
  "case-notes",
  "watch",
];

export const HUNT_PRIMARY_STATION_ORDER: HuntStationId[] = [
  "signal",
  "targets",
  "run",
  "receipts",
  "case-notes",
];

export const HUNT_PERIMETER_STATION_ID: HuntStationId = "watch";
export const HUNT_CORE_LABEL = "Thesis Core";

export const HUNT_STATION_LABELS: Record<HuntStationId, string> = {
  signal: "Horizon",
  targets: "Subjects",
  run: "Operations",
  receipts: "Evidence",
  "case-notes": "Judgment",
  watch: "Watchfield",
};

export const HUNT_STATION_PLACEMENTS: HuntStationPlacement[] = [
  { id: "signal", label: HUNT_STATION_LABELS.signal, angleDeg: -132, radius: 1 },
  { id: "targets", label: HUNT_STATION_LABELS.targets, angleDeg: -54, radius: 1 },
  { id: "run", label: HUNT_STATION_LABELS.run, angleDeg: 6, radius: 1 },
  { id: "receipts", label: HUNT_STATION_LABELS.receipts, angleDeg: 66, radius: 1 },
  { id: "case-notes", label: HUNT_STATION_LABELS["case-notes"], angleDeg: 126, radius: 1 },
  { id: "watch", label: HUNT_STATION_LABELS.watch, angleDeg: 180, radius: 1.26 },
];
