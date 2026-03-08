/**
 * Hunt domain model types and factory functions.
 *
 * Core entities: Hunt, Run, Artifact, Case
 * State containers: HuntDockState, HuntStore
 */

export type HuntStatus = "active" | "paused" | "completed" | "archived";
export type RunStatus = "running" | "completed" | "failed" | "cancelled";
export type CaseStatus = "open" | "investigating" | "resolved" | "closed";
export type ArtifactKind =
  | "signal"
  | "entity"
  | "file"
  | "receipt"
  | "note"
  | "query"
  | "snapshot"
  | "evidence";

export type SemanticAttachment =
  | "target"
  | "evidence"
  | "run-input"
  | "notes"
  | "watch"
  | "mount"
  | "cite"
  | "compare";

export interface SemanticAssignmentIndex {
  [semantic: string]: string[];
}

export interface Artifact {
  id: string;
  kind: ArtifactKind;
  title: string;
  sourceUri: string;
  createdAt: number;
  metadata?: Record<string, unknown>;
}

export interface Run {
  id: string;
  huntId: string;
  label: string;
  status: RunStatus;
  artifactIds: string[];
  semanticAssignments: SemanticAssignmentIndex;
}

export interface Hunt {
  id: string;
  title: string;
  status: HuntStatus;
  artifactIds: string[];
  runIds: string[];
  caseId: string | null;
  color: string;
  icon: string;
  semanticAssignments: SemanticAssignmentIndex;
}

export interface Case {
  id: string;
  title: string;
  status: CaseStatus;
  huntIds: string[];
  artifactIds: string[];
  semanticAssignments: SemanticAssignmentIndex;
}

export interface HuntDockState {
  activeHuntId: string | null;
  recentHuntIds: string[];
  pinnedHuntIds: string[];
  collapsed: boolean;
  bucketSummaryCollapsed: boolean;
}

export interface HuntStore {
  hunts: Record<string, Hunt>;
  runs: Record<string, Run>;
  artifacts: Record<string, Artifact>;
  cases: Record<string, Case>;
  dock: HuntDockState;
}

// ── Factory Functions ──────────────────────────────────────────────

let idCounter = 0;

function uid(prefix: string): string {
  return `${prefix}_${Date.now()}_${++idCounter}`;
}

export function createHuntId(): string {
  return uid("hunt");
}
export function createRunId(): string {
  return uid("run");
}
export function createArtifactId(): string {
  return uid("art");
}
export function createCaseId(): string {
  return uid("case");
}

export function createInitialHuntStore(): HuntStore {
  // Seed demo hunts so the dock has interactive pills on first launch
  const now = Date.now();

  const demoArtifacts: Record<string, Artifact> = {
    "art_demo_1": { id: "art_demo_1", kind: "signal", title: "Suspicious lateral movement", sourceUri: "alerts://siem/lat-001", createdAt: now - 3600_000 },
    "art_demo_2": { id: "art_demo_2", kind: "entity", title: "10.0.12.47", sourceUri: "entities://host/10.0.12.47", createdAt: now - 2400_000 },
    "art_demo_3": { id: "art_demo_3", kind: "file", title: "payload.bin", sourceUri: "files://samples/payload.bin", createdAt: now - 1800_000 },
    "art_demo_4": { id: "art_demo_4", kind: "receipt", title: "Guard evaluation #4481", sourceUri: "receipts://eval/4481", createdAt: now - 1200_000 },
    "art_demo_5": { id: "art_demo_5", kind: "entity", title: "svc-admin@corp.local", sourceUri: "entities://identity/svc-admin", createdAt: now - 900_000 },
    "art_demo_6": { id: "art_demo_6", kind: "note", title: "C2 beacon analysis", sourceUri: "notes://hunt-1/c2-beacon", createdAt: now - 600_000 },
    "art_demo_7": { id: "art_demo_7", kind: "evidence", title: "Memory dump 0x7FF", sourceUri: "evidence://memdump/7ff", createdAt: now - 300_000 },
    "art_demo_8": { id: "art_demo_8", kind: "signal", title: "DNS exfil pattern", sourceUri: "alerts://siem/dns-exfil-002", createdAt: now - 120_000 },
  };

  const demoRuns: Record<string, Run> = {
    "run_demo_1": {
      id: "run_demo_1",
      huntId: "hunt_demo_1",
      label: "YARA scan",
      status: "running",
      artifactIds: ["art_demo_3"],
      semanticAssignments: { mount: ["art_demo_3"] },
    },
    "run_demo_2": {
      id: "run_demo_2",
      huntId: "hunt_demo_2",
      label: "Entity graph",
      status: "completed",
      artifactIds: ["art_demo_5"],
      semanticAssignments: { target: ["art_demo_5"] },
    },
  };

  const demoHunts: Record<string, Hunt> = {
    "hunt_demo_1": {
      id: "hunt_demo_1", title: "Lateral Movement", status: "active",
      artifactIds: ["art_demo_1", "art_demo_2", "art_demo_3", "art_demo_6"],
      runIds: ["run_demo_1"],
      caseId: null,
      color: "#d4a84b",
      icon: "crosshair",
      semanticAssignments: {
        target: ["art_demo_2"],
        evidence: ["art_demo_3"],
        notes: ["art_demo_6"],
      },
    },
    "hunt_demo_2": {
      id: "hunt_demo_2", title: "Credential Abuse", status: "active",
      artifactIds: ["art_demo_4", "art_demo_5"],
      runIds: ["run_demo_2"],
      caseId: null,
      color: "#3dbf84",
      icon: "shield",
      semanticAssignments: {
        evidence: ["art_demo_4"],
        target: ["art_demo_5"],
      },
    },
    "hunt_demo_3": {
      id: "hunt_demo_3", title: "C2 Infrastructure", status: "paused",
      artifactIds: ["art_demo_7", "art_demo_8"],
      runIds: [],
      caseId: null,
      color: "#c45c5c",
      icon: "radar",
      semanticAssignments: {
        evidence: ["art_demo_7"],
        watch: ["art_demo_8"],
      },
    },
  };

  return {
    hunts: demoHunts,
    runs: demoRuns,
    artifacts: demoArtifacts,
    cases: {},
    dock: {
      activeHuntId: "hunt_demo_1",
      recentHuntIds: ["hunt_demo_1", "hunt_demo_2", "hunt_demo_3"],
      pinnedHuntIds: ["hunt_demo_1"],
      collapsed: false,
      bucketSummaryCollapsed: false,
    },
  };
}

// ── Utilities ──────────────────────────────────────────────────────

export function groupArtifactsByKind(
  artifactIds: string[],
  artifacts: Record<string, Artifact>,
): Record<ArtifactKind, number> {
  const counts: Record<string, number> = {};
  for (const id of artifactIds) {
    const a = artifacts[id];
    if (a) counts[a.kind] = (counts[a.kind] ?? 0) + 1;
  }
  return counts as Record<ArtifactKind, number>;
}

export function formatArtifactBreakdown(counts: Record<ArtifactKind, number>): string {
  const LABELS: Partial<Record<ArtifactKind, string>> = {
    signal: "signals",
    entity: "entities",
    file: "files",
    receipt: "receipts",
    note: "notes",
    query: "queries",
    snapshot: "snapshots",
    evidence: "evidence",
  };
  return Object.entries(counts)
    .filter(([, n]) => n > 0)
    .map(([k, n]) => `${n} ${LABELS[k as ArtifactKind] ?? k}`)
    .join(" \u00b7 ");
}

export function formatSemanticAssignments(assignments: SemanticAssignmentIndex): string {
  const LABELS: Record<string, string> = {
    target: "targets",
    evidence: "evidence",
    watch: "watch",
    notes: "notes",
    "run-input": "inputs",
    mount: "mounts",
    cite: "citations",
    compare: "comparisons",
  };

  return Object.entries(assignments)
    .filter(([, ids]) => ids.length > 0)
    .map(([semantic, ids]) => `${ids.length} ${LABELS[semantic] ?? semantic}`)
    .join(" · ");
}

// ── Palette ────────────────────────────────────────────────────────

export const HUNT_COLORS = [
  "#d4a84b",
  "#3dbf84",
  "#6f7f9a",
  "#c77d2e",
  "#7a6f8f",
  "#c45c5c",
  "#6b8cbe",
  "#8fa87a",
] as const;

export const HUNT_ICONS = [
  "crosshair",
  "shield",
  "search",
  "alert",
  "radar",
  "bug",
  "lock",
  "target",
] as const;
