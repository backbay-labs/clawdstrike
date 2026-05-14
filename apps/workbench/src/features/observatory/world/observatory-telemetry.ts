import type {
  AgentBaseline,
  AgentEvent,
  HuntPattern,
  Investigation,
} from "@/lib/workbench/hunt-types";
import type {
  ObservatoryStation,
  ObservatoryStationKind,
  ObservatoryExplanationCause,
  ObservatoryPressureLane,
  ObservatoryStationExplanation,
} from "../types";
import { HUNT_STATION_LABELS, HUNT_STATION_ORDER } from "./stations";
import type {
  HuntObservatoryReceiveState,
  HuntStationId,
  HuntStationStatus,
} from "./types";

const RECENT_WINDOW_MS = 90 * 60 * 1000;
const REPLAY_SPAN_MS = 24 * 60 * 60 * 1000;
const REPLAY_STEP_MS = 30 * 60 * 1000;
const SMOOTHING_ALPHA = 0.36;
const LEADER_SWAP_DELTA = 0.06;
const STATUS_HYSTERESIS = 0.08;

export interface ObservatoryRouteDescriptor {
  kind: ObservatoryStationKind;
  label: string;
  route: string;
}

export interface ObservatoryTelemetryInput {
  baselines?: AgentBaseline[];
  connected: boolean;
  events?: AgentEvent[];
  investigations?: Investigation[];
  nowMs?: number;
  patterns?: HuntPattern[];
  previousTelemetry?: DerivedObservatoryTelemetry | null;
  snapshotMs?: number | null;
}

export interface ObservatoryReplayFrame {
  eventCount: number;
  label: string;
  likelyStationId?: HuntStationId | null;
  spike?: boolean;
  timestampMs: number;
}

export interface DerivedObservatoryTelemetry {
  confidence: number;
  likelyStationId: HuntStationId | null;
  pressureLanes: ObservatoryPressureLane[];
  roomReceiveState: HuntObservatoryReceiveState;
  stations: ObservatoryStation[];
  telemetrySnapshotMs: number;
}

export interface ObservatoryReplayDistrictSnapshot {
  districtId: HuntStationId;
  label: string;
  status: HuntStationStatus | null;
  artifactCount: number;
  affinity: number;
  emphasis: number;
  route: string;
  routeLabel: string | null;
  reason: string | null;
  explanation: ObservatoryStationExplanation | null;
}

export interface ObservatoryReplaySnapshot {
  frameIndex: number;
  timestampMs: number;
  label: string;
  eventCount: number;
  confidence: number;
  likelyStationId: HuntStationId | null;
  roomReceiveState: HuntObservatoryReceiveState;
  districts: ObservatoryReplayDistrictSnapshot[];
}

export interface ObservatoryReplaySpike {
  frameIndex: number;
  timestampMs: number;
  districtId: HuntStationId;
  districtLabel: string;
  severity: "medium" | "high";
  summary: string;
  emphasisDelta: number;
  artifactDelta: number;
  statusBefore: HuntStationStatus | null;
  statusAfter: HuntStationStatus | null;
  reason: string | null;
}

export interface ObservatoryReplayTimeline {
  frames: ObservatoryReplayFrame[];
  snapshots: ObservatoryReplaySnapshot[];
  spikes: ObservatoryReplaySpike[];
}

const STATION_ROUTE_MAP: Record<HuntStationId, ObservatoryRouteDescriptor> = {
  signal: {
    kind: "hunt",
    label: "Hunt Stream",
    route: "/hunt",
  },
  targets: {
    kind: "hunt",
    label: "Pattern Mining",
    route: "/hunt?tab=patterns",
  },
  run: {
    kind: "missions",
    label: "Mission Control",
    route: "/missions",
  },
  receipts: {
    kind: "receipt-preview",
    label: "Receipt Preview",
    route: "/receipt-preview",
  },
  "case-notes": {
    kind: "findings",
    label: "Findings",
    route: "/findings",
  },
  watch: {
    kind: "nexus",
    label: "Nexus",
    route: "/nexus",
  },
};

function countUnique<T>(values: T[]): number {
  return new Set(values).size;
}

function compareStationOrder(left: HuntStationId, right: HuntStationId): number {
  return HUNT_STATION_ORDER.indexOf(left) - HUNT_STATION_ORDER.indexOf(right);
}

function normalizeScore(value: number, maxValue: number): number {
  if (maxValue <= 0) return 0;
  return Math.min(1, value / maxValue);
}

function formatPressureRead(label: string, count: number, detail: string): string {
  if (count <= 0) {
    return `${label} is holding a quiet posture. ${detail}`;
  }
  if (count === 1) {
    return `${label} is tracking 1 active pressure. ${detail}`;
  }
  return `${label} is tracking ${count} active pressures. ${detail}`;
}

function resolveStationStatus(input: {
  activeCount: number;
  connected: boolean;
  emphasis: number;
  receiving?: boolean;
}): HuntStationStatus {
  if (!input.connected && input.activeCount <= 0) {
    return "blocked";
  }
  if (input.receiving) {
    return "receiving";
  }
  if (input.activeCount >= 3 || input.emphasis >= 0.72) {
    return "active";
  }
  if (input.activeCount > 0 || input.emphasis >= 0.25) {
    return "warming";
  }
  return "idle";
}

function createEmptyCauseMap(): Record<HuntStationId, ObservatoryExplanationCause[]> {
  return {
    signal: [],
    targets: [],
    run: [],
    receipts: [],
    "case-notes": [],
    watch: [],
  };
}

function pushCause(
  buckets: Record<HuntStationId, ObservatoryExplanationCause[]>,
  stationId: HuntStationId,
  cause: Omit<ObservatoryExplanationCause, "route" | "routeLabel">,
): void {
  if (cause.count <= 0 || cause.weight <= 0) {
    return;
  }
  const route = resolveObservatoryStationRoute(stationId);
  buckets[stationId].push({
    ...cause,
    route: route.route,
    routeLabel: route.label,
  });
}

function buildObservatoryCauseBuckets(input: {
  ingressEvents: AgentEvent[];
  investigations: Investigation[];
  livePatterns: HuntPattern[];
  openInvestigations: Investigation[];
  operationsEvents: AgentEvent[];
  policyGapInvestigations: Investigation[];
  receiptEvents: AgentEvent[];
  targetEvents: AgentEvent[];
  watchEvents: AgentEvent[];
}): Record<HuntStationId, ObservatoryExplanationCause[]> {
  const buckets = createEmptyCauseMap();
  const ingressSessions = countUnique(input.ingressEvents.map((event) => event.sessionId));
  const targetAgents = countUnique(input.targetEvents.map((event) => event.agentId));
  const receiptIds = countUnique(
    input.receiptEvents.map((event) => event.receiptId ?? event.id),
  );
  const openAnnotationCount = input.openInvestigations.reduce(
    (sum, investigation) => sum + investigation.annotations.length,
    0,
  );

  pushCause(buckets, "signal", {
    id: "signal-ingress",
    kind: "traffic",
    label: "Ingress lanes",
    summary: "Recent fleet traffic is concentrating across the Horizon ingress lattice.",
    count: input.ingressEvents.length,
    weight: input.ingressEvents.length + ingressSessions * 0.45,
  });
  pushCause(buckets, "signal", {
    id: "signal-sessions",
    kind: "traffic",
    label: "Active ingress sessions",
    summary: "Multiple live sessions are keeping the Horizon sweep engaged.",
    count: ingressSessions,
    weight: ingressSessions * 0.8,
  });

  pushCause(buckets, "targets", {
    id: "targets-anomalies",
    kind: "anomaly",
    label: "Anomalous subject clusters",
    summary: "Elevated anomaly scores are clustering around live subject activity.",
    count: input.targetEvents.length,
    weight: input.targetEvents.length + targetAgents * 0.55,
  });
  pushCause(buckets, "targets", {
    id: "targets-patterns",
    kind: "pattern",
    label: "Confirmed patterns",
    summary: "Confirmed hunt patterns are reinforcing the current Subjects lane.",
    count: input.livePatterns.length,
    weight: input.livePatterns.length * 1.1,
  });

  pushCause(buckets, "run", {
    id: "run-operations",
    kind: "operations",
    label: "Execution pressure",
    summary: "Operator machinery is carrying the current execution load.",
    count: input.operationsEvents.length,
    weight: input.operationsEvents.length + countUnique(input.operationsEvents.map((event) => event.agentId)) * 0.5,
  });

  pushCause(buckets, "receipts", {
    id: "receipts-arrivals",
    kind: "receipt",
    label: "Receipt arrivals",
    summary: "Evidence receipts are accumulating faster than the archive can settle them.",
    count: input.receiptEvents.length,
    weight: input.receiptEvents.length + receiptIds * 0.55,
  });
  pushCause(buckets, "receipts", {
    id: "receipts-investigations",
    kind: "investigation",
    label: "Open investigations",
    summary: "Investigations are pinning new evidence arrivals to active analyst work.",
    count: input.openInvestigations.length,
    weight: input.openInvestigations.length * 1.25 + openAnnotationCount * 0.15,
  });
  pushCause(buckets, "receipts", {
    id: "receipts-policy-gap",
    kind: "policy-gap",
    label: "Policy drift",
    summary: "Policy-gap verdicts are keeping the receipt lane hot.",
    count: input.policyGapInvestigations.length,
    weight: input.policyGapInvestigations.length * 1.4,
  });

  pushCause(buckets, "case-notes", {
    id: "case-findings",
    kind: "investigation",
    label: "Authored findings",
    summary: "Investigations and annotations are hardening into authored findings.",
    count: input.openInvestigations.length,
    weight: input.openInvestigations.length * 1.05 + openAnnotationCount * 0.18,
  });
  pushCause(buckets, "case-notes", {
    id: "case-patterns",
    kind: "pattern",
    label: "Pattern corroboration",
    summary: "Live patterns are reinforcing the current Judgment track.",
    count: input.livePatterns.length,
    weight: input.livePatterns.length * 0.95,
  });
  pushCause(buckets, "case-notes", {
    id: "case-policy-gap",
    kind: "policy-gap",
    label: "Policy gap findings",
    summary: "Policy drift is being converted into new authored findings.",
    count: input.policyGapInvestigations.length,
    weight: input.policyGapInvestigations.length * 1.2,
  });

  pushCause(buckets, "watch", {
    id: "watch-alerts",
    kind: "watch",
    label: "Outer alerts",
    summary: "Denied or high-risk activity is keeping the outer watchfield awake.",
    count: input.watchEvents.length,
    weight: input.watchEvents.length + countUnique(input.watchEvents.map((event) => event.agentId)) * 0.5,
  });
  pushCause(buckets, "watch", {
    id: "watch-policy-gap",
    kind: "policy-gap",
    label: "Escalation watch",
    summary: "Escalations and policy drift are widening the watch perimeter.",
    count: input.policyGapInvestigations.length,
    weight: input.policyGapInvestigations.length * 0.8,
  });

  return buckets;
}

function rankObservatoryExplanationCauses(
  causes: ObservatoryExplanationCause[],
): ObservatoryExplanationCause[] {
  return [...causes].sort((left, right) => {
    if (right.weight !== left.weight) {
      return right.weight - left.weight;
    }
    if (right.count !== left.count) {
      return right.count - left.count;
    }
    return left.label.localeCompare(right.label);
  });
}

function buildExplanationSummary(
  stationLabel: string,
  causes: ObservatoryExplanationCause[],
): string {
  const [primary, secondary] = causes;
  if (!primary) {
    return `${stationLabel} is stable. Telemetry is not surfacing a dominant pressure source right now.`;
  }
  if (!secondary) {
    return `${stationLabel} is elevated because ${primary.summary.toLowerCase()}`;
  }
  return `${stationLabel} is elevated because ${primary.summary.toLowerCase()} ${secondary.summary}`;
}

function smoothNumeric(nextValue: number, previousValue?: number): number {
  if (previousValue == null) {
    return nextValue;
  }
  return previousValue + (nextValue - previousValue) * SMOOTHING_ALPHA;
}

const STATUS_WEIGHT: Record<HuntStationStatus, number> = {
  blocked: 0,
  idle: 1,
  warming: 2,
  receiving: 3,
  active: 4,
};

function applyStatusHysteresis(
  nextStatus: HuntStationStatus,
  previousStatus: HuntStationStatus | undefined,
  nextEmphasis: number,
  previousEmphasis: number | undefined,
  connected: boolean,
): HuntStationStatus {
  if (!previousStatus || previousEmphasis == null) {
    return nextStatus;
  }
  if (!connected && nextStatus === "blocked") {
    return nextStatus;
  }
  if (
    STATUS_WEIGHT[previousStatus] > STATUS_WEIGHT[nextStatus]
    && previousEmphasis - nextEmphasis <= STATUS_HYSTERESIS
  ) {
    return previousStatus;
  }
  return nextStatus;
}

function resolveObservatoryPrimaryLane(
  lanes: ObservatoryPressureLane[],
  previousTelemetry: DerivedObservatoryTelemetry | null | undefined,
): HuntStationId | null {
  if (lanes.length === 0) {
    return null;
  }
  const sorted = [...lanes].sort((left, right) => {
    if (right.score !== left.score) {
      return right.score - left.score;
    }
    return compareStationOrder(left.stationId, right.stationId);
  });
  const candidate = sorted[0];
  const previousPrimaryId =
    previousTelemetry?.pressureLanes.find((lane) => lane.isPrimary)?.stationId
    ?? previousTelemetry?.likelyStationId
    ?? null;
  if (!previousPrimaryId || previousPrimaryId === candidate.stationId) {
    return candidate.stationId;
  }
  const previousLane = lanes.find((lane) => lane.stationId === previousPrimaryId);
  if (!previousLane) {
    return candidate.stationId;
  }
  if (candidate.score - previousLane.score < LEADER_SWAP_DELTA) {
    return previousPrimaryId;
  }
  return candidate.stationId;
}

function applyObservatoryLaneSmoothing(input: {
  connected: boolean;
  nextLanes: ObservatoryPressureLane[];
  nextStations: ObservatoryStation[];
  previousTelemetry?: DerivedObservatoryTelemetry | null;
}): Pick<DerivedObservatoryTelemetry, "likelyStationId" | "pressureLanes" | "stations"> {
  const previousLaneMap = new Map(
    (input.previousTelemetry?.pressureLanes ?? []).map((lane) => [lane.stationId, lane]),
  );
  const previousStationMap = new Map(
    (input.previousTelemetry?.stations ?? []).map((station) => [station.id, station]),
  );

  const smoothedStations = input.nextStations.map((station) => {
    const previousStation = previousStationMap.get(station.id);
    const affinity = smoothNumeric(station.affinity ?? 0, previousStation?.affinity);
    const emphasis = smoothNumeric(station.emphasis ?? 0, previousStation?.emphasis);
    return {
      ...station,
      affinity,
      emphasis,
      explanation: station.explanation
        ? {
            ...station.explanation,
            primaryLaneId: input.previousTelemetry?.likelyStationId ?? null,
          }
        : null,
      status: applyStatusHysteresis(
        station.status ?? "idle",
        previousStation?.status,
        emphasis,
        previousStation?.emphasis,
        input.connected,
      ),
    };
  });

  const smoothedLaneSeed = input.nextLanes.map((lane) => {
    const previousLane = previousLaneMap.get(lane.stationId);
    const station = smoothedStations.find((candidate) => candidate.id === lane.stationId);
    return {
      ...lane,
      affinity: station?.affinity ?? lane.affinity,
      emphasis: station?.emphasis ?? lane.emphasis,
      score: smoothNumeric(lane.score, previousLane?.score),
      status: station?.status ?? lane.status,
    };
  });

  const primaryLaneId = resolveObservatoryPrimaryLane(smoothedLaneSeed, input.previousTelemetry);
  const pressureLanes = [...smoothedLaneSeed]
    .sort((left, right) => {
      if (left.stationId === primaryLaneId) return -1;
      if (right.stationId === primaryLaneId) return 1;
      if (right.score !== left.score) {
        return right.score - left.score;
      }
      return compareStationOrder(left.stationId, right.stationId);
    })
    .map((lane, index) => ({
      ...lane,
      isPrimary: lane.stationId === primaryLaneId,
      rank: index + 1,
    }));

  const stations = smoothedStations.map((station) => ({
    ...station,
    explanation: station.explanation
      ? {
          ...station.explanation,
          primaryLaneId,
        }
      : null,
  }));

  return {
    likelyStationId: primaryLaneId,
    pressureLanes,
    stations,
  };
}

export function resolveObservatoryStationRoute(
  stationId: HuntStationId,
): ObservatoryRouteDescriptor {
  return STATION_ROUTE_MAP[stationId];
}

export function buildObservatoryReplayFrames(
  events: AgentEvent[],
  nowMs = Date.now(),
): ObservatoryReplayFrame[] {
  const horizonStartMs = nowMs - REPLAY_SPAN_MS;
  const relevantEvents = events
    .map((event) => Date.parse(event.timestamp))
    .filter((timestampMs) => Number.isFinite(timestampMs) && timestampMs >= horizonStartMs)
    .sort((left, right) => left - right);

  const firstFrameMs = relevantEvents[0] ?? horizonStartMs;
  const startMs = Math.max(horizonStartMs, firstFrameMs);
  const frames: ObservatoryReplayFrame[] = [];

  for (let timestampMs = startMs; timestampMs <= nowMs; timestampMs += REPLAY_STEP_MS) {
    frames.push({
      eventCount: relevantEvents.filter((eventMs) => eventMs <= timestampMs).length,
      label: new Date(timestampMs).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }),
      timestampMs,
    });
  }

  if (frames.length === 0 || frames[frames.length - 1]?.timestampMs !== nowMs) {
    frames.push({
      eventCount: relevantEvents.filter((eventMs) => eventMs <= nowMs).length,
      label: "Now",
      timestampMs: nowMs,
    });
  }

  return frames;
}

function compareReplayDistrictOrder(
  left: ObservatoryReplayDistrictSnapshot,
  right: ObservatoryReplayDistrictSnapshot,
): number {
  if (right.emphasis !== left.emphasis) {
    return right.emphasis - left.emphasis;
  }
  if (right.artifactCount !== left.artifactCount) {
    return right.artifactCount - left.artifactCount;
  }
  return left.label.localeCompare(right.label);
}

function formatReplaySignedDelta(value: number): string {
  const rounded = Math.round(value * 100) / 100;
  return `${rounded >= 0 ? "+" : ""}${rounded.toFixed(2)}`;
}

function getReplayPrimaryDistrict(
  snapshot: ObservatoryReplaySnapshot,
): ObservatoryReplayDistrictSnapshot | null {
  return snapshot.districts.reduce<ObservatoryReplayDistrictSnapshot | null>((best, current) => {
    if (!best) {
      return current;
    }
    return compareReplayDistrictOrder(current, best) < 0 ? current : best;
  }, null);
}

export function buildObservatoryReplaySnapshot(input: {
  frame: ObservatoryReplayFrame;
  frameIndex: number;
  telemetry: DerivedObservatoryTelemetry;
}): ObservatoryReplaySnapshot {
  return {
    confidence: input.telemetry.confidence,
    districts: input.telemetry.stations.map((station) => ({
      affinity: station.affinity ?? 0,
      artifactCount: station.artifactCount,
      districtId: station.id,
      emphasis: station.emphasis ?? 0,
      explanation: station.explanation ?? null,
      label: station.label,
      reason: station.reason ?? station.explanation?.summary ?? null,
      route: station.route,
      routeLabel: station.routeLabel ?? null,
      status: station.status ?? null,
    })),
    eventCount: input.frame.eventCount,
    frameIndex: input.frameIndex,
    label: input.frame.label,
    likelyStationId: input.telemetry.likelyStationId,
    roomReceiveState: input.telemetry.roomReceiveState,
    timestampMs: input.frame.timestampMs,
  };
}

export function buildObservatoryReplayTimeline(
  input: ObservatoryTelemetryInput,
): ObservatoryReplayTimeline {
  const frames = buildObservatoryReplayFrames(input.events ?? [], input.nowMs ?? Date.now());
  const snapshots = frames.map((frame, frameIndex) =>
    buildObservatoryReplaySnapshot({
      frame,
      frameIndex,
      telemetry: deriveObservatoryTelemetry({
        ...input,
        snapshotMs: frame.timestampMs,
      }),
    }),
  );
  return {
    frames,
    snapshots,
    spikes: detectObservatoryReplaySpikes(snapshots),
  };
}

export function detectObservatoryReplaySpikes(
  snapshots: ObservatoryReplaySnapshot[],
): ObservatoryReplaySpike[] {
  const spikes: ObservatoryReplaySpike[] = [];

  for (let index = 1; index < snapshots.length; index += 1) {
    const previous = snapshots[index - 1];
    const current = snapshots[index];
    const previousDistricts = new Map(previous.districts.map((district) => [district.districtId, district]));
    const previousPrimary = getReplayPrimaryDistrict(previous);
    const currentPrimary = getReplayPrimaryDistrict(current);

    for (const district of current.districts) {
      const before = previousDistricts.get(district.districtId);
      if (!before) {
        continue;
      }

      const emphasisDelta = district.emphasis - before.emphasis;
      const artifactDelta = district.artifactCount - before.artifactCount;
      const statusChanged = before.status !== district.status;
      const enteredHotState = statusChanged && district.status !== null && district.status !== "idle";
      const emphasisSpike = Math.abs(emphasisDelta) >= 0.18;
      const artifactSpike = artifactDelta >= 3 && enteredHotState;
      const primaryMoved =
        current.likelyStationId !== previous.likelyStationId
        && previousPrimary !== null
        && currentPrimary !== null
        && currentPrimary.districtId === district.districtId
        && previousPrimary.districtId !== currentPrimary.districtId
        && Math.abs(currentPrimary.emphasis - previousPrimary.emphasis) >= 0.12;

      if (!emphasisSpike && !artifactSpike && !primaryMoved) {
        continue;
      }

      const movementScore =
        Math.abs(emphasisDelta)
        + Math.min(1, Math.abs(artifactDelta) / 6)
        + (statusChanged ? 0.12 : 0)
        + (primaryMoved ? 0.1 : 0);
      const severity =
        movementScore >= 0.72 || Math.abs(emphasisDelta) >= 0.28 || Math.abs(artifactDelta) >= 5
          ? "high"
          : "medium";
      const summaryReason = district.reason ?? before.reason ?? "Telemetry is still settling.";
      const statusTransition = statusChanged
        ? `${before.status ?? "unknown"} to ${district.status ?? "unknown"}`
        : `${district.status ?? "steady"}`;

      spikes.push({
        artifactDelta,
        districtId: district.districtId,
        districtLabel: district.label,
        emphasisDelta,
        frameIndex: current.frameIndex,
        reason: district.reason ?? null,
        severity,
        statusAfter: district.status,
        statusBefore: before.status,
        summary: `${district.label} shifted from ${statusTransition} (${formatReplaySignedDelta(artifactDelta)} artifacts, ${formatReplaySignedDelta(emphasisDelta)} emphasis). ${summaryReason}`,
        timestampMs: current.timestampMs,
      });
    }
  }

  return spikes;
}

export function findObservatoryReplaySpikeFrameIndex(
  spikes: ObservatoryReplaySpike[],
  currentFrameIndex: number,
  direction: "prev" | "next",
): number | null {
  const ordered = [...spikes].sort((left, right) => left.frameIndex - right.frameIndex);

  if (direction === "prev") {
    for (let index = ordered.length - 1; index >= 0; index -= 1) {
      if (ordered[index].frameIndex < currentFrameIndex) {
        return ordered[index].frameIndex;
      }
    }
    return null;
  }

  for (const spike of ordered) {
    if (spike.frameIndex > currentFrameIndex) {
      return spike.frameIndex;
    }
  }

  return null;
}

export function deriveObservatoryTelemetry({
  baselines = [],
  connected,
  events = [],
  investigations = [],
  nowMs = Date.now(),
  patterns = [],
  previousTelemetry = null,
  snapshotMs = null,
}: ObservatoryTelemetryInput): DerivedObservatoryTelemetry {
  const effectiveNowMs = snapshotMs ?? nowMs;
  const horizonStartMs = effectiveNowMs - REPLAY_SPAN_MS;
  const recentStartMs = effectiveNowMs - RECENT_WINDOW_MS;
  const boundedEvents = events.filter((event) => {
    const timestampMs = Date.parse(event.timestamp);
    return Number.isFinite(timestampMs) && timestampMs >= horizonStartMs && timestampMs <= effectiveNowMs;
  });
  const recentEvents = boundedEvents.filter((event) => Date.parse(event.timestamp) >= recentStartMs);
  const openInvestigations = investigations.filter(
    (investigation) => investigation.status === "open" || investigation.status === "in-progress",
  );
  const policyGapInvestigations = investigations.filter(
    (investigation) => investigation.verdict === "policy-gap",
  );
  const livePatterns = patterns.filter((pattern) => pattern.status !== "dismissed");
  const baselineAgents = baselines.length > 0 ? baselines.length : countUnique(recentEvents.map((event) => event.agentId));

  const ingressEvents = recentEvents.filter(
    (event) => event.actionType === "network_egress" || event.actionType === "user_input",
  );
  const targetEvents = recentEvents.filter(
    (event) => (event.anomalyScore ?? 0) >= 0.55,
  );
  const operationsEvents = recentEvents.filter((event) =>
    event.actionType === "shell_command"
    || event.actionType === "mcp_tool_call"
    || event.actionType === "patch_apply",
  );
  const receiptEvents = recentEvents.filter((event) =>
    Boolean(event.receiptId)
    || event.verdict !== "allow"
    || event.guardResults.length > 0,
  );
  const watchEvents = recentEvents.filter((event) =>
    event.verdict === "deny"
    || (event.anomalyScore ?? 0) >= 0.72,
  );
  const judgmentPressure = openInvestigations.length + livePatterns.length + policyGapInvestigations.length;
  const causeBuckets = buildObservatoryCauseBuckets({
    ingressEvents,
    investigations,
    livePatterns,
    openInvestigations,
    operationsEvents,
    policyGapInvestigations,
    receiptEvents,
    targetEvents,
    watchEvents,
  });

  const stationRawPressure: Record<HuntStationId, number> = {
    signal: causeBuckets.signal.reduce((sum, cause) => sum + cause.weight, 0),
    targets: causeBuckets.targets.reduce((sum, cause) => sum + cause.weight, 0),
    run: causeBuckets.run.reduce((sum, cause) => sum + cause.weight, 0),
    receipts: causeBuckets.receipts.reduce((sum, cause) => sum + cause.weight, 0),
    "case-notes": causeBuckets["case-notes"].reduce((sum, cause) => sum + cause.weight, 0),
    watch: causeBuckets.watch.reduce((sum, cause) => sum + cause.weight, 0),
  };
  const maxPressure = Math.max(...Object.values(stationRawPressure), 1);
  const provisionalPrimaryLaneId = HUNT_STATION_ORDER.reduce<HuntStationId | null>((best, stationId) => {
    if (best == null) {
      return stationId;
    }
    return stationRawPressure[stationId] > stationRawPressure[best] ? stationId : best;
  }, null);
  const evidenceReceiving =
    receiptEvents.length > 0 && receiptEvents.length >= Math.max(2, operationsEvents.length);

  const stations: ObservatoryStation[] = HUNT_STATION_ORDER.map((stationId) => {
    const route = resolveObservatoryStationRoute(stationId);
    const pressure = stationRawPressure[stationId];
    const emphasisBase = normalizeScore(pressure, maxPressure);
    const rankedCauses = rankObservatoryExplanationCauses(causeBuckets[stationId]);
    const affinity =
      stationId === "signal"
        ? normalizeScore(countUnique(ingressEvents.map((event) => event.sessionId)), Math.max(1, baselineAgents))
        : stationId === "targets"
          ? normalizeScore(countUnique(targetEvents.map((event) => event.agentId)), Math.max(1, baselineAgents))
          : stationId === "run"
            ? normalizeScore(countUnique(operationsEvents.map((event) => event.agentId)), Math.max(1, baselineAgents))
            : stationId === "receipts"
              ? normalizeScore(countUnique(receiptEvents.map((event) => event.receiptId ?? event.id)), Math.max(1, boundedEvents.length))
              : stationId === "case-notes"
                ? normalizeScore(judgmentPressure, Math.max(1, openInvestigations.length + livePatterns.length + 1))
                : normalizeScore(countUnique(watchEvents.map((event) => event.agentId)), Math.max(1, baselineAgents));
    const emphasis = Math.min(
      1,
      emphasisBase * 0.72
        + affinity * 0.2
        + (provisionalPrimaryLaneId === stationId ? 0.08 : 0),
    );
    const status = resolveStationStatus({
      activeCount: pressure,
      connected,
      emphasis,
      receiving: stationId === "receipts" && evidenceReceiving,
    });
    const artifactCount =
      stationId === "signal"
        ? ingressEvents.length
        : stationId === "targets"
          ? targetEvents.length
          : stationId === "run"
            ? operationsEvents.length
            : stationId === "receipts"
              ? receiptEvents.length
              : stationId === "case-notes"
                ? judgmentPressure
                : watchEvents.length;
    const reason =
      rankedCauses.length > 0
        ? buildExplanationSummary(HUNT_STATION_LABELS[stationId], rankedCauses)
        : stationId === "signal"
          ? formatPressureRead(HUNT_STATION_LABELS[stationId], artifactCount, "Ingress lanes are reacting to recent fleet traffic.")
          : stationId === "targets"
            ? formatPressureRead(HUNT_STATION_LABELS[stationId], artifactCount, "The anomaly field is clustering around live subjects.")
            : stationId === "run"
              ? formatPressureRead(HUNT_STATION_LABELS[stationId], artifactCount, "Operator machinery is carrying the current execution load.")
              : stationId === "receipts"
                ? formatPressureRead(HUNT_STATION_LABELS[stationId], artifactCount, "Evidence receipts and policy checks are accumulating.")
                : stationId === "case-notes"
                  ? formatPressureRead(HUNT_STATION_LABELS[stationId], artifactCount, "Investigations, patterns, and policy gaps are hardening into authored findings.")
                  : formatPressureRead(HUNT_STATION_LABELS[stationId], artifactCount, "Peripheral anomalies are keeping the watchfield awake.");

    return {
      affinity,
      artifactCount,
      emphasis,
      explanation: {
        causes: rankedCauses,
        generatedAtMs: effectiveNowMs,
        primaryLaneId: provisionalPrimaryLaneId,
        stationId,
        summary: reason,
      },
      hasUnread: artifactCount > 0,
      id: stationId,
      kind: route.kind,
      label: HUNT_STATION_LABELS[stationId],
      reason,
      route: route.route,
      routeLabel: route.label,
      status,
    };
  });

  const nextLanes: ObservatoryPressureLane[] = stations.map((station) => ({
    affinity: station.affinity ?? 0,
    emphasis: station.emphasis ?? 0,
    isPrimary: false,
    label: station.label,
    rank: 0,
    rawPressure: stationRawPressure[station.id],
    route: station.route,
    routeLabel: station.routeLabel ?? station.label,
    score: Math.min(
      1,
      normalizeScore(stationRawPressure[station.id], maxPressure) * 0.7
        + (station.affinity ?? 0) * 0.3,
    ),
    stationId: station.id,
    status: station.status ?? "idle",
  }));
  const stabilizedTelemetry = applyObservatoryLaneSmoothing({
    connected,
    nextLanes,
    nextStations: stations,
    previousTelemetry,
  });

  return {
    confidence: Math.min(0.98, 0.3 + Math.log10(boundedEvents.length + 1) * 0.28),
    likelyStationId: stabilizedTelemetry.likelyStationId,
    pressureLanes: stabilizedTelemetry.pressureLanes,
    roomReceiveState:
      evidenceReceiving
      || (
        previousTelemetry?.roomReceiveState === "receiving"
        && (stabilizedTelemetry.pressureLanes.find((lane) => lane.stationId === "receipts")?.score ?? 0) > 0.35
      )
        ? "receiving"
        : boundedEvents.length > 0
          ? "aftermath"
          : "idle",
    stations: stabilizedTelemetry.stations,
    telemetrySnapshotMs: effectiveNowMs,
  };
}
