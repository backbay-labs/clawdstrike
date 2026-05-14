import type { AgentEvent, Investigation } from "@/lib/workbench/hunt-types";
import type { ObservatoryStation } from "../types";
import { resolveObservatoryStationRoute } from "./observatory-telemetry";
import type { ObservatoryProbeState } from "./probeRuntime";
import type { HuntObservatoryMode, HuntStationId } from "./types";

export type ObservatoryGhostSourceKind = "finding" | "receipt";
export type ObservatoryGhostPresentation = "off" | "auto" | "focused" | "full";

export interface ObservatoryGhostTrace {
  id: string;
  stationId: HuntStationId;
  route: string;
  routeLabel: string;
  sourceKind: ObservatoryGhostSourceKind;
  sourceId: string | null;
  authorLabel: string | null;
  headline: string;
  detail: string;
  timestampMs: number;
  score: number;
}

export interface DeriveObservatoryGhostMemoriesInput {
  activeStationId?: HuntStationId | null;
  events?: AgentEvent[];
  ghostMode?: ObservatoryGhostPresentation;
  investigations?: Investigation[];
  likelyStationId?: HuntStationId | null;
  missionTargetStationId?: HuntStationId | null;
  mode?: HuntObservatoryMode;
  nowMs: number;
  probeState?: ObservatoryProbeState | null;
  replayEnabled?: boolean;
  selectedStationId?: HuntStationId | null;
  stations: ObservatoryStation[];
}

export interface ResolveObservatoryGhostPresentationInput {
  activeStationId?: HuntStationId | null;
  ghostMode?: ObservatoryGhostPresentation;
  mode?: HuntObservatoryMode;
  probeState?: ObservatoryProbeState | null;
  replayEnabled?: boolean;
  selectedStationId?: HuntStationId | null;
  traceCount?: number;
}

function hashString(input: string): number {
  let hash = 0;
  for (let index = 0; index < input.length; index += 1) {
    hash = (hash * 33 + input.charCodeAt(index)) >>> 0;
  }
  return hash;
}

function scoreDistrictRelevance(input: {
  districtId: HuntStationId;
  activeStationId?: HuntStationId | null;
  likelyStationId?: HuntStationId | null;
  missionTargetStationId?: HuntStationId | null;
  selectedStationId?: HuntStationId | null;
}): number {
  return (
    (input.districtId === input.selectedStationId ? 1.2 : 0) +
    (input.districtId === input.missionTargetStationId ? 1.0 : 0) +
    (input.districtId === input.likelyStationId ? 0.75 : 0) +
    (input.districtId === input.activeStationId ? 0.85 : 0)
  );
}

function lowerCaseTokens(value: string): string[] {
  return value
    .toLowerCase()
    .split(/[^a-z0-9]+/g)
    .filter(Boolean);
}

function resolveStationByText(input: {
  defaultStationId: HuntStationId;
  text: string;
}): HuntStationId {
  const tokens = lowerCaseTokens(input.text);
  const score = new Map<HuntStationId, number>([
    ["signal", 0],
    ["targets", 0],
    ["run", 0],
    ["receipts", 0],
    ["case-notes", 0],
    ["watch", 0],
  ]);

  for (const token of tokens) {
    if (token.includes("receipt") || token.includes("evidence") || token.includes("denied")) {
      score.set("receipts", (score.get("receipts") ?? 0) + 2);
    }
    if (token.includes("watch") || token.includes("perimeter") || token.includes("nexus")) {
      score.set("watch", (score.get("watch") ?? 0) + 2);
    }
    if (token.includes("judg") || token.includes("finding") || token.includes("policy") || token.includes("case")) {
      score.set("case-notes", (score.get("case-notes") ?? 0) + 2);
    }
    if (token.includes("run") || token.includes("ops") || token.includes("operation")) {
      score.set("run", (score.get("run") ?? 0) + 2);
    }
    if (token.includes("subject") || token.includes("target") || token.includes("pattern")) {
      score.set("targets", (score.get("targets") ?? 0) + 2);
    }
    if (token.includes("signal") || token.includes("ingress") || token.includes("horizon")) {
      score.set("signal", (score.get("signal") ?? 0) + 2);
    }
  }

  const winner = Array.from(score.entries()).sort((left, right) => {
    if (right[1] !== left[1]) return right[1] - left[1];
    return left[0].localeCompare(right[0]);
  })[0];

  if (!winner || winner[1] <= 0) {
    return input.defaultStationId;
  }
  return winner[0];
}

function buildFindingTrace(input: {
  activeStationId?: HuntStationId | null;
  investigation: Investigation;
  likelyStationId?: HuntStationId | null;
  missionTargetStationId?: HuntStationId | null;
  selectedStationId?: HuntStationId | null;
  stationsById: Map<HuntStationId, ObservatoryStation>;
}): ObservatoryGhostTrace | null {
  const text = [
    input.investigation.title,
    input.investigation.annotations.map((annotation) => annotation.text).join(" "),
    input.investigation.verdict ?? "",
    input.investigation.actions?.join(" ") ?? "",
  ].join(" ");
  const stationId = resolveStationByText({
    defaultStationId: "case-notes",
    text,
  });
  const station = input.stationsById.get(stationId);
  if (!station) {
    return null;
  }
  const route = resolveObservatoryStationRoute(stationId);
  const timestampMs = Date.parse(input.investigation.updatedAt || input.investigation.createdAt);
  const annotationCount = input.investigation.annotations.length;
  const score =
    3.5 +
    annotationCount * 0.75 +
    (input.investigation.status === "open" || input.investigation.status === "in-progress" ? 1.2 : 0) +
    scoreDistrictRelevance({
      activeStationId: input.activeStationId,
      districtId: stationId,
      likelyStationId: input.likelyStationId,
      missionTargetStationId: input.missionTargetStationId,
      selectedStationId: input.selectedStationId,
    });

  return {
    authorLabel: input.investigation.createdBy,
    detail: annotationCount > 0
      ? input.investigation.annotations[0]?.text ?? input.investigation.title
      : input.investigation.title,
    headline: input.investigation.title,
    id: `finding:${input.investigation.id}`,
    route: route.route,
    routeLabel: route.label,
    score,
    sourceId: input.investigation.id,
    sourceKind: "finding",
    stationId,
    timestampMs: Number.isFinite(timestampMs) ? timestampMs : 0,
  };
}

function buildReceiptTrace(input: {
  activeStationId?: HuntStationId | null;
  event: AgentEvent;
  likelyStationId?: HuntStationId | null;
  missionTargetStationId?: HuntStationId | null;
  selectedStationId?: HuntStationId | null;
  stationsById: Map<HuntStationId, ObservatoryStation>;
}): ObservatoryGhostTrace | null {
  const event = input.event;
  const text = [event.target, event.content ?? "", event.flags.map((flag) => ("label" in flag ? flag.label : flag.type)).join(" ")].join(" ");
  const stationId = resolveStationByText({
    defaultStationId: "receipts",
    text,
  });
  const station = input.stationsById.get(stationId);
  if (!station) {
    return null;
  }
  const route = resolveObservatoryStationRoute(stationId);
  const timestampMs = Date.parse(event.timestamp);
  const receiptLabel = event.receiptId ? `Receipt ${event.receiptId}` : `Event ${event.id}`;
  const denied = event.verdict !== "allow";
  const score =
    1.75 +
    (event.receiptId ? 1 : 0) +
    (denied ? 1.1 : 0) +
    (event.guardResults.length > 0 ? 0.8 : 0) +
    scoreDistrictRelevance({
      activeStationId: input.activeStationId,
      districtId: stationId,
      likelyStationId: input.likelyStationId,
      missionTargetStationId: input.missionTargetStationId,
      selectedStationId: input.selectedStationId,
    });

  return {
    authorLabel: event.agentName,
    detail: denied
      ? `${receiptLabel} was denied with ${event.guardResults.length} guard result(s).`
      : `${receiptLabel} is still tracing the evidence path.`,
    headline: denied ? `Denied ${receiptLabel}` : receiptLabel,
    id: `receipt:${event.receiptId ?? event.id}`,
    route: route.route,
    routeLabel: route.label,
    score,
    sourceId: event.receiptId ?? event.id,
    sourceKind: "receipt",
    stationId,
    timestampMs: Number.isFinite(timestampMs) ? timestampMs : 0,
  };
}

function trimText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

export function deriveObservatoryGhostMemories(
  input: DeriveObservatoryGhostMemoriesInput,
): ObservatoryGhostTrace[] {
  const stationsById = new Map(input.stations.map((station) => [station.id, station]));
  const rawTraces: ObservatoryGhostTrace[] = [];

  for (const investigation of input.investigations ?? []) {
    const trace = buildFindingTrace({
      activeStationId: input.activeStationId,
      investigation,
      likelyStationId: input.likelyStationId,
      missionTargetStationId: input.missionTargetStationId,
      selectedStationId: input.selectedStationId,
      stationsById,
    });
    if (trace) {
      rawTraces.push(trace);
    }
  }

  for (const event of input.events ?? []) {
    if (!event.receiptId && event.verdict === "allow" && event.guardResults.length === 0) {
      continue;
    }
    const trace = buildReceiptTrace({
      activeStationId: input.activeStationId,
      event,
      likelyStationId: input.likelyStationId,
      missionTargetStationId: input.missionTargetStationId,
      selectedStationId: input.selectedStationId,
      stationsById,
    });
    if (trace) {
      rawTraces.push(trace);
    }
  }

  const merged = new Map<string, ObservatoryGhostTrace>();
  for (const trace of rawTraces) {
    const dedupeKey = `${trace.sourceKind}:${trace.sourceId ?? trace.id}`;
    const current = merged.get(dedupeKey);
    if (!current || current.score < trace.score) {
      merged.set(dedupeKey, {
        ...trace,
        detail: trimText(trace.detail),
        headline: trimText(trace.headline),
      });
    }
  }

  const cappedByDistrict = new Map<HuntStationId, ObservatoryGhostTrace[]>();
  const sorted = Array.from(merged.values()).sort((left, right) => {
    if (right.score !== left.score) return right.score - left.score;
    if (right.timestampMs !== left.timestampMs) return right.timestampMs - left.timestampMs;
    return left.headline.localeCompare(right.headline);
  });

  for (const trace of sorted) {
    const district = cappedByDistrict.get(trace.stationId) ?? [];
    if (district.length >= 2) {
      continue;
    }
    district.push(trace);
    cappedByDistrict.set(trace.stationId, district);
  }

  return Array.from(cappedByDistrict.values()).flat().sort((left, right) => {
    if (right.score !== left.score) return right.score - left.score;
    if (right.timestampMs !== left.timestampMs) return right.timestampMs - left.timestampMs;
    return left.headline.localeCompare(right.headline);
  });
}

export function resolveObservatoryGhostPresentation(
  input: ResolveObservatoryGhostPresentationInput,
): ObservatoryGhostPresentation {
  if (input.ghostMode === "off") {
    return "off";
  }

  const activeProbePressure = input.probeState?.status === "active" || input.probeState?.status === "cooldown";
  const clutterRisk =
    Boolean(input.replayEnabled) ||
    input.mode === "flow" ||
    activeProbePressure ||
    (input.traceCount ?? 0) > 8;

  if (clutterRisk) {
    return "focused";
  }

  if (input.ghostMode === "full") {
    return "full";
  }

  if (input.ghostMode === "focused") {
    return "focused";
  }

  return "auto";
}

