import type { AgentEvent, Investigation } from "@/lib/workbench/hunt-types";
import type {
  ObservatoryReplayAnnotation,
  ObservatoryReplayBookmark,
  ObservatoryReplayMarker,
} from "../types";
import type { ObservatoryReplayFrame } from "./observatory-telemetry";
import type { HuntStationId } from "./types";

export interface BuildObservatoryReplayMarkersInput {
  annotations?: ObservatoryReplayAnnotation[];
  bookmarks?: ObservatoryReplayBookmark[];
  events?: AgentEvent[];
  frames: ObservatoryReplayFrame[];
  investigations?: Investigation[];
}

function tokenize(value: string): string[] {
  return value.toLowerCase().split(/[^a-z0-9]+/g).filter(Boolean);
}

function resolveMarkerDistrict(text: string): HuntStationId | null {
  const tokens = tokenize(text);
  if (tokens.some((token) => token.includes("receipt") || token.includes("evidence") || token.includes("deny"))) {
    return "receipts";
  }
  if (tokens.some((token) => token.includes("watch") || token.includes("nexus") || token.includes("perimeter"))) {
    return "watch";
  }
  if (tokens.some((token) => token.includes("case") || token.includes("finding") || token.includes("judg") || token.includes("policy"))) {
    return "case-notes";
  }
  if (tokens.some((token) => token.includes("target") || token.includes("subject") || token.includes("pattern"))) {
    return "targets";
  }
  if (tokens.some((token) => token.includes("run") || token.includes("mission") || token.includes("ops"))) {
    return "run";
  }
  if (tokens.some((token) => token.includes("signal") || token.includes("horizon") || token.includes("ingress"))) {
    return "signal";
  }
  return null;
}

function addDistrictScore(
  scores: Partial<Record<HuntStationId, number>>,
  districtId: HuntStationId,
  amount: number,
): void {
  scores[districtId] = (scores[districtId] ?? 0) + amount;
}

function applyEventDistrictScores(
  event: AgentEvent,
  scores: Partial<Record<HuntStationId, number>>,
): void {
  if (event.actionType === "network_egress" || event.actionType === "user_input") {
    addDistrictScore(scores, "signal", 0.85);
  }
  if ((event.anomalyScore ?? 0) >= 0.55) {
    addDistrictScore(scores, "targets", 1.1);
  }
  if (
    event.actionType === "shell_command"
    || event.actionType === "mcp_tool_call"
    || event.actionType === "patch_apply"
  ) {
    addDistrictScore(scores, "run", 0.95);
  }
  if (Boolean(event.receiptId) || event.verdict !== "allow" || event.guardResults.length > 0) {
    addDistrictScore(scores, "receipts", 1.35);
  }
  if (event.verdict === "deny" || (event.anomalyScore ?? 0) >= 0.72) {
    addDistrictScore(scores, "watch", 1.2);
  }
}

function resolveInvestigationDistrict(
  investigation: Investigation,
  linkedEvents: AgentEvent[],
): HuntStationId | null {
  const scores: Partial<Record<HuntStationId, number>> = {};
  const heuristicDistrict = resolveMarkerDistrict(
    [
      investigation.title,
      investigation.verdict ?? "",
      investigation.annotations.map((annotation) => annotation.text).join(" "),
    ].join(" "),
  );

  if (heuristicDistrict) {
    addDistrictScore(scores, heuristicDistrict, 0.8);
  }
  if (investigation.verdict === "policy-gap") {
    addDistrictScore(scores, "case-notes", 0.6);
  }
  for (const event of linkedEvents) {
    applyEventDistrictScores(event, scores);
  }

  const rankedDistricts = Object.entries(scores)
    .filter((entry): entry is [HuntStationId, number] => entry[1] != null && entry[1] > 0)
    .sort((left, right) => {
      if (right[1] !== left[1]) {
        return right[1] - left[1];
      }
      return left[0].localeCompare(right[0]);
    });

  return rankedDistricts[0]?.[0] ?? null;
}

function resolveNearestFrame(
  frames: ObservatoryReplayFrame[],
  timestampMs: number,
): { frame: ObservatoryReplayFrame; frameIndex: number } | null {
  if (frames.length === 0) {
    return null;
  }
  return frames.reduce<{ frame: ObservatoryReplayFrame; frameIndex: number }>((best, current, frameIndex) => {
    return Math.abs(current.timestampMs - timestampMs) < Math.abs(best.frame.timestampMs - timestampMs)
      ? { frame: current, frameIndex }
      : best;
  }, { frame: frames[0]!, frameIndex: 0 });
}

function compareMarkers(left: ObservatoryReplayMarker, right: ObservatoryReplayMarker): number {
  if (left.timestampMs !== right.timestampMs) {
    return left.timestampMs - right.timestampMs;
  }
  if (left.frameIndex !== right.frameIndex) {
    return left.frameIndex - right.frameIndex;
  }
  return left.label.localeCompare(right.label);
}

export function buildObservatoryReplayMarkers({
  annotations = [],
  bookmarks = [],
  events = [],
  frames,
  investigations = [],
}: BuildObservatoryReplayMarkersInput): ObservatoryReplayMarker[] {
  const eventsById = new Map(events.map((event) => [event.id, event]));
  const eventsBySessionId = events.reduce<Map<string, AgentEvent[]>>((map, event) => {
    const current = map.get(event.sessionId) ?? [];
    current.push(event);
    map.set(event.sessionId, current);
    return map;
  }, new Map());
  const bookmarkMarkers: ObservatoryReplayMarker[] = bookmarks.map((bookmark) => ({
    authorLabel: null,
    districtId: bookmark.districtId,
    frameIndex: bookmark.frameIndex,
    id: bookmark.id,
    label: bookmark.label,
    sourceId: bookmark.id,
    sourceType: "bookmark",
    timestampMs: bookmark.timestampMs,
  }));
  const annotationMarkers: ObservatoryReplayMarker[] = annotations.map((annotation) => ({
    authorLabel: annotation.authorLabel,
    districtId: annotation.districtId,
    frameIndex: annotation.frameIndex,
    id: annotation.id,
    label: annotation.body,
    sourceId: annotation.sourceId ?? annotation.id,
    sourceType: annotation.sourceType === "manual" ? "analyst" : "annotation",
    timestampMs: annotation.timestampMs,
  }));
  const investigationMarkers: ObservatoryReplayMarker[] = investigations.map((investigation) => {
    const timestampMs = Date.parse(
      investigation.updatedAt
        || investigation.timeRange?.end
        || investigation.createdAt,
    );
    const closestFrame = resolveNearestFrame(frames, Number.isFinite(timestampMs) ? timestampMs : 0);
    const linkedEvents = [
      ...investigation.eventIds
        .map((eventId) => eventsById.get(eventId))
        .filter((event): event is AgentEvent => event != null),
      ...investigation.sessionIds.flatMap((sessionId) => eventsBySessionId.get(sessionId) ?? []),
    ];
    return {
      authorLabel: investigation.createdBy,
      districtId: resolveInvestigationDistrict(investigation, linkedEvents),
      frameIndex: closestFrame?.frameIndex ?? 0,
      id: `investigation:${investigation.id}`,
      label: investigation.title,
      sourceId: investigation.id,
      sourceType: "investigation",
      timestampMs: Number.isFinite(timestampMs) ? timestampMs : closestFrame?.frame.timestampMs ?? 0,
    };
  });

  return [...bookmarkMarkers, ...annotationMarkers, ...investigationMarkers].sort(compareMarkers);
}

export function mergeObservatoryReplayMarkers(
  localMarkers: ObservatoryReplayMarker[],
  derivedMarkers: ObservatoryReplayMarker[],
): ObservatoryReplayMarker[] {
  const merged = new Map<string, ObservatoryReplayMarker>();
  for (const marker of [...localMarkers, ...derivedMarkers]) {
    merged.set(`${marker.sourceType}:${marker.sourceId ?? marker.id}`, marker);
  }
  return [...merged.values()].sort(compareMarkers);
}
