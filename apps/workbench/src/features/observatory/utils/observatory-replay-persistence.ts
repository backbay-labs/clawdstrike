import type {
  ObservatoryReplayAnnotation,
  ObservatoryReplayBookmark,
  ObservatoryAnnotationPin,
  ConstellationRoute,
} from "../types";

export const OBSERVATORY_REPLAY_PERSISTENCE_KEY = "clawdstrike:observatory:replay:v1";
export const OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2 = "clawdstrike:observatory:replay:v2";

export interface PersistedObservatoryReplayArtifacts {
  annotations: ObservatoryReplayAnnotation[];
  bookmarks: ObservatoryReplayBookmark[];
}

export interface PersistedObservatoryReplayArtifactsV2 extends PersistedObservatoryReplayArtifacts {
  annotationPins: ObservatoryAnnotationPin[];
  constellations: ConstellationRoute[];
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function asBookmarks(value: unknown): ObservatoryReplayBookmark[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry): entry is ObservatoryReplayBookmark => (
    isObject(entry)
    && typeof entry.id === "string"
    && typeof entry.frameIndex === "number"
    && typeof entry.timestampMs === "number"
    && typeof entry.label === "string"
    && typeof entry.districtId === "string"
  ));
}

function asAnnotations(value: unknown): ObservatoryReplayAnnotation[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry): entry is ObservatoryReplayAnnotation => (
    isObject(entry)
    && typeof entry.id === "string"
    && typeof entry.frameIndex === "number"
    && typeof entry.timestampMs === "number"
    && typeof entry.districtId === "string"
    && typeof entry.authorLabel === "string"
    && typeof entry.body === "string"
    && typeof entry.sourceType === "string"
  ));
}

function asAnnotationPins(value: unknown): ObservatoryAnnotationPin[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is ObservatoryAnnotationPin => (
    isObject(entry)
    && typeof entry.id === "string"
    && typeof entry.frameIndex === "number"
    && typeof entry.timestampMs === "number"
    && Array.isArray(entry.worldPosition)
    && entry.worldPosition.length === 3
    && entry.worldPosition.every((v: unknown) => typeof v === "number")
    && typeof entry.note === "string"
    && typeof entry.districtId === "string"
  ));
}

function asConstellationRoutes(value: unknown): ConstellationRoute[] {
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is ConstellationRoute => (
    isObject(entry)
    && typeof entry.id === "string"
    && typeof entry.name === "string"
    && typeof entry.createdAtMs === "number"
    && Array.isArray(entry.stationPath)
    && entry.stationPath.every((v: unknown) => typeof v === "string")
    && typeof entry.missionHuntId === "string"
  ));
}

export function loadPersistedObservatoryReplayArtifacts(): PersistedObservatoryReplayArtifacts {
  if (typeof window === "undefined" || !("localStorage" in window)) {
    return { annotations: [], bookmarks: [] };
  }
  try {
    const raw = window.localStorage.getItem(OBSERVATORY_REPLAY_PERSISTENCE_KEY);
    if (!raw) {
      return { annotations: [], bookmarks: [] };
    }
    const parsed = JSON.parse(raw) as unknown;
    if (!isObject(parsed)) {
      return { annotations: [], bookmarks: [] };
    }
    return {
      annotations: asAnnotations(parsed.annotations),
      bookmarks: asBookmarks(parsed.bookmarks),
    };
  } catch {
    return { annotations: [], bookmarks: [] };
  }
}

export function savePersistedObservatoryReplayArtifacts(
  input: PersistedObservatoryReplayArtifacts,
): void {
  if (typeof window === "undefined" || !("localStorage" in window)) {
    return;
  }
  window.localStorage.setItem(
    OBSERVATORY_REPLAY_PERSISTENCE_KEY,
    JSON.stringify(input),
  );
}

export function loadPersistedObservatoryReplayArtifactsV2(): PersistedObservatoryReplayArtifactsV2 {
  if (typeof window === "undefined" || !("localStorage" in window)) {
    return { annotations: [], bookmarks: [], annotationPins: [], constellations: [] };
  }
  try {
    const rawV2 = window.localStorage.getItem(OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2);
    if (rawV2) {
      const parsed = JSON.parse(rawV2) as unknown;
      if (!isObject(parsed)) {
        return { annotations: [], bookmarks: [], annotationPins: [], constellations: [] };
      }
      return {
        annotations: asAnnotations(parsed.annotations),
        bookmarks: asBookmarks(parsed.bookmarks),
        annotationPins: asAnnotationPins(parsed.annotationPins),
        constellations: asConstellationRoutes(parsed.constellations),
      };
    }
    const rawV1 = window.localStorage.getItem(OBSERVATORY_REPLAY_PERSISTENCE_KEY);
    if (rawV1) {
      const parsed = JSON.parse(rawV1) as unknown;
      if (!isObject(parsed)) {
        return { annotations: [], bookmarks: [], annotationPins: [], constellations: [] };
      }
      return {
        annotations: asAnnotations(parsed.annotations),
        bookmarks: asBookmarks(parsed.bookmarks),
        annotationPins: [],
        constellations: [],
      };
    }
    return { annotations: [], bookmarks: [], annotationPins: [], constellations: [] };
  } catch {
    return { annotations: [], bookmarks: [], annotationPins: [], constellations: [] };
  }
}

export function savePersistedObservatoryReplayArtifactsV2(
  input: PersistedObservatoryReplayArtifactsV2,
): void {
  if (typeof window === "undefined" || !("localStorage" in window)) return;
  window.localStorage.setItem(
    OBSERVATORY_REPLAY_PERSISTENCE_KEY_V2,
    JSON.stringify(input),
  );
}
