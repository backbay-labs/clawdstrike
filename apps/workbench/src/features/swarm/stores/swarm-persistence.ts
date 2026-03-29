import { isDesktop } from "@/lib/tauri-bridge";
import {
  readAppPersistenceFileNative,
  writeAppPersistenceFileNative,
} from "@/lib/tauri-commands";

export const SWARM_BOARD_PERSISTENCE_FILE = "swarm-board-state.v1.json";
export const SWARMS_PERSISTENCE_FILE = "swarms-state.v1.json";
export const SWARM_FEED_PERSISTENCE_FILE = "swarm-feed-state.v1.json";

const PERSISTENCE_VERSION = 2;

interface PersistedEnvelope<T> {
  version: number;
  savedAt: string;
  payload: T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

// ---------------------------------------------------------------------------
// Version migration
// ---------------------------------------------------------------------------

/** Migrate a v1 payload to v2 by adding empty highWaterMarks if missing. */
function migrateV1ToV2(payload: unknown): unknown {
  if (isRecord(payload) && !("highWaterMarks" in payload)) {
    return { ...payload, highWaterMarks: {} };
  }
  return payload;
}

// ---------------------------------------------------------------------------
// Envelope unwrapping with version handling
// ---------------------------------------------------------------------------

function unwrapEnvelope(raw: string): unknown | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed)) {
      return null;
    }

    if (typeof parsed.version === "number" && "payload" in parsed) {
      if (parsed.version === 1) {
        // Migrate v1 -> v2: add highWaterMarks if missing
        return migrateV1ToV2(parsed.payload);
      }
      if (parsed.version === 2) {
        return parsed.payload;
      }
      // Future versions: refuse to load (forward safety)
      console.warn(
        `[swarm-persistence] Unsupported persisted state version: ${parsed.version}`,
      );
      return null;
    }

    // No version field (legacy unversioned): return as-is
    return parsed;
  } catch (error) {
    console.warn("[swarm-persistence] Failed to parse persisted state:", error);
    return null;
  }
}

/** @internal Exposed for testing version migration logic. */
export const unwrapEnvelopeForTesting = unwrapEnvelope;

// ---------------------------------------------------------------------------
// Archive filename generation
// ---------------------------------------------------------------------------

/**
 * Generate a monthly archive filename for retention overflow.
 * Uses the provided monthKey or defaults to the current month (YYYY-MM).
 */
export function getArchiveFilename(monthKey?: string): string {
  const key = monthKey ?? new Date().toISOString().slice(0, 7);
  return `swarm-feed-archive-${key}.json`;
}

// ---------------------------------------------------------------------------
// Archive write (overflow rotation)
// ---------------------------------------------------------------------------

/**
 * Write retention overflow to a monthly archive file.
 * Archive files are plain JSON arrays (not versioned envelopes).
 * Each entry includes an `archivedAt` timestamp.
 */
export async function writeArchivePayload(overflow: unknown): Promise<boolean> {
  if (!isDesktop()) {
    return false;
  }

  const filename = getArchiveFilename();

  // Read existing archive entries (if any)
  const existing = await readAppPersistenceFileNative(filename);
  let merged: unknown[];
  if (existing) {
    try {
      const parsed = JSON.parse(existing);
      merged = Array.isArray(parsed) ? parsed : [parsed];
    } catch {
      merged = [];
    }
  } else {
    merged = [];
  }

  merged.push({ archivedAt: new Date().toISOString(), ...(overflow as object) });
  return writeAppPersistenceFileNative(filename, JSON.stringify(merged, null, 2));
}

// ---------------------------------------------------------------------------
// Public persistence API
// ---------------------------------------------------------------------------

export async function readSwarmPersistencePayload(
  filename: string,
): Promise<unknown | null> {
  if (!isDesktop()) {
    return null;
  }

  const raw = await readAppPersistenceFileNative(filename);
  if (!raw) {
    return null;
  }

  return unwrapEnvelope(raw);
}

export async function writeSwarmPersistencePayload(
  filename: string,
  payload: unknown,
): Promise<boolean> {
  if (!isDesktop()) {
    return false;
  }

  const envelope: PersistedEnvelope<unknown> = {
    version: PERSISTENCE_VERSION,
    savedAt: new Date().toISOString(),
    payload,
  };

  return writeAppPersistenceFileNative(filename, JSON.stringify(envelope, null, 2));
}
