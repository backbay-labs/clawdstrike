import { isDesktop } from "@/lib/tauri-bridge";
import {
  readAppPersistenceFileNative,
  writeAppPersistenceFileNative,
} from "@/lib/tauri-commands";

export const SWARM_BOARD_PERSISTENCE_FILE = "swarm-board-state.v1.json";
export const SWARMS_PERSISTENCE_FILE = "swarms-state.v1.json";
export const SWARM_FEED_PERSISTENCE_FILE = "swarm-feed-state.v1.json";

const PERSISTENCE_VERSION = 1;

interface PersistedEnvelope<T> {
  version: number;
  savedAt: string;
  payload: T;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function unwrapEnvelope(raw: string): unknown | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    if (!isRecord(parsed)) {
      return null;
    }

    if (typeof parsed.version === "number" && "payload" in parsed) {
      if (parsed.version !== PERSISTENCE_VERSION) {
        console.warn(
          `[swarm-persistence] Unsupported persisted state version: ${parsed.version}`,
        );
        return null;
      }
      return parsed.payload;
    }

    return parsed;
  } catch (error) {
    console.warn("[swarm-persistence] Failed to parse persisted state:", error);
    return null;
  }
}

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
