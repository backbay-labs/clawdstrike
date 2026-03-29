import type { UnlistenFn } from "@tauri-apps/api/event";
import {
  configureSwarmFileWatcherNative,
  stopSwarmFileWatcherNative,
  type TauriSwarmFileWatchEvent,
} from "@/lib/tauri-commands";

const SWARM_FILE_WATCH_EVENT = "swarm:file-watch";
const SELF_WRITE_TTL_MS = 1_500;

export interface SwarmFileWatchConfig {
  persistenceFilenames?: string[];
  workspacePaths?: string[];
}

type SwarmFileWatchListener = (event: TauriSwarmFileWatchEvent) => void;

const scopeConfigs = new Map<string, SwarmFileWatchConfig>();
const listeners = new Set<SwarmFileWatchListener>();
const selfWriteDeadlines = new Map<string, number>();

let unlistenPromise: Promise<UnlistenFn | null> | null = null;
let activeUnlisten: UnlistenFn | null = null;

function isDesktopRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function normalizeSwarmFileWatchPath(path: string): string {
  const normalized = path.replace(/\\/g, "/");
  if (typeof navigator !== "undefined" && /^win/i.test(navigator.platform)) {
    return normalized.toLowerCase();
  }
  return normalized;
}

function pruneExpiredSelfWrites(now = Date.now()): void {
  for (const [path, deadline] of selfWriteDeadlines.entries()) {
    if (deadline <= now) {
      selfWriteDeadlines.delete(path);
    }
  }
}

export function markSwarmFileWatchSelfWrite(path?: string | null): void {
  if (!path) {
    return;
  }
  pruneExpiredSelfWrites();
  selfWriteDeadlines.set(
    normalizeSwarmFileWatchPath(path),
    Date.now() + SELF_WRITE_TTL_MS,
  );
}

function filterSelfWrittenPaths(paths: string[]): string[] {
  pruneExpiredSelfWrites();
  return paths.filter((path) => {
    const normalized = normalizeSwarmFileWatchPath(path);
    const deadline = selfWriteDeadlines.get(normalized);
    if (!deadline) {
      return true;
    }
    if (deadline <= Date.now()) {
      selfWriteDeadlines.delete(normalized);
      return true;
    }
    return false;
  });
}

function dedupeSorted(values: Array<string | undefined>): string[] {
  return Array.from(
    new Set(
      values
        .flatMap((value) => (value ? [value.trim()] : []))
        .filter((value) => value.length > 0),
    ),
  ).sort();
}

function workspaceFilename(path: string): string | undefined {
  const trimmed = path.trim();
  if (!trimmed) {
    return undefined;
  }
  const parts = trimmed.split(/[\\/]/);
  return parts[parts.length - 1];
}

function aggregateScopeConfig(): Required<SwarmFileWatchConfig> {
  const persistenceFilenames: string[] = [];
  const workspacePaths: string[] = [];

  for (const config of scopeConfigs.values()) {
    persistenceFilenames.push(...(config.persistenceFilenames ?? []));
    workspacePaths.push(...(config.workspacePaths ?? []));
  }

  return {
    persistenceFilenames: dedupeSorted(persistenceFilenames),
    workspacePaths: dedupeSorted(workspacePaths),
  };
}

async function ensureEventListener(): Promise<UnlistenFn | null> {
  if (!isDesktopRuntime()) {
    return null;
  }
  if (activeUnlisten) {
    return activeUnlisten;
  }
  if (unlistenPromise) {
    return unlistenPromise;
  }

  unlistenPromise = import("@tauri-apps/api/event")
    .then(({ listen }) =>
      listen<TauriSwarmFileWatchEvent>(SWARM_FILE_WATCH_EVENT, ({ payload }) => {
        const filteredPaths = filterSelfWrittenPaths(payload.paths);
        if (filteredPaths.length === 0) {
          return;
        }

          const nextPayload: TauriSwarmFileWatchEvent = {
            ...payload,
            paths: filteredPaths,
            filenames: dedupeSorted(
              payload.category === "workspace"
                ? filteredPaths.map((path) => workspaceFilename(path))
                : payload.filenames,
            ),
          };

        for (const listener of listeners) {
          listener(nextPayload);
        }
      }),
    )
    .then((unlisten) => {
      activeUnlisten = unlisten;
      unlistenPromise = null;
      return unlisten;
    })
    .catch((error) => {
      console.error("[swarm-file-watch] Failed to attach Tauri event listener:", error);
      unlistenPromise = null;
      return null;
    });

  return unlistenPromise;
}

async function syncBackendWatcher(): Promise<void> {
  if (!isDesktopRuntime()) {
    return;
  }

  const aggregate = aggregateScopeConfig();
  if (
    aggregate.persistenceFilenames.length === 0 &&
    aggregate.workspacePaths.length === 0
  ) {
    await stopSwarmFileWatcherNative();
    if (activeUnlisten) {
      activeUnlisten();
      activeUnlisten = null;
    }
    return;
  }

  await ensureEventListener();
  await configureSwarmFileWatcherNative({
    persistence_filenames: aggregate.persistenceFilenames,
    workspace_paths: aggregate.workspacePaths,
  });
}

export async function setSwarmFileWatchScope(
  scopeId: string,
  config: SwarmFileWatchConfig,
): Promise<void> {
  scopeConfigs.set(scopeId, {
    persistenceFilenames: dedupeSorted(config.persistenceFilenames ?? []),
    workspacePaths: dedupeSorted(
      (config.workspacePaths ?? []).map((path) => normalizeSwarmFileWatchPath(path)),
    ),
  });
  await syncBackendWatcher();
}

export async function clearSwarmFileWatchScope(scopeId: string): Promise<void> {
  scopeConfigs.delete(scopeId);
  await syncBackendWatcher();
}

export function subscribeSwarmFileWatchEvents(
  listener: SwarmFileWatchListener,
): () => void {
  listeners.add(listener);
  void ensureEventListener();
  return () => {
    listeners.delete(listener);
  };
}
