import { pluginLoader } from '../plugin-loader';
import { pluginRegistry } from '../plugin-registry';
import type { PluginManifest } from '../types';
import type { PluginUpdateEvent, DevLifecycleEvent } from './types';
import { PLUGIN_UPDATE_EVENT } from './types';
import { getSnapshot, restoreToApi, trackStorageWrite } from './storage-snapshot';

type DevEventListener = (event: DevLifecycleEvent) => void;
const listeners = new Set<DevEventListener>();

export function onDevLifecycleEvent(cb: DevEventListener): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

function emit(event: DevLifecycleEvent): void {
  for (const listener of listeners) {
    try {
      listener(event);
    } catch {
      /* best-effort */
    }
  }
}

export async function handlePluginUpdate(
  data: PluginUpdateEvent,
): Promise<void> {
  const { pluginId, entryPath, timestamp } = data;
  const startTime = performance.now();

  emit({
    type: 'hmr:start',
    pluginId,
    timestamp: Date.now(),
    message: `HMR reload starting for ${pluginId}`,
  });

  try {
    const storageSnapshot = getSnapshot(pluginId);

    const registered = pluginRegistry.get(pluginId);
    if (!registered) {
      throw new Error(`Plugin "${pluginId}" not found in registry for HMR`);
    }
    const manifest: PluginManifest = { ...registered.manifest };

    await pluginLoader.deactivatePlugin(pluginId);
    emit({
      type: 'deactivated',
      pluginId,
      timestamp: Date.now(),
      message: `Deactivated ${pluginId} for HMR`,
    });

    pluginRegistry.unregister(pluginId);

    manifest.main = `${entryPath}?t=${timestamp}`;

    pluginRegistry.register(manifest);
    emit({
      type: 'registered',
      pluginId,
      timestamp: Date.now(),
      message: `Re-registered ${pluginId} with cache-bust`,
    });

    await pluginLoader.loadPlugin(pluginId);

    if (storageSnapshot.size > 0) {
      restoreToApi(pluginId, {
        set: (key: string, value: unknown) => trackStorageWrite(pluginId, key, value),
      });
    }

    const durationMs = performance.now() - startTime;
    emit({
      type: 'hmr:complete',
      pluginId,
      timestamp: Date.now(),
      message: `HMR complete for ${pluginId} in ${durationMs.toFixed(0)}ms`,
      durationMs,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    emit({
      type: 'hmr:error',
      pluginId,
      timestamp: Date.now(),
      message: `HMR failed for ${pluginId}: ${message}`,
      detail: err,
    });
  }
}

/** Call once during workbench init in dev mode. Returns dispose function. */
export function setupPluginHmr(): () => void {
  if (!import.meta.hot) return () => {};

  const handler = (data: PluginUpdateEvent) => {
    void handlePluginUpdate(data);
  };

  import.meta.hot.on(PLUGIN_UPDATE_EVENT, handler);

  return () => {
    import.meta.hot?.off?.(PLUGIN_UPDATE_EVENT, handler);
  };
}
