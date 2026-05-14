/** Write-through cache preserving plugin storage across HMR reloads. */
const devStorageCache = new Map<string, Map<string, unknown>>();

export function trackStorageWrite(
  pluginId: string,
  key: string,
  value: unknown,
): void {
  let pluginCache = devStorageCache.get(pluginId);
  if (!pluginCache) {
    pluginCache = new Map<string, unknown>();
    devStorageCache.set(pluginId, pluginCache);
  }
  pluginCache.set(key, value);
}

export function getSnapshot(pluginId: string): Map<string, unknown> {
  const pluginCache = devStorageCache.get(pluginId);
  if (!pluginCache) {
    return new Map();
  }
  return new Map(pluginCache);
}

export function restoreToApi(
  pluginId: string,
  api: { set(key: string, value: unknown): void },
): void {
  const pluginCache = devStorageCache.get(pluginId);
  if (!pluginCache) {
    return;
  }
  for (const [key, value] of pluginCache) {
    api.set(key, value);
  }
}

export function clearSnapshot(pluginId: string): void {
  devStorageCache.delete(pluginId);
}
