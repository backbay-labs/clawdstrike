import { resolve } from 'path';
import type { ViteDevServer } from 'vite';
import type { ClawdstrikePluginOptions } from './types';
import { PLUGIN_UPDATE_EVENT } from './types';
import type { PluginUpdateEvent } from './types';
import { FilePluginMap } from './file-plugin-map';

export function setupPluginWatcher(
  server: ViteDevServer,
  fileMap: FilePluginMap,
  options: ClawdstrikePluginOptions,
): void {
  for (const plugin of options.plugins) {
    const absoluteDir = resolve(plugin.dir);
    fileMap.register(plugin.pluginId, absoluteDir, plugin.entry);

    // Add directory to Vite's chokidar watch list
    server.watcher.add(absoluteDir);

  }

  const handleFileChange = (filePath: string): void => {
    try {
      const pluginId = fileMap.resolve(filePath);
      if (!pluginId) {
        return; // File is not part of any registered plugin
      }

      const entryPath = fileMap.getEntry(pluginId);
      if (!entryPath) {
        return; // Should not happen if resolve() returned a pluginId
      }

      const payload: PluginUpdateEvent = {
        pluginId,
        entryPath,
        timestamp: Date.now(),
      };

      server.ws.send(PLUGIN_UPDATE_EVENT, payload);
    } catch (err) {
      console.error(`[clawdstrike] File watcher error for ${filePath}:`, err);
    }
  };

  server.watcher.on('change', handleFileChange);
  server.watcher.on('add', handleFileChange);
}
