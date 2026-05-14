import type { Plugin } from 'vite';
import type { ClawdstrikePluginOptions } from './types';
import { FilePluginMap } from './file-plugin-map';
import { setupPluginWatcher } from './watcher';

export type { ClawdstrikePluginOptions, PluginDevEntry, PluginUpdateEvent } from './types';
export { PLUGIN_UPDATE_EVENT } from './types';
export { FilePluginMap } from './file-plugin-map';

/**
 * Create a Vite plugin that watches ClawdStrike plugin source directories
 * and sends custom HMR events on file changes.
 *
 * Usage in vite.config.ts:
 * ```ts
 * import { clawdstrikePlugin } from '@clawdstrike/vite-plugin-clawdstrike';
 *
 * export default defineConfig({
 *   plugins: [
 *     clawdstrikePlugin({
 *       plugins: [
 *         { dir: '../my-plugin', pluginId: 'clawdstrike.my-guard' },
 *       ],
 *     }),
 *   ],
 * });
 * ```
 */
export function clawdstrikePlugin(options: ClawdstrikePluginOptions): Plugin {
  const fileMap = new FilePluginMap();
  return {
    name: 'vite-plugin-clawdstrike',
    configureServer(server) {
      setupPluginWatcher(server, fileMap, options);
    },
  };
}

export default clawdstrikePlugin;
