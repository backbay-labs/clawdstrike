/** Options for the clawdstrike Vite plugin. */
export interface ClawdstrikePluginOptions {
  /** Array of plugin directories to watch. Each entry maps a directory path to a plugin ID. */
  plugins: PluginDevEntry[];
}

/** A single plugin development entry: directory + metadata. */
export interface PluginDevEntry {
  /** Absolute or relative path to the plugin source directory. */
  dir: string;
  /** The plugin's manifest ID (e.g. "clawdstrike.my-guard"). */
  pluginId: string;
  /** The entry point file relative to dir (defaults to "src/index.ts"). */
  entry?: string;
}

/** Payload sent over the Vite HMR WebSocket on plugin file change. */
export interface PluginUpdateEvent {
  /** The ID of the changed plugin. */
  pluginId: string;
  /** Absolute path to the plugin's entry file. */
  entryPath: string;
  /** Unix timestamp (ms) when the change was detected. */
  timestamp: number;
}

/** The custom HMR event name used for plugin updates. */
export const PLUGIN_UPDATE_EVENT = 'clawdstrike:plugin-update' as const;
