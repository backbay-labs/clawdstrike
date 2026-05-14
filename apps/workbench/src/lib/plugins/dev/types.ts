/** Payload received from the Vite plugin HMR WebSocket event. */
export interface PluginUpdateEvent {
  pluginId: string;
  entryPath: string;
  timestamp: number;
}

/** Types of plugin lifecycle events captured by the dev console. */
export type DevLifecycleEventType =
  | 'registered'
  | 'activating'
  | 'activated'
  | 'deactivated'
  | 'error'
  | 'hmr:start'
  | 'hmr:complete'
  | 'hmr:error'
  | 'contribution:registered'
  | 'contribution:unregistered'
  | 'console:log'
  | 'console:warn'
  | 'console:error';

/** A timestamped lifecycle event for the dev console log. */
export interface DevLifecycleEvent {
  type: DevLifecycleEventType;
  pluginId: string;
  timestamp: number;
  message: string;
  detail?: unknown;
  /** Duration in ms for timed events like hmr:complete. */
  durationMs?: number;
}

/** The custom HMR event name. Must match vite-plugin-clawdstrike. */
export const PLUGIN_UPDATE_EVENT = 'clawdstrike:plugin-update' as const;
