/**
 * Shell Plugin System - Type Definitions
 */
import type { ReactNode } from "react";

/** Application/plugin identifier. Built-in IDs listed in BUILTIN_APP_IDS; plugins register arbitrary strings. */
export type AppId = string;

export const BUILTIN_APP_IDS = [
  "nexus",
  "operations",
  "events",
  "policies",
  "policy-tester",
  "swarm",
  "marketplace",
  "workflows",
  "threat-radar",
  "attack-graph",
  "network-map",
  "security-overview",
] as const;

export interface PluginRoute {
  path: string;
  element: ReactNode;
  index?: boolean;
}

export interface PluginCommand {
  id: string;
  title: string;
  shortcut?: string;
  handler: () => void | Promise<void>;
}

export interface AppPlugin {
  id: AppId;
  name: string;
  icon: PluginIcon;
  description: string;
  order: number;
  routes: PluginRoute[];
  commands?: PluginCommand[];
  hidden?: boolean;
}

/** Plugin icon identifier. Built-in icons listed in BUILTIN_PLUGIN_ICONS; plugins can register custom icon paths. */
export type PluginIcon = string;

export const BUILTIN_PLUGIN_ICONS = [
  "nexus",
  "activity",
  "shield",
  "beaker",
  "network",
  "store",
  "workflow",
  "settings",
  "radar",
  "graph",
  "topology",
  "dashboard",
  "river",
] as const;

export interface PluginRegistry {
  getPlugins: () => AppPlugin[];
  getPlugin: (id: AppId) => AppPlugin | undefined;
}

// --- Plugin Icon Registry ---

const pluginIconMap = new Map<string, string>();

// Register built-in icons
const BUILTIN_ICON_PATHS: Record<string, string> = {
  nexus: "M12 2l3 5h6l-3 5 3 5h-6l-3 5-3-5H3l3-5-3-5h6z",
  activity: "M22 12h-4l-3 9L9 3l-3 9H2",
  shield: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  beaker: "M9 3h6v5l4 8H5l4-8V3M8 22h8",
  network: "M12 2a10 10 0 100 20 10 10 0 000-20M12 2v20M2 12h20",
  store: "M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z",
  workflow:
    "M5 5h4v4H5zM15 5h4v4h-4zM5 15h4v4H5zM15 15h4v4h-4zM9 7h6M7 9v6M17 9v6M9 17h6",
  settings:
    "M12 15a3 3 0 100-6 3 3 0 000 6z M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06a1.65 1.65 0 00.33-1.82 1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06a1.65 1.65 0 001.82.33H9a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06a1.65 1.65 0 00-.33 1.82V9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z",
  radar:
    "M12 2a10 10 0 100 20 10 10 0 000-20zM12 6a6 6 0 100 12 6 6 0 000-12zM12 10a2 2 0 100 4 2 2 0 000-4zM12 2v10l7 7",
  graph:
    "M4 6a2 2 0 100-4 2 2 0 000 4zM12 14a2 2 0 100-4 2 2 0 000 4zM20 6a2 2 0 100-4 2 2 0 000 4zM12 22a2 2 0 100-4 2 2 0 000 4zM5.6 5l5 5.2M18.4 5l-5 5.2M12 14v6",
  topology:
    "M12 2a2 2 0 100 4 2 2 0 000-4zM4 8a2 2 0 100 4 2 2 0 000-4zM20 8a2 2 0 100 4 2 2 0 000-4zM4 18a2 2 0 100 4 2 2 0 000-4zM20 18a2 2 0 100 4 2 2 0 000-4zM12 6v0l-7 4M12 6l7 4M5 12l-1 6M19 12l1 6M6 20h12",
  dashboard:
    "M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7zM5 5v3h3V5zM16 5v3h3V5zM5 16v3h3v-3zM16 16v3h3v-3z",
  river:
    "M2 12c2-3 4-3 6 0s4 3 6 0 4-3 6 0M2 17c2-3 4-3 6 0s4 3 6 0 4-3 6 0M2 7c2-3 4-3 6 0s4 3 6 0 4-3 6 0",
};
for (const [id, path] of Object.entries(BUILTIN_ICON_PATHS)) {
  pluginIconMap.set(id, path);
}

/** Get SVG path for a plugin icon. Returns undefined for unknown icons. */
export function getPluginIconPath(icon: string): string | undefined {
  return pluginIconMap.get(icon);
}

/** Register a custom icon SVG path. Returns dispose function that restores the previous value. */
export function registerPluginIcon(
  icon: string,
  svgPath: string,
): () => void {
  const previous = pluginIconMap.get(icon);
  pluginIconMap.set(icon, svgPath);
  return () => {
    if (previous !== undefined) {
      pluginIconMap.set(icon, previous);
    } else {
      pluginIconMap.delete(icon);
    }
  };
}

/** @deprecated Use getPluginIconPath(). Kept for backward compatibility. */
export const PLUGIN_ICONS: Record<string, string> = new Proxy(
  {} as Record<string, string>,
  {
    get(target, prop: string, receiver: unknown) {
      if (typeof prop === "symbol") return Reflect.get(target, prop, receiver);
      // Fall through to Object.prototype for inherited methods (toString, valueOf, etc.)
      if (!pluginIconMap.has(prop) && prop in Object.prototype) {
        return Reflect.get(target, prop, receiver);
      }
      return pluginIconMap.get(prop);
    },
    ownKeys() {
      return Array.from(pluginIconMap.keys());
    },
    getOwnPropertyDescriptor(_target, prop: string) {
      if (pluginIconMap.has(prop)) {
        return {
          configurable: true,
          enumerable: true,
          value: pluginIconMap.get(prop),
        };
      }
      return undefined;
    },
    has(_target, prop: string) {
      return pluginIconMap.has(prop) || prop in Object.prototype;
    },
    set(target, prop: string, value: string, receiver: unknown) {
      if (typeof prop === "symbol") {
        return Reflect.set(target, prop, value, receiver);
      }
      pluginIconMap.set(prop, value);
      return true;
    },
    deleteProperty(target, prop: string) {
      if (typeof prop === "symbol") {
        return Reflect.deleteProperty(target, prop);
      }
      return pluginIconMap.delete(prop);
    },
  },
);
