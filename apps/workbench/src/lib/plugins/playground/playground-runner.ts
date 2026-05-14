import { createPlugin } from "../plugin-sdk-shim";
import { transpilePlugin } from "./playground-transpiler";
import {
  getPlaygroundState,
  setRunning,
  clearErrors,
  incrementRunCount,
  addError,
  setTranspiled,
  setContributions,
  setLastRunTimestamp,
  addConsoleEntry,
} from "./playground-store";
import type { PlaygroundError, ContributionSnapshot } from "./playground-store";
import { pluginLoader } from "../plugin-loader";
import { pluginRegistry } from "../plugin-registry";
import { clearSnapshot } from "../dev/storage-snapshot";
import type { PluginManifest } from "../types";

declare global {
  interface Window {
    __PLAYGROUND_CONSOLE__?: Record<string, (...args: unknown[]) => void>;
    __CLAWDSTRIKE_PLUGIN_SDK__?: { createPlugin: typeof createPlugin };
    __PLAYGROUND_PLUGIN__?: {
      manifest?: PluginManifest;
      activate?: unknown;
      deactivate?: unknown;
    };
  }
}

const PLAYGROUND_PLUGIN_ID = "__playground__";

export function setupConsoleProxy(): () => void {
  const proxy: Record<string, (...args: unknown[]) => void> = {};
  const levels = ["log", "warn", "error", "info"] as const;

  for (const level of levels) {
    proxy[level] = (...args: unknown[]) => {
      // eslint-disable-next-line no-console
      console[level](...args);
      addConsoleEntry({
        level,
        args,
        timestamp: Date.now(),
      });
    };
  }

  window.__PLAYGROUND_CONSOLE__ = proxy;

  return () => {
    delete window.__PLAYGROUND_CONSOLE__;
  };
}

export async function runPlaygroundPlugin(): Promise<void> {
  const { source, runCount } = getPlaygroundState();
  const currentRunCount = runCount + 1;

  setRunning(true);
  clearErrors();
  incrementRunCount();

  const cleanupConsole = setupConsoleProxy();

  try {
    const { code, error } = transpilePlugin(source);
    if (error) {
      addError(error);
      setRunning(false);
      cleanupConsole();
      return;
    }

    setTranspiled(code);

    const response = await fetch("/__plugin-eval/", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, runId: currentRunCount }),
    });

    if (!response.ok) {
      const errBody = await response.json().catch(() => ({ error: "Failed to store code" }));
      addError({ message: (errBody as { error?: string }).error ?? "Eval server error" });
      setRunning(false);
      cleanupConsole();
      return;
    }

    const { url: evalUrl } = (await response.json()) as { url: string };

    try {
      const existing = pluginRegistry.get(PLAYGROUND_PLUGIN_ID);
      if (existing) {
        await pluginLoader.deactivatePlugin(PLAYGROUND_PLUGIN_ID);
        pluginRegistry.unregister(PLAYGROUND_PLUGIN_ID);
      }
    } catch {
      // Best-effort cleanup of previous instance
    }

    clearSnapshot(PLAYGROUND_PLUGIN_ID);

    window.__CLAWDSTRIKE_PLUGIN_SDK__ = { createPlugin };

    // TS control-flow narrows __PLAYGROUND_PLUGIN__ to never after delete,
    // so we read via bracket notation to bypass narrowing.
    delete window.__PLAYGROUND_PLUGIN__;
    await import(/* @vite-ignore */ evalUrl);

    type PluginDefShape = { manifest?: PluginManifest; activate?: unknown; deactivate?: unknown };
    const pluginDef = (window as unknown as Record<string, PluginDefShape | undefined>).__PLAYGROUND_PLUGIN__;
    const defManifest = pluginDef?.manifest;

    if (!defManifest) {
      addError({
        message: "Plugin did not export a valid definition. Make sure your plugin uses: export default createPlugin({ ... })",
      });
      setRunning(false);
      cleanupConsole();
      return;
    }

    const manifest: PluginManifest = {
      ...defManifest,
      id: PLAYGROUND_PLUGIN_ID,
      trust: "internal",
    };

    pluginRegistry.register(manifest);
    await pluginLoader.loadPlugin(PLAYGROUND_PLUGIN_ID);

    const contributions = manifest.contributions;
    const snapshot: ContributionSnapshot = {
      guards: contributions?.guards?.map((g) => g.name ?? g.id) ?? [],
      commands: contributions?.commands?.map((c) => c.title ?? c.id) ?? [],
      fileTypes: contributions?.fileTypes?.map((f) => f.label ?? f.id) ?? [],
      editorTabs: contributions?.editorTabs?.map((t) => t.label ?? t.id) ?? [],
      bottomPanelTabs: contributions?.bottomPanelTabs?.map((t) => t.label ?? t.id) ?? [],
      rightSidebarPanels: contributions?.rightSidebarPanels?.map((p) => p.label ?? p.id) ?? [],
      statusBarItems: contributions?.statusBarItems?.map((s) => s.id) ?? [],
    };
    setContributions(snapshot);
    setLastRunTimestamp(Date.now());
    setRunning(false);
  } catch (err: unknown) {
    const playgroundError: PlaygroundError = {
      message: err instanceof Error ? err.message : String(err),
      stack: err instanceof Error ? err.stack : undefined,
    };
    addError(playgroundError);
    setRunning(false);
    cleanupConsole();
  }
}
