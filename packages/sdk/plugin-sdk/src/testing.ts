import type {
  Disposable,
  ComponentType,
  PluginContributions,
  CommandContribution,
  GuardContribution,
  FileTypeContribution,
  StatusBarItemContribution,
  ActivityBarItemContribution,
  EditorTabViewContribution,
  BottomPanelTabViewContribution,
  RightSidebarPanelViewContribution,
  StatusBarWidgetViewContribution,
} from "./types";

import type {
  PluginContext,
  StorageApi,
  SecretsApi,
} from "./context";

import type { PluginDefinition } from "./create-plugin";

import {
  validateManifest,
  createTestManifest,
  type ManifestValidationError,
  type ManifestValidationResult,
} from "./manifest-validation";


export { createTestManifest, type ManifestValidationError, type ManifestValidationResult };


export class MockStorageApi implements StorageApi {
  private _store = new Map<string, unknown>();

  get(key: string): unknown {
    return this._store.get(key);
  }

  set(key: string, value: unknown): void {
    this._store.set(key, value);
  }

  entries(): Array<[string, unknown]> {
    return Array.from(this._store.entries());
  }

  clear(): void {
    this._store.clear();
  }
}


export class MockSecretsApi implements SecretsApi {
  private _store = new Map<string, string>();

  get(key: string): Promise<string | null> {
    return Promise.resolve(this._store.get(key) ?? null);
  }

  set(key: string, value: string): Promise<void> {
    this._store.set(key, value);
    return Promise.resolve();
  }

  delete(key: string): Promise<void> {
    this._store.delete(key);
    return Promise.resolve();
  }

  has(key: string): Promise<boolean> {
    return Promise.resolve(this._store.has(key));
  }
}


export interface SpyData {
  commands: { registered: Array<{ contribution: CommandContribution; handler: () => void }> };
  guards: { registered: GuardContribution[] };
  fileTypes: { registered: FileTypeContribution[] };
  statusBar: { registered: StatusBarItemContribution[] };
  sidebar: { registered: ActivityBarItemContribution[] };
  views: {
    editorTabs: EditorTabViewContribution[];
    bottomPanelTabs: BottomPanelTabViewContribution[];
    rightSidebarPanels: RightSidebarPanelViewContribution[];
    statusBarWidgets: StatusBarWidgetViewContribution[];
  };
  enrichmentRenderers: { registered: Array<{ type: string; component: ComponentType }> };
  storage: MockStorageApi;
  secrets: MockSecretsApi;
  subscriptions: Disposable[];
}

export interface SpyContext {
  ctx: PluginContext;
  spy: SpyData;
}


const noop: Disposable = () => {};


export function createMockContext(overrides?: Partial<PluginContext>): PluginContext {
  return {
    pluginId: "test.plugin",
    subscriptions: [],
    commands: {
      register: (_command: CommandContribution, _handler: () => void): Disposable => noop,
    },
    guards: {
      register: (_guard: GuardContribution): Disposable => noop,
    },
    fileTypes: {
      register: (_fileType: FileTypeContribution): Disposable => noop,
    },
    statusBar: {
      register: (_item: StatusBarItemContribution): Disposable => noop,
    },
    sidebar: {
      register: (_item: ActivityBarItemContribution): Disposable => noop,
    },
    storage: new MockStorageApi(),
    views: {
      registerEditorTab: (_contribution: EditorTabViewContribution): Disposable => noop,
      registerBottomPanelTab: (_contribution: BottomPanelTabViewContribution): Disposable => noop,
      registerRightSidebarPanel: (_contribution: RightSidebarPanelViewContribution): Disposable => noop,
      registerStatusBarWidget: (_contribution: StatusBarWidgetViewContribution): Disposable => noop,
    },
    secrets: new MockSecretsApi(),
    enrichmentRenderers: {
      register: (_type: string, _component: ComponentType): Disposable => noop,
    },
    ...overrides,
  };
}


function makeRemovingDisposable<T>(arr: T[], item: T): Disposable {
  return () => {
    const idx = arr.indexOf(item);
    if (idx !== -1) {
      arr.splice(idx, 1);
    }
  };
}

/**
 * Overrides merge on top -- overridden APIs will NOT have spy tracking.
 */
export function createSpyContext(overrides?: Partial<PluginContext>): SpyContext {
  const commandsRegistered: Array<{ contribution: CommandContribution; handler: () => void }> = [];
  const guardsRegistered: GuardContribution[] = [];
  const fileTypesRegistered: FileTypeContribution[] = [];
  const statusBarRegistered: StatusBarItemContribution[] = [];
  const sidebarRegistered: ActivityBarItemContribution[] = [];
  const editorTabs: EditorTabViewContribution[] = [];
  const bottomPanelTabs: BottomPanelTabViewContribution[] = [];
  const rightSidebarPanels: RightSidebarPanelViewContribution[] = [];
  const statusBarWidgets: StatusBarWidgetViewContribution[] = [];
  const enrichmentRenderersRegistered: Array<{ type: string; component: ComponentType }> = [];
  const storage = new MockStorageApi();
  const secrets = new MockSecretsApi();
  const subscriptions: Disposable[] = [];

  const ctx: PluginContext = {
    pluginId: "test.plugin",
    subscriptions,
    commands: {
      register: (command: CommandContribution, handler: () => void): Disposable => {
        const entry = { contribution: command, handler };
        commandsRegistered.push(entry);
        return makeRemovingDisposable(commandsRegistered, entry);
      },
    },
    guards: {
      register: (guard: GuardContribution): Disposable => {
        guardsRegistered.push(guard);
        return makeRemovingDisposable(guardsRegistered, guard);
      },
    },
    fileTypes: {
      register: (fileType: FileTypeContribution): Disposable => {
        fileTypesRegistered.push(fileType);
        return makeRemovingDisposable(fileTypesRegistered, fileType);
      },
    },
    statusBar: {
      register: (item: StatusBarItemContribution): Disposable => {
        statusBarRegistered.push(item);
        return makeRemovingDisposable(statusBarRegistered, item);
      },
    },
    sidebar: {
      register: (item: ActivityBarItemContribution): Disposable => {
        sidebarRegistered.push(item);
        return makeRemovingDisposable(sidebarRegistered, item);
      },
    },
    storage,
    views: {
      registerEditorTab: (contribution: EditorTabViewContribution): Disposable => {
        editorTabs.push(contribution);
        return makeRemovingDisposable(editorTabs, contribution);
      },
      registerBottomPanelTab: (contribution: BottomPanelTabViewContribution): Disposable => {
        bottomPanelTabs.push(contribution);
        return makeRemovingDisposable(bottomPanelTabs, contribution);
      },
      registerRightSidebarPanel: (contribution: RightSidebarPanelViewContribution): Disposable => {
        rightSidebarPanels.push(contribution);
        return makeRemovingDisposable(rightSidebarPanels, contribution);
      },
      registerStatusBarWidget: (contribution: StatusBarWidgetViewContribution): Disposable => {
        statusBarWidgets.push(contribution);
        return makeRemovingDisposable(statusBarWidgets, contribution);
      },
    },
    secrets,
    enrichmentRenderers: {
      register: (type: string, component: ComponentType): Disposable => {
        const entry = { type, component };
        enrichmentRenderersRegistered.push(entry);
        return makeRemovingDisposable(enrichmentRenderersRegistered, entry);
      },
    },
    ...overrides,
  };

  const spy: SpyData = {
    commands: { registered: commandsRegistered },
    guards: { registered: guardsRegistered },
    fileTypes: { registered: fileTypesRegistered },
    statusBar: { registered: statusBarRegistered },
    sidebar: { registered: sidebarRegistered },
    views: {
      editorTabs,
      bottomPanelTabs,
      rightSidebarPanels,
      statusBarWidgets,
    },
    enrichmentRenderers: { registered: enrichmentRenderersRegistered },
    storage,
    secrets,
    subscriptions,
  };

  return { ctx, spy };
}


export function assertContributions(
  plugin: PluginDefinition,
  expected: Partial<Record<keyof PluginContributions, number>>,
): void {
  const contributions = plugin.manifest.contributions;
  const mismatches: string[] = [];

  for (const [key, expectedCount] of Object.entries(expected)) {
    const actual = (contributions?.[key as keyof PluginContributions] as unknown[] | undefined) ?? [];
    const actualCount = actual.length;
    if (actualCount !== expectedCount) {
      mismatches.push(`${key}: expected ${expectedCount}, got ${actualCount}`);
    }
  }

  if (mismatches.length > 0) {
    throw new Error("Contribution count mismatch:\n" + mismatches.join("\n"));
  }
}

export function assertManifestValid(manifest: unknown): void {
  const result = validateManifest(manifest);
  if (!result.valid) {
    throw new Error(
      `Invalid manifest (${result.errors.length} error(s)):\n` +
        result.errors.map((e) => `  - ${e.field}: ${e.message}`).join("\n"),
    );
  }
}
