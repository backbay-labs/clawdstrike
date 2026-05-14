/**
 * Plugin Context
 *
 * Defines the PluginContext interface and its namespaced API surfaces.
 * The PluginContext is provided to a plugin's activate() function by the
 * workbench PluginLoader at activation time. The SDK only defines the shape --
 * the workbench creates concrete implementations.
 */

import type {
  Disposable,
  ComponentType,
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

// ---- Namespaced API Interfaces ----

/**
 * API for registering commands in the command palette.
 */
export interface CommandsApi {
  /** Register a command with a handler. Returns a disposable to unregister. */
  register(command: CommandContribution, handler: () => void): Disposable;
}

/**
 * API for registering custom guards in the guard pipeline.
 */
export interface GuardsApi {
  /** Register a guard contribution. Returns a disposable to unregister. */
  register(guard: GuardContribution): Disposable;
}

/**
 * API for registering custom file types for detection engineering.
 */
export interface FileTypesApi {
  /** Register a file type contribution. Returns a disposable to unregister. */
  register(fileType: FileTypeContribution): Disposable;
}

/**
 * API for registering status bar items.
 */
export interface StatusBarApi {
  /** Register a status bar item. Returns a disposable to unregister. */
  register(item: StatusBarItemContribution): Disposable;
}

/**
 * API for registering activity bar (left sidebar) items.
 */
export interface SidebarApi {
  /** Register an activity bar item. Returns a disposable to unregister. */
  register(item: ActivityBarItemContribution): Disposable;
}

/**
 * API for plugin-scoped key-value storage.
 */
export interface StorageApi {
  /** Retrieve a value by key. Returns undefined if not set. */
  get(key: string): unknown;
  /** Set a value by key. */
  set(key: string, value: unknown): void;
}

/**
 * API for registering plugin-contributed views in workbench UI slots.
 *
 * Each method accepts an SDK view contribution (with a component or lazy factory)
 * and returns a Disposable that unregisters the view. Plugin authors should push
 * the disposable to `ctx.subscriptions` for automatic cleanup on deactivation.
 */
export interface ViewsApi {
  /** Register an editor tab view. */
  registerEditorTab(contribution: EditorTabViewContribution): Disposable;
  /** Register a bottom panel tab view. */
  registerBottomPanelTab(contribution: BottomPanelTabViewContribution): Disposable;
  /** Register a right sidebar panel view. */
  registerRightSidebarPanel(contribution: RightSidebarPanelViewContribution): Disposable;
  /** Register a status bar widget view. */
  registerStatusBarWidget(contribution: StatusBarWidgetViewContribution): Disposable;
}

// ---- Enrichment Renderers API ----

/**
 * API for registering custom enrichment type renderers.
 * Allows plugins to override the generic enrichment display for specific types.
 */
export interface EnrichmentRenderersApi {
  /** Register a custom renderer for an enrichment type. Returns a disposable to unregister. */
  register(type: string, component: ComponentType): Disposable;
}

// ---- Secrets API ----

/**
 * API for plugin-scoped secret/credential storage.
 * Keys are automatically prefixed with `plugin:{pluginId}:` by the workbench.
 * Backed by the secure store (Stronghold on desktop, in-memory fallback on web).
 */
export interface SecretsApi {
  /** Retrieve a secret by key. Returns null if not set. */
  get(key: string): Promise<string | null>;
  /** Store a secret by key. */
  set(key: string, value: string): Promise<void>;
  /** Delete a secret by key. */
  delete(key: string): Promise<void>;
  /** Check if a secret exists for key. */
  has(key: string): Promise<boolean>;
}

// ---- PluginContext ----

/**
 * The context object provided to a plugin's activate() function.
 * Provides namespaced API access to workbench registries and services.
 *
 * The workbench PluginLoader creates concrete implementations of each
 * API surface and injects them here. The SDK only defines the interface shape.
 */
export interface PluginContext {
  /** The ID of the plugin being activated. */
  pluginId: string;
  /** Subscriptions array -- push disposables here for automatic cleanup on deactivate. */
  subscriptions: Disposable[];
  /** Command palette registration API. */
  commands: CommandsApi;
  /** Guard pipeline registration API. */
  guards: GuardsApi;
  /** File type registration API. */
  fileTypes: FileTypesApi;
  /** Status bar registration API. */
  statusBar: StatusBarApi;
  /** Activity bar (left sidebar) registration API. */
  sidebar: SidebarApi;
  /** Plugin-scoped key-value storage API. */
  storage: StorageApi;
  /** View registration API for contributing to UI slots. */
  views: ViewsApi;
  /** Plugin-scoped secret/credential storage API. */
  secrets: SecretsApi;
  /** Enrichment renderer registration API for custom enrichment type display. */
  enrichmentRenderers: EnrichmentRenderersApi;
}
