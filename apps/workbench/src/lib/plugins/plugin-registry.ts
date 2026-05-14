/**
 * Plugin Registry
 *
 * Central authority for plugin state in the ClawdStrike workbench.
 * Tracks all known plugins with lifecycle states, emits typed events,
 * and supports contribution-type filtering.
 *
 * Ported from the Athas ExtensionRegistry pattern (Map-based singleton),
 * consistent with guard-registry.ts and other Phase 1 registries.
 *
 * The loader (Phase 3) registers plugins here, the SDK (Phase 4) reads
 * from it, and the marketplace UI (Phase 6) displays its contents.
 */

import type {
  PluginManifest,
  RegisteredPlugin,
  PluginLifecycleState,
  ContributionPointType,
} from "./types";
import {
  validateManifest,
  type ManifestValidationError,
} from "./manifest-validation";

// ---- Event Types ----

/** Event types emitted by the PluginRegistry. */
export type PluginRegistryEventType =
  | "registered"
  | "unregistered"
  | "stateChanged";

/** Event payload for PluginRegistry events. */
export interface PluginRegistryEvent {
  /** The type of event that occurred. */
  type: PluginRegistryEventType;
  /** The plugin ID this event pertains to. */
  pluginId: string;
  /** The registered plugin snapshot (present for "registered" events). */
  plugin?: RegisteredPlugin;
  /** Previous lifecycle state (present for "stateChanged" events). */
  oldState?: PluginLifecycleState;
  /** New lifecycle state (present for "stateChanged" events). */
  newState?: PluginLifecycleState;
}

/** Callback signature for PluginRegistry event subscribers. */
export type PluginRegistryCallback = (event: PluginRegistryEvent) => void;

// ---- Error Types ----

/**
 * Error thrown when plugin registration fails due to validation or
 * duplicate ID. Includes the validation errors if applicable.
 */
export class PluginRegistrationError extends Error {
  /** Validation errors from manifest validation, if any. */
  validationErrors?: ManifestValidationError[];

  constructor(message: string, validationErrors?: ManifestValidationError[]) {
    super(message);
    this.name = "PluginRegistrationError";
    this.validationErrors = validationErrors;
  }
}

// ---- PluginRegistry ----

/**
 * The PluginRegistry is the central authority for plugin state.
 * It stores registered plugins in a Map keyed by plugin ID, tracks
 * lifecycle states, and emits events to subscribers.
 *
 * Exported as both the class (for fresh instances in tests) and
 * a singleton (`pluginRegistry`).
 */
export class PluginRegistry {
  private plugins = new Map<string, RegisteredPlugin>();
  private listeners = new Map<
    PluginRegistryEventType,
    Set<PluginRegistryCallback>
  >();

  // ---- Registration ----

  /**
   * Register a plugin by its manifest.
   *
   * Validates the manifest via `validateManifest()`. If invalid, throws
   * a `PluginRegistrationError` with the accumulated validation errors.
   * If a plugin with the same ID is already registered, throws a
   * `PluginRegistrationError` mentioning the duplicate ID.
   *
   * On success, the plugin is stored with state "installed" and an
   * `installedAt` timestamp. A "registered" event is emitted.
   */
  register(manifest: PluginManifest): void {
    // Validate the manifest
    const result = validateManifest(manifest);
    if (!result.valid) {
      throw new PluginRegistrationError(
        `Invalid plugin manifest: ${result.errors.map((e) => `${e.field}: ${e.message}`).join("; ")}`,
        result.errors,
      );
    }

    // Check for duplicates
    if (this.plugins.has(manifest.id)) {
      throw new PluginRegistrationError(
        `Plugin '${manifest.id}' is already registered`,
      );
    }

    // Create the registered plugin entry
    const registered: RegisteredPlugin = {
      manifest,
      state: "installed",
      installedAt: Date.now(),
    };

    this.plugins.set(manifest.id, registered);

    // Emit "registered" event
    this.emit({
      type: "registered",
      pluginId: manifest.id,
      plugin: registered,
    });
  }

  // ---- Unregistration ----

  /**
   * Unregister a plugin by ID.
   * No-op if the plugin is not found (does not throw).
   * Emits an "unregistered" event if the plugin existed.
   */
  unregister(id: string): void {
    const plugin = this.plugins.get(id);
    if (!plugin) {
      return;
    }

    this.plugins.delete(id);

    this.emit({
      type: "unregistered",
      pluginId: id,
      plugin,
    });
  }

  // ---- Query ----

  /**
   * Get a registered plugin by ID.
   * Returns undefined if not found.
   */
  get(id: string): RegisteredPlugin | undefined {
    return this.plugins.get(id);
  }

  /**
   * Get all registered plugins as an array.
   */
  getAll(): RegisteredPlugin[] {
    return Array.from(this.plugins.values());
  }

  /**
   * Get all plugins that declare a non-empty contribution of the given type.
   *
   * For example, `getByContributionType("guards")` returns only plugins
   * whose manifest has a non-empty `contributions.guards` array.
   */
  getByContributionType(type: ContributionPointType): RegisteredPlugin[] {
    return this.getAll().filter((plugin) => {
      const contributions = plugin.manifest.contributions;
      if (!contributions) return false;
      const arr = contributions[type];
      return Array.isArray(arr) && arr.length > 0;
    });
  }

  // ---- Lifecycle ----

  /**
   * Set the lifecycle state of a registered plugin.
   *
   * Throws if the plugin is not found. If the new state is "activated",
   * sets the `activatedAt` timestamp. If the new state is "error" and
   * an error message is provided, stores it on the plugin.
   *
   * Emits a "stateChanged" event with the old and new states.
   */
  setState(id: string, state: PluginLifecycleState, error?: string): void {
    const plugin = this.plugins.get(id);
    if (!plugin) {
      throw new Error(`Plugin '${id}' is not registered`);
    }

    const oldState = plugin.state;
    plugin.state = state;

    if (state === "activated") {
      plugin.activatedAt = Date.now();
    }

    if (state === "error" && error !== undefined) {
      plugin.error = error;
    }

    this.emit({
      type: "stateChanged",
      pluginId: id,
      plugin,
      oldState,
      newState: state,
    });
  }

  // ---- Events ----

  /**
   * Subscribe to a registry event type. Returns a dispose function
   * that removes the subscription.
   */
  subscribe(
    eventType: PluginRegistryEventType,
    callback: PluginRegistryCallback,
  ): () => void {
    let listeners = this.listeners.get(eventType);
    if (!listeners) {
      listeners = new Set();
      this.listeners.set(eventType, listeners);
    }
    listeners.add(callback);

    return () => {
      listeners!.delete(callback);
    };
  }

  // ---- Reset ----

  /**
   * Clear all plugins from the registry. Emits an "unregistered" event
   * for each plugin before clearing. Useful for tests and hot reload.
   */
  reset(): void {
    // Emit unregistered for each plugin before clearing
    for (const [id, plugin] of this.plugins) {
      this.emit({
        type: "unregistered",
        pluginId: id,
        plugin,
      });
    }
    this.plugins.clear();
  }

  // ---- Private ----

  private emit(event: PluginRegistryEvent): void {
    const listeners = this.listeners.get(event.type);
    if (listeners) {
      for (const callback of listeners) {
        callback(event);
      }
    }
  }
}

// ---- Singleton ----

/** Singleton PluginRegistry instance for the workbench. */
export const pluginRegistry = new PluginRegistry();
