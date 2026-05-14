/**
 * createPlugin Factory
 *
 * The createPlugin() function is an identity function that provides type
 * checking at the call site. When a plugin author writes:
 *
 * ```typescript
 * export default createPlugin({
 *   manifest: { id: "my.plugin", ... },
 *   activate(ctx) { ctx.commands.register(...); },
 *   deactivate() { ... },
 * });
 * ```
 *
 * TypeScript enforces that:
 * - `manifest` matches `PluginManifest`
 * - `activate` receives `PluginContext`
 * - Return type is `Disposable[] | void`
 * - `deactivate` is optional
 */

import type { PluginManifest, Disposable } from "./types";
import type { PluginContext } from "./context";

/**
 * A fully-defined plugin with manifest and lifecycle hooks.
 * Created via the `createPlugin()` factory.
 */
export interface PluginDefinition {
  /** The plugin's manifest declaration. */
  manifest: PluginManifest;
  /**
   * Called when the plugin is activated. Receives a PluginContext with
   * namespaced APIs for registering contributions. May return an array
   * of disposables for cleanup on deactivation.
   */
  activate(context: PluginContext): Disposable[] | void;
  /**
   * Optional cleanup hook called when the plugin is deactivated.
   */
  deactivate?(): void;
}

/**
 * Create a type-safe plugin definition.
 *
 * This is an identity function -- it returns the definition unchanged.
 * Its purpose is to provide TypeScript inference and validation at the
 * call site so plugin authors get full autocompletion and error checking.
 *
 * @param definition - The plugin definition with manifest and lifecycle hooks
 * @returns The same definition, typed as PluginDefinition
 */
export function createPlugin(definition: PluginDefinition): PluginDefinition {
  return definition;
}
