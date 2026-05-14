/**
 * Plugin Installer
 *
 * Orchestration layer that composes PluginRegistry and PluginLoader
 * to provide a complete install/uninstall lifecycle.
 *
 * installPlugin: register manifest -> load plugin (trust check, contribution routing, activate)
 * uninstallPlugin: deactivate plugin -> unregister manifest
 *
 * These are standalone functions, not a class. They compose the registry
 * and loader singletons by default, with DI options for testing.
 */

import { PluginRegistry, pluginRegistry } from "./plugin-registry";
import { PluginLoader, pluginLoader } from "./plugin-loader";
import type { PluginManifest, PluginPermission, NetworkPermission } from "./types";

// ---- Types ----

/**
 * Callback invoked before installing a community plugin with declared permissions.
 * Receives the manifest and its permissions for the operator to review.
 * Return true to approve installation, false to reject.
 */
export type PermissionPromptCallback = (
  manifest: PluginManifest,
  permissions: (PluginPermission | NetworkPermission)[],
) => Promise<boolean>;

/**
 * Options for install/uninstall functions.
 * Allows dependency injection of registry and loader for testing.
 */
export interface InstallOptions {
  /** Plugin registry instance (defaults to singleton). */
  registry?: PluginRegistry;
  /** Plugin loader instance (defaults to singleton). */
  loader?: PluginLoader;
  /**
   * Permission prompt callback. Called before installing a community plugin
   * with declared permissions. If the callback returns false, installation
   * is aborted with an error.
   */
  onPermissionPrompt?: PermissionPromptCallback;
}

// ---- Install ----

/**
 * Install a plugin by registering its manifest and loading it.
 *
 * Orchestrates the full install lifecycle:
 * 1. Register the manifest in the plugin registry (validates, sets state to "installed")
 * 2. Load the plugin via PluginLoader (trust check, contribution routing, activate)
 *
 * On error during loadPlugin, the loader itself sets state to "error",
 * so no additional cleanup is needed here -- the plugin stays registered
 * with error state so the user can see what went wrong.
 *
 * Throws PluginRegistrationError if the manifest is invalid or the ID is already registered.
 */
export async function installPlugin(
  manifest: PluginManifest,
  options?: InstallOptions,
): Promise<void> {
  const registry = options?.registry ?? pluginRegistry;
  const loader = options?.loader ?? pluginLoader;
  const onPermissionPrompt = options?.onPermissionPrompt;

  // Permission prompt for community plugins with declared permissions
  if (
    manifest.trust === "community" &&
    manifest.permissions &&
    manifest.permissions.length > 0 &&
    onPermissionPrompt
  ) {
    const approved = await onPermissionPrompt(manifest, manifest.permissions);
    if (!approved) {
      throw new Error(
        "Installation cancelled: permissions not approved by operator",
      );
    }
  }

  // Register the manifest (validates + checks for duplicates)
  // Throws PluginRegistrationError on failure
  registry.register(manifest);

  // Load the plugin (trust gate -> resolve module -> route contributions -> activate)
  await loader.loadPlugin(manifest.id);
}

// ---- Uninstall ----

/**
 * Uninstall a plugin by deactivating it and removing it from the registry.
 *
 * Orchestrates the full uninstall lifecycle:
 * 1. Check if the plugin exists in the registry -- if not, return early (no-op)
 * 2. Deactivate the plugin via PluginLoader (cleanup contributions, call deactivate)
 * 3. Unregister the plugin from the registry (removes entry, emits "unregistered" event)
 */
export async function uninstallPlugin(
  pluginId: string,
  options?: InstallOptions,
): Promise<void> {
  const registry = options?.registry ?? pluginRegistry;
  const loader = options?.loader ?? pluginLoader;

  // Check if plugin exists -- no-op if not found
  const plugin = registry.get(pluginId);
  if (!plugin) {
    return;
  }

  // Deactivate the plugin (cleanup contributions and set state to "deactivated")
  await loader.deactivatePlugin(pluginId);

  // Unregister the plugin from the registry
  registry.unregister(pluginId);
}
