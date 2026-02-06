export type { Policy } from './policy/schema.js';
export { loadPolicyFromFile, loadPolicyFromString } from './policy/loader.js';
export { validatePolicy } from './policy/validator.js';
export type { PolicyLoadOptions } from './policy/loader.js';

export type { PolicyEngineOptions } from './engine.js';
export { createPolicyEngine, createPolicyEngineFromPolicy } from './engine.js';
export type { PolicyEngineFromPolicyOptions } from './engine.js';

export type { CustomGuard, CustomGuardFactory } from './custom-registry.js';
export { CustomGuardRegistry } from './custom-registry.js';

export type {
  PluginCapabilities,
  PluginGuardHandle,
  PluginGuardManifestEntry,
  PluginManifest,
  PluginResourceLimits,
  PluginVersionCompatibility,
} from './plugins/manifest.js';
export { parsePluginManifest } from './plugins/manifest.js';
export type {
  PluginExecutionMode,
  PluginInspectResult,
  PluginLoadResult,
  PluginLoaderOptions,
  PluginResolveOptions,
} from './plugins/loader.js';
export {
  inspectPlugin,
  loadTrustedPluginIntoRegistry,
  PluginLoader,
  resolvePluginRoot,
} from './plugins/loader.js';
