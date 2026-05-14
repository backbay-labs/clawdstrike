/**
 * Sandbox Module Barrel Export
 *
 * Re-exports the complete sandbox public API: the PluginSandbox component,
 * the srcdoc builder function, and the CSP constant.
 */

export { PluginSandbox } from "./plugin-sandbox";
export type { PluginSandboxProps } from "./plugin-sandbox";
export { buildPluginSrcdoc, PLUGIN_CSP } from "./srcdoc-builder";
export type { SrcdocOptions } from "./srcdoc-builder";
