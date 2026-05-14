/**
 * EgressAllowlistGuard Plugin
 *
 * Demonstrates extracting a built-in guard into a standalone plugin using
 * the createPlugin() factory from @clawdstrike/plugin-sdk.
 *
 * The guard contribution declares identical metadata to the built-in
 * egress_allowlist guard (name, description, category, icon, configFields)
 * but uses a distinct ID ("egress_allowlist_plugin") to avoid collision
 * with the built-in guard that is auto-registered at module load time.
 *
 * This proves the full pipeline: SDK -> manifest -> loader -> guard registry -> config UI.
 */

import { createPlugin } from "../plugin-sdk-shim";
import type { PluginContext, GuardContribution, ConfigFieldDef } from "../plugin-sdk-shim";

const EGRESS_CONFIG_FIELDS: ConfigFieldDef[] = [
  { key: "enabled", label: "Enabled", type: "toggle", defaultValue: true },
  { key: "allow", label: "Allowed Domains", type: "string_list", description: "Domain patterns to allow (supports wildcards like *.openai.com)" },
  { key: "block", label: "Blocked Domains", type: "string_list", description: "Domain patterns to block (takes precedence over allow)" },
  { key: "default_action", label: "Default Action", type: "select", defaultValue: "block", options: [{ value: "allow", label: "Allow" }, { value: "block", label: "Block" }, { value: "log", label: "Log" }] },
];

const EGRESS_GUARD: GuardContribution = {
  id: "egress_allowlist_plugin",
  name: "Egress Control",
  technicalName: "EgressAllowlistGuard",
  description: "Controls network egress by domain. Block unknown endpoints, allow trusted APIs and registries.",
  category: "network",
  defaultVerdict: "deny",
  icon: "IconNetwork",
  configFields: EGRESS_CONFIG_FIELDS,
};

export default createPlugin({
  manifest: {
    id: "clawdstrike.egress-guard-plugin",
    name: "egress-guard-plugin",
    displayName: "Egress Guard Plugin",
    description: "EgressAllowlistGuard extracted as a plugin to demonstrate guard contribution points.",
    version: "1.0.0",
    publisher: "clawdstrike",
    categories: ["guards"],
    trust: "internal",
    activationEvents: ["onStartup"],
    main: "./egress-guard-plugin.ts",
    contributions: {
      guards: [EGRESS_GUARD],
    },
  },
  activate(ctx: PluginContext) {
    // The PluginLoader already routes contributions from the manifest to
    // registries BEFORE calling activate(). This means the guard is already
    // registered by the time activate() runs. The activate() hook is for
    // additional setup (e.g., event listeners, state initialization).
    //
    // If the plugin were loaded outside the PluginLoader (e.g., standalone),
    // it could self-register via ctx.guards.register(EGRESS_GUARD).
  },
});
